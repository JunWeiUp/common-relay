// Package server mounts the three cleanly separated planes of Common Relay v2:
//   - /v2/*         Device Kernel Plane (Relay-Access + Device Bearer Token)
//   - /v2/admin/*   Root Admin Control Plane (Relay-Access + Admin Token / Admin Device)
//   - /edge/<id>/*  Pluggable Edge Protocol Plane (per-plugin auth)
package server

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

type Config struct {
	AccessHash      string   // Optional 64-char hex SHA-256 of Relay-Access password
	AccessSource    string   // "file" or "db" (display metadata only)
	AccessUpdatedAt int64    // Optional unix timestamp of last password update
	RootAdminHash   string   // 64-char hex SHA-256 of bootstrap Root Admin secret (for /v2/admin/*)
	SelfServiceAll  bool     // True when --self-service-apps includes "*"
	SelfServiceApps []string // Configured self-service apps list
}

type Server struct {
	Store               *core.Store
	Pipe                *core.PipeHub
	Plugins             *plugin.Host
	OnAccessHashChanged func(hexHash string)
	cfg                 Config
	accessMu            sync.RWMutex
	accessHash          string
	accessSource        string
	accessUpdatedAt     int64
}

func New(store *core.Store, cfg Config) *Server {
	pipe := core.NewPipeHub(store)
	src := cfg.AccessSource
	if src == "" && cfg.AccessHash != "" {
		src = "file"
	}
	return &Server{
		Store:           store,
		Pipe:            pipe,
		Plugins:         plugin.NewHost(store, pipe),
		cfg:             cfg,
		accessHash:      strings.ToLower(strings.TrimSpace(cfg.AccessHash)),
		accessSource:    src,
		accessUpdatedAt: cfg.AccessUpdatedAt,
	}
}

func (s *Server) currentAccessHash() string {
	s.accessMu.RLock()
	h := s.accessHash
	s.accessMu.RUnlock()
	return h
}

func (s *Server) accessMeta() (hash string, source string, updatedAt int64) {
	s.accessMu.RLock()
	hash, source, updatedAt = s.accessHash, s.accessSource, s.accessUpdatedAt
	s.accessMu.RUnlock()
	return
}

func (s *Server) setAccessHash(hexHash string, updatedAt int64) {
	s.accessMu.Lock()
	s.accessHash = hexHash
	s.accessSource = "db"
	s.accessUpdatedAt = updatedAt
	s.accessMu.Unlock()
	if s.OnAccessHashChanged != nil {
		s.OnAccessHashChanged(hexHash)
	}
}

func (s *Server) RegisterPlugin(p plugin.Plugin) error {
	return s.Plugins.Register(p)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.Store.DB.Ping() != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/v2/ws", s.requireAccess(s.handleWS))
	mux.HandleFunc("/v2/me", s.requireAccess(s.handleMe))
	mux.HandleFunc("/v2/admin/", s.requireAccess(s.requireAdmin(s.handleAdmin)))
	mux.HandleFunc("/v2/spaces/", s.requireAccess(s.handleSpaceDevice))
	mux.HandleFunc("/edge/", s.handleEdge)
	return mux
}

/* ───────── Auth Middleware ───────── */

func (s *Server) requireAccess(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if want := s.currentAccessHash(); want != "" {
			got := r.Header.Get("Relay-Access")
			if !plugin.SecretMatchesHash(got, want) {
				http.Error(w, "relay access denied", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if s.cfg.RootAdminHash != "" && plugin.SecretMatchesHash(tok, s.cfg.RootAdminHash) {
			next(w, r)
			return
		}
		dev, err := s.Store.AuthenticateDevice(tok)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !dev.IsAdmin {
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

/* ───────── Edge Plugin Dispatcher (/edge/<plugin>/...) ───────── */

// EdgeMaxBody caps any edge request body; plugins apply their own tighter limits.
const EdgeMaxBody = core.HardBoxMaxBytes + 1<<20

func (s *Server) handleEdge(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/edge/")
	pluginID, subPath, _ := strings.Cut(rest, "/")
	h, ok := s.Plugins.Handler(pluginID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// A panicking plugin must not take its stack trace to the client or leave the
	// response half-written without a log line naming the plugin.
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			log.Printf("edge plugin %s panic: %v\n%s", pluginID, v, debug.Stack())
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/" + subPath
	r2.URL.RawPath = ""
	if r2.Body != nil && r2.Body != http.NoBody {
		r2.Body = http.MaxBytesReader(w, r2.Body, EdgeMaxBody)
	}
	h.ServeHTTP(w, r2)
}

/* ───────── Device Kernel Plane (/v2/ws & /v2/spaces/...) ───────── */

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	dev, err := s.Store.AuthenticateDevice(bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.Pipe.ServeWS(w, r, dev)
}

// handleMe tells a device who it is, so admin tools can add themselves to the
// spaces they create. The Root Admin secret is not a device and gets 404.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok := bearerToken(r)
	dev, err := s.Store.AuthenticateDevice(tok)
	if err != nil {
		if s.cfg.RootAdminHash != "" && plugin.SecretMatchesHash(tok, s.cfg.RootAdminHash) {
			replyJSON(w, http.StatusOK, map[string]any{"ok": true, "root_admin": true})
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	replyJSON(w, http.StatusOK, map[string]any{"ok": true, "device": dev})
}

// Routes under /v2/spaces/{space}/boxes/{box}/...
func (s *Server) handleSpaceDevice(w http.ResponseWriter, r *http.Request) {
	dev, err := s.Store.AuthenticateDevice(bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v2/spaces/")
	spaceID, tail, ok := strings.Cut(rest, "/")
	if !ok || !core.ValidIdent(spaceID) {
		http.NotFound(w, r)
		return
	}
	role, err := s.Store.MemberRole(spaceID, dev.ID)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !strings.HasPrefix(tail, "boxes/") {
		http.NotFound(w, r)
		return
	}
	boxName, action, sub, ok := splitBoxPath(strings.TrimPrefix(tail, "boxes/"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if action == "items" {
		s.handleBoxItems(w, r, dev, role, spaceID, boxName, sub)
	} else {
		s.handleBoxObjects(w, r, role, spaceID, boxName, sub)
	}
}

// splitBoxPath splits "{box...}/items[/{id}]" or "{box...}/objects[/{key...}]"
// on whole path segments. Box names may contain "/" but never a bare "items" or
// "objects" segment (core.ValidBoxName), so the first such segment is the action.
func splitBoxPath(p string) (box, action, sub string, ok bool) {
	segs := strings.Split(p, "/")
	for i := 1; i < len(segs); i++ {
		if segs[i] == "items" || segs[i] == "objects" {
			box = strings.Join(segs[:i], "/")
			if !core.ValidBoxName(box) {
				return "", "", "", false
			}
			sub = strings.Join(segs[i+1:], "/")
			if segs[i] == "items" && strings.Contains(sub, "/") {
				return "", "", "", false
			}
			return box, segs[i], sub, true
		}
	}
	return "", "", "", false
}

func (s *Server) handleBoxItems(w http.ResponseWriter, r *http.Request, dev core.Device, role core.MemberRole, spaceID, boxName, sub string) {
	sub = strings.Trim(sub, "/")
	switch {
	case sub == "" && r.Method == http.MethodGet:
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := s.Store.ListBoxItems(spaceID, boxName, after, limit)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "items": items})

	case sub == "" && r.Method == http.MethodPost:
		if !role.CanWrite() {
			http.Error(w, "read-only role", http.StatusForbidden)
			return
		}
		ttl, _ := strconv.ParseInt(r.URL.Query().Get("ttl"), 10, 64)
		item, err := s.Store.PutBoxItem(spaceID, boxName, dev.ID, r.Header.Get("Content-Type"), r.Header.Get("X-Box-Meta"), ttl, r.Body)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusCreated, map[string]any{"ok": true, "item": item})

	case sub != "" && r.Method == http.MethodGet:
		f, item, err := s.Store.OpenBoxItem(spaceID, boxName, sub)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", item.ContentType)
		w.Header().Set("X-Box-Seq", strconv.FormatInt(item.Seq, 10))
		w.Header().Set("X-Box-SHA256", item.SHA256)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)

	case sub != "" && r.Method == http.MethodDelete:
		if !role.CanWrite() {
			http.Error(w, "read-only role", http.StatusForbidden)
			return
		}
		if err := s.Store.AckBoxItem(spaceID, boxName, sub); err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBoxObjects(w http.ResponseWriter, r *http.Request, role core.MemberRole, spaceID, boxName, sub string) {
	key := strings.Trim(sub, "/")
	switch {
	case key == "" && r.Method == http.MethodGet:
		objs, err := s.Store.ListBoxObjects(spaceID, boxName, r.URL.Query().Get("prefix"))
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "objects": objs})

	case key != "" && r.Method == http.MethodPut:
		if !role.CanWrite() {
			http.Error(w, "read-only observer cannot write", http.StatusForbidden)
			return
		}
		obj, err := s.Store.PutBoxObject(spaceID, boxName, key, r.Header.Get("Content-Type"), r.Header.Get("X-Box-Meta"), r.Header.Get("If-Match"), r.Body)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		w.Header().Set("ETag", `"`+obj.ETag+`"`)
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "object": obj})

	case key != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		if r.URL.Query().Get("versions") == "1" {
			vers, err := s.Store.ListObjectVersions(spaceID, boxName, key)
			if err != nil {
				writeCoreErr(w, err)
				return
			}
			replyJSON(w, http.StatusOK, map[string]any{"ok": true, "versions": vers})
			return
		}
		ver, _ := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
		f, obj, err := s.Store.OpenBoxObject(spaceID, boxName, key, ver)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		defer f.Close()
		etag := `"` + obj.ETag + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Object-Version", strconv.FormatInt(obj.Version, 10))
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Cache-Control", "no-store")
		if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && subtle.ConstantTimeCompare([]byte(strings.Trim(inm, `"`)), []byte(obj.ETag)) == 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)

	case key != "" && r.Method == http.MethodDelete:
		if !role.CanWrite() {
			http.Error(w, "read-only role", http.StatusForbidden)
			return
		}
		if err := s.Store.DeleteBoxObject(spaceID, boxName, key); err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

/* ───────── Admin Control Plane (/v2/admin/...) ───────── */

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v2/admin/"), "/")
	switch {
	case p == "status" && r.Method == http.MethodGet:
		st, err := s.Store.Status(s.Pipe.OnlineCount(), s.Plugins.IDs())
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "status": st})

	case p == "access-password" && r.Method == http.MethodGet:
		h, src, upd := s.accessMeta()
		prefix := ""
		if len(h) >= 8 {
			prefix = h[:8]
		}
		replyJSON(w, http.StatusOK, map[string]any{
			"ok":                true,
			"configured":        h != "",
			"source":            src,
			"hash_prefix":       prefix,
			"updated_at":        upd,
			"self_service_all":  s.cfg.SelfServiceAll,
			"self_service_apps": s.cfg.SelfServiceApps,
		})

	case p == "access-password" && r.Method == http.MethodPut:
		var in struct {
			AccessHash string `json:"access_hash"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		norm := strings.ToLower(strings.TrimSpace(in.AccessHash))
		raw, err := hex.DecodeString(norm)
		if err != nil || len(raw) != 32 || norm != strings.TrimSpace(in.AccessHash) {
			writeCoreErr(w, core.ErrInvalidInput)
			return
		}
		upd, err := s.Store.SetSetting("access_hash", norm)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		s.setAccessHash(norm, upd)
		replyJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"source":      "db",
			"hash_prefix": norm[:8],
			"updated_at":  upd,
		})

	case p == "devices" && r.Method == http.MethodGet:
		list, err := s.Store.ListDevices()
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "devices": list})

	case p == "devices" && r.Method == http.MethodPost:
		var in struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			IsAdmin   bool   `json:"is_admin"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		dev, tok, err := s.Store.CreateDevice(in.ID, in.Name, in.PublicKey, in.IsAdmin)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusCreated, map[string]any{"ok": true, "device": dev, "token": tok})

	case strings.HasPrefix(p, "devices/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(p, "devices/")
		if err := s.Store.RevokeDevice(id); err != nil {
			writeCoreErr(w, err)
			return
		}
		// A revoked device must lose its live /v2/ws session immediately.
		s.Pipe.DisconnectDevice(id)
		replyJSON(w, http.StatusOK, map[string]any{"ok": true})

	case p == "spaces" && r.Method == http.MethodGet:
		list, err := s.Store.ListSpaces()
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		online := s.Pipe.OnlineDeviceSet()
		byMembers, _ := s.Store.ListAllSpaceMembers()
		byBoxes, _ := s.Store.ListAllBoxesWithStats()
		byBytes, _ := s.Store.SpaceUsedBytes()
		for i := range list {
			sid := list[i].ID
			list[i].UsedBytes = byBytes[sid]
			if mems := byMembers[sid]; len(mems) > 0 {
				enriched := make([]core.SpaceMemberView, len(mems))
				for j, m := range mems {
					m.Online = online[m.DeviceID]
					enriched[j] = m
				}
				list[i].Members = enriched
			}
			if boxes := byBoxes[sid]; len(boxes) > 0 {
				list[i].Boxes = boxes
			}
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "spaces": list})

	case p == "spaces" && r.Method == http.MethodPost:
		var in struct {
			ID         string          `json:"id"`
			Name       string          `json:"name"`
			TrustLevel core.TrustLevel `json:"trust_level"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		sp, err := s.Store.CreateSpace(in.ID, in.Name, in.TrustLevel)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusCreated, map[string]any{"ok": true, "space": sp})

	case strings.HasPrefix(p, "spaces/") && strings.HasSuffix(p, "/members") && r.Method == http.MethodPut:
		spaceID := strings.TrimSuffix(strings.TrimPrefix(p, "spaces/"), "/members")
		var in struct {
			DeviceID string          `json:"device_id"`
			Role     core.MemberRole `json:"role"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		mem, err := s.Store.SetSpaceMember(spaceID, in.DeviceID, in.Role)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		// Live sessions snapshot space roles at connect time; force a reconnect so
		// the new role (e.g. downgrade to archive_observer) takes effect at once.
		s.Pipe.DisconnectDevice(in.DeviceID)
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "member": mem})

	case strings.HasPrefix(p, "spaces/") && strings.HasSuffix(p, "/boxes") && r.Method == http.MethodPost:
		spaceID := strings.TrimSuffix(strings.TrimPrefix(p, "spaces/"), "/boxes")
		var in core.Box
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		in.SpaceID = spaceID
		box, err := s.Store.CreateBox(in)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusCreated, map[string]any{"ok": true, "box": box})

	case strings.HasPrefix(p, "spaces/") && strings.HasSuffix(p, "/boxes") && r.Method == http.MethodGet:
		spaceID := strings.TrimSuffix(strings.TrimPrefix(p, "spaces/"), "/boxes")
		boxes, err := s.Store.ListBoxes(spaceID)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "boxes": boxes})

	case p == "plugins" && r.Method == http.MethodGet:
		list, err := s.Plugins.ListBindings(r.URL.Query().Get("plugin_id"))
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		online := s.Pipe.OnlineDeviceSet()
		for i := range list {
			accts, _ := s.Plugins.ListAccounts(list[i].ID)
			list[i] = sanitizePluginBinding(list[i], online, accts)
		}
		replyJSON(w, http.StatusOK, map[string]any{
			"ok": true, "registered": s.Plugins.IDs(), "plugins": s.Plugins.Infos(), "bindings": list,
		})

	case p == "plugins" && r.Method == http.MethodPut:
		// PUT replaces the public config; secret keys omitted from config are kept
		// (write-only), so callers can change settings without re-sending tokens.
		var in struct {
			PluginID  string         `json:"plugin_id"`
			Mount     string         `json:"mount"`
			SpaceID   string         `json:"space_id"`
			BoxName   string         `json:"box_name"`
			Config    map[string]any `json:"config"`
			Enabled   *bool          `json:"enabled"`
			IfVersion int64          `json:"if_version"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		// enabled omitted: new bindings start enabled, existing ones keep their state.
		b, err := s.Plugins.SaveBinding(plugin.BindingUpdate{
			PluginID: in.PluginID, Mount: in.Mount, SpaceID: &in.SpaceID, BoxName: &in.BoxName,
			Enabled: in.Enabled, Config: in.Config, ReplacePublic: true, IfVersion: in.IfVersion,
		})
		s.replyBinding(w, b, err)

	case strings.HasPrefix(p, "plugins/") && strings.Count(p, "/") == 2 && (r.Method == http.MethodGet || r.Method == http.MethodPatch):
		pid, mount, _ := strings.Cut(strings.TrimPrefix(p, "plugins/"), "/")
		if r.Method == http.MethodGet {
			b, err := s.Plugins.GetBinding(pid, mount)
			s.replyBinding(w, b, err)
			return
		}
		// PATCH merges: listed keys are set, null deletes, everything else is kept.
		var in struct {
			SpaceID   *string        `json:"space_id"`
			BoxName   *string        `json:"box_name"`
			Enabled   *bool          `json:"enabled"`
			Config    map[string]any `json:"config"`
			IfVersion int64          `json:"if_version"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if _, err := s.Plugins.GetBinding(pid, mount); err != nil {
			writeCoreErr(w, err) // PATCH never creates a binding
			return
		}
		b, err := s.Plugins.SaveBinding(plugin.BindingUpdate{
			PluginID: pid, Mount: mount, SpaceID: in.SpaceID, BoxName: in.BoxName,
			Enabled: in.Enabled, Config: in.Config, IfVersion: in.IfVersion,
		})
		s.replyBinding(w, b, err)

	case strings.HasPrefix(p, "plugins/") && strings.HasSuffix(p, "/accounts"):
		s.handleAdminPluginAccounts(w, r, p)

	case strings.HasPrefix(p, "plugins/") && r.Method == http.MethodDelete:
		rest := strings.TrimPrefix(p, "plugins/")
		pid, mount, ok := strings.Cut(rest, "/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if err := s.Plugins.DeleteBinding(pid, mount); err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAdminPluginAccounts(w http.ResponseWriter, r *http.Request, p string) {
	rest := strings.TrimSuffix(strings.TrimPrefix(p, "plugins/"), "/accounts")
	pid, mount, ok := strings.Cut(rest, "/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Admin account management must work while the binding is disabled.
	binding, err := s.Plugins.GetBinding(pid, mount)
	if err != nil {
		writeCoreErr(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.Plugins.ListAccounts(binding.ID)
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "accounts": list})

	case http.MethodPut:
		var in struct {
			ScopeKey     string `json:"scope_key"`
			Username     string `json:"username"`
			SecretSHA256 string `json:"secret_sha256"` // legacy: unsalted SHA-256
			Password     string `json:"password"`      // preferred: stored as salted scrypt
			Mode         string `json:"mode"`
			MetaJSON     string `json:"meta_json"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		var acct core.PluginAccount
		switch {
		case in.Password != "" && in.SecretSHA256 != "":
			writeCoreErr(w, core.ErrInvalidInput)
			return
		case in.Password != "":
			acct, err = s.Plugins.UpsertAccountPassword(binding.ID, in.ScopeKey, in.Username, in.Password, in.Mode, in.MetaJSON)
		default:
			acct, err = s.Plugins.UpsertAccount(binding.ID, in.ScopeKey, in.Username, in.SecretSHA256, in.Mode, in.MetaJSON)
		}
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "account": acct})

	case http.MethodDelete:
		scopeKey := r.URL.Query().Get("scope_key")
		if err := s.Plugins.DeleteAccount(binding.ID, scopeKey); err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) replyBinding(w http.ResponseWriter, b core.PluginBinding, err error) {
	if err != nil {
		writeCoreErr(w, err)
		return
	}
	accts, _ := s.Plugins.ListAccounts(b.ID)
	replyJSON(w, http.StatusOK, map[string]any{"ok": true, "binding": sanitizePluginBinding(b, s.Pipe.OnlineDeviceSet(), accts)})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func replyJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeCoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrInvalidInput):
		replyJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, core.ErrDenied):
		replyJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, core.ErrTrustBoundary):
		replyJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, core.ErrNotFound):
		replyJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, core.ErrConflict):
		replyJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, core.ErrQuota):
		replyJSON(w, http.StatusInsufficientStorage, map[string]any{"ok": false, "error": err.Error()})
	default:
		replyJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "storage"})
	}
}

func isSecretConfigKey(k string) bool {
	lk := strings.ToLower(k)
	if lk == plugin.SealPublicKeyField {
		return false // a public key: clients compare it with their own sealing key
	}
	for _, needle := range []string{"secret", "token", "password", "hash", "key"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

func sanitizePluginBinding(b core.PluginBinding, online map[string]bool, accounts []core.PluginAccount) core.PluginBinding {
	var raw map[string]any
	if err := json.Unmarshal([]byte(b.ConfigJSON), &raw); err == nil && raw != nil {
		sum := &core.PluginBindingSummary{}
		hasSum := false
		if v, ok := raw["target_device"].(string); ok && strings.TrimSpace(v) != "" {
			sum.TargetDevice = strings.TrimSpace(v)
			sum.TargetOnline = online[sum.TargetDevice]
			hasSum = true
		}
		if v, ok := raw["public_base"].(string); ok && strings.TrimSpace(v) != "" {
			sum.PublicBase = strings.TrimSpace(v)
			hasSum = true
		}
		if v, ok := raw["tag"].(string); ok && strings.TrimSpace(v) != "" {
			sum.Tag = strings.TrimSpace(v)
			hasSum = true
		}
		// Secrets are write-only: presence comes from the stored secret key list.
		for _, k := range b.SecretKeys {
			switch k {
			case "hmac_secret":
				sum.HasHMAC, hasSum = true, true
			case "token_sha256":
				sum.HasToken, hasSum = true, true
			}
		}
		if arr, ok := raw["cors_origins"].([]any); ok && len(arr) > 0 {
			for _, it := range arr {
				if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
					sum.CORSOrigins = append(sum.CORSOrigins, strings.TrimSpace(s))
				}
			}
			if len(sum.CORSOrigins) > 0 {
				hasSum = true
			}
		}
		if hasSum {
			b.Summary = sum
		}
		safe := make(map[string]any, len(raw))
		for k, v := range raw {
			if !isSecretConfigKey(k) {
				safe[k] = v
			}
		}
		if enc, err := json.Marshal(safe); err == nil {
			b.ConfigJSON = string(enc)
		} else {
			b.ConfigJSON = "{}"
		}
	} else {
		b.ConfigJSON = "{}"
	}
	if len(accounts) > 0 {
		b.Accounts = make([]core.PluginAccountView, 0, len(accounts))
		for _, a := range accounts {
			b.Accounts = append(b.Accounts, core.PluginAccountView{
				ScopeKey: a.ScopeKey,
				Username: a.Username,
				Mode:     a.Mode,
			})
		}
	}
	return b
}

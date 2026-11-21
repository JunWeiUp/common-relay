// Package server mounts the three cleanly separated planes of Common Relay v2:
//   - /v2/*         Device Kernel Plane (Relay-Access + Device Bearer Token)
//   - /v2/admin/*   Root Admin Control Plane (Relay-Access + Admin Token / Admin Device)
//   - /edge/<id>/*  Pluggable Edge Protocol Plane (per-plugin auth)
package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

type Config struct {
	AccessHash    string // Optional 64-char hex SHA-256 of Relay-Access password
	RootAdminHash string // 64-char hex SHA-256 of bootstrap Root Admin secret (for /v2/admin/*)
}

type Server struct {
	Store   *core.Store
	Pipe    *core.PipeHub
	Plugins *plugin.Host
	cfg     Config
}

func New(store *core.Store, cfg Config) *Server {
	pipe := core.NewPipeHub(store)
	return &Server{
		Store:   store,
		Pipe:    pipe,
		Plugins: plugin.NewHost(store, pipe),
		cfg:     cfg,
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
	mux.HandleFunc("/v2/admin/", s.requireAccess(s.requireAdmin(s.handleAdmin)))
	mux.HandleFunc("/v2/spaces/", s.requireAccess(s.handleSpaceDevice))
	mux.HandleFunc("/edge/", s.handleEdge)
	return mux
}

/* ───────── Auth Middleware ───────── */

func (s *Server) requireAccess(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AccessHash != "" {
			got := r.Header.Get("Relay-Access")
			if !plugin.SecretMatchesHash(got, s.cfg.AccessHash) {
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

func (s *Server) handleEdge(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/edge/")
	pluginID, subPath, _ := strings.Cut(rest, "/")
	p, ok := s.Plugins.Get(pluginID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/" + subPath
	p.EdgeHandler(s.Plugins).ServeHTTP(w, r2)
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
	boxTail := strings.TrimPrefix(tail, "boxes/")
	// Split into boxName and action (/items, /items/{id}, /objects, /objects/{key})
	if idx := strings.Index(boxTail, "/items"); idx > 0 {
		s.handleBoxItems(w, r, dev, role, spaceID, boxTail[:idx], strings.TrimPrefix(boxTail[idx:], "/items"))
		return
	}
	if idx := strings.Index(boxTail, "/objects"); idx > 0 {
		s.handleBoxObjects(w, r, role, spaceID, boxTail[:idx], strings.TrimPrefix(boxTail[idx:], "/objects"))
		return
	}
	http.NotFound(w, r)
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
		replyJSON(w, http.StatusOK, map[string]any{"ok": true})

	case p == "spaces" && r.Method == http.MethodGet:
		list, err := s.Store.ListSpaces()
		if err != nil {
			writeCoreErr(w, err)
			return
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
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "registered": s.Plugins.IDs(), "bindings": list})

	case p == "plugins" && r.Method == http.MethodPut:
		var in struct {
			PluginID string          `json:"plugin_id"`
			Mount    string          `json:"mount"`
			SpaceID  string          `json:"space_id"`
			BoxName  string          `json:"box_name"`
			Config   json.RawMessage `json:"config"`
			Enabled  *bool           `json:"enabled"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		en := true
		if in.Enabled != nil {
			en = *in.Enabled
		}
		cfgStr := "{}"
		if len(in.Config) > 0 {
			cfgStr = string(in.Config)
		}
		b, err := s.Plugins.UpsertBinding(core.PluginBinding{
			PluginID: in.PluginID, Mount: in.Mount, SpaceID: in.SpaceID,
			BoxName: in.BoxName, ConfigJSON: cfgStr, Enabled: en,
		})
		if err != nil {
			writeCoreErr(w, err)
			return
		}
		replyJSON(w, http.StatusOK, map[string]any{"ok": true, "binding": b})

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
	binding, _, err := s.Plugins.LookupBinding(pid, mount)
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
			SecretSHA256 string `json:"secret_sha256"`
			Mode         string `json:"mode"`
			MetaJSON     string `json:"meta_json"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		acct, err := s.Plugins.UpsertAccount(binding.ID, in.ScopeKey, in.Username, in.SecretSHA256, in.Mode, in.MetaJSON)
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

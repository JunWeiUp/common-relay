// Package webdav implements the dual-mode WebDAV edge plugin (/edge/webdav/{mount}/...).
//
// Each folder-scoped Basic Auth account is dynamically managed via the Admin API
// and operates in one of two explicit modes:
//   - "queue"  (requires Space.TrustLevel == bridge_allowed): write-only inbox;
//     PUT enqueues into Box(queue), GET file returns 403.
//   - "object" (allowed on client_encrypted or bridge_allowed): bidirectional
//     opaque ciphertext store backed by Box(object); supports GET/HEAD/PUT/DELETE/PROPFIND.
package webdav

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

const allowMethods = "OPTIONS, PROPFIND, PROPPATCH, MKCOL, PUT, HEAD, GET, DELETE"

type Plugin struct {
	limiter *plugin.FailLimiter
}

func New() *Plugin {
	return &Plugin{limiter: plugin.NewFailLimiter(20, 10*time.Minute)}
}

func (p *Plugin) ID() string                     { return "webdav" }
func (p *Plugin) RequiredTrust() core.TrustLevel { return core.TrustClientEncrypted }

func (p *Plugin) ConfigSchema() []plugin.FieldSpec {
	return []plugin.FieldSpec{
		{Key: "cors_origins", Type: "string_list", Description: "browser Origins allowed to call this mount"},
		{Key: "strict_queue_methods", Type: "bool", Description: "queue mode: reject DELETE with 403 instead of the compatibility no-op 204"},
		plugin.BridgeSchema,
	}
}

// Browser extensions (e.g. a password-vault mirror) call WebDAV from their own origin.
var allowedOriginScheme = map[string]bool{
	"https": true, "http": true, "chrome-extension": true, "moz-extension": true, "safari-web-extension": true,
}

func (p *Plugin) ValidateConfig(cfg map[string]any) error {
	for k, v := range cfg {
		switch k {
		case "cors_origins":
			arr, ok := v.([]any)
			if !ok {
				return errors.New("cors_origins must be a list of origins")
			}
			for _, it := range arr {
				o, ok := it.(string)
				if !ok {
					return errors.New("cors_origins must be a list of origins")
				}
				if u, err := url.Parse(o); err != nil || !allowedOriginScheme[u.Scheme] || u.Host == "" || u.Path != "" || u.RawQuery != "" {
					return fmt.Errorf("invalid origin %q", o)
				}
			}
		case "strict_queue_methods":
			if _, ok := v.(bool); !ok {
				return errors.New("strict_queue_methods must be a boolean")
			}
		case plugin.SealPublicKeyField:
		default:
			return fmt.Errorf("unknown webdav config key %q", k)
		}
	}
	return nil
}

func (p *Plugin) EdgeHandler(host *plugin.Host) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/")
		mount, relRaw, _ := strings.Cut(rest, "/")
		if !core.ValidIdent(mount) {
			http.NotFound(w, r)
			return
		}
		binding, space, err := host.LookupBinding(p.ID(), mount)
		if err != nil {
			if errors.Is(err, core.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		srcKey := host.SourceKey(binding.ID, r)
		if p.limiter.Blocked(srcKey) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if originAllowed(binding.ConfigJSON, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", allowMethods)
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Depth, If-Match, If-None-Match")
				w.Header().Set("Access-Control-Expose-Headers", "ETag, Content-Length, Last-Modified, DAV")
				w.Header().Set("Access-Control-Max-Age", "600")
				if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					w.Header().Set("DAV", "1")
					w.Header().Set("Allow", allowMethods)
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="common-relay-webdav"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		acct, err := host.AuthAccount(binding.ID, user, pass)
		if err != nil {
			p.limiter.Fail(srcKey)
			w.Header().Set("WWW-Authenticate", `Basic realm="common-relay-webdav"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.limiter.Reset(srcKey)

		mode := core.BoxMode(acct.Mode)
		if mode != core.ModeObject {
			mode = core.ModeQueue
		}
		if mode == core.ModeQueue && !space.TrustLevel.Allows(core.TrustBridgeAllowed) {
			http.Error(w, "space trust boundary forbids plaintext queue mode", http.StatusForbidden)
			return
		}

		folder, ok := cleanPath(acct.ScopeKey)
		if !ok || folder == "" {
			http.Error(w, "invalid account scope", http.StatusServiceUnavailable)
			return
		}
		rel, ok := cleanPath(relRaw)
		if !ok {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		// Enforce strict folder isolation: account may only access root ("") or inside its own folder.
		if rel != "" && rel != folder && !strings.HasPrefix(rel, folder+"/") {
			http.Error(w, "forbidden outside account folder", http.StatusForbidden)
			return
		}

		boxName := boxNameForFolder(binding.BoxName, folder)
		if _, err := host.EnsureBox(core.Box{
			SpaceID: binding.SpaceID, Name: boxName, Mode: mode, KeepVersions: 10,
		}); err != nil {
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}

		baseHref := "/edge/webdav/" + mount + "/"
		innerKey := ""
		if strings.HasPrefix(rel, folder+"/") {
			innerKey = strings.TrimPrefix(rel, folder+"/")
		}

		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("DAV", "1")
			w.Header().Set("Allow", allowMethods)
			w.WriteHeader(http.StatusOK)

		case "MKCOL":
			// Collections are virtual (derived from object keys); creating one is
			// a successful no-op so clients that MKCOL before PUT keep working.
			if r.ContentLength > 0 {
				http.Error(w, "unsupported body", http.StatusUnsupportedMediaType)
				return
			}
			w.WriteHeader(http.StatusCreated)

		case "PROPPATCH":
			w.WriteHeader(http.StatusOK)

		case "PROPFIND":
			p.handlePropfind(w, r, host, binding.SpaceID, boxName, mode, baseHref, folder, rel, innerKey)

		case http.MethodPut:
			if innerKey == "" {
				http.Error(w, "cannot PUT to directory", http.StatusMethodNotAllowed)
				return
			}
			p.handlePut(w, r, host, binding, boxName, mount, mode, folder, rel, innerKey)

		case http.MethodGet, http.MethodHead:
			if innerKey == "" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte("Common Relay v2 WebDAV folder\n"))
				}
				return
			}
			if mode == core.ModeQueue {
				http.Error(w, "write-only inbox: GET disabled", http.StatusForbidden)
				return
			}
			p.handleGetObject(w, r, host, binding.SpaceID, boxName, innerKey)

		case http.MethodDelete:
			if innerKey == "" || mode == core.ModeQueue {
				// Queue items are owned by the consumer once uploaded. Backup apps
				// that rotate old files expect DELETE to succeed, so the default is
				// an explicit, flagged no-op; strict_queue_methods makes it a 403.
				var cfg struct {
					Strict bool `json:"strict_queue_methods"`
				}
				_ = json.Unmarshal([]byte(binding.ConfigJSON), &cfg)
				if cfg.Strict && innerKey != "" {
					http.Error(w, "write-only inbox: DELETE disabled", http.StatusForbidden)
					return
				}
				w.Header().Set("X-Relay-Noop", "queue-mode")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if err := host.DeleteObject(binding.SpaceID, boxName, innerKey); err != nil && !errors.Is(err, core.ErrNotFound) {
				http.Error(w, "storage", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			w.Header().Set("Allow", allowMethods)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (p *Plugin) handlePut(w http.ResponseWriter, r *http.Request, host *plugin.Host, binding core.PluginBinding, boxName, mount string, mode core.BoxMode, folder, fullRel, innerKey string) {
	spaceID := binding.SpaceID
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		if ext := mime.TypeByExtension(path.Ext(innerKey)); ext != "" {
			ct = ext
		} else {
			ct = "application/octet-stream"
		}
	}
	metaMap := map[string]any{
		"plugin":      "webdav",
		"mount":       mount,
		"folder":      folder,
		"path":        "/" + fullRel,
		"name":        path.Base(innerKey),
		"mode":        string(mode),
		"received_at": time.Now().UnixMilli(),
	}
	meta, _ := json.Marshal(metaMap)

	if mode == core.ModeQueue {
		item, err := host.PutBridgedItem(binding, boxName, "plugin:webdav:"+mount, ct, metaMap, r.Body)
		if err != nil {
			if errors.Is(err, core.ErrQuota) {
				http.Error(w, "quota exceeded", http.StatusInsufficientStorage)
				return
			}
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", `"`+item.SHA256+`"`)
		w.WriteHeader(http.StatusCreated)
		return
	}

	// Bidirectional client-encrypted object mode.
	expectedETag := strings.TrimSpace(r.Header.Get("If-Match"))
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == "*" {
		expectedETag = "none"
	}
	obj, err := host.PutObject(spaceID, boxName, innerKey, ct, string(meta), expectedETag, r.Body)
	if err != nil {
		if errors.Is(err, core.ErrConflict) {
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return
		}
		if errors.Is(err, core.ErrQuota) {
			http.Error(w, "quota exceeded", http.StatusInsufficientStorage)
			return
		}
		http.Error(w, "storage", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("ETag", `"`+obj.ETag+`"`)
	if obj.Version > 1 {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (p *Plugin) handleGetObject(w http.ResponseWriter, r *http.Request, host *plugin.Host, spaceID, boxName, innerKey string) {
	f, obj, err := host.OpenObject(spaceID, boxName, innerKey)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "storage", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	etag := `"` + obj.ETag + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	w.Header().Set("Last-Modified", time.Unix(obj.CreatedAt, 0).UTC().Format(http.TimeFormat))
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm == etag || inm == obj.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

type davPropItem struct {
	href       string
	name       string
	collection bool
	size       int64
	etag       string
	ct         string
	mod        int64
}

func (p *Plugin) handlePropfind(w http.ResponseWriter, r *http.Request, host *plugin.Host, spaceID, boxName string, mode core.BoxMode, baseHref, folder, rel, innerKey string) {
	depth := strings.TrimSpace(r.Header.Get("Depth"))
	if depth == "" || strings.EqualFold(depth, "infinity") {
		depth = "1"
	}
	now := time.Now().Unix()
	var items []davPropItem

	if rel == "" {
		items = append(items, davPropItem{href: baseHref, name: "", collection: true, mod: now})
		if depth != "0" {
			items = append(items, davPropItem{href: baseHref + encodeHref(folder) + "/", name: folder, collection: true, mod: now})
		}
	} else if rel == folder {
		items = append(items, davPropItem{href: baseHref + encodeHref(folder) + "/", name: folder, collection: true, mod: now})
		if depth != "0" && mode == core.ModeObject {
			objs, _ := host.ListObjects(spaceID, boxName, "")
			for _, o := range objs {
				items = append(items, davPropItem{
					href: baseHref + encodeHref(folder+"/"+o.Key), name: path.Base(o.Key),
					size: o.Size, etag: o.ETag, ct: o.ContentType, mod: o.CreatedAt,
				})
			}
		}
	} else {
		if mode == core.ModeObject {
			objs, _ := host.ListObjects(spaceID, boxName, innerKey)
			if len(objs) == 0 {
				http.NotFound(w, r)
				return
			}
			for _, o := range objs {
				items = append(items, davPropItem{
					href: baseHref + encodeHref(folder+"/"+o.Key), name: path.Base(o.Key),
					size: o.Size, etag: o.ETag, ct: o.ContentType, mod: o.CreatedAt,
				})
			}
		} else {
			items = append(items, davPropItem{href: baseHref + encodeHref(rel) + "/", name: path.Base(rel), collection: true, mod: now})
		}
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
	for _, it := range items {
		b.WriteString(`<D:response><D:href>`)
		_ = xml.EscapeText(&b, []byte(it.href))
		b.WriteString(`</D:href><D:propstat><D:prop><D:displayname>`)
		_ = xml.EscapeText(&b, []byte(it.name))
		b.WriteString(`</D:displayname>`)
		if it.collection {
			b.WriteString(`<D:resourcetype><D:collection/></D:resourcetype>`)
		} else {
			b.WriteString(fmt.Sprintf(`<D:resourcetype/><D:getcontentlength>%d</D:getcontentlength>`, it.size))
			if it.ct != "" {
				b.WriteString(`<D:getcontenttype>`)
				_ = xml.EscapeText(&b, []byte(it.ct))
				b.WriteString(`</D:getcontenttype>`)
			}
			if it.etag != "" {
				b.WriteString(`<D:getetag>"`)
				_ = xml.EscapeText(&b, []byte(it.etag))
				b.WriteString(`"</D:getetag>`)
			}
		}
		ts := time.Unix(it.mod, 0).UTC()
		lm := ts.Format(http.TimeFormat)
		cd := ts.Format(time.RFC3339)
		b.WriteString(`<D:getlastmodified>` + lm + `</D:getlastmodified><D:creationdate>` + cd + `</D:creationdate></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
	}
	b.WriteString(`</D:multistatus>`)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = w.Write([]byte(b.String()))
}

func cleanPath(raw string) (string, bool) {
	p := strings.Trim(raw, "/")
	if p == "" {
		return "", true
	}
	if len(p) > 1024 {
		return "", false
	}
	parts := strings.Split(p, "/")
	if len(parts) > 16 {
		return "", false
	}
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." || len(seg) > 255 || strings.ContainsRune(seg, '\\') {
			return "", false
		}
	}
	return p, true
}

func boxNameForFolder(prefix, folder string) string {
	base := "webdav"
	if prefix != "" {
		base = prefix
	}
	candidate := base + "/" + folder
	if core.ValidBoxName(candidate) {
		return candidate
	}
	return base + "/f-" + core.HashSecret(folder)[:12]
}

func encodeHref(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func originAllowed(configJSON, origin string) bool {
	if configJSON == "" || origin == "" {
		return false
	}
	var cfg struct {
		CORSOrigins []string `json:"cors_origins"`
	}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return false
	}
	for _, allowed := range cfg.CORSOrigins {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}

// Package mcpedge implements the read-only MCP HTTP Gateway plugin
// (/edge/mcpedge/{mount}/mcp and /edge/mcpedge/{mount}/photo/{token}),
// subsuming standalone mcp-gateway directly into Common Relay v2.
//
// Security boundaries preserved:
//   - Requires Space.TrustLevel == bridge_allowed (forbidden on strict_e2e Spaces)
//   - Rejects any request carrying an Origin header (403, anti-CSRF)
//   - Per-client Bearer / X-Console-Key tokens stored as SHA-256 hashes in v2_plugin_accounts
//   - Forwarded over the target device's existing /v2/ws Pipe via CallRPC
//   - Short-lived (5m) photo capability URLs store only SHA-256 token hashes in memory;
//     credentials are never placed in URLs, and photo responses carry strict sandbox CSP.
package mcpedge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

type config struct {
	TargetDevice string `json:"target_device"` // Device ID of local Hub answering "mcp" RPC
	PublicBase   string `json:"public_base,omitempty"`
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type photoLease struct {
	spaceID      string
	targetDevice string
	rpcPayload   string
	expires      time.Time
}

type authCacheEntry struct {
	ok      bool
	expires time.Time
}

var leaseRe = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

type Plugin struct {
	limiter *plugin.FailLimiter
	slots   chan struct{}
	leaseMu sync.Mutex
	leases  map[[32]byte]photoLease
	authMu  sync.Mutex
	authMap map[string]authCacheEntry
}

func New() *Plugin {
	return &Plugin{
		limiter: plugin.NewFailLimiter(30, 10*time.Minute),
		slots:   make(chan struct{}, 8),
		leases:  map[[32]byte]photoLease{},
		authMap: map[string]authCacheEntry{},
	}
}

func (p *Plugin) ID() string                     { return "mcpedge" }
func (p *Plugin) RequiredTrust() core.TrustLevel { return core.TrustBridgeAllowed }

// RPCTimeout bounds each forwarded query so stalled hubes release slots.
const RPCTimeout = 10 * time.Second

func (p *Plugin) ConfigSchema() []plugin.FieldSpec {
	return []plugin.FieldSpec{
		{Key: "target_device", Type: "string", Required: true, Description: "device ID of the Hub answering \"mcp\" RPCs"},
		{Key: "public_base", Type: "string", Description: "public https base URL used for short-lived photo links"},
	}
}

func (p *Plugin) ValidateConfig(cfg map[string]any) error {
	for k, v := range cfg {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s must be a string", k)
		}
		switch k {
		case "target_device":
			if !core.ValidIdent(s) {
				return errors.New("target_device must be a device ID")
			}
		case "public_base":
			if s == "" {
				continue
			}
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
				return errors.New("public_base must be an http(s) base URL")
			}
		default:
			return fmt.Errorf("unknown mcpedge config key %q", k)
		}
	}
	if s, _ := cfg["target_device"].(string); s == "" {
		return errors.New("target_device is required")
	}
	return nil
}

// acquire takes a forwarding slot; every path that can trigger an RPC (including
// ck_* verification and photo leases) must hold one.
func (p *Plugin) acquire() (release func(), ok bool) {
	select {
	case p.slots <- struct{}{}:
		return func() { <-p.slots }, true
	default:
		return nil, false
	}
}

func (p *Plugin) EdgeHandler(host *plugin.Host) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		rest := strings.TrimPrefix(r.URL.Path, "/")
		mount, sub, ok := strings.Cut(rest, "/")
		if !ok || !core.ValidIdent(mount) {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(sub, "photo/") {
			p.servePhoto(w, r, host, strings.TrimPrefix(sub, "photo/"))
			return
		}
		if sub != "mcp" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		binding, _, err := host.LookupBinding(p.ID(), mount)
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
		var cfg config
		if json.Unmarshal([]byte(binding.ConfigJSON), &cfg) != nil || cfg.TargetDevice == "" {
			http.Error(w, "mcpedge target_device not configured", http.StatusServiceUnavailable)
			return
		}

		token := r.Header.Get("X-Console-Key")
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="console-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Hold a slot before anything that may issue an RPC (ck_* verification).
		release, ok := p.acquire()
		if !ok {
			http.Error(w, "too many queries", http.StatusTooManyRequests)
			return
		}
		defer release()
		// Match against registered plugin accounts (including legacy shared token) or
		// delegate per-client ck_* grant verification to the local Hub via RPC.
		grantName, authStatus := p.authorizeClient(r.Context(), host, binding, cfg, token)
		if authStatus != 0 {
			if authStatus == http.StatusUnauthorized {
				p.limiter.Fail(srcKey)
				w.Header().Set("WWW-Authenticate", `Bearer realm="console-mcp"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			} else {
				http.Error(w, "console offline; cannot verify token", authStatus)
			}
			return
		}
		p.limiter.Reset(srcKey)

		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
			return
		}
		var q rpcReq
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		if dec.Decode(&q) != nil || dec.Decode(new(any)) != io.EOF || q.JSONRPC != "2.0" || q.Method == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if len(q.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		var result any
		var errValue any
		switch q.Method {
		case "initialize":
			var a struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(q.Params, &a)
			if a.ProtocolVersion == "" {
				a.ProtocolVersion = "2025-11-25"
			}
			result = map[string]any{
				"protocolVersion": a.ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": "工作台", "version": "2.0.0"},
				"instructions":    "本机工作台只读 MCP 入口（经 Common Relay v2 加密通道）。仅支持只读查询，禁止写操作或读取凭据。",
			}
		case "ping":
			result = map[string]any{}
		case "resources/list":
			result = map[string]any{"resources": []any{}}
		case "prompts/list":
			result = map[string]any{"prompts": []any{}}
		case "tools/list", "tools/call":
			if q.Method == "tools/call" {
				var peek struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(q.Params, &peek) == nil && peek.Name == "console_connection_test" {
					result = map[string]any{
						"content": []map[string]any{{"type": "text", "text": "启动台 MCP 网关已就绪；真实查询使用 Common Relay v2 加密通道。"}},
					}
					break
				}
			}
			fwd, _ := json.Marshal(map[string]any{
				"method": q.Method,
				"grant":  grantName,
				"params": json.RawMessage(q.Params),
			})
			rawRes, err := host.CallRPCTimeout(r.Context(), RPCTimeout, binding.SpaceID, cfg.TargetDevice, "mcp", string(fwd))
			if err != nil {
				errValue = map[string]any{"code": -32000, "message": "hub offline or unavailable"}
				break
			}
			var decoded map[string]any
			if json.Unmarshal([]byte(rawRes), &decoded) != nil {
				errValue = map[string]any{"code": -32603, "message": "invalid hub response"}
				break
			}
			if q.Method == "tools/call" && cfg.PublicBase != "" {
				p.maybeAttachPhotoLink(decoded, binding.SpaceID, cfg, mount, string(fwd))
			}
			result = decoded
		default:
			errValue = map[string]any{"code": -32601, "message": "Method not found"}
		}

		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"jsonrpc": "2.0", "id": q.ID}
		if errValue != nil {
			out["error"] = errValue
		} else {
			out["result"] = result
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

func (p *Plugin) authorizeClient(ctx context.Context, host *plugin.Host, binding core.PluginBinding, cfg config, token string) (string, int) {
	if len(token) > 256 {
		return "", http.StatusUnauthorized
	}
	// Support "clientName:secret" direct lookup or fallback scan over binding accounts.
	if u, sec, ok := strings.Cut(token, ":"); ok && u != "" && sec != "" {
		if acct, err := host.AuthAccount(binding.ID, u, sec); err == nil {
			return acct.ScopeKey, 0
		}
	}
	// Bare tokens are matched only against legacy fast-hash accounts: scanning
	// salted (scrypt) accounts per request would let one bad token cost N KDFs.
	if accts, err := host.ListAccounts(binding.ID); err == nil {
		for _, a := range accts {
			if plugin.IsSaltedHash(a.SecretHash) {
				continue
			}
			if _, err := host.AuthAccount(binding.ID, a.Username, token); err == nil {
				return a.ScopeKey, 0
			}
		}
	}
	// Per-client Hub tokens (ck_...) are validated by SHA-256 hash on the local Hub.
	if !strings.HasPrefix(token, "ck_") {
		return "", http.StatusUnauthorized
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	cacheKey := binding.ID + ":" + hash
	now := time.Now()
	p.authMu.Lock()
	if ent, ok := p.authMap[cacheKey]; ok && now.Before(ent.expires) {
		p.authMu.Unlock()
		if ent.ok {
			return hash, 0
		}
		return "", http.StatusUnauthorized
	}
	p.authMu.Unlock()

	fwd, _ := json.Marshal(map[string]any{
		"method": "tools/call",
		"grant":  hash,
		"params": map[string]any{"name": "console_auth", "arguments": map[string]any{}},
	})
	rawRes, err := host.CallRPCTimeout(ctx, RPCTimeout, binding.SpaceID, cfg.TargetDevice, "mcp", string(fwd))
	if err != nil {
		return "", http.StatusServiceUnavailable
	}
	var decoded struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	ok := json.Unmarshal([]byte(rawRes), &decoded) == nil && !decoded.IsError && len(decoded.Content) > 0 && strings.Contains(decoded.Content[0].Text, `"ok":true`)
	ttl := 15 * time.Second
	if ok {
		ttl = 60 * time.Second
	}
	p.authMu.Lock()
	if len(p.authMap) >= 256 {
		for k, v := range p.authMap {
			if !now.Before(v.expires) {
				delete(p.authMap, k)
			}
		}
		if len(p.authMap) >= 256 {
			p.authMap = map[string]authCacheEntry{}
		}
	}
	p.authMap[cacheKey] = authCacheEntry{ok: ok, expires: now.Add(ttl)}
	p.authMu.Unlock()
	if ok {
		return hash, 0
	}
	return "", http.StatusUnauthorized
}

func (p *Plugin) maybeAttachPhotoLink(res map[string]any, spaceID string, cfg config, mount, rpcPayload string) {
	items, ok := res["content"].([]any)
	if !ok {
		return
	}
	hasImage := false
	for _, it := range items {
		if m, ok := it.(map[string]any); ok && m["type"] == "image" {
			hasImage = true
			break
		}
	}
	if !hasImage {
		return
	}
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return
	}
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(tok))
	now := time.Now()
	p.leaseMu.Lock()
	for k, v := range p.leases {
		if !now.Before(v.expires) {
			delete(p.leases, k)
		}
	}
	if len(p.leases) >= 128 {
		p.leaseMu.Unlock()
		return
	}
	p.leases[sum] = photoLease{spaceID: spaceID, targetDevice: cfg.TargetDevice, rpcPayload: rpcPayload, expires: now.Add(5 * time.Minute)}
	p.leaseMu.Unlock()

	base := strings.TrimRight(cfg.PublicBase, "/")
	photoURL := base + "/edge/mcpedge/" + mount + "/photo/" + tok
	if strings.HasSuffix(base, "/console-mcp") {
		photoURL = base + "/photo/" + tok
	}
	note, _ := json.Marshal(map[string]any{
		"imageUrl":         photoURL,
		"expiresInSeconds": 300,
	})
	res["content"] = append(items, map[string]any{"type": "text", "text": string(note)})
}

func (p *Plugin) servePhoto(w http.ResponseWriter, r *http.Request, host *plugin.Host, tok string) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !leaseRe.MatchString(tok) {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256([]byte(tok))
	p.leaseMu.Lock()
	lease, ok := p.leases[sum]
	if ok && !time.Now().Before(lease.expires) {
		delete(p.leases, sum)
		ok = false
	}
	p.leaseMu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	release, ok := p.acquire()
	if !ok {
		http.Error(w, "too many queries", http.StatusTooManyRequests)
		return
	}
	defer release()
	rawRes, err := host.CallRPCTimeout(r.Context(), RPCTimeout, lease.spaceID, lease.targetDevice, "mcp", lease.rpcPayload)
	if err != nil {
		http.Error(w, "photo unavailable", http.StatusServiceUnavailable)
		return
	}
	var decoded struct {
		Content []struct {
			Type     string `json:"type"`
			MimeType string `json:"mimeType"`
			Data     string `json:"data"`
		} `json:"content"`
	}
	if json.Unmarshal([]byte(rawRes), &decoded) != nil {
		http.Error(w, "invalid photo response", http.StatusServiceUnavailable)
		return
	}
	for _, c := range decoded.Content {
		if c.Type != "image" {
			continue
		}
		if c.MimeType != "image/jpeg" && c.MimeType != "image/png" && c.MimeType != "image/webp" && c.MimeType != "image/gif" {
			break
		}
		imgBytes, err := base64.StdEncoding.DecodeString(c.Data)
		if err != nil || len(imgBytes) > 8<<20 {
			break
		}
		w.Header().Set("Content-Type", c.MimeType)
		w.Header().Set("Content-Disposition", `inline; filename="archive-photo"`)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		_, _ = w.Write(imgBytes)
		return
	}
	http.Error(w, "unsupported photo", http.StatusUnsupportedMediaType)
}

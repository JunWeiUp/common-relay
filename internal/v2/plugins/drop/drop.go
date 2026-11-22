// Package drop implements the ultra-simple HTTPS Drop plugin (/edge/drop/{mount})
// for iOS Shortcuts, shell scripts, and explicit SyncApp-to-Hub sends.
// Any authorized POST enqueues the payload (optionally sealed) into the bound Box(queue).
package drop

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

const DefaultMaxBytes = 32 << 20

type config struct {
	TokenSHA256 string `json:"token_sha256"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
}

type Plugin struct {
	limiter *plugin.FailLimiter
}

func New() *Plugin {
	return &Plugin{limiter: plugin.NewFailLimiter(20, 10*time.Minute)}
}

func (p *Plugin) ID() string                     { return "drop" }
func (p *Plugin) RequiredTrust() core.TrustLevel { return core.TrustBridgeAllowed }

func (p *Plugin) ConfigSchema() []plugin.FieldSpec {
	return []plugin.FieldSpec{
		{Key: "token_sha256", Type: "hex64", Secret: true, Required: true, Description: "SHA-256 of the Bearer token (submit plaintext as \"token\" to have it hashed)"},
		{Key: "max_bytes", Type: "int", Description: fmt.Sprintf("body limit, default %d, max %d", DefaultMaxBytes, core.HardBoxMaxBytes)},
		plugin.BridgeSchema,
	}
}

func (p *Plugin) ValidateConfig(cfg map[string]any) error {
	for k, v := range cfg {
		switch k {
		case "token_sha256":
			s, _ := v.(string)
			if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
				return errors.New("token_sha256 must be 64 hex")
			}
		case "max_bytes":
			n, ok := v.(float64)
			if !ok || n <= 0 || n > core.HardBoxMaxBytes {
				return fmt.Errorf("max_bytes must be 1..%d", core.HardBoxMaxBytes)
			}
		case plugin.SealPublicKeyField:
		default:
			return fmt.Errorf("unknown drop config key %q", k)
		}
	}
	if _, ok := cfg["token_sha256"]; !ok {
		return errors.New("token_sha256 is required — submit a plaintext token as \"token\"")
	}
	return nil
}

func (p *Plugin) EdgeHandler(host *plugin.Host) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mount := strings.Trim(r.URL.Path, "/")
		if mount == "" || strings.Contains(mount, "/") {
			http.NotFound(w, r)
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
		if json.Unmarshal([]byte(binding.ConfigJSON), &cfg) != nil || len(cfg.TokenSHA256) != 64 {
			http.Error(w, "plugin misconfigured", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if !strings.HasPrefix(auth, "Bearer ") || len(token) < 16 || !plugin.SecretMatchesHash(token, cfg.TokenSHA256) {
			p.limiter.Fail(srcKey)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.limiter.Reset(srcKey)

		boxName := binding.BoxName
		if boxName == "" {
			boxName = "drop/" + mount
		}
		maxBytes := cfg.MaxBytes
		if maxBytes <= 0 {
			maxBytes = DefaultMaxBytes
		}
		if r.ContentLength > maxBytes {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		// Sealing adds framing overhead; size the box above the plaintext limit.
		if _, err := host.EnsureBox(core.Box{
			SpaceID: binding.SpaceID, Name: boxName, Mode: core.ModeQueue, MaxBytes: maxBytes + maxBytes/256 + (1 << 20),
		}); err != nil {
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		meta := map[string]any{
			"plugin":      "drop",
			"mount":       mount,
			"name":        strings.TrimSpace(r.URL.Query().Get("name")),
			"tag":         strings.TrimSpace(r.URL.Query().Get("tag")),
			"received_at": time.Now().UnixMilli(),
		}
		item, err := host.PutBridgedItem(binding, boxName, "plugin:drop:"+mount, ct, meta, http.MaxBytesReader(w, r.Body, maxBytes))
		if err != nil {
			var mbe *http.MaxBytesError
			switch {
			case errors.As(err, &mbe):
				http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			case errors.Is(err, core.ErrQuota):
				http.Error(w, "quota exceeded", http.StatusInsufficientStorage)
			default:
				http.Error(w, "storage", http.StatusServiceUnavailable)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"id":     item.ID,
			"seq":    item.Seq,
			"size":   item.Size,
			"sha256": item.SHA256,
		})
	})
}

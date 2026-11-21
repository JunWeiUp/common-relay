// Package drop implements the ultra-simple HTTPS Drop plugin (/edge/drop/{mount})
// for iOS Shortcuts, shell scripts, and explicit Clipy-to-Workbench sends.
// Any authorized POST enqueues the payload directly into the bound Box(queue).
package drop

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

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
		if p.limiter.Blocked(binding.ID) {
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
			p.limiter.Fail(binding.ID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.limiter.Reset(binding.ID)

		boxName := binding.BoxName
		if boxName == "" {
			boxName = "drop/" + mount
		}
		maxBytes := cfg.MaxBytes
		if maxBytes <= 0 {
			maxBytes = 32 << 20
		}
		if _, err := host.EnsureBox(core.Box{
			SpaceID: binding.SpaceID, Name: boxName, Mode: core.ModeQueue, MaxBytes: maxBytes,
		}); err != nil {
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}

		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		metaBytes, _ := json.Marshal(map[string]any{
			"plugin":      "drop",
			"mount":       mount,
			"name":        strings.TrimSpace(r.URL.Query().Get("name")),
			"tag":         strings.TrimSpace(r.URL.Query().Get("tag")),
			"received_at": time.Now().UnixMilli(),
		})
		item, err := host.PutQueueItem(binding.SpaceID, boxName, "plugin:drop:"+mount, ct, string(metaBytes), r.Body)
		if err != nil {
			if errors.Is(err, core.ErrQuota) {
				http.Error(w, "quota exceeded", http.StatusInsufficientStorage)
				return
			}
			http.Error(w, "storage", http.StatusServiceUnavailable)
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

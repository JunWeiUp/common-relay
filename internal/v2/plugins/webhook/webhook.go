// Package webhook implements the JSON Webhook plugin (/edge/webhook/{mount})
// with Bearer auth, optional HMAC-SHA256 timestamp signature verification, and
// direct enqueueing into a Box(queue).
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

type config struct {
	TokenSHA256     string `json:"token_sha256"`
	HMACSecret      string `json:"hmac_secret,omitempty"`
	TimestampHeader string `json:"timestamp_header,omitempty"`
	SignatureHeader string `json:"signature_header,omitempty"`
	MaxBytes        int64  `json:"max_bytes,omitempty"`
}

type Plugin struct {
	limiter *plugin.FailLimiter
}

func New() *Plugin {
	return &Plugin{limiter: plugin.NewFailLimiter(20, 10*time.Minute)}
}

func (p *Plugin) ID() string                     { return "webhook" }
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

		maxBytes := cfg.MaxBytes
		if maxBytes <= 0 {
			maxBytes = 32 << 20
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBytes {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		if cfg.HMACSecret != "" {
			tsHdr := cfg.TimestampHeader
			if tsHdr == "" {
				tsHdr = "X-Webhook-Timestamp"
			}
			sigHdr := cfg.SignatureHeader
			if sigHdr == "" {
				sigHdr = "X-Webhook-Signature"
			}
			tsRaw := strings.TrimSpace(r.Header.Get(tsHdr))
			sigRaw := strings.TrimSpace(r.Header.Get(sigHdr))
			ts, err := strconv.ParseInt(tsRaw, 10, 64)
			if err != nil || abs64(time.Now().Unix()-ts) > 300 {
				p.limiter.Fail(binding.ID)
				http.Error(w, "invalid timestamp", http.StatusUnauthorized)
				return
			}
			mac := hmac.New(sha256.New, []byte(cfg.HMACSecret))
			mac.Write([]byte(tsRaw))
			mac.Write([]byte("."))
			mac.Write(body)
			want := hex.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(strings.ToLower(sigRaw)), []byte(want)) {
				p.limiter.Fail(binding.ID)
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		}
		p.limiter.Reset(binding.ID)

		boxName := binding.BoxName
		if boxName == "" {
			boxName = "webhook/" + mount
		}
		if _, err := host.EnsureBox(core.Box{
			SpaceID: binding.SpaceID, Name: boxName, Mode: core.ModeQueue, MaxBytes: maxBytes,
		}); err != nil {
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}

		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		metaBytes, _ := json.Marshal(map[string]any{
			"plugin":          "webhook",
			"mount":           mount,
			"idempotency_key": strings.TrimSpace(r.Header.Get("Idempotency-Key")),
			"received_at":     time.Now().UnixMilli(),
		})
		item, err := host.PutQueueItem(binding.SpaceID, boxName, "plugin:webhook:"+mount, ct, string(metaBytes), bytes.NewReader(body))
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
			"sha256": item.SHA256,
		})
	})
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

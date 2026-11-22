// Package webhook implements the JSON Webhook plugin (/edge/webhook/{mount})
// with Bearer auth, optional HMAC-SHA256 timestamp signature verification with
// replay protection, Idempotency-Key de-duplication, and direct (optionally
// sealed) enqueueing into a Box(queue).
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

const (
	// DefaultMaxBytes applies when max_bytes is unset.
	DefaultMaxBytes = 32 << 20
	// HardMaxBytes caps max_bytes: signed bodies are buffered for HMAC checks.
	HardMaxBytes = 64 << 20
	// SignatureWindow is the accepted clock skew for signed requests.
	SignatureWindow = 5 * time.Minute
	maxIdemKeyLen   = 200
)

type config struct {
	TokenSHA256     string `json:"token_sha256"`
	HMACSecret      string `json:"hmac_secret,omitempty"`
	TimestampHeader string `json:"timestamp_header,omitempty"`
	SignatureHeader string `json:"signature_header,omitempty"`
	Tag             string `json:"tag,omitempty"`
	MaxBytes        int64  `json:"max_bytes,omitempty"`
}

type Plugin struct {
	limiter *plugin.FailLimiter

	replayMu sync.Mutex
	replay   map[string]time.Time // binding|signature -> expiry
}

func New() *Plugin {
	return &Plugin{
		limiter: plugin.NewFailLimiter(20, 10*time.Minute),
		replay:  map[string]time.Time{},
	}
}

func (p *Plugin) ID() string                     { return "webhook" }
func (p *Plugin) RequiredTrust() core.TrustLevel { return core.TrustBridgeAllowed }

func (p *Plugin) ConfigSchema() []plugin.FieldSpec {
	return []plugin.FieldSpec{
		{Key: "token_sha256", Type: "hex64", Secret: true, Required: true, Description: "SHA-256 of the Bearer token (submit plaintext as \"token\" to have it hashed)"},
		{Key: "hmac_secret", Type: "string", Secret: true, Description: "optional HMAC-SHA256 signing key (16-256 chars, 32+ recommended)"},
		{Key: "timestamp_header", Type: "string", Description: "default X-Webhook-Timestamp"},
		{Key: "signature_header", Type: "string", Description: "default X-Webhook-Signature"},
		{Key: "tag", Type: "string", Description: "label stored in item meta"},
		{Key: "max_bytes", Type: "int", Description: fmt.Sprintf("body limit, default %d, max %d", DefaultMaxBytes, HardMaxBytes)},
		plugin.BridgeSchema,
	}
}

func (p *Plugin) ValidateConfig(cfg map[string]any) error {
	known := map[string]bool{}
	for _, f := range p.ConfigSchema() {
		known[f.Key] = true
	}
	for k := range cfg {
		if !known[k] {
			return fmt.Errorf("unknown webhook config key %q", k)
		}
	}
	if h, _ := cfg["token_sha256"].(string); !isHex64(h) {
		return errors.New("token_sha256 is required (64 hex) — submit a plaintext token as \"token\"")
	}
	if v, ok := cfg["hmac_secret"]; ok {
		s, _ := v.(string)
		// 16 keeps pre-existing bindings editable; new keys should be >=32.
		if len(s) < 16 || len(s) > 256 {
			return errors.New("hmac_secret must be 16-256 characters")
		}
	}
	for _, k := range []string{"timestamp_header", "signature_header", "tag"} {
		if v, ok := cfg[k]; ok {
			if s, ok := v.(string); !ok || len(s) > 128 {
				return fmt.Errorf("%s must be a short string", k)
			}
		}
	}
	if v, ok := cfg["max_bytes"]; ok {
		n, ok := v.(float64)
		if !ok || n <= 0 || n > HardMaxBytes {
			return fmt.Errorf("max_bytes must be 1..%d", HardMaxBytes)
		}
	}
	return nil
}

func isHex64(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
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

		maxBytes := cfg.MaxBytes
		if maxBytes <= 0 {
			maxBytes = DefaultMaxBytes
		}
		if maxBytes > HardMaxBytes {
			maxBytes = HardMaxBytes
		}
		if r.ContentLength > maxBytes {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
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
			if err != nil || abs64(time.Now().Unix()-ts) > int64(SignatureWindow/time.Second) {
				p.limiter.Fail(srcKey)
				http.Error(w, "invalid timestamp", http.StatusUnauthorized)
				return
			}
			mac := hmac.New(sha256.New, []byte(cfg.HMACSecret))
			mac.Write([]byte(tsRaw))
			mac.Write([]byte("."))
			mac.Write(body)
			want := hex.EncodeToString(mac.Sum(nil))
			got := strings.TrimPrefix(strings.ToLower(sigRaw), "sha256=")
			if !hmac.Equal([]byte(got), []byte(want)) {
				p.limiter.Fail(srcKey)
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
			// A valid signature may be accepted once within its time window.
			if !p.claimSignature(binding.ID, want) {
				http.Error(w, "replayed request", http.StatusConflict)
				return
			}
		}
		p.limiter.Reset(srcKey)

		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		if strings.Contains(strings.ToLower(ct), "json") && !json.Valid(body) {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if len(idemKey) > maxIdemKeyLen {
			http.Error(w, "Idempotency-Key too long", http.StatusBadRequest)
			return
		}
		if idemKey != "" {
			if itemID, seq, ok, err := host.Store().LookupReceipt(binding.ID, idemKey); err == nil && ok {
				replyAccepted(w, http.StatusOK, map[string]any{"ok": true, "duplicate": true, "id": itemID, "seq": seq})
				return
			}
		}

		boxName := binding.BoxName
		if boxName == "" {
			boxName = "webhook/" + mount
		}
		if _, err := host.EnsureBox(core.Box{
			SpaceID: binding.SpaceID, Name: boxName, Mode: core.ModeQueue, MaxBytes: maxBytes + (1 << 20),
		}); err != nil {
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}

		tag := strings.TrimSpace(cfg.Tag)
		if tag == "" {
			tag = mount
		}
		bodySum := sha256.Sum256(body)
		meta := map[string]any{
			"plugin":          "webhook",
			"mount":           mount,
			"tag":             tag,
			"idempotency_key": idemKey,
			"body_sha256":     hex.EncodeToString(bodySum[:]),
			"received_at":     time.Now().UnixMilli(),
		}
		item, err := host.PutBridgedItem(binding, boxName, "plugin:webhook:"+mount, ct, meta, bytes.NewReader(body))
		if err != nil {
			if errors.Is(err, core.ErrQuota) {
				http.Error(w, "quota exceeded", http.StatusInsufficientStorage)
				return
			}
			http.Error(w, "storage", http.StatusServiceUnavailable)
			return
		}
		if idemKey != "" {
			_ = host.Store().SaveReceipt(binding.ID, idemKey, item.ID, item.Seq)
		}
		replyAccepted(w, http.StatusAccepted, map[string]any{
			"ok":     true,
			"id":     item.ID,
			"seq":    item.Seq,
			"sha256": hex.EncodeToString(bodySum[:]),
		})
	})
}

func replyAccepted(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// claimSignature records a verified signature; false means it was already used.
func (p *Plugin) claimSignature(bindingID, sig string) bool {
	now := time.Now()
	key := bindingID + "|" + sig
	p.replayMu.Lock()
	defer p.replayMu.Unlock()
	if len(p.replay) > 4096 {
		for k, exp := range p.replay {
			if now.After(exp) {
				delete(p.replay, k)
			}
		}
	}
	if exp, ok := p.replay[key]; ok && now.Before(exp) {
		return false
	}
	// Twice the window covers the full span a timestamp can stay valid.
	p.replay[key] = now.Add(2 * SignatureWindow)
	return true
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

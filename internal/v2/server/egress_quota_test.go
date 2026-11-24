package server_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugins/egress"
	v2server "github.com/JunWeiUp/common-relay/internal/v2/server"
)

func TestPerSpaceQuotaAndEgressPlugin(t *testing.T) {
	store, err := core.OpenStore(filepath.Join(t.TempDir(), "relay_v2.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	accessPw := "access-pass-123456"
	adminSecret := "root-admin-secret-12345678901234567890"
	srv := v2server.New(store, v2server.Config{
		AccessHash:    core.HashSecret(accessPw),
		RootAdminHash: core.HashSecret(adminSecret),
	})
	if err := srv.RegisterPlugin(egress.New()); err != nil {
		t.Fatalf("RegisterPlugin(egress): %v", err)
	}
	defer srv.Plugins.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	adminDo := func(method, path string, body any) *http.Response {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, ts.URL+path, r)
		req.Header.Set("Relay-Access", accessPw)
		req.Header.Set("Authorization", "Bearer "+adminSecret)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	// 1. Create a strict_e2e space and a bridge_allowed space with tight 16-byte quota.
	resp := adminDo(http.MethodPost, "/v2/admin/spaces", map[string]any{
		"id": "sp-strict", "name": "Strict", "trust_level": "strict_e2e",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create sp-strict: %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = adminDo(http.MethodPost, "/v2/admin/spaces", map[string]any{
		"id": "sp-bridge", "name": "Bridge", "trust_level": "bridge_allowed", "quota_bytes": 16,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create sp-bridge: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Create a queue box in sp-bridge and verify 16-byte per-space quota enforces ErrQuota.
	if _, err := store.CreateBox(core.Box{SpaceID: "sp-bridge", Name: "inbox", Mode: core.ModeQueue}); err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	if _, err := store.PutBoxItem("sp-bridge", "inbox", "dev1", "text/plain", "{}", 0, strings.NewReader("0123456789abcdefX")); err != core.ErrQuota {
		t.Fatalf("expected ErrQuota for 17-byte item under 16-byte space quota, got %v", err)
	}

	// Raise sp-bridge quota via PUT /v2/admin/spaces/sp-bridge/quota.
	resp = adminDo(http.MethodPut, "/v2/admin/spaces/sp-bridge/quota", map[string]any{"quota_bytes": 4096})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update quota: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Egress receiver server.
	type received struct {
		Event string
		Sig   string
		TS    string
		Body  []byte
	}
	gotCh := make(chan received, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotCh <- received{
			Event: r.Header.Get("X-Relay-Event"),
			Sig:   r.Header.Get("X-Relay-Signature"),
			TS:    r.Header.Get("X-Relay-Timestamp"),
			Body:  b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	// 3. Binding egress to strict_e2e must be rejected (trust boundary).
	resp = adminDo(http.MethodPut, "/v2/admin/plugins", map[string]any{
		"plugin_id": "egress",
		"mount":     "hook-bad",
		"space_id":  "sp-strict",
		"box_name":  "inbox",
		"enabled":   true,
		"config": map[string]any{
			"target_url":        receiver.URL,
			"allow_private_url": true,
		},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 binding egress to strict_e2e, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Binding egress to loopback without allow_private_url must be rejected (SSRF guard).
	resp = adminDo(http.MethodPut, "/v2/admin/plugins", map[string]any{
		"plugin_id": "egress",
		"mount":     "hook-ssrf",
		"space_id":  "sp-bridge",
		"box_name":  "inbox",
		"enabled":   true,
		"config": map[string]any{
			"target_url": receiver.URL,
		},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting private URL without opt-in, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5. Valid binding on sp-bridge with HMAC secret.
	secret := "egress-hmac-secret-1234567890"
	resp = adminDo(http.MethodPut, "/v2/admin/plugins", map[string]any{
		"plugin_id": "egress",
		"mount":     "hook-ok",
		"space_id":  "sp-bridge",
		"box_name":  "inbox",
		"enabled":   true,
		"config": map[string]any{
			"target_url":        receiver.URL,
			"hmac_secret":       secret,
			"box_filter":        "inbox",
			"allow_private_url": true,
		},
	})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("bind egress: %d %s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// Write a sensitive payload into inbox; egress must fire with metadata only and valid HMAC.
	const sensitivePayload = "TOP-SECRET-CIPHERTEXT-BYTES"
	item, err := store.PutBoxItem("sp-bridge", "inbox", "dev1", "application/octet-stream", "{}", 0, strings.NewReader(sensitivePayload))
	if err != nil {
		t.Fatalf("PutQueueItem: %v", err)
	}

	select {
	case got := <-gotCh:
		if got.Event != "item" {
			t.Fatalf("expected X-Relay-Event=item, got %q", got.Event)
		}
		if strings.Contains(string(got.Body), sensitivePayload) {
			t.Fatalf("egress body leaked payload bytes!")
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(got.TS))
		mac.Write([]byte("."))
		mac.Write(got.Body)
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got.Sig != wantSig {
			t.Fatalf("HMAC mismatch: got %q want %q", got.Sig, wantSig)
		}
		var ev struct {
			Space string `json:"space"`
			Box   string `json:"box"`
			Event string `json:"event"`
			Ref   string `json:"ref"`
			Seq   int64  `json:"seq"`
		}
		if err := json.Unmarshal(got.Body, &ev); err != nil {
			t.Fatalf("unmarshal egress body: %v", err)
		}
		if ev.Space != "sp-bridge" || ev.Box != "inbox" || ev.Ref != item.ID || ev.Seq != item.Seq {
			t.Fatalf("unexpected egress metadata: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for egress webhook delivery")
	}

	// 6. Verify /v2/admin/metrics exposes sync_conflicts.
	resp = adminDo(http.MethodGet, "/v2/admin/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if _, ok := m["sync_conflicts"]; !ok {
		t.Fatalf("metrics missing sync_conflicts field: %+v", m)
	}
}

package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	sdk "github.com/JunWeiUp/common-relay/sdk/go"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type hookFixture struct {
	s                    *Server
	http                 *httptest.Server
	token, receiverToken string
	receiver             *sdk.Identity
	config               string
	route                *WebhookRoute
}

func newHookFixture(t *testing.T) *hookFixture {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store)
	s.DiskReserve = 0
	sk, pk, err := sdk.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rk, rp, err := sdk.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rt := RandomID() + RandomID()
	token := RandomID() + RandomID()
	for _, v := range []struct {
		d     Device
		token string
	}{{Device{App: "test", Group: "group", ID: "bridge", PublicKey: pk}, RandomID() + RandomID()}, {Device{App: "test", Group: "group", ID: "mac", PublicKey: rp}, rt}} {
		if err = store.AddDevice(v.d, v.token); err != nil {
			t.Fatal(err)
		}
	}
	h := &WebhookRoute{Route: "phone", App: "test", Group: "group", Sender: "bridge", Recipient: "mac", SecretKey: sk, RecipientKey: rp, TokenHash: hashToken(token)}
	config := filepath.Join(t.TempDir(), "webhooks.json")
	b, _ := json.Marshal([]*WebhookRoute{h})
	if err = os.WriteFile(config, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.LoadWebhooks(config); err != nil {
		t.Fatal(err)
	}
	receiver, err := sdk.NewIdentity("test", "group", "mac", rk, map[string]string{"bridge": pk})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.Handler())
	t.Cleanup(func() { httpServer.Close(); s.Close(); store.DB.Close() })
	return &hookFixture{s, httpServer, token, rt, receiver, config, h}
}
func (f *hookFixture) post(t *testing.T, token, body, key string) (int, string) {
	t.Helper()
	r, err := http.NewRequest("POST", f.http.URL+"/relay/v1/webhooks/phone", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
func TestWebhookEncryptedDeliveryAndAck(t *testing.T) {
	f := newHookFixture(t)
	body := `{"text":"示例测试","records":[1,2]}`
	if status, msg := f.post(t, f.token, body, "event-1"); status != 202 {
		t.Fatalf("%d %s", status, msg)
	}
	client, err := sdk.NewFiles(f.http.URL+"/relay/v1/files", f.receiverToken, sdk.Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	inbox, err := client.Inbox(context.Background())
	if err != nil || len(inbox) != 1 {
		t.Fatalf("%v %v", inbox, err)
	}
	info := inbox[0]
	if info.Expires != webhookExpiry {
		t.Fatal(info.Expires)
	}
	cipher, _ := os.ReadFile(f.s.path(info.ID))
	if bytes.Contains(cipher, []byte("示例")) {
		t.Fatal("plaintext in ciphertext")
	}
	dir := t.TempDir()
	staged := filepath.Join(dir, "cipher")
	if err = client.Download(context.Background(), info, staged); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain")
	metadata, err := sdk.DecryptFile(f.receiver, "bridge", info, staged, plain)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(metadata, &m); err != nil || m["type"] != "webhook" || m["route"] != "phone" {
		t.Fatalf("%s %v", metadata, err)
	}
	raw, _ := os.ReadFile(plain)
	if string(raw) != body {
		t.Fatal(string(raw))
	}
	if err = f.s.Collect(); err != nil {
		t.Fatal(err)
	}
	if err = client.Delete(context.Background(), info.ID); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.post(t, f.token, body, "event-1"); status != 202 {
		t.Fatal(status)
	}
	inbox, err = client.Inbox(context.Background())
	if err != nil || len(inbox) != 0 {
		t.Fatalf("%v %v", inbox, err)
	}
	if status, _ := f.post(t, f.token, `{"different":true}`, "event-1"); status != 409 {
		t.Fatal(status)
	}
}
func TestWebhookRejectsAndQuota(t *testing.T) {
	f := newHookFixture(t)
	for _, c := range []struct {
		token, body string
		want        int
	}{{"bad", `{}`, 401}, {f.token, `not json`, 400}} {
		if status, _ := f.post(t, c.token, c.body, ""); status != c.want {
			t.Fatal(status)
		}
	}
	f.s.Store.AppQuota = 1
	if status, _ := f.post(t, f.token, `{}`, ""); status != 507 {
		t.Fatal(status)
	}
	f.s.Store.AppQuota = 1 << 20
	if err := f.s.Store.Revoke(Device{App: "test", Group: "group", ID: "mac"}); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.post(t, f.token, `{}`, ""); status != 403 {
		t.Fatal(status)
	}
}
func TestWebhookRecoveryAndIsolation(t *testing.T) {
	f := newHookFixture(t)
	if status, _ := f.post(t, f.token, `{"restart":true}`, "restart"); status != 202 {
		t.Fatal(status)
	}
	// Simulate crash between file publication and final ready transaction.
	if _, err := f.s.Store.DB.Exec("UPDATE files SET state='webhook-staging'; UPDATE webhook_receipts SET ready=0"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(f.s.Store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	next := New(reopened)
	if err = next.RecoverWebhooks(); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.post(t, f.token, `{"restart":true}`, "restart"); status != 202 {
		t.Fatal(status)
	}
	alien := Device{App: "other", Group: "group", ID: "mac", PublicKey: f.route.RecipientKey}
	at := RandomID() + RandomID()
	if err = reopened.AddDevice(alien, at); err != nil {
		t.Fatal(err)
	}
	c, err := sdk.NewFiles(f.http.URL+"/relay/v1/files", at, sdk.Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	inbox, err := c.Inbox(context.Background())
	if err != nil || len(inbox) != 0 {
		t.Fatalf("%v %v", inbox, err)
	}
	// An incomplete ciphertext must never be exposed after recovery.
	var id string
	if err = reopened.DB.QueryRow("SELECT id FROM files").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.DB.Exec("UPDATE files SET state='webhook-staging'"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(next.path(id), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = next.RecoverWebhooks(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = reopened.DB.QueryRow("SELECT count(*) FROM files").Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
func TestWebhookConfigurationAndDisabled(t *testing.T) {
	f := newHookFixture(t)
	if err := os.Chmod(f.config, 0644); err != nil {
		t.Fatal(err)
	}
	if err := New(f.s.Store).LoadWebhooks(f.config); err == nil {
		t.Fatal("accepted public config")
	}
	request := httptest.NewRequest("POST", "/relay/v1/webhooks/phone", nil)
	w := httptest.NewRecorder()
	New(f.s.Store).Handler().ServeHTTP(w, request)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestWebhookConcurrentRetries(t *testing.T) {
	f := newHookFixture(t)
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { status, _ := f.post(t, f.token, `{"event":1}`, "same-request"); codes <- status }()
	}
	for i := 0; i < 2; i++ {
		if code := <-codes; code != 202 {
			t.Fatal(code)
		}
	}
	var count int
	if err := f.s.Store.DB.QueryRow("SELECT count(*) FROM files").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestWebhookOptionalSignature(t *testing.T) {
	f := newHookFixture(t)
	f.route.Signature = &WebhookSignature{Secret: "test-signing-key-32-bytes-long-only", TimestampHeader: "X-Test-Time", SignatureHeader: "X-Test-Signature"}
	raw, _ := json.Marshal([]*WebhookRoute{f.route})
	if err := os.WriteFile(f.config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.s.LoadWebhooks(f.config); err != nil {
		t.Fatal(err)
	}
	for _, expired := range []bool{false, true} {
		stamp := time.Now().Unix()
		if expired {
			stamp -= 301
		}
		ts := strconv.FormatInt(stamp, 10)
		body := []byte(`{"signed":true}`)
		mac := hmac.New(sha256.New, []byte(f.route.Signature.Secret))
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		req := httptest.NewRequest("POST", "/relay/v1/webhooks/phone", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+f.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Time", ts)
		req.Header.Set("X-Test-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		w := httptest.NewRecorder()
		f.s.Handler().ServeHTTP(w, req)
		want := 202
		if expired {
			want = 401
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if status, _ := f.post(t, f.token, `{}`, ""); status != 401 {
		t.Fatal(status)
	}
}

func TestWebhookSystemdReadOnlyCredential(t *testing.T) {
	f := newHookFixture(t)
	if err := os.Chmod(f.config, 0440); err != nil {
		t.Fatal(err)
	}
	if err := New(f.s.Store).LoadWebhooks(f.config); err == nil {
		t.Fatal("ordinary group-readable config accepted")
	}
	if err := os.Chmod(filepath.Dir(f.config), 0550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Dir(f.config), 0700) })
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Dir(f.config))
	if err := New(f.s.Store).LoadWebhooks(f.config); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.config, 0640); err != nil {
		t.Fatal(err)
	}
	if err := New(f.s.Store).LoadWebhooks(f.config); err == nil {
		t.Fatal("writable credential accepted")
	}
}

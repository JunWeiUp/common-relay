package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
	"github.com/coder/websocket"
)

// seedPersonal creates a bridge_allowed space with an admin hub device.
func seedPersonal(t *testing.T, e *testEnv) (deskTok string) {
	t.Helper()
	_, d := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "hub-host", "public_key": fakePubKey(), "is_admin": true})
	e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": "personal", "name": "Personal", "trust_level": "bridge_allowed"})
	e.adminJSON("PUT", "/v2/admin/spaces/personal/members", map[string]any{"device_id": "hub-host", "role": "admin"})
	return d["token"].(string)
}

func (e *testEnv) deviceGet(tok, path string) (*http.Response, []byte) {
	e.t.Helper()
	resp := e.do("GET", path, nil, map[string]string{"Relay-Access": e.access, "Authorization": "Bearer " + tok})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

func TestPluginPatchKeepsWriteOnlySecretsAndVersions(t *testing.T) {
	e := newEnv(t)
	seedPersonal(t, e)
	token := strings.Repeat("t", 40)

	code, res := e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "drop", "mount": "phone", "space_id": "personal",
		"config": map[string]any{"token": token, "max_bytes": 1024},
	})
	if code != 200 {
		t.Fatalf("create drop = %d %v", code, res)
	}
	b := res["binding"].(map[string]any)
	if strings.Contains(b["config_json"].(string), "token") || b["config_version"].(float64) != 1 {
		t.Fatalf("plaintext token must be hashed into a secret: %v", b)
	}
	post := func(tok string) int {
		r := e.do("POST", "/edge/drop/phone", strings.NewReader("hi"), map[string]string{"Authorization": "Bearer " + tok})
		r.Body.Close()
		return r.StatusCode
	}
	if c := post(token); c != 202 {
		t.Fatalf("drop with token = %d", c)
	}

	// Pause without rotating the token.
	code, res = e.adminJSON("PATCH", "/v2/admin/plugins/drop/phone", map[string]any{"enabled": false, "if_version": 1})
	if code != 200 {
		t.Fatalf("PATCH disable = %d %v", code, res)
	}
	if c := post(token); c != 403 {
		t.Fatalf("disabled drop = %d, want 403", c)
	}
	// A stale if_version is refused.
	if code, _ = e.adminJSON("PATCH", "/v2/admin/plugins/drop/phone", map[string]any{"enabled": true, "if_version": 1}); code != 409 {
		t.Fatalf("stale if_version = %d, want 409", code)
	}
	// Re-enable and delete max_bytes (null) while keeping the token.
	code, res = e.adminJSON("PATCH", "/v2/admin/plugins/drop/phone", map[string]any{"enabled": true, "config": map[string]any{"max_bytes": nil}})
	if code != 200 {
		t.Fatalf("PATCH enable = %d %v", code, res)
	}
	b = res["binding"].(map[string]any)
	if b["config_json"] != "{}" || b["config_version"].(float64) != 3 {
		t.Fatalf("PATCH must delete max_bytes and bump version: %v", b)
	}
	if c := post(token); c != 202 {
		t.Fatalf("re-enabled drop with original token = %d", c)
	}
	// PATCH never creates bindings; required secrets cannot be removed.
	if code, _ = e.adminJSON("PATCH", "/v2/admin/plugins/drop/missing", map[string]any{"enabled": true}); code != 404 {
		t.Fatalf("PATCH missing = %d, want 404", code)
	}
	if code, _ = e.adminJSON("PATCH", "/v2/admin/plugins/drop/phone", map[string]any{"config": map[string]any{"token_sha256": nil}}); code != 400 {
		t.Fatalf("removing required token = %d, want 400", code)
	}
	if code, _ = e.adminJSON("PATCH", "/v2/admin/plugins/drop/phone", map[string]any{"config": map[string]any{"bogus": 1}}); code != 400 {
		t.Fatalf("unknown key = %d, want 400", code)
	}
	// GET returns the public view and schema is published.
	code, res = e.adminJSON("GET", "/v2/admin/plugins/drop/phone", nil)
	if code != 200 || res["binding"].(map[string]any)["secret_keys"].([]any)[0] != "token_sha256" {
		t.Fatalf("GET binding = %d %v", code, res)
	}
	_, res = e.adminJSON("GET", "/v2/admin/plugins", nil)
	if len(res["plugins"].([]any)) != 3 {
		t.Fatalf("plugin schemas missing: %v", res["plugins"])
	}
}

func TestWebhookReplayIdempotencyAndSourceLimiter(t *testing.T) {
	e := newEnv(t)
	deskTok := seedPersonal(t, e)
	token := strings.Repeat("w", 40)
	secret := strings.Repeat("s", 32)
	if code, res := e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webhook", "mount": "hook", "space_id": "personal",
		"config": map[string]any{"token": token, "hmac_secret": secret},
	}); code != 200 {
		t.Fatalf("bind webhook = %d %v", code, res)
	}
	body := `{"a":1}`
	sign := func(ts string) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(ts + "." + body))
		return "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	send := func(ts, sig, idem, ip, tok string) (int, map[string]any) {
		h := map[string]string{
			"Authorization": "Bearer " + tok, "Content-Type": "application/json",
			"X-Webhook-Timestamp": ts, "X-Webhook-Signature": sig, "X-Real-IP": ip,
		}
		if idem != "" {
			h["Idempotency-Key"] = idem
		}
		r := e.do("POST", "/edge/webhook/hook", strings.NewReader(body), h)
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if c, out := send(ts, sign(ts), "evt-1", "10.0.0.1", token); c != 202 {
		t.Fatalf("first delivery = %d %v", c, out)
	}
	if c, _ := send(ts, sign(ts), "evt-1", "10.0.0.1", token); c != 409 {
		t.Fatalf("replayed signature = %d, want 409", c)
	}
	ts2 := strconv.FormatInt(time.Now().Unix()+1, 10)
	c, out := send(ts2, sign(ts2), "evt-1", "10.0.0.1", token)
	if c != 200 || out["duplicate"] != true {
		t.Fatalf("idempotent retry = %d %v, want 200 duplicate", c, out)
	}
	_, list := e.deviceGet(deskTok, "/v2/spaces/personal/boxes/webhook/hook/items?after=0")
	var items struct{ Items []core.BoxItem }
	_ = json.Unmarshal(list, &items)
	if len(items.Items) != 1 {
		t.Fatalf("idempotency must store one item, got %d", len(items.Items))
	}

	// Brute force from one source must not lock out another source.
	for i := 0; i < 25; i++ {
		send(ts, "bad", "", "203.0.113.9", "wrong-token-wrong-token-wrong-token")
	}
	if c, _ := send(ts, "bad", "", "203.0.113.9", token); c != 429 {
		t.Fatalf("attacker source = %d, want 429", c)
	}
	ts3 := strconv.FormatInt(time.Now().Unix()+2, 10)
	if c, out := send(ts3, sign(ts3), "evt-2", "10.0.0.1", token); c != 202 {
		t.Fatalf("legitimate source while attacker blocked = %d %v", c, out)
	}
}

func TestSealedBridgePayloadNeverStoredInPlaintext(t *testing.T) {
	e := newEnv(t)
	deskTok := seedPersonal(t, e)
	pubHex, privHex, err := v2client.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("d", 40)
	if code, res := e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "drop", "mount": "sealed", "space_id": "personal",
		"config": map[string]any{"token": token, "seal_public_key": pubHex},
	}); code != 200 || res["binding"].(map[string]any)["sealed"] != true {
		t.Fatalf("bind sealed drop = %d %v", code, res)
	}
	_, got := e.adminJSON("GET", "/v2/admin/plugins/drop/sealed", nil)
	if cj, _ := got["binding"].(map[string]any)["config_json"].(string); !strings.Contains(cj, pubHex) {
		t.Fatalf("seal_public_key must stay visible so consumers can verify it: %s", cj)
	}
	secretText := "very private clipboard text"
	r := e.do("POST", "/edge/drop/sealed?name=n.txt", strings.NewReader(secretText), map[string]string{
		"Authorization": "Bearer " + token, "Content-Type": "text/plain",
	})
	r.Body.Close()
	if r.StatusCode != 202 {
		t.Fatalf("sealed drop = %d", r.StatusCode)
	}
	_, list := e.deviceGet(deskTok, "/v2/spaces/personal/boxes/drop/sealed/items?after=0")
	var items struct{ Items []core.BoxItem }
	_ = json.Unmarshal(list, &items)
	if len(items.Items) != 1 {
		t.Fatalf("items = %s", list)
	}
	it := items.Items[0]
	resp, raw := e.deviceGet(deskTok, "/v2/spaces/personal/boxes/drop/sealed/items/"+it.ID)
	if resp.Header.Get("Content-Type") != "application/vnd.common-relay.sealed" || strings.Contains(string(raw), secretText) {
		t.Fatalf("stored payload is not sealed: ct=%s", resp.Header.Get("Content-Type"))
	}
	pub, _ := v2client.ParsePublicKey(pubHex)
	priv, _ := v2client.ParsePublicKey(privHex)
	plain, err := v2client.OpenSealed(raw, pub, priv)
	if err != nil || string(plain) != secretText {
		t.Fatalf("OpenSealed = %q %v", plain, err)
	}
	if !strings.Contains(it.MetaJSON, `"content_type":"text/plain"`) {
		t.Fatalf("original content type must survive in meta: %s", it.MetaJSON)
	}
}

func TestBoxRoutingUsesWholeSegments(t *testing.T) {
	e := newEnv(t)
	deskTok := seedPersonal(t, e)
	if code, _ := e.adminJSON("POST", "/v2/admin/spaces/personal/boxes", map[string]any{"name": "notes/itemsx", "mode": "queue"}); code != 201 {
		t.Fatalf("box with items-prefixed segment = %d", code)
	}
	if code, _ := e.adminJSON("POST", "/v2/admin/spaces/personal/boxes", map[string]any{"name": "a/items", "mode": "queue"}); code != 400 {
		t.Fatalf("reserved segment box = %d, want 400", code)
	}
	r := e.do("POST", "/v2/spaces/personal/boxes/notes/itemsx/items", strings.NewReader("x"), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + deskTok, "Content-Type": "text/plain",
	})
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatalf("post to notes/itemsx = %d", r.StatusCode)
	}
}

func TestRevokeAndRoleChangeDropLiveSessions(t *testing.T) {
	e := newEnv(t)
	seedPersonal(t, e)
	_, d := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "phone", "public_key": fakePubKey()})
	tok := d["token"].(string)
	e.adminJSON("PUT", "/v2/admin/spaces/personal/members", map[string]any{"device_id": "phone", "role": "member"})

	dial := func() *websocket.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.ts.URL, "http")+"/v2/ws", &websocket.DialOptions{
			HTTPHeader: http.Header{"Relay-Access": []string{e.access}, "Authorization": []string{"Bearer " + tok}},
		})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return c
	}
	waitClosed := func(c *websocket.Conn, why string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for {
			if _, _, err := c.Read(ctx); err != nil {
				if ctx.Err() != nil {
					t.Fatalf("%s: session still open", why)
				}
				return
			}
		}
	}
	c := dial()
	e.adminJSON("PUT", "/v2/admin/spaces/personal/members", map[string]any{"device_id": "phone", "role": "archive_observer"})
	waitClosed(c, "role change")

	c = dial()
	if code, _ := e.adminJSON("DELETE", "/v2/admin/devices/phone", nil); code != 200 {
		t.Fatalf("revoke = %d", code)
	}
	waitClosed(c, "revoke")
}

func TestWebDAVPasswordAccountsManageableWhileDisabled(t *testing.T) {
	e := newEnv(t)
	seedPersonal(t, e)
	if code, _ := e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webdav", "mount": "bak", "space_id": "personal", "enabled": false,
	}); code != 200 {
		t.Fatalf("bind disabled webdav = %d", code)
	}
	pass := "correct-horse-battery-staple"
	if code, res := e.adminJSON("PUT", "/v2/admin/plugins/webdav/bak/accounts", map[string]any{
		"scope_key": "bak", "username": "u1", "password": pass, "mode": "queue",
	}); code != 200 {
		t.Fatalf("password account on disabled binding = %d %v", code, res)
	}
	if code, _ := e.adminJSON("PUT", "/v2/admin/plugins/webdav/bak/accounts", map[string]any{
		"scope_key": "bak2", "username": "u2", "password": "short", "mode": "queue",
	}); code != 400 {
		t.Fatalf("short password = %d, want 400", code)
	}
	e.adminJSON("PATCH", "/v2/admin/plugins/webdav/bak", map[string]any{"enabled": true})
	req, _ := http.NewRequest("PUT", e.ts.URL+"/edge/webdav/bak/bak/f.txt", strings.NewReader("data"))
	req.SetBasicAuth("u1", pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("webdav PUT with scrypt account = %d", resp.StatusCode)
	}
}

func TestGoSDKPatchAndUnsupportedDetection(t *testing.T) {
	e := newEnv(t)
	seedPersonal(t, e)
	c, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.UpsertPlugin(ctx, "drop", "sdk", "personal", "", map[string]any{"token": strings.Repeat("k", 40)}, true); err != nil {
		t.Fatal(err)
	}
	off := false
	b, err := c.PatchPlugin(ctx, "drop", "sdk", v2client.PluginPatch{Enabled: &off})
	if err != nil || b.Enabled || b.ConfigVersion != 2 || len(b.SecretKeys) != 1 {
		t.Fatalf("PatchPlugin = %+v %v", b, err)
	}
	_, err = c.PatchPlugin(ctx, "drop", "nope", v2client.PluginPatch{Enabled: &off})
	if err == nil || v2client.IsUnsupported(err) {
		t.Fatalf("missing binding must be a JSON 404, not unsupported: %v", err)
	}
	infos, err := c.PluginCatalog(ctx)
	if err != nil || len(infos) != 3 {
		t.Fatalf("catalog = %v %v", infos, err)
	}
	if !v2client.IsUnsupported(&v2client.APIError{Status: 404, Msg: "404 page not found"}) {
		t.Fatal("plain 404 from an old server must be unsupported")
	}
}

func TestMeIdentifiesDeviceAndRootAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, isRoot, err := root.Me(ctx); err != nil || !isRoot {
		t.Fatalf("root Me = %v %v", isRoot, err)
	}
	_, tok, err := root.CreateDevice(ctx, "console", "Console", strings.Repeat("ab", 32), true)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: tok, AllowLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	if d, isRoot, err := dev.Me(ctx); err != nil || isRoot || d.ID != "console" {
		t.Fatalf("device Me = %+v %v %v", d, isRoot, err)
	}
	bad, _ := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: "nope", AllowLocal: true})
	if _, _, err := bad.Me(ctx); err == nil {
		t.Fatal("unknown token must be rejected")
	}
}

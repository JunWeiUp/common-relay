package server_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugins/drop"
	"github.com/JunWeiUp/common-relay/internal/v2/plugins/webdav"
	"github.com/JunWeiUp/common-relay/internal/v2/plugins/webhook"
	"github.com/JunWeiUp/common-relay/internal/v2/server"
	"github.com/coder/websocket"
)

type testEnv struct {
	t         *testing.T
	srv       *server.Server
	ts        *httptest.Server
	access    string
	rootAdmin string
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	access := "test-relay-access-secret-123456"
	rootAdmin := "test-root-admin-secret-9876543210"
	srv := server.New(st, server.Config{
		AccessHash:    core.HashSecret(access),
		RootAdminHash: core.HashSecret(rootAdmin),
	})
	for _, p := range []interface{ Register() error }{} {
		_ = p
	}
	if err := srv.RegisterPlugin(drop.New()); err != nil {
		t.Fatal(err)
	}
	if err := srv.RegisterPlugin(webhook.New()); err != nil {
		t.Fatal(err)
	}
	if err := srv.RegisterPlugin(webdav.New()); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{t: t, srv: srv, ts: ts, access: access, rootAdmin: rootAdmin}
}

func (e *testEnv) do(method, path string, body io.Reader, headers map[string]string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *testEnv) adminJSON(method, path string, payload any) (int, map[string]any) {
	e.t.Helper()
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	resp := e.do(method, path, body, map[string]string{
		"Relay-Access":  e.access,
		"Authorization": "Bearer " + e.rootAdmin,
		"Content-Type":  "application/json",
	})
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func fakePubKey() string { return core.RandomHex(32) }

func TestThreePlaneAuthAndTrustBoundaries(t *testing.T) {
	e := newEnv(t)

	// 1. Create ordinary device via Root Admin.
	code, res := e.adminJSON("POST", "/v2/admin/devices", map[string]any{
		"id": "phone-1", "name": "iPhone", "public_key": fakePubKey(), "is_admin": false,
	})
	if code != 201 {
		t.Fatalf("create device = %d %v", code, res)
	}
	phoneToken := res["token"].(string)

	// 2. Ordinary device MUST be rejected from /v2/admin/* (403).
	resp := e.do("GET", "/v2/admin/status", nil, map[string]string{
		"Relay-Access":  e.access,
		"Authorization": "Bearer " + phoneToken,
	})
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("ordinary device on admin = %d, want 403", resp.StatusCode)
	}

	// 3. Missing Relay-Access MUST be rejected on /v2/admin/* (401).
	resp = e.do("GET", "/v2/admin/status", nil, map[string]string{
		"Authorization": "Bearer " + e.rootAdmin,
	})
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("missing Relay-Access = %d, want 401", resp.StatusCode)
	}

	// 4. Create strict_e2e Space (VaultApp) -> MUST reject drop, webhook, and webdav!
	code, _ = e.adminJSON("POST", "/v2/admin/spaces", map[string]any{
		"id": "pv", "name": "VaultApp", "trust_level": "strict_e2e",
	})
	if code != 201 {
		t.Fatalf("create pv space = %d", code)
	}
	for _, pid := range []string{"drop", "webhook", "webdav"} {
		code, _ = e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
			"plugin_id": pid, "mount": "bad-" + pid, "space_id": "pv",
		})
		if code != 403 {
			t.Fatalf("binding %s to strict_e2e space = %d, want 403", pid, code)
		}
	}
}

func TestVaultAppObjectCASAndArchiveObserver(t *testing.T) {
	e := newEnv(t)

	_, dPV := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "pv-mac", "public_key": fakePubKey()})
	_, dDesk := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "desk-mac", "public_key": fakePubKey()})
	pvTok := dPV["token"].(string)
	deskTok := dDesk["token"].(string)

	e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": "pv", "name": "VaultApp", "trust_level": "strict_e2e"})
	e.adminJSON("PUT", "/v2/admin/spaces/pv/members", map[string]any{"device_id": "pv-mac", "role": "member"})
	e.adminJSON("PUT", "/v2/admin/spaces/pv/members", map[string]any{"device_id": "desk-mac", "role": "archive_observer"})
	e.adminJSON("POST", "/v2/admin/spaces/pv/boxes", map[string]any{"name": "vault", "mode": "object", "keep_versions": 3})

	// Put v1 with If-Match: none.
	r1 := e.do("PUT", "/v2/spaces/pv/boxes/vault/objects/main.pvenc", strings.NewReader("CIPHER_V1"), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + pvTok, "If-Match": "none",
	})
	var j1 map[string]any
	_ = json.NewDecoder(r1.Body).Decode(&j1)
	r1.Body.Close()
	if r1.StatusCode != 200 {
		t.Fatalf("put v1 = %d %v", r1.StatusCode, j1)
	}
	etag1 := r1.Header.Get("ETag")

	// Update v2 with valid CAS.
	r2 := e.do("PUT", "/v2/spaces/pv/boxes/vault/objects/main.pvenc", strings.NewReader("CIPHER_V2"), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + pvTok, "If-Match": etag1,
	})
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("put v2 = %d", r2.StatusCode)
	}

	// Stale CAS with etag1 MUST return 409 Conflict!
	rStale := e.do("PUT", "/v2/spaces/pv/boxes/vault/objects/main.pvenc", strings.NewReader("CIPHER_STALE"), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + pvTok, "If-Match": etag1,
	})
	rStale.Body.Close()
	if rStale.StatusCode != 409 {
		t.Fatalf("stale CAS = %d, want 409", rStale.StatusCode)
	}

	// Archive observer (Hub) CAN read opaque ciphertext & versions, CANNOT write!
	rObsGet := e.do("GET", "/v2/spaces/pv/boxes/vault/objects/main.pvenc", nil, map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + deskTok,
	})
	gotBytes, _ := io.ReadAll(rObsGet.Body)
	rObsGet.Body.Close()
	if rObsGet.StatusCode != 200 || string(gotBytes) != "CIPHER_V2" {
		t.Fatalf("observer GET = %d %q", rObsGet.StatusCode, string(gotBytes))
	}

	rObsPut := e.do("PUT", "/v2/spaces/pv/boxes/vault/objects/main.pvenc", strings.NewReader("BAD"), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + deskTok,
	})
	rObsPut.Body.Close()
	if rObsPut.StatusCode != 403 {
		t.Fatalf("observer PUT = %d, want 403", rObsPut.StatusCode)
	}
}

func TestSyncAppPipeStreamAndEphemeralBox(t *testing.T) {
	e := newEnv(t)

	_, d1 := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "syncapp-mac", "public_key": fakePubKey()})
	_, d2 := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "syncapp-phone", "public_key": fakePubKey()})
	tok1, tok2 := d1["token"].(string), d2["token"].(string)

	e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": "syncapp", "name": "SyncApp", "trust_level": "strict_e2e"})
	e.adminJSON("PUT", "/v2/admin/spaces/syncapp/members", map[string]any{"device_id": "syncapp-mac", "role": "member"})
	e.adminJSON("PUT", "/v2/admin/spaces/syncapp/members", map[string]any{"device_id": "syncapp-phone", "role": "member"})
	e.adminJSON("POST", "/v2/admin/spaces/syncapp/boxes", map[string]any{"name": "xfer", "mode": "ephemeral", "ttl_sec": 3600})

	dial := func(tok string) *websocket.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		wsURL := "ws" + strings.TrimPrefix(e.ts.URL, "http") + "/v2/ws"
		c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{
				"Relay-Access":  []string{e.access},
				"Authorization": []string{"Bearer " + tok},
			},
		})
		if err != nil {
			t.Fatalf("ws dial: %v", err)
		}
		return c
	}

	c1 := dial(tok1)
	defer c1.CloseNow()
	c2 := dial(tok2)
	defer c2.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open a zero-disk bidirectional stream (16-byte stream ID).
	streamID := "0123456789abcdef"
	openEv, _ := json.Marshal(core.PipeEvent{Type: "stream.open", Space: "syncapp", ID: streamID, To: "syncapp-phone", Topic: "folder"})
	if err := c1.Write(ctx, websocket.MessageText, openEv); err != nil {
		t.Fatal(err)
	}

	// Phone waits for stream.open and accepts it.
	for {
		_, data, err := c2.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ev core.PipeEvent
		if json.Unmarshal(data, &ev) == nil && ev.Type == "stream.open" && ev.ID == streamID {
			acc, _ := json.Marshal(core.PipeEvent{Type: "stream.accept", Space: "syncapp", ID: streamID})
			if err := c2.Write(ctx, websocket.MessageText, acc); err != nil {
				t.Fatal(err)
			}
			break
		}
	}

	// Mac waits for stream.accept, then sends encrypted binary frame.
	for {
		_, data, err := c1.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ev core.PipeEvent
		if json.Unmarshal(data, &ev) == nil && ev.Type == "stream.accept" && ev.ID == streamID {
			break
		}
	}
	payload := append([]byte(streamID), []byte("ZIP_STREAM_CHUNK_DATA")...)
	if err := c1.Write(ctx, websocket.MessageBinary, payload); err != nil {
		t.Fatal(err)
	}

	// Phone receives exact binary frame.
	kind, gotFrame, err := c2.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || string(gotFrame) != string(payload) {
		t.Fatalf("binary stream mismatch: kind=%v frame=%q err=%v", kind, string(gotFrame), err)
	}

	// Also verify Ephemeral Box upload & SweepExpired.
	rUp := e.do("POST", "/v2/spaces/syncapp/boxes/xfer/items?ttl=1", strings.NewReader("OFFLINE_FOLDER_ZIP"), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + tok1,
	})
	rUp.Body.Close()
	if rUp.StatusCode != 201 {
		t.Fatalf("ephemeral upload = %d", rUp.StatusCode)
	}
	// Force expiry in DB and verify SweepExpired cleans blob + row.
	_, _ = e.srv.Store.DB.Exec(`UPDATE v2_box_items SET expires_at = 1 WHERE space_id='syncapp'`)
	removed, _ := e.srv.Store.SweepExpired()
	if removed != 1 {
		t.Fatalf("expected 1 expired item swept, got %d", removed)
	}
}

func TestEdgePluginsDropWebhookAndDualModeWebDAV(t *testing.T) {
	e := newEnv(t)

	_, dDesk := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": "hub", "public_key": fakePubKey(), "is_admin": true})
	deskTok := dDesk["token"].(string)

	e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": "personal", "name": "Personal", "trust_level": "bridge_allowed"})
	e.adminJSON("PUT", "/v2/admin/spaces/personal/members", map[string]any{"device_id": "hub", "role": "admin"})

	e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": "pv-bak", "name": "PV Backup", "trust_level": "client_encrypted"})
	e.adminJSON("PUT", "/v2/admin/spaces/pv-bak/members", map[string]any{"device_id": "hub", "role": "admin"})

	// 1. Drop plugin: POST -> Box(queue) -> Hub lists & ACKs.
	dropSecret := "drop-secret-token-abcdef123456"
	code, _ := e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "drop", "mount": "shortcuts", "space_id": "personal", "box_name": "drop/shortcuts",
		"config": map[string]any{"token_sha256": core.HashSecret(dropSecret)},
	})
	if code != 200 {
		t.Fatalf("bind drop = %d", code)
	}
	rDrop := e.do("POST", "/edge/drop/shortcuts?name=idea.txt&tag=note", strings.NewReader("buy milk"), map[string]string{
		"Authorization": "Bearer " + dropSecret,
		"Content-Type":  "text/plain",
	})
	var dropResp map[string]any
	_ = json.NewDecoder(rDrop.Body).Decode(&dropResp)
	rDrop.Body.Close()
	if rDrop.StatusCode != 202 || dropResp["seq"].(float64) != 1 {
		t.Fatalf("drop POST = %d %v", rDrop.StatusCode, dropResp)
	}

	// Hub pulls via Device Plane using cursor after=0, downloads, ACKs.
	rList := e.do("GET", "/v2/spaces/personal/boxes/drop/shortcuts/items?after=0", nil, map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + deskTok,
	})
	var listResp struct {
		Items []core.BoxItem `json:"items"`
	}
	_ = json.NewDecoder(rList.Body).Decode(&listResp)
	rList.Body.Close()
	if len(listResp.Items) != 1 {
		t.Fatalf("expected 1 queued item, got %d", len(listResp.Items))
	}
	rAck := e.do("DELETE", "/v2/spaces/personal/boxes/drop/shortcuts/items/"+listResp.Items[0].ID, nil, map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + deskTok,
	})
	rAck.Body.Close()
	if rAck.StatusCode != 200 {
		t.Fatalf("ACK item = %d", rAck.StatusCode)
	}

	// 2. Webhook plugin with HMAC signature.
	whToken := "webhook-secret-token-abcdef123456"
	whHMAC := "hmac-signing-key-abcdef123456"
	e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webhook", "mount": "demo-hook", "space_id": "personal", "box_name": "demo-hook",
		"config": map[string]any{"token_sha256": core.HashSecret(whToken), "hmac_secret": whHMAC},
	})
	tsNow := strconv.FormatInt(time.Now().Unix(), 10)
	whBody := `{"event":"note"}`
	mac := hmac.New(sha256.New, []byte(whHMAC))
	mac.Write([]byte(tsNow + "." + whBody))
	sig := hex.EncodeToString(mac.Sum(nil))

	rWh := e.do("POST", "/edge/webhook/demo-hook", strings.NewReader(whBody), map[string]string{
		"Authorization":       "Bearer " + whToken,
		"X-Webhook-Timestamp": tsNow,
		"X-Webhook-Signature": sig,
	})
	rWh.Body.Close()
	if rWh.StatusCode != 202 {
		t.Fatalf("webhook valid HMAC = %d, want 202", rWh.StatusCode)
	}
	rWhBad := e.do("POST", "/edge/webhook/demo-hook", strings.NewReader(whBody), map[string]string{
		"Authorization":       "Bearer " + whToken,
		"X-Webhook-Timestamp": tsNow,
		"X-Webhook-Signature": "0000",
	})
	rWhBad.Body.Close()
	if rWhBad.StatusCode != 401 {
		t.Fatalf("webhook bad HMAC = %d, want 401", rWhBad.StatusCode)
	}

	// 3. WebDAV dual-mode:
	// 3a) Queue mode (write-only) on bridge_allowed space.
	e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webdav", "mount": "backup", "space_id": "personal",
	})
	billsPass := "bills-pass-secret-123456"
	e.adminJSON("PUT", "/v2/admin/plugins/webdav/backup/accounts", map[string]any{
		"scope_key": "Bills", "username": "u_bills", "secret_sha256": core.HashSecret(billsPass), "mode": "queue",
	})

	reqPut, _ := http.NewRequest("PUT", e.ts.URL+"/edge/webdav/backup/Bills/2026.zip", strings.NewReader("ZIP_BYTES"))
	reqPut.SetBasicAuth("u_bills", billsPass)
	rDavPut, err := http.DefaultClient.Do(reqPut)
	if err != nil || rDavPut.StatusCode != 201 {
		t.Fatalf("webdav queue PUT = %v %v", rDavPut, err)
	}
	rDavPut.Body.Close()

	// Write-only queue mode MUST reject GET (403) and sibling folder access (403)!
	reqGet, _ := http.NewRequest("GET", e.ts.URL+"/edge/webdav/backup/Bills/2026.zip", nil)
	reqGet.SetBasicAuth("u_bills", billsPass)
	rDavGet, _ := http.DefaultClient.Do(reqGet)
	rDavGet.Body.Close()
	if rDavGet.StatusCode != 403 {
		t.Fatalf("webdav queue GET = %d, want 403", rDavGet.StatusCode)
	}
	reqSib, _ := http.NewRequest("PROPFIND", e.ts.URL+"/edge/webdav/backup/OtherFolder/", nil)
	reqSib.SetBasicAuth("u_bills", billsPass)
	rDavSib, _ := http.DefaultClient.Do(reqSib)
	rDavSib.Body.Close()
	if rDavSib.StatusCode != 403 {
		t.Fatalf("webdav sibling folder access = %d, want 403", rDavSib.StatusCode)
	}

	// 3a-unicode) Queue mode with Unicode folder name (e.g. 示例目录) uses deterministic ASCII box name.
	unicodePass := "unicode-pass-secret-123456"
	e.adminJSON("PUT", "/v2/admin/plugins/webdav/backup/accounts", map[string]any{
		"scope_key": "示例目录", "username": "u_unicode", "secret_sha256": core.HashSecret(unicodePass), "mode": "queue",
	})
	reqUnicodePut, _ := http.NewRequest("PUT", e.ts.URL+"/edge/webdav/backup/"+url.PathEscape("示例目录")+"/backup.zip", strings.NewReader("UNICODE_ZIP"))
	reqUnicodePut.SetBasicAuth("u_unicode", unicodePass)
	rUnicodePut, err := http.DefaultClient.Do(reqUnicodePut)
	if err != nil || rUnicodePut.StatusCode != 201 {
		t.Fatalf("webdav unicode PUT = %v %v", rUnicodePut, err)
	}
	rUnicodePut.Body.Close()
	reqUnicodeGet, _ := http.NewRequest("GET", e.ts.URL+"/edge/webdav/backup/"+url.PathEscape("示例目录")+"/backup.zip", nil)
	reqUnicodeGet.SetBasicAuth("u_unicode", unicodePass)
	rUnicodeGet, _ := http.DefaultClient.Do(reqUnicodeGet)
	rUnicodeGet.Body.Close()
	if rUnicodeGet.StatusCode != 403 {
		t.Fatalf("webdav unicode queue GET = %d, want 403", rUnicodeGet.StatusCode)
	}

	// 3b) Object mode (bidirectional client-encrypted) on client_encrypted space.
	code, _ = e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webdav", "mount": "vaultmirror", "space_id": "pv-bak",
		"config": map[string]any{"cors_origins": []string{"chrome-extension://demotestextension"}},
	})
	if code != 200 {
		t.Fatalf("bind webdav to client_encrypted = %d", code)
	}
	pvPass := "pv-backup-pass-123456"
	e.adminJSON("PUT", "/v2/admin/plugins/webdav/vaultmirror/accounts", map[string]any{
		"scope_key": "VaultApp", "username": "u_pv", "secret_sha256": core.HashSecret(pvPass), "mode": "object",
	})

	// CORS preflight: allowlisted origin -> 204 without auth; foreign origin -> 401.
	reqPreflight, _ := http.NewRequest("OPTIONS", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/", nil)
	reqPreflight.Header.Set("Origin", "chrome-extension://demotestextension")
	reqPreflight.Header.Set("Access-Control-Request-Method", "PROPFIND")
	rPre, _ := http.DefaultClient.Do(reqPreflight)
	rPre.Body.Close()
	if rPre.StatusCode != 204 || rPre.Header.Get("Access-Control-Allow-Origin") != "chrome-extension://demotestextension" {
		t.Fatalf("cors preflight allowlisted = %d acao=%q", rPre.StatusCode, rPre.Header.Get("Access-Control-Allow-Origin"))
	}
	reqBadPre, _ := http.NewRequest("OPTIONS", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/", nil)
	reqBadPre.Header.Set("Origin", "https://evil.example")
	reqBadPre.Header.Set("Access-Control-Request-Method", "PROPFIND")
	rBadPre, _ := http.DefaultClient.Do(reqBadPre)
	rBadPre.Body.Close()
	if rBadPre.StatusCode != 401 || rBadPre.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("cors preflight foreign = %d acao=%q", rBadPre.StatusCode, rBadPre.Header.Get("Access-Control-Allow-Origin"))
	}

	reqObjPut, _ := http.NewRequest("PUT", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/snap.backup", strings.NewReader("ENCRYPTED_PV_SNAP"))
	reqObjPut.SetBasicAuth("u_pv", pvPass)
	reqObjPut.Header.Set("If-None-Match", "*")
	rObjPut, _ := http.DefaultClient.Do(reqObjPut)
	etag := rObjPut.Header.Get("ETag")
	rObjPut.Body.Close()
	if rObjPut.StatusCode != 201 || etag == "" {
		t.Fatalf("webdav object PUT = %d etag=%q", rObjPut.StatusCode, etag)
	}
	// Duplicate PUT with If-None-Match: * MUST return 412 Precondition Failed (VaultApp no-overwrite guarantee).
	reqObjDup, _ := http.NewRequest("PUT", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/snap.backup", strings.NewReader("OVERWRITE_ATTEMPT"))
	reqObjDup.SetBasicAuth("u_pv", pvPass)
	reqObjDup.Header.Set("If-None-Match", "*")
	rObjDup, _ := http.DefaultClient.Do(reqObjDup)
	rObjDup.Body.Close()
	if rObjDup.StatusCode != 412 {
		t.Fatalf("webdav object duplicate If-None-Match:* = %d, want 412", rObjDup.StatusCode)
	}
	// PROPFIND on folder returns multistatus XML with creationdate and href.
	reqProp, _ := http.NewRequest("PROPFIND", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/", nil)
	reqProp.SetBasicAuth("u_pv", pvPass)
	reqProp.Header.Set("Depth", "1")
	rProp, _ := http.DefaultClient.Do(reqProp)
	propXML, _ := io.ReadAll(rProp.Body)
	rProp.Body.Close()
	if rProp.StatusCode != 207 || !strings.Contains(string(propXML), "/edge/webdav/vaultmirror/VaultApp/snap.backup") || !strings.Contains(string(propXML), "<D:creationdate>") {
		t.Fatalf("webdav object PROPFIND = %d xml=%s", rProp.StatusCode, string(propXML))
	}
	reqObjGet, _ := http.NewRequest("GET", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/snap.backup", nil)
	reqObjGet.SetBasicAuth("u_pv", pvPass)
	rObjGet, _ := http.DefaultClient.Do(reqObjGet)
	gotSnap, _ := io.ReadAll(rObjGet.Body)
	rObjGet.Body.Close()
	if rObjGet.StatusCode != 200 || string(gotSnap) != "ENCRYPTED_PV_SNAP" {
		t.Fatalf("webdav object GET = %d %q", rObjGet.StatusCode, string(gotSnap))
	}
	req304, _ := http.NewRequest("GET", e.ts.URL+"/edge/webdav/vaultmirror/VaultApp/snap.backup", nil)
	req304.SetBasicAuth("u_pv", pvPass)
	req304.Header.Set("If-None-Match", etag)
	r304, _ := http.DefaultClient.Do(req304)
	r304.Body.Close()
	if r304.StatusCode != 304 {
		t.Fatalf("webdav object If-None-Match = %d, want 304", r304.StatusCode)
	}

	// 4. Verify Admin status endpoint works cleanly for Hub #settings/sync.
	code, st := e.adminJSON("GET", "/v2/admin/status", nil)
	if code != 200 || st["ok"] != true {
		t.Fatalf("admin status = %d %v", code, st)
	}
	fmt.Printf("admin status snapshot: %v\n", st["status"])
}

func TestAdminTopologyAndSecretSanitization(t *testing.T) {
	e := newEnv(t)

	// 1. Project a managed E2E group with app metadata and a manager role.
	if err := e.srv.Store.SyncManagedGroupWithApp("g-1234567890abcdef", "vaultapp", "VaultApp", []core.ManagedMember{
		{ID: "mac-pro", Name: "MacBook Pro", PublicKey: fakePubKey(), TokenHash: core.HashSecret("tok-mac"), Manager: true},
		{ID: "phone-1", Name: "Phone", PublicKey: fakePubKey(), TokenHash: core.HashSecret("tok-phone"), Manager: false},
	}, nil, false); err != nil {
		t.Fatalf("SyncManagedGroupWithApp: %v", err)
	}

	// 2. Create a bridge space + box + webhook plugin containing secrets + webdav plugin with accounts.
	e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": "personal", "name": "Personal", "trust_level": "bridge_allowed"})
	e.adminJSON("POST", "/v2/admin/spaces/personal/boxes", map[string]any{"name": "demo-hook", "mode": "queue"})
	code, _ := e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webhook",
		"mount":     "demo-hook-mobile",
		"space_id":  "personal",
		"box_name":  "demo-hook",
		"config": map[string]any{
			"token_sha256": core.HashSecret("super-secret-token"),
			"hmac_secret":  "super-secret-hmac-value",
			"tag":          "device-tag",
		},
	})
	if code != 200 {
		t.Fatalf("upsert webhook = %d", code)
	}
	code, _ = e.adminJSON("PUT", "/v2/admin/plugins", map[string]any{
		"plugin_id": "webdav",
		"mount":     "backup",
		"space_id":  "personal",
		"box_name":  "webdav",
	})
	if code != 200 {
		t.Fatalf("upsert webdav = %d", code)
	}
	code, _ = e.adminJSON("PUT", "/v2/admin/plugins/webdav/backup/accounts", map[string]any{
		"scope_key":     "bills",
		"username":      "u_bills",
		"secret_sha256": core.HashSecret("dav-secret-pass"),
		"mode":          "queue",
	})
	if code != 200 {
		t.Fatalf("upsert webdav account = %d", code)
	}

	// 3. Verify GET /v2/admin/spaces returns enriched app, members (with roles), and boxes.
	code, spRes := e.adminJSON("GET", "/v2/admin/spaces", nil)
	if code != 200 || spRes["ok"] != true {
		t.Fatalf("GET spaces = %d %v", code, spRes)
	}
	rawSpaces, _ := json.Marshal(spRes["spaces"])
	var spaces []core.Space
	if err := json.Unmarshal(rawSpaces, &spaces); err != nil {
		t.Fatalf("unmarshal spaces: %v", err)
	}
	var gotGroup, gotPersonal *core.Space
	for i := range spaces {
		switch spaces[i].ID {
		case "g-1234567890abcdef":
			gotGroup = &spaces[i]
		case "personal":
			gotPersonal = &spaces[i]
		}
	}
	if gotGroup == nil || gotGroup.App != "vaultapp" || len(gotGroup.Members) != 2 {
		t.Fatalf("expected enriched E2E group, got %+v", gotGroup)
	}
	if gotGroup.Members[0].DeviceID != "mac-pro" || gotGroup.Members[0].Role != core.RoleAdmin {
		t.Fatalf("expected manager promoted to admin role first, got %+v", gotGroup.Members)
	}
	if gotPersonal == nil || len(gotPersonal.Boxes) != 1 || gotPersonal.Boxes[0].Name != "demo-hook" {
		t.Fatalf("expected enriched boxes on personal space, got %+v", gotPersonal)
	}

	// 4. Verify GET /v2/admin/plugins returns summary + accounts and NEVER leaks secrets.
	code, plRes := e.adminJSON("GET", "/v2/admin/plugins", nil)
	if code != 200 || plRes["ok"] != true {
		t.Fatalf("GET plugins = %d %v", code, plRes)
	}
	rawPlugins, _ := json.Marshal(plRes)
	bodyStr := string(rawPlugins)
	for _, secret := range []string{"super-secret-hmac-value", core.HashSecret("super-secret-token"), core.HashSecret("dav-secret-pass"), "secret_hash"} {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("GET /v2/admin/plugins leaked secret %q in payload: %s", secret, bodyStr)
		}
	}
	// Secret key *names* may appear in secret_keys/schema, never in config_json.
	for _, b := range plRes["bindings"].([]any) {
		cj, _ := b.(map[string]any)["config_json"].(string)
		if strings.Contains(cj, "hmac_secret") || strings.Contains(cj, "token_sha256") {
			t.Fatalf("config_json carries secret keys: %s", cj)
		}
	}
	var bindings []core.PluginBinding
	rawB, _ := json.Marshal(plRes["bindings"])
	if err := json.Unmarshal(rawB, &bindings); err != nil {
		t.Fatalf("unmarshal bindings: %v", err)
	}
	var gotWH, gotDAV *core.PluginBinding
	for i := range bindings {
		switch bindings[i].PluginID {
		case "webhook":
			gotWH = &bindings[i]
		case "webdav":
			gotDAV = &bindings[i]
		}
	}
	if gotWH == nil || gotWH.Summary == nil || gotWH.Summary.Tag != "device-tag" || !gotWH.Summary.HasHMAC || !gotWH.Summary.HasToken {
		t.Fatalf("expected webhook summary, got %+v", gotWH)
	}
	if gotDAV == nil || len(gotDAV.Accounts) != 1 || gotDAV.Accounts[0].Username != "u_bills" || gotDAV.Accounts[0].ScopeKey != "bills" {
		t.Fatalf("expected webdav accounts view, got %+v", gotDAV)
	}
}

func TestAdminAccessPasswordRotation(t *testing.T) {
	e := newEnv(t)
	var syncedHash string
	e.srv.OnAccessHashChanged = func(h string) { syncedHash = h }

	// 1. Read current access password metadata (must not expose full hash).
	code, meta := e.adminJSON("GET", "/v2/admin/access-password", nil)
	if code != 200 || meta["ok"] != true || meta["configured"] != true {
		t.Fatalf("GET access-password = %d %v", code, meta)
	}

	// 2. Rotate access password via SHA-256 hash.
	newPass := "rotated-relay-access-2026!"
	newHash := core.HashSecret(newPass)
	code, upd := e.adminJSON("PUT", "/v2/admin/access-password", map[string]any{"access_hash": newHash})
	if code != 200 || upd["ok"] != true || upd["hash_prefix"] != newHash[:8] {
		t.Fatalf("PUT access-password = %d %v", code, upd)
	}
	if syncedHash != newHash {
		t.Fatalf("OnAccessHashChanged got %q, want %q", syncedHash, newHash)
	}

	// 3. Old access password MUST immediately be rejected (401).
	resp := e.do("GET", "/v2/admin/status", nil, map[string]string{
		"Relay-Access":  e.access,
		"Authorization": "Bearer " + e.rootAdmin,
	})
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("old Relay-Access should fail with 401, got %d", resp.StatusCode)
	}

	// 4. New access password succeeds and persists in v2_settings.
	resp = e.do("GET", "/v2/admin/status", nil, map[string]string{
		"Relay-Access":  newPass,
		"Authorization": "Bearer " + e.rootAdmin,
	})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("new Relay-Access should succeed with 200, got %d", resp.StatusCode)
	}
	saved, _, ok, err := e.srv.Store.GetSetting("access_hash")
	if err != nil || !ok || saved != newHash {
		t.Fatalf("persisted access_hash = (%q, %v, %v), want %q", saved, ok, err, newHash)
	}
}

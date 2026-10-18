package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/coder/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	t      *testing.T
	s      *Server
	http   *httptest.Server
	tokens map[string]string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store)
	s.DiskReserve = 0
	f := &fixture{t: t, s: s, http: httptest.NewServer(s.Handler()), tokens: map[string]string{}}
	t.Cleanup(func() { s.Close(); f.http.Close(); store.DB.Close() })
	return f
}
func (f *fixture) add(id, app string) Device {
	d := Device{App: app, Group: "test", ID: id, PublicKey: strings.Repeat("01", 32)}
	token := RandomID() + RandomID()
	if err := f.s.Store.AddDevice(d, token); err != nil {
		f.t.Fatal(err)
	}
	f.tokens[id] = token
	return d
}
func (f *fixture) dial(id string) *websocket.Conn {
	f.t.Helper()
	h := http.Header{"Authorization": []string{"Bearer " + f.tokens[id]}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.http.URL, "http")+"/relay/v1/ws", &websocket.DialOptions{HTTPHeader: h, Subprotocols: []string{"common-relay.v1"}})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { ws.CloseNow() })
	e := readEvent(f.t, ws)
	if e.Type != "welcome" {
		f.t.Fatal(e)
	}
	return ws
}
func readEvent(t *testing.T, ws *websocket.Conn) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var e Event
	if err = json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if e.Type == "peer.up" || e.Type == "peer.down" {
		return readEvent(t, ws)
	}
	return e
}
func sendEvent(t *testing.T, ws *websocket.Conn, e Event) {
	t.Helper()
	b, _ := json.Marshal(e)
	if err := ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}
func TestIsolationOfflineAndRevocation(t *testing.T) {
	f := setup(t)
	alice := f.add("alice", "one")
	bob := f.add("bob", "one")
	f.add("outsider", "two")
	a := f.dial("alice")
	x := f.dial("outsider")
	sendEvent(t, x, Event{Type: "message", ID: RandomID(), To: "alice", Body: "opaque"})
	if e := readEvent(t, x); e.Code != "unknown_peer" {
		t.Fatal(e)
	}
	id := RandomID()
	sendEvent(t, a, Event{Type: "message", ID: id, To: "bob", Body: "opaque", Offline: true})
	if e := readEvent(t, a); e.Type != "stored" {
		t.Fatal(e)
	}
	b := f.dial("bob")
	if e := readEvent(t, b); e.ID != id || e.From != "alice" {
		t.Fatal(e)
	}
	sendEvent(t, b, Event{Type: "ack", ID: id, From: "alice"})
	if e := readEvent(t, b); e.Type != "acked" {
		t.Fatal(e)
	}
	sendEvent(t, a, Event{Type: "message", ID: id, To: "bob", Body: "opaque", Offline: true})
	if e := readEvent(t, a); e.Type != "received" {
		t.Fatal(e)
	}
	if err := f.s.Store.Revoke(bob); err != nil {
		t.Fatal(err)
	}
	sendEvent(t, a, Event{Type: "message", ID: RandomID(), To: "bob", Body: "opaque"})
	if e := readEvent(t, a); e.Code != "unknown_peer" {
		t.Fatal(e)
	}
	if _, err := f.s.Store.Authenticate(f.tokens["bob"]); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if _, err := f.s.Store.Peer(alice, "bob"); err == nil {
		t.Fatal("revoked peer visible")
	}
}
func TestStreamsRequireAcceptAndSequence(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	a, b := f.dial("alice"), f.dial("bob")
	id := RandomID()
	sendEvent(t, a, Event{Type: "stream.open", ID: id, To: "bob", Body: "encrypted descriptor"})
	if e := readEvent(t, b); e.Type != "stream.open" {
		t.Fatal(e)
	}
	sendEvent(t, b, Event{Type: "stream.accept", ID: id, Body: "encrypted reply"})
	if e := readEvent(t, a); e.Type != "stream.accept" {
		t.Fatal(e)
	}
	if e := readEvent(t, b); e.Type != "stream.ready" {
		t.Fatal(e)
	}
	raw := make([]byte, 26)
	raw[0] = 1
	sid, _ := hex.DecodeString(id)
	copy(raw[1:17], sid)
	raw[25] = 42
	a.Write(context.Background(), websocket.MessageBinary, raw)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	kind, got, err := b.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || !bytes.Equal(got, raw) {
		t.Fatalf("binary: %v", err)
	}
	a.Write(context.Background(), websocket.MessageBinary, raw)
	if e := readEvent(t, a); e.Code != "invalid_sequence" {
		t.Fatal(e)
	}
	if e := readEvent(t, b); e.Type != "stream.close" {
		t.Fatal(e)
	}
}
func (f *fixture) request(id, method, path string, body []byte, headers map[string]string) (int, []byte) {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.http.URL+"/relay/v1/files"+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.tokens[id])
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}
func TestFilesResumeIsolationCommitAndCleanup(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	f.add("outsider", "two")
	data := []byte("opaque ciphertext with final tag")
	sum := sha256.Sum256(data)
	id := RandomID()
	info := File{ID: id, To: "bob", Size: int64(len(data)), Metadata: "encrypted", Digest: hex.EncodeToString(sum[:])}
	j, _ := json.Marshal(info)
	if code, b := f.request("alice", "POST", "", j, nil); code != 201 {
		t.Fatalf("create %d %s", code, b)
	}
	if code, _ := f.request("outsider", "GET", "/"+id, nil, nil); code != 404 {
		t.Fatal(code)
	}
	if code, _ := f.request("bob", "GET", "/"+id+"/data", nil, nil); code != 409 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "PUT", "/"+id+"/data", data[:5], map[string]string{"Upload-Offset": "0"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "PUT", "/"+id+"/data", data[5:], map[string]string{"Upload-Offset": "0"}); code != 409 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "PUT", "/"+id+"/data", data[5:], map[string]string{"Upload-Offset": "5"}); code != 200 {
		t.Fatal(code)
	}
	if code, b := f.request("alice", "POST", "/"+id+"/commit", nil, nil); code != 200 {
		t.Fatalf("commit %d %s", code, b)
	}
	if code, b := f.request("bob", "GET", "/"+id+"/data", nil, map[string]string{"Range": "bytes=5-"}); code != 206 || !bytes.Equal(b, data[5:]) {
		t.Fatalf("range %d %s", code, b)
	}
	f.s.Store.DB.Exec("UPDATE files SET expires=0 WHERE id=?", id)
	if err := f.s.Collect(); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.request("alice", "GET", "/"+id, nil, nil); code != 404 {
		t.Fatal(code)
	}
}
func TestQuotaAndMessageIDConflict(t *testing.T) {
	f := setup(t)
	a := f.add("alice", "one")
	f.add("bob", "one")
	f.s.Store.AppQuota = 10
	id := RandomID()
	if _, err := f.s.Store.PutMessage(a, "bob", id, []byte("1234567890"), 60); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Store.PutMessage(a, "bob", RandomID(), []byte("x"), 60); err != ErrQuota {
		t.Fatal(fmt.Sprint(err))
	}
	if _, err := f.s.Store.PutMessage(a, "bob", id, []byte("different"), 60); err == nil {
		t.Fatal("ID overwrite")
	}
}

func TestFileDeleteRetainsQuotaOnFilesystemFailure(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	id := RandomID()
	digest := sha256.Sum256([]byte("x"))
	body, _ := json.Marshal(map[string]any{"id": id, "to": "bob", "size": 1, "metadata": "cipher", "sha256": hex.EncodeToString(digest[:])})
	if code, response := f.request("alice", "POST", "", body, nil); code != 201 {
		t.Fatalf("create %d %s", code, response)
	}
	path := f.s.path(id)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(path, "blocked")
	if err := os.WriteFile(child, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.request("alice", "DELETE", "/"+id, nil, nil); code != 500 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "GET", "/"+id, nil, nil); code != 200 {
		t.Fatal("quota row lost", code)
	}
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.request("alice", "DELETE", "/"+id, nil, nil); code != 204 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "GET", "/"+id, nil, nil); code != 404 {
		t.Fatal(code)
	}
}

func TestEmptyDiscoveryIsAnArray(t *testing.T) {
	f := setup(t)
	f.add("alone", "isolated")
	ws := f.dial("alone")
	sendEvent(t, ws, Event{Type: "peers", ID: RandomID()})
	event := readEvent(t, ws)
	if event.Type != "peers" || event.Devices == nil || len(event.Devices) != 0 {
		t.Fatalf("empty discovery must include devices: []: %#v", event)
	}
}

package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
)

type fixture struct {
	t      *testing.T
	s      *Server
	hub    *fakeHub
	http   *httptest.Server
	tokens map[string]string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	v2, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(v2)
	if err != nil {
		t.Fatal(err)
	}
	s := New(store)
	s.DiskReserve = 0
	hub := &fakeHub{}
	s.Hub = hub
	f := &fixture{t: t, s: s, hub: hub, http: httptest.NewServer(s.Handler()), tokens: map[string]string{}}
	t.Cleanup(func() { f.http.Close(); v2.Close() })
	return f
}

// fakeHub records what the ledger pushes to live sessions.
type fakeHub struct {
	mu           sync.Mutex
	online       map[string][]string
	notified     []string // space@revision
	disconnected []string
}

func (h *fakeHub) OnlineDevices(space string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.online[space]...)
}
func (h *fakeHub) NotifyGroupChanged(space string, revision int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notified = append(h.notified, fmt.Sprintf("%s@%d", space, revision))
}
func (h *fakeHub) DisconnectDevice(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disconnected = append(h.disconnected, id)
}
func (f *fixture) add(id, app string) Device {
	d := Device{App: app, Group: "test", ID: id, PublicKey: strings.Repeat("01", 32)}
	token := RandomID() + RandomID()
	if err := addTestDevice(f.s.Store, d, token); err != nil {
		f.t.Fatal(err)
	}
	f.tokens[id] = token
	return d
}

// addTestDevice inserts a credential row directly; production devices only
// arrive through the signed group ledger.
func addTestDevice(s *Store, d Device, token string) error {
	_, err := s.DB.Exec("INSERT INTO v2_ledger_devices(app,grp,id,token_hash,public_key) VALUES(?,?,?,?,?)", d.App, d.Group, d.ID, hashToken(token), d.PublicKey)
	return err
}
func (f *fixture) request(id, method, path string, body []byte, headers map[string]string) (int, []byte) {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.http.URL+"/v2/files"+path, bytes.NewReader(body))
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
	f.s.Store.DB.Exec("UPDATE v2_ledger_files SET expires=0 WHERE id=?", id)
	if err := f.s.Collect(); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.request("alice", "GET", "/"+id, nil, nil); code != 404 {
		t.Fatal(code)
	}
}
func TestFileQuota(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	f.s.Store.AppQuota = 10
	create := func(size int) int {
		digest := sha256.Sum256(bytes.Repeat([]byte("x"), size))
		body, _ := json.Marshal(map[string]any{"id": RandomID(), "to": "bob", "size": size, "metadata": "cipher", "sha256": hex.EncodeToString(digest[:])})
		code, _ := f.request("alice", "POST", "", body, nil)
		return code
	}
	if code := create(10); code != 201 {
		t.Fatal(code)
	}
	if code := create(1); code != 507 {
		t.Fatal("quota exceeded but accepted", code)
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

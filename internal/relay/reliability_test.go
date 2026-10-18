package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReceiverStreamLimitAndIndependentExpiry(t *testing.T) {
	f := setup(t)
	f.add("receiver", "one")
	b := f.dial("receiver")
	for i := 0; i < 9; i++ {
		name := string(rune('a' + i))
		f.add(name, "one")
		a := f.dial(name)
		sendEvent(t, a, Event{Type: "stream.open", ID: RandomID(), To: "receiver", Body: "opaque"})
		if i < 8 {
			if e := readEvent(t, b); e.Type != "stream.open" {
				t.Fatal(e)
			}
		} else {
			if e := readEvent(t, a); e.Code != "capacity" {
				t.Fatal(e)
			}
		}
	}
	// Move deadlines into the past; the real heartbeat must collect them without a new open.
	f.s.mu.Lock()
	for _, st := range f.s.streams {
		st.deadline = time.Now().Add(-time.Second)
	}
	f.s.mu.Unlock()
	for i := 0; i < 8; i++ {
		if e := readEvent(t, b); e.Type != "stream.close" || e.Code != "timeout" {
			t.Fatal(e)
		}
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if len(f.s.streams) != 0 {
		t.Fatal("expired streams retained")
	}
}

func createTestFile(t *testing.T, f *fixture) string {
	t.Helper()
	id := RandomID()
	digest := sha256.Sum256([]byte("x"))
	body, _ := json.Marshal(map[string]any{"id": id, "to": "bob", "size": 1, "metadata": "cipher", "sha256": hex.EncodeToString(digest[:])})
	if code, b := f.request("alice", "POST", "", body, nil); code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	return id
}

type slowBody struct {
	started chan struct{}
	release chan struct{}
	sent    bool
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.EOF
	}
	close(b.started)
	<-b.release
	b.sent = true
	p[0] = 'x'
	return 1, nil
}
func (*slowBody) Close() error { return nil }

func TestSlowUploadOnlyLocksItsOwnFile(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	id := createTestFile(t, f)
	body := &slowBody{started: make(chan struct{}), release: make(chan struct{})}
	req := httptest.NewRequest("PUT", "/relay/v1/files/"+id+"/data", body)
	req.ContentLength = 1
	req.Header.Set("Authorization", "Bearer "+f.tokens["alice"])
	req.Header.Set("Upload-Offset", "0")
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); f.s.Handler().ServeHTTP(w, req); done <- w.Code }()
	<-body.started
	released := false
	defer func() {
		if !released {
			close(body.release)
		}
	}()
	// A different object's full lifecycle proceeds while the first upload is stalled.
	other := createTestFile(t, f)
	if code, _ := f.request("alice", "PUT", "/"+other+"/data", []byte("x"), map[string]string{"Upload-Offset": "0"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "POST", "/"+other+"/commit", nil, nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.request("bob", "GET", "/"+other+"/data", nil, nil); code != 200 {
		t.Fatal(code)
	}
	close(body.release)
	released = true
	if code := <-done; code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.request("alice", "PUT", "/"+id+"/data", []byte("x"), map[string]string{"Upload-Offset": "0"}); code != 409 {
		t.Fatal("stale offset accepted", code)
	}
	f.s.fileLocksMu.Lock()
	defer f.s.fileLocksMu.Unlock()
	if len(f.s.fileLocks) != 0 {
		t.Fatal("file lock leaked")
	}
}

func TestCollectContinuesAfterFailedFileAndRetries(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	blocked, good := createTestFile(t, f), createTestFile(t, f)
	if err := os.Mkdir(f.s.path(blocked), 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(f.s.path(blocked), "blocked")
	if err := os.WriteFile(child, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.s.path(good), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Store.DB.Exec("UPDATE files SET expires=0"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Collect(); err == nil {
		t.Fatal("expected deletion failure")
	}
	var count int
	f.s.Store.DB.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	if _, err := os.Stat(f.s.path(good)); !os.IsNotExist(err) {
		t.Fatal("healthy expired file retained", err)
	}
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Collect(); err != nil {
		t.Fatal(err)
	}
	f.s.Store.DB.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
	if count != 0 {
		t.Fatal(count)
	}
}

func TestSameFileConcurrentUploadCommitAndCollection(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	id := createTestFile(t, f)
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() {
			req := httptest.NewRequest("PUT", "/relay/v1/files/"+id+"/data", bytes.NewReader([]byte("x")))
			req.Header.Set("Authorization", "Bearer "+f.tokens["alice"])
			req.Header.Set("Upload-Offset", "0")
			w := httptest.NewRecorder()
			f.s.Handler().ServeHTTP(w, req)
			results <- w.Code
		}()
	}
	a, b := <-results, <-results
	if !((a == 200 && b == 409) || (a == 409 && b == 200)) {
		t.Fatal(a, b)
	}
	// Expiry wins whichever operation gets the per-file lock first; no ready orphan remains.
	f.s.Store.DB.Exec("UPDATE files SET expires=0 WHERE id=?", id)
	cleaned := make(chan error, 1)
	go func() { cleaned <- f.s.Collect() }()
	if code, _ := f.request("alice", "POST", "/"+id+"/commit", nil, nil); code != 404 {
		t.Fatal(code)
	}
	if err := <-cleaned; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.s.path(id)); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestAbsoluteExpiryCannotBeRenewed(t *testing.T) {
	f := setup(t)
	f.add("alice", "one")
	f.add("bob", "one")
	a := f.dial("alice")
	id := RandomID()
	expiry := time.Now().Unix() + 60
	event := Event{Type: "message", ID: id, To: "bob", Body: "opaque", Offline: true, Expires: expiry}
	sendEvent(t, a, event)
	if e := readEvent(t, a); e.Type != "stored" {
		t.Fatal(e)
	}
	sendEvent(t, a, event)
	if e := readEvent(t, a); e.Type != "stored" {
		t.Fatal(e)
	}
	var got int64
	f.s.Store.DB.QueryRow("SELECT expires FROM messages WHERE id=?", id).Scan(&got)
	if got != expiry {
		t.Fatal(got, expiry)
	}
	event.Expires = time.Now().Unix() - 1
	sendEvent(t, a, event)
	if e := readEvent(t, a); !strings.Contains(e.Code, "expiry") {
		t.Fatal(e)
	}
}

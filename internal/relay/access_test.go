package relay

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestAccessPasswordRequiredOnEveryEndpoint(t *testing.T) {
	f := setup(t)
	f.s.AccessHash = mustHash(t, "correct-horse-1")
	f.add("a", "example")
	paths := []string{"/relay/v1/ws", "/relay/v1/group", "/relay/v1/group/create", "/relay/v1/enroll/" + strings.Repeat("a", 32), "/relay/v1/files", "/relay/v1/files/x"}
	for _, pw := range []string{"", "wrong-password"} {
		for _, p := range paths {
			req, _ := http.NewRequest("GET", f.http.URL+p, nil)
			req.Header.Set("Authorization", "Bearer "+f.tokens["a"])
			if pw != "" {
				req.Header.Set(AccessHeader, pw)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != 401 {
				t.Fatalf("%s with %q: got %d", p, pw, res.StatusCode)
			}
		}
	}
	res, err := http.Get(f.http.URL + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("healthz must not require password: %v %v", err, res)
	}
	res.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h := http.Header{"Authorization": {"Bearer " + f.tokens["a"]}, AccessHeader: {"correct-horse-1"}}
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.http.URL, "http")+"/relay/v1/ws", &websocket.DialOptions{HTTPHeader: h, Subprotocols: []string{"common-relay.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if e := readEvent(t, ws); e.Type != "welcome" {
		t.Fatalf("expected welcome, got %s", e.Type)
	}
}

func TestAccessPasswordFileAndValidation(t *testing.T) {
	for _, p := range []string{"short", "has space1", strings.Repeat("a", 129), "tab\tpassword"} {
		if ValidAccessPassword(p) {
			t.Fatalf("%q should be invalid", p)
		}
	}
	if !ValidAccessPassword("Abc-123!xyz") {
		t.Fatal("valid password rejected")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(AccessPasswordHash("Abc-123!xyz")+"\n"), 0600)
	if _, err := LoadAccessHash(good); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("Abc-123!xyz\n"), 0600)
	if _, err := LoadAccessHash(bad); err == nil {
		t.Fatal("plaintext password file must be rejected")
	}
}

func mustHash(t *testing.T, p string) []byte {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "h")
	os.WriteFile(dir, []byte(AccessPasswordHash(p)), 0600)
	h, err := LoadAccessHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

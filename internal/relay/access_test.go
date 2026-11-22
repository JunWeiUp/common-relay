package relay

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessPasswordRequiredOnEveryEndpoint(t *testing.T) {
	f := setup(t)
	f.s.AccessHash = mustHash(t, "correct-horse-1")
	f.add("a", "example")
	paths := []string{"/v2/group", "/v2/group/create", "/v2/enroll/" + strings.Repeat("a", 32), "/v2/files", "/v2/files/x"}
	do := func(path, pw string) int {
		req, _ := http.NewRequest("GET", f.http.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+f.tokens["a"])
		if pw != "" {
			req.Header.Set(AccessHeader, pw)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	for _, pw := range []string{"", "wrong-password"} {
		for _, p := range paths {
			if code := do(p, pw); code != 401 {
				t.Fatalf("%s with %q: got %d", p, pw, code)
			}
		}
	}
	// The correct password reaches the handler: an authenticated file listing succeeds.
	if code := do("/v2/files", "correct-horse-1"); code != 200 {
		t.Fatalf("correct password rejected: %d", code)
	}
	// Removed v1 routes are gone, not merely guarded.
	for _, p := range []string{"/relay/v1/ws", "/relay/v1/files", "/relay/v1/group"} {
		if code := do(p, "correct-horse-1"); code != 404 {
			t.Fatalf("%s: got %d, want 404", p, code)
		}
	}
	rec := httptest.NewRecorder()
	f.s.Healthz(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("healthz: %d", rec.Code)
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

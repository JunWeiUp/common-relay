package relay

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testAccess = "correct-horse-1"

type headerLog struct {
	mu   sync.Mutex
	seen []string
}

func (h *headerLog) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.seen = append(h.seen, r.URL.Path+"="+r.Header.Get(AccessHeader))
		h.mu.Unlock()
		http.Error(w, "unauthorized", 401)
	}))
	t.Cleanup(s.Close)
	return s
}
func (h *headerLog) all(t *testing.T, want string) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.seen) == 0 {
		t.Fatal("no request reached the server")
	}
	for _, v := range h.seen {
		if !strings.HasSuffix(v, "="+want) {
			t.Fatalf("access header %q, want %q", v, want)
		}
	}
}

func TestAccessPasswordValidation(t *testing.T) {
	for _, p := range []string{"short", "has space1", strings.Repeat("a", 129), "tab\tpassword", "密码密码密码"} {
		if validAccessPassword(p) == nil {
			t.Fatalf("%q accepted", p)
		}
	}
	for _, p := range []string{"", "Abc-123!xyz", strings.Repeat("~", 128)} {
		if validAccessPassword(p) != nil {
			t.Fatalf("%q rejected", p)
		}
	}
	h := &headerLog{}
	s := h.server(t)
	ws := strings.Replace(s.URL, "http://", "ws://", 1) + "/relay/v1/ws"
	if _, err := NewGroups(&GroupConfig{URL: ws, Password: "bad pass word"}, true); err == nil {
		t.Fatal("groups accepted invalid password")
	}
	if _, err := NewFiles(s.URL+"/relay/v1/files", strings.Repeat("x", 64), Options{AllowLocalTest: true, Password: "short"}); err == nil {
		t.Fatal("files accepted invalid password")
	}
	if _, err := Dial(context.Background(), ws, strings.Repeat("x", 64), &Identity{}, Options{AllowLocalTest: true, Password: "short"}); err == nil || strings.Contains(err.Error(), "short") {
		t.Fatalf("dial accepted invalid password or leaked it: %v", err)
	}
	if len(h.seen) != 0 {
		t.Fatal("invalid password reached the network")
	}
}

func TestAccessHeaderOnEveryRequest(t *testing.T) {
	for _, pw := range []string{testAccess, ""} {
		h := &headerLog{}
		s := h.server(t)
		ws := strings.Replace(s.URL, "http://", "ws://", 1) + "/relay/v1/ws"
		token := strings.Repeat("x", 64)
		Dial(context.Background(), ws, token, &Identity{}, Options{AllowLocalTest: true, Password: pw})
		g, err := NewGroups(&GroupConfig{URL: ws, App: "example", Token: token, Password: pw}, true)
		if err != nil {
			t.Fatal(err)
		}
		var out any
		g.call("GET", "/group", nil, "", &out)
		id := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
		key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		if _, err = g.ResolveInvitation("common-relay://" + strings.TrimPrefix(s.URL, "http://") + "/i/" + id + "#" + key); err == nil || strings.Contains(err.Error(), testAccess) {
			t.Fatalf("resolve: %v", err)
		}
		f, err := NewFiles(s.URL+"/relay/v1/files", token, Options{AllowLocalTest: true, Password: pw})
		if err != nil {
			t.Fatal(err)
		}
		if r, err := f.do(context.Background(), "GET", "/x", nil, nil); err == nil {
			r.Body.Close()
		}
		h.all(t, pw)
		h.mu.Lock()
		joined := strings.Join(h.seen, " ")
		h.mu.Unlock()
		for _, p := range []string{"/relay/v1/ws", "/relay/v1/group", "/relay/v1/enroll/", "/relay/v1/files/x"} {
			if !strings.Contains(joined, p) {
				t.Fatalf("missing request %s in %s", p, joined)
			}
		}
	}
}

func TestResolveInvitationForeignRelayGetsNoPassword(t *testing.T) {
	own, foreign := &headerLog{}, &headerLog{}
	o, f := own.server(t), foreign.server(t)
	g, err := NewGroups(&GroupConfig{URL: strings.Replace(o.URL, "http://", "ws://", 1) + "/relay/v1/ws", App: "example", Password: testAccess}, true)
	if err != nil {
		t.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err = g.ResolveInvitation("common-relay://" + strings.TrimPrefix(f.URL, "http://") + "/i/" + id + "#" + key); err == nil {
		t.Fatal("expected failure")
	}
	foreign.all(t, "")
	own.mu.Lock()
	n := len(own.seen)
	own.mu.Unlock()
	if n != 0 {
		t.Fatal("own relay unexpectedly contacted")
	}
}

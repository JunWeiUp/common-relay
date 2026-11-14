package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticatedClientFlow(t *testing.T) {
	p := probe{tokenHash: sha256.Sum256([]byte("test-only-token"))}
	for _, tc := range []struct {
		name, body string
		status     int
		contains   string
	}{
		{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`, 200, `"protocolVersion":"2025-03-26"`},
		{"initialized", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ""},
		{"list", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, 200, "console_connection_test"},
		{"call", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"console_connection_test","arguments":{}}}`, 200, "连接测试成功"},
		{"unknown tool", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_private_data"}}`, 200, `"code":-32602`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/mcp", strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer test-only-token")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if w.Code == 200 && !json.Valid(w.Body.Bytes()) {
				t.Fatal("invalid JSON response")
			}
		})
	}
}

func TestAccessBoundaries(t *testing.T) {
	p := probe{tokenHash: sha256.Sum256([]byte("test-only-token"))}
	for _, tc := range []struct {
		name, method, token, origin, body string
		status                            int
	}{
		{"missing auth", "POST", "", "", `{}`, 401},
		{"wrong auth", "POST", "Bearer wrong", "", `{}`, 401},
		{"browser origin", "POST", "Bearer test-only-token", "https://untrusted.example", `{}`, 403},
		{"no SSE stream", "GET", "Bearer test-only-token", "", "", 405},
		{"malformed JSON", "POST", "Bearer test-only-token", "", `{`, 400},
		{"trailing payload", "POST", "Bearer test-only-token", "", `{} {}`, 400},
		{"oversized", "POST", "Bearer test-only-token", "", strings.Repeat(" ", 1<<20) + `{}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/mcp", strings.NewReader(tc.body))
			r.Header.Set("Authorization", tc.token)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
		})
	}
}

func TestPublicProbeHasOnlyFixedText(t *testing.T) {
	p := probe{}
	r := httptest.NewRequest("POST", "/public-probe", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"console_connection_test"}}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "连接测试成功") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestCustomCredentialHeader(t *testing.T) {
	p := probe{tokenHash: sha256.Sum256([]byte("test-only-token"))}
	for _, key := range []string{"test-only-token", "wrong"} {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Console-Key", key)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		want := 401
		if key == "test-only-token" {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
	}
}

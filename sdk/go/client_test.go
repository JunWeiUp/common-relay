package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func vectors(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../protocol/crypto-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]json.RawMessage
	if err = json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for k, v := range all {
		var s string
		if json.Unmarshal(v, &s) == nil {
			result[k] = s
		}
	}
	return result
}
func bob(t *testing.T) *Identity {
	t.Helper()
	v := vectors(t)
	i, err := NewIdentity(v["app"], v["group"], "bob", v["bob_secret"], map[string]string{"alice": v["alice_public"]})
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func TestCryptoVectors(t *testing.T) {
	v := vectors(t)
	b := bob(t)
	if b.PublicKey() != v["bob_public"] {
		t.Fatal("public key mismatch")
	}
	plain, err := b.OpenMessage("alice", v["id"], v["message"])
	if err != nil || string(plain) != "hello" {
		t.Fatalf("vector: %v", err)
	}
	for _, entry := range [][3]string{{"alice", strings.Repeat("02", 16), v["message"]}, {"unknown", v["id"], v["message"]}, {"alice", v["id"], v["offline_message"]}, {"alice", v["id"], v["message"] + "\n"}} {
		if _, err = b.OpenMessage(entry[0], entry[1], entry[2]); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
	a, err := NewIdentity(v["app"], v["group"], "alice", v["alice_secret"], map[string]string{"bob": v["bob_public"]})
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.SealMessage("bob", v["id"], []byte("你好"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err = b.OpenMessage("alice", v["id"], body)
	if err != nil || string(plain) != "你好" {
		t.Fatal("round trip failed")
	}
	if _, err = a.SealMessage("bob", v["id"], make([]byte, 200000)); err == nil {
		t.Fatal("accepted oversize message")
	}
	if _, err = NewIdentity(v["app"], v["group"], "alice", v["alice_secret"], map[string]string{"bob": strings.Repeat("00", 32)}); err == nil {
		t.Fatal("accepted low order peer")
	}
	secret, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewIdentity("example", "test", "new", secret, nil)
	if err != nil || i.PublicKey() != public {
		t.Fatal("generated keys mismatch")
	}
}

func testServer(t *testing.T, handler func(context.Context, *websocket.Conn), mismatch bool) string {
	t.Helper()
	b := bob(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 64) {
			t.Error("missing credential")
			w.WriteHeader(401)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"common-relay.v1"}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		device := "bob"
		if mismatch {
			device = "other"
		}
		raw, _ := json.Marshal(Event{Type: "welcome", Version: 1, Identity: &Peer{b.app, b.group, device, b.public}})
		if conn.Write(ctx, websocket.MessageText, raw) != nil {
			return
		}
		handler(ctx, conn)
	}))
	t.Cleanup(s.Close)
	return "ws" + strings.TrimPrefix(s.URL, "http") + "/relay/v1/ws"
}
func TestClientMessagesPeersAndCancellation(t *testing.T) {
	v := vectors(t)
	endpoint := testServer(t, func(ctx context.Context, conn *websocket.Conn) {
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var e Event
			if json.Unmarshal(raw, &e) != nil {
				t.Error("bad request")
				return
			}
			var response Event
			if e.Type == "peers" {
				response = Event{Type: "peers", ID: e.ID, Devices: []Peer{{v["app"], v["group"], "alice", v["alice_public"]}}}
			} else {
				a, _ := NewIdentity(v["app"], v["group"], "alice", v["alice_secret"], map[string]string{"bob": v["bob_public"]})
				data, err := a.OpenMessage("bob", e.ID, e.Body)
				if err != nil || string(data) != "hello" || e.Offline {
					t.Error("invalid message")
				}
				response = Event{Type: "forwarded", ID: e.ID}
			}
			out, _ := json.Marshal(response)
			if conn.Write(ctx, websocket.MessageText, out) != nil {
				return
			}
			if e.Type == "message" {
				out, _ = json.Marshal(Event{Type: "message", ID: v["id"], From: "alice", Body: v["message"]})
				if conn.Write(ctx, websocket.MessageText, out) != nil {
					return
				}
			}
		}
	}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, endpoint, strings.Repeat("x", 64), bob(t), Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peers, err := c.Peers(ctx)
	if err != nil || len(peers) != 1 || peers[0].Device != "alice" {
		t.Fatalf("peers: %v", err)
	}
	receipt, err := c.Message(ctx, "alice", []byte("hello"))
	if err != nil || receipt.Type != "forwarded" {
		t.Fatalf("message: %v", err)
	}
	event, err := c.NextEvent(ctx)
	if err != nil || string(event.Data) != "hello" {
		t.Fatalf("receive: %v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err = c.NextEvent(cancelled); err == nil {
		t.Fatal("cancel ignored")
	}
	c.Close()
	if _, err = c.Peers(ctx); err == nil {
		t.Fatal("request after close")
	}
}
func TestFailClosedAndRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	token := strings.Repeat("x", 64)
	if _, err := Dial(ctx, "ws://127.0.0.1:1/relay/v1/ws", token, bob(t), Options{}); err == nil {
		t.Fatal("accepted insecure endpoint")
	}
	idle := func(ctx context.Context, conn *websocket.Conn) {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}
	endpoint := testServer(t, idle, true)
	if _, err := Dial(ctx, endpoint, token, bob(t), Options{true}); err == nil {
		t.Fatal("accepted mismatched identity")
	}
	endpoint = testServer(t, idle, false)
	c, err := Dial(ctx, endpoint, token, bob(t), Options{true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err = c.Peers(short); err == nil {
		t.Fatal("timeout ignored")
	}
	c.mu.Lock()
	n := len(c.pending)
	c.mu.Unlock()
	if n != 0 {
		t.Fatal("pending request leaked")
	}
	result := make(chan error, 1)
	go func() { _, err := c.Peers(ctx); result <- err }()
	c.Close()
	if err = <-result; err == nil {
		t.Fatal("close did not reject pending request")
	}
}
func TestRedirectNeverForwardsCredential(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true); w.WriteHeader(400) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/relay/v1/ws", 302) }))
	defer source.Close()
	_, err := Dial(context.Background(), "ws"+strings.TrimPrefix(source.URL, "http")+"/relay/v1/ws", strings.Repeat("x", 64), bob(t), Options{true})
	if err == nil || reached.Load() {
		t.Fatal("redirect accepted")
	}
}
func TestOfflineReceptionRejected(t *testing.T) {
	v := vectors(t)
	endpoint := testServer(t, func(ctx context.Context, conn *websocket.Conn) {
		raw, _ := json.Marshal(Event{Type: "message", ID: v["id"], From: "alice", Body: v["message"], Offline: true})
		conn.Write(ctx, websocket.MessageText, raw)
		if _, _, err := conn.Read(ctx); err == nil {
			t.Error("unexpected ACK")
		}
	}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, endpoint, strings.Repeat("x", 64), bob(t), Options{true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.NextEvent(ctx); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline not rejected: %v", err)
	}
}

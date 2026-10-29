package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeRelay is a minimal two-device relay for client tests: it routes messages,
// stream control and binary records, and enforces the 8-record credit window.
type fakeRelay struct {
	t        *testing.T
	url      string
	mu       sync.Mutex
	conns    map[string]*websocket.Conn
	ready    map[string]chan struct{}
	windows  map[string]*[2]uint64 // per stream/direction: sent, acknowledged
	opener   map[string]string
	stored   map[string]string // offline message ID -> recipient while unacknowledged
	received map[string]bool
	onText   func(device string, e Event) bool // Return true when handled.
}

func fakeToken(device string) string { return strings.Repeat(device[:1], 64) }

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	v := vectors(t)
	keys := map[string]string{"alice": v["alice_public"], "bob": v["bob_public"]}
	r := &fakeRelay{t: t, conns: map[string]*websocket.Conn{}, ready: map[string]chan struct{}{"alice": make(chan struct{}), "bob": make(chan struct{})}, windows: map[string]*[2]uint64{}, opener: map[string]string{}, stored: map[string]string{}, received: map[string]bool{}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		device := ""
		for name := range keys {
			if req.Header.Get("Authorization") == "Bearer "+fakeToken(name) {
				device = name
			}
		}
		if device == "" {
			w.WriteHeader(401)
			return
		}
		conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{Subprotocols: []string{"common-relay.v1"}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(1 << 20)
		ctx := req.Context()
		r.write(conn, Event{Type: "welcome", Version: 1, Identity: &Peer{v["app"], v["group"], device, keys[device]}})
		r.mu.Lock()
		r.conns[device] = conn
		close(r.ready[device])
		r.mu.Unlock()
		for {
			kind, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if kind == websocket.MessageBinary {
				r.binary(device, raw)
				continue
			}
			var e Event
			if json.Unmarshal(raw, &e) != nil {
				t.Error("invalid JSON from client")
				return
			}
			r.mu.Lock()
			handler := r.onText
			r.mu.Unlock()
			if handler != nil && handler(device, e) {
				continue
			}
			r.control(device, e)
		}
	}))
	t.Cleanup(s.Close)
	r.url = "ws" + strings.TrimPrefix(s.URL, "http") + "/relay/v1/ws"
	return r
}

func (r *fakeRelay) setOnText(f func(string, Event) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onText = f
}

func (r *fakeRelay) other(device string) string {
	if device == "alice" {
		return "bob"
	}
	return "alice"
}

func (r *fakeRelay) conn(device string) *websocket.Conn {
	<-r.ready[device]
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[device]
}

func (r *fakeRelay) write(conn *websocket.Conn, e Event) {
	raw, _ := json.Marshal(e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn.Write(ctx, websocket.MessageText, raw)
}

func (r *fakeRelay) send(device string, e Event) { r.write(r.conn(device), e) }

func (r *fakeRelay) direction(id, sender string) *[2]uint64 {
	key := id + "/" + sender
	if r.windows[key] == nil {
		r.windows[key] = &[2]uint64{}
	}
	return r.windows[key]
}

func (r *fakeRelay) binary(device string, raw []byte) {
	if len(raw) < 42 || raw[0] != 1 {
		r.t.Error("invalid frame")
		return
	}
	id, seq := hex.EncodeToString(raw[1:17]), binary.BigEndian.Uint64(raw[17:25])
	r.mu.Lock()
	w := r.direction(id, device)
	if seq != w[0] || seq-w[1] >= 8 {
		r.t.Errorf("credit window or sequence violated: seq=%d sent=%d acked=%d", seq, w[0], w[1])
	}
	w[0]++
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.conn(r.other(device)).Write(ctx, websocket.MessageBinary, raw)
}

func (r *fakeRelay) control(device string, e Event) {
	peer := r.other(device)
	switch e.Type {
	case "peers":
		r.send(device, Event{Type: "peers", ID: e.ID, Devices: []Peer{}})
	case "message":
		e.From, e.To = device, ""
		state := "forwarded"
		if e.Offline {
			r.mu.Lock()
			state = "stored"
			if r.received[e.ID] {
				state = "received"
			} else {
				r.stored[e.ID] = peer
			}
			r.mu.Unlock()
		}
		if state != "received" {
			r.send(peer, e)
		}
		r.send(device, Event{Type: state, ID: e.ID})
	case "ack":
		r.mu.Lock()
		delete(r.stored, e.ID)
		r.received[e.ID] = true
		r.mu.Unlock()
		r.send(device, Event{Type: "acked", ID: e.ID})
	case "stream.open":
		r.mu.Lock()
		r.opener[e.ID] = device
		r.mu.Unlock()
		e.From, e.To = device, ""
		r.send(peer, e)
	case "stream.accept":
		e.From = device
		r.send(peer, e)
		r.send(device, Event{Type: "stream.ready", ID: e.ID})
	case "stream.credit":
		r.mu.Lock()
		w := r.direction(e.ID, peer)
		if e.Sequence < w[1] || e.Sequence > w[0] {
			r.t.Errorf("invalid credit %d", e.Sequence)
		}
		w[1] = e.Sequence
		r.mu.Unlock()
		r.send(peer, Event{Type: "stream.credit", ID: e.ID, Sequence: e.Sequence})
	case "stream.close":
		r.send(device, e)
		r.send(peer, e)
	default:
		r.send(device, Event{Type: "error", ID: e.ID, Code: "unknown_type"})
	}
}

func (r *fakeRelay) identity(t *testing.T, device string) *Identity {
	t.Helper()
	v := vectors(t)
	peer := r.other(device)
	i, err := NewIdentity(v["app"], v["group"], device, v[device+"_secret"], map[string]string{peer: v[peer+"_public"]})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func (r *fakeRelay) dial(t *testing.T, device string, journal *Journal) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialJournal(ctx, r.url, fakeToken(device), r.identity(t, device), journal, Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func openTestJournal(t *testing.T, dir string, clock func() int64) *Journal {
	t.Helper()
	j, err := OpenJournal(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func nextOf(t *testing.T, c *Client, kind string) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		e, err := c.NextEvent(ctx)
		if err != nil {
			t.Fatalf("waiting for %s: %v", kind, err)
		}
		if e.Type == kind {
			return e
		}
	}
}

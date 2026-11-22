package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/coder/websocket"
)

type inlineEnv struct {
	*testEnv
	tokens map[string]string
}

// newInlineEnv: space "q" with members alice (member), bob (member), obs
// (archive_observer), boxes "inbox" and "other" (queue); space "far" with
// alice as member and box "inbox"; outsider belongs to no space.
func newInlineEnv(t *testing.T) *inlineEnv {
	t.Helper()
	e := &inlineEnv{testEnv: newEnv(t), tokens: map[string]string{}}
	for _, id := range []string{"alice", "bob", "obs", "outsider"} {
		_, d := e.adminJSON("POST", "/v2/admin/devices", map[string]any{"id": id, "public_key": fakePubKey()})
		e.tokens[id] = d["token"].(string)
	}
	for _, sp := range []string{"q", "far"} {
		e.adminJSON("POST", "/v2/admin/spaces", map[string]any{"id": sp, "name": sp, "trust_level": "strict_e2e"})
		e.adminJSON("POST", "/v2/admin/spaces/"+sp+"/boxes", map[string]any{"name": "inbox", "mode": "queue"})
		e.adminJSON("PUT", "/v2/admin/spaces/"+sp+"/members", map[string]any{"device_id": "alice", "role": "member"})
	}
	e.adminJSON("POST", "/v2/admin/spaces/q/boxes", map[string]any{"name": "other", "mode": "queue"})
	e.adminJSON("PUT", "/v2/admin/spaces/q/members", map[string]any{"device_id": "bob", "role": "member"})
	e.adminJSON("PUT", "/v2/admin/spaces/q/members", map[string]any{"device_id": "obs", "role": "archive_observer"})
	return e
}

func (e *inlineEnv) dev(id, method, path string, body []byte) (int, []byte) {
	e.t.Helper()
	resp := e.do(method, path, bytes.NewReader(body), map[string]string{
		"Relay-Access": e.access, "Authorization": "Bearer " + e.tokens[id], "Content-Type": "application/json",
	})
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *inlineEnv) put(id, space, box string, data []byte) core.BoxItem {
	e.t.Helper()
	code, b := e.dev(id, "POST", "/v2/spaces/"+space+"/boxes/"+box+"/items", data)
	if code != http.StatusCreated {
		e.t.Fatalf("put: %d %s", code, b)
	}
	var out struct{ Item core.BoxItem }
	_ = json.Unmarshal(b, &out)
	return out.Item
}

func (e *inlineEnv) list(id, space, box string) []core.BoxItem {
	e.t.Helper()
	code, b := e.dev(id, "GET", "/v2/spaces/"+space+"/boxes/"+box+"/items", nil)
	if code != 200 {
		e.t.Fatalf("list: %d %s", code, b)
	}
	var out struct{ Items []core.BoxItem }
	_ = json.Unmarshal(b, &out)
	return out.Items
}

func (e *inlineEnv) dial(id, query string) *websocket.Conn {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.ts.URL, "http")+"/v2/ws"+query, &websocket.DialOptions{
		HTTPHeader: http.Header{"Relay-Access": {e.access}, "Authorization": {"Bearer " + e.tokens[id]}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	c.SetReadLimit(1 << 20)
	e.t.Cleanup(func() { c.CloseNow() })
	return c
}

// nextBoxChanged reads frames until a box.changed arrives and returns it with its raw size.
func nextBoxChanged(t *testing.T, c *websocket.Conn) (core.PipeEvent, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for box.changed: %v", err)
		}
		var ev core.PipeEvent
		if json.Unmarshal(data, &ev) == nil && ev.Type == "box.changed" {
			return ev, len(data)
		}
	}
}

func TestBoxChangedInlinesSmallItemsForOptedInPeers(t *testing.T) {
	e := newInlineEnv(t)
	inl := e.dial("bob", "?features=box-inline")
	obsInl := e.dial("obs", "")
	// The header opt-in works too; a legacy peer (no opt-in) keeps the compact event.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hdrConn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.ts.URL, "http")+"/v2/ws", &websocket.DialOptions{
		HTTPHeader: http.Header{"Relay-Access": {e.access}, "Authorization": {"Bearer " + e.tokens["alice"]}, "X-Relay-Features": {"other, box-inline"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hdrConn.CloseNow()
	hdrConn.SetReadLimit(1 << 20)
	time.Sleep(50 * time.Millisecond) // let the hub register the sessions

	small := bytes.Repeat([]byte("s"), core.InlineMaxBytes) // exactly at the limit
	item := e.put("alice", "q", "inbox", small)
	ev, size := nextBoxChanged(t, inl)
	if ev.Item == nil {
		t.Fatalf("opted-in peer got no inline item (frame %d bytes)", size)
	}
	if size > core.MaxPipeMessage {
		t.Fatalf("inline frame %d exceeds MaxPipeMessage", size)
	}
	data, _ := base64.StdEncoding.DecodeString(ev.Item.DataB64)
	sum := sha256.Sum256(small)
	if !bytes.Equal(data, small) || ev.Item.ID != item.ID || ev.Item.Seq != item.Seq || ev.Item.SHA256 != hex.EncodeToString(sum[:]) ||
		ev.Item.Size != int64(len(small)) || ev.Item.Sender != "alice" || ev.Ref != item.ID || ev.Seq != item.Seq || ev.Event != "item" {
		t.Fatalf("inline item mismatch: %+v", ev.Item.BoxItem)
	}
	if ev, _ := nextBoxChanged(t, hdrConn); ev.Item == nil {
		t.Fatal("X-Relay-Features opt-in ignored")
	}
	if ev, size := nextBoxChanged(t, obsInl); ev.Item != nil || size > 512 || ev.Ref != item.ID {
		t.Fatalf("legacy peer must get the compact event, got %d bytes item=%v", size, ev.Item != nil)
	}

	// Larger than InlineMaxBytes: compact event for everyone.
	big := e.put("alice", "q", "inbox", bytes.Repeat([]byte("b"), core.InlineMaxBytes+1))
	if ev, _ := nextBoxChanged(t, inl); ev.Item != nil || ev.Ref != big.ID {
		t.Fatal("large item must not be inlined")
	}

	// Inline is only a prefetch: both items remain queued until ACKed.
	if items := e.list("bob", "q", "inbox"); len(items) != 2 {
		t.Fatalf("items after inline delivery: %d", len(items))
	}
	// bob and alice (opted in) got the small item inline and the big one plain.
	waitFor(t, "inline metrics", func() bool {
		m := e.srv.Pipe.Metrics.Snapshot()
		return m.BoxInline == 2 && m.BoxInlineSkipped == 2
	})
}

func TestBatchAckSemantics(t *testing.T) {
	e := newInlineEnv(t)
	a1 := e.put("alice", "q", "inbox", []byte("1"))
	a2 := e.put("alice", "q", "inbox", []byte("2"))
	a3 := e.put("alice", "q", "inbox", []byte("3"))
	other := e.put("alice", "q", "other", []byte("x"))
	far := e.put("alice", "far", "inbox", []byte("y"))

	ack := func(id, space, box string, ids []string) (int, []string, []string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"ids": ids})
		code, b := e.dev(id, "POST", "/v2/spaces/"+space+"/boxes/"+box+"/items/ack", body)
		var out struct{ Acked, Missing []string }
		_ = json.Unmarshal(b, &out)
		return code, out.Acked, out.Missing
	}
	eq := func(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

	// IDs from another Box or Space are reported missing and left untouched.
	code, acked, missing := ack("bob", "q", "inbox", []string{a1.ID, a2.ID, other.ID, far.ID, a1.ID, "nope"})
	if code != 200 || !eq(acked, []string{a1.ID, a2.ID}) || !eq(missing, []string{other.ID, far.ID, "nope"}) {
		t.Fatalf("batch: %d acked=%v missing=%v", code, acked, missing)
	}
	if items := e.list("bob", "q", "other"); len(items) != 1 {
		t.Fatal("item of another box was deleted")
	}
	if items := e.list("alice", "far", "inbox"); len(items) != 1 {
		t.Fatal("item of another space was deleted")
	}
	if items := e.list("bob", "q", "inbox"); len(items) != 1 || items[0].ID != a3.ID {
		t.Fatalf("remaining: %+v", items)
	}
	// Idempotent retry.
	if code, acked, missing := ack("bob", "q", "inbox", []string{a1.ID, a2.ID}); code != 200 || len(acked) != 0 || len(missing) != 2 {
		t.Fatalf("retry: %d %v %v", code, acked, missing)
	}
	// Authorization matches single ACK: read-only role and non-members are refused.
	if code, _, _ := ack("obs", "q", "inbox", []string{a3.ID}); code != http.StatusForbidden {
		t.Fatalf("observer batch ack: %d", code)
	}
	if code, _, _ := ack("outsider", "q", "inbox", []string{a3.ID}); code != http.StatusForbidden {
		t.Fatalf("outsider batch ack: %d", code)
	}
	if code, _ := e.dev("obs", "DELETE", "/v2/spaces/q/boxes/inbox/items/"+a3.ID, nil); code != http.StatusForbidden {
		t.Fatalf("observer single ack: %d", code)
	}
	// Input bounds.
	if code, _, _ := ack("bob", "q", "inbox", nil); code != http.StatusBadRequest {
		t.Fatalf("empty: %d", code)
	}
	tooMany := make([]string, core.MaxAckBatch+1)
	for i := range tooMany {
		tooMany[i] = core.RandomHex(16)
	}
	if code, _, _ := ack("bob", "q", "inbox", tooMany); code != http.StatusBadRequest {
		t.Fatalf("too many: %d", code)
	}
	if code, _ := e.dev("bob", "POST", "/v2/spaces/q/boxes/inbox/items/ack", []byte("{")); code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", code)
	}
	if code, _, _ := ack("bob", "q", "inbox", []string{a3.ID}); code != 200 {
		t.Fatal(code)
	}
	if items := e.list("bob", "q", "inbox"); len(items) != 0 {
		t.Fatalf("left: %+v", items)
	}
}

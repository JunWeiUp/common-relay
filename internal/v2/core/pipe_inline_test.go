package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// TestInlineFallsBackUnderQueuePressure: an opted-in peer whose send queue is
// at least half full gets the compact event instead of the inline frame, so
// inlining never pushes a slow peer into the queue-full disconnect.
func TestInlineFallsBackUnderQueuePressure(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := NewPipeHub(st)
	if _, err := st.CreateSpace("sp", "", TrustStrictE2E); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateBox(Box{SpaceID: "sp", Name: "q", Mode: ModeQueue}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &pipePeer{dev: Device{ID: "d"}, spaces: map[string]MemberRole{"sp": RoleMember}, inline: true,
		out: make(chan wsPacket, PeerOutQueueSize), ctx: ctx, cancel: cancel}
	h.peers["d"] = p

	last := func() PipeEvent {
		t.Helper()
		var pkt wsPacket
		for len(p.out) > 0 {
			pkt = <-p.out
			h.queued.Add(-int64(len(pkt.data)))
		}
		var ev PipeEvent
		if err := json.Unmarshal(pkt.data, &ev); err != nil {
			t.Fatal(err)
		}
		return ev
	}

	if _, err := st.PutBoxItem("sp", "q", "d", "", "", 0, strings.NewReader("hi")); err != nil {
		t.Fatal(err)
	}
	if ev := last(); ev.Item == nil || ev.Item.DataB64 != "aGk=" {
		t.Fatalf("idle peer should get inline item: %+v", ev)
	}

	for i := 0; i < PeerOutQueueSize/2; i++ {
		h.send(p, websocket.MessageText, []byte(`{"type":"pong"}`))
	}
	if _, err := st.PutBoxItem("sp", "q", "d", "", "", 0, strings.NewReader("hi")); err != nil {
		t.Fatal(err)
	}
	if ev := last(); ev.Type != "box.changed" || ev.Item != nil {
		t.Fatalf("busy peer must get the compact event: %+v", ev)
	}
	if ctx.Err() != nil {
		t.Fatal("peer was dropped")
	}

	// Global pressure: same fallback.
	h.queued.Add(MaxGlobalQueued / 2)
	if _, err := st.PutBoxItem("sp", "q", "d", "", "", 0, strings.NewReader("hi")); err != nil {
		t.Fatal(err)
	}
	if ev := last(); ev.Item != nil {
		t.Fatal("global queue pressure must disable inlining")
	}
	h.queued.Add(-MaxGlobalQueued / 2)
}

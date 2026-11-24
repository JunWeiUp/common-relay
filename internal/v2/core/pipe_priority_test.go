package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestPipePriorityQueuesAndBackpressure(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "relay_v2.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	hub := NewPipeHub(store)
	hub.Metrics = NewMetrics()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	peerA := &pipePeer{
		dev:     Device{ID: "dev-a"},
		spaces:  map[string]MemberRole{"sp-1": RoleMember},
		credit:  true,
		out:     make(chan wsPacket, PeerOutQueueSize),
		dataOut: make(chan wsPacket, 2),
		ctx:     ctxA,
		cancel:  cancelA,
	}
	peerB := &pipePeer{
		dev:     Device{ID: "dev-b"},
		spaces:  map[string]MemberRole{"sp-1": RoleMember},
		credit:  true,
		out:     make(chan wsPacket, PeerOutQueueSize),
		dataOut: make(chan wsPacket, 2),
		ctx:     ctxB,
		cancel:  cancelB,
	}

	sid := "0123456789abcdef"
	hub.streams[sid] = &pipeStream{id: sid, space: "sp-1", a: peerA, b: peerB, ready: true}

	// Fill peerB's dataOut (capacity 2) and send a 3rd binary frame.
	frame := append([]byte(sid), []byte("payload")...)
	hub.handleBinaryFrame(peerA, frame)
	hub.handleBinaryFrame(peerA, frame)
	hub.handleBinaryFrame(peerA, frame) // should backpressure-drop without cancelling peerB

	if ctxB.Err() != nil {
		t.Fatalf("peerB context should not be cancelled on binary backpressure")
	}
	if len(peerB.dataOut) != 2 {
		t.Fatalf("expected 2 buffered binary frames, got %d", len(peerB.dataOut))
	}
	// Control plane on peerB must still accept events cleanly.
	if !hub.sendEvent(peerB, PipeEvent{Type: "pong", ID: "p1"}) {
		t.Fatalf("control frame should succeed even when dataOut is full")
	}
	if len(peerB.out) != 1 {
		t.Fatalf("expected 1 control frame on peerB.out, got %d", len(peerB.out))
	}

	// peerA opted in to stream-credit, so it should receive a Seq=0 backpressure hint.
	if len(peerA.out) != 1 {
		t.Fatalf("expected 1 stream.credit backpressure hint on peerA.out, got %d", len(peerA.out))
	}
	pkt := <-peerA.out
	var hint PipeEvent
	if err := json.Unmarshal(pkt.data, &hint); err != nil {
		t.Fatalf("unmarshal hint: %v", err)
	}
	if hint.Type != "stream.credit" || hint.ID != sid || hint.Space != "sp-1" || hint.Seq != 0 {
		t.Fatalf("unexpected backpressure hint: %+v", hint)
	}

	// peerB grants credit back to peerA.
	hub.handleEvent(peerB, PipeEvent{Type: "stream.credit", ID: sid, Seq: 16})
	if len(peerA.out) != 1 {
		t.Fatalf("expected forwarded stream.credit on peerA.out, got %d", len(peerA.out))
	}
	pkt = <-peerA.out
	var grant PipeEvent
	if err := json.Unmarshal(pkt.data, &grant); err != nil {
		t.Fatalf("unmarshal grant: %v", err)
	}
	if grant.Type != "stream.credit" || grant.ID != sid || grant.From != "dev-b" || grant.Seq != 16 {
		t.Fatalf("unexpected forwarded credit: %+v", grant)
	}

	// Negative credit is rejected.
	hub.handleEvent(peerB, PipeEvent{Type: "stream.credit", ID: sid, Seq: -1})
	pkt = <-peerB.out // first was pong
	pkt = <-peerB.out // second is error
	var errEv PipeEvent
	_ = json.Unmarshal(pkt.data, &errEv)
	if errEv.Type != "error" || errEv.Code != "invalid_stream" {
		t.Fatalf("expected invalid_stream error, got %+v", errEv)
	}

	// Verify per-space and global stream metrics.
	snap := hub.Metrics.Snapshot()
	if snap.StreamFrames != 2 || snap.StreamDrops != 1 {
		t.Fatalf("unexpected global stream metrics: frames=%d drops=%d", snap.StreamFrames, snap.StreamDrops)
	}
	sc := snap.Spaces["sp-1"]
	if sc.StreamFrames != 2 || sc.StreamDrops != 1 || sc.StreamBytes != int64(2*len(frame)) {
		t.Fatalf("unexpected space metrics: %+v", sc)
	}
}

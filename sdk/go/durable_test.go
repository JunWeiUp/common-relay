package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJournalRestartRetryExpiryAndTombstones(t *testing.T) {
	dir := t.TempDir()
	var now atomic.Int64
	now.Store(1_000_000)
	clock := func() int64 { return now.Load() }
	j, err := OpenJournal(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3}
	body, expires, err := j.prepare("a", "id", "b", data, 60, func(e int64) (string, error) { return fmt.Sprintf("cipher-%d", e), nil })
	if err != nil || body != "cipher-1000060" || expires != 1000060 {
		t.Fatalf("prepare: %q %d %v", body, expires, err)
	}
	if _, err = OpenJournal(dir, clock); !errors.Is(err, ErrJournalLocked) {
		t.Fatalf("second owner accepted: %v", err)
	}
	j.Close()
	now.Add(30)
	j = openTestJournal(t, dir, clock)
	again, expiresAgain, err := j.prepare("a", "id", "b", data, 86400, func(int64) (string, error) { return "", errors.New("re-encrypted") })
	if err != nil || again != body || expiresAgain != expires {
		t.Fatalf("retry did not reuse ciphertext/expiry: %v", err)
	}
	if _, _, err = j.prepare("a", "id", "b", []byte{9}, 60, nil); err == nil {
		t.Fatal("same ID with different content accepted")
	}
	if _, _, err = j.prepare("a", "id", "c", data, 60, nil); err == nil {
		t.Fatal("same ID with different recipient accepted")
	}
	if _, _, err = j.prepare("a", "x", "b", data, 86401, nil); err == nil {
		t.Fatal("TTL above 24h accepted")
	}
	if err = j.acknowledge("a", "b", "in"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := j.contains("a", "b", "in"); !ok {
		t.Fatal("ack not recorded")
	}
	if ok, _ := j.contains("other", "b", "in"); ok {
		t.Fatal("scope isolation broken")
	}
	if ok, _ := j.contains("a", "c", "in"); ok {
		t.Fatal("peer isolation broken")
	}
	now.Add(30)
	if err = j.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.prepare("a", "id", "b", data, 60, nil); err == nil {
		t.Fatal("expired message was resent")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(raw), "cipher") || bytes.Contains(raw, data) {
			t.Fatalf("ciphertext kept after expiry in %s", e.Name())
		}
		if info, _ := e.Info(); info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("record %s is not private: %v", e.Name(), info.Mode())
		}
	}
	now.Add(7 * 86400)
	if err = j.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := j.contains("a", "b", "in"); ok {
		t.Fatal("dedupe record outlived 7 days")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(matches) != 0 {
		t.Fatalf("records not purged: %v", matches)
	}
	if _, _, err = j.prepare("a", "done", "b", data, 60, func(int64) (string, error) { return "cipher", nil }); err != nil {
		t.Fatal(err)
	}
	if err = j.complete("a", "done"); err != nil {
		t.Fatal(err)
	}
	body, _, err = j.prepare("a", "done", "b", data, 60, func(int64) (string, error) { return "", errors.New("resealed") })
	if err != nil || body != "" {
		t.Fatalf("received tombstone not honoured: %q %v", body, err)
	}
	// Repeated acknowledgements never extend dedupe retention.
	j.acknowledge("a", "b", "again")
	now.Add(86400)
	j.acknowledge("a", "b", "again")
	now.Add(6*86400 + 1)
	if ok, _ := j.contains("a", "b", "again"); ok {
		t.Fatal("repeated ack extended retention")
	}
}

func TestJournalBoundedCleanupAndCorruption(t *testing.T) {
	dir := t.TempDir()
	var now atomic.Int64
	now.Store(1_000_000)
	j := openTestJournal(t, dir, func() int64 { return now.Load() })
	for i := range 300 {
		if _, _, err := j.prepare("a", fmt.Sprint(i), "b", []byte("x"), 60, func(int64) (string, error) { return "c", nil }); err != nil {
			t.Fatal(err)
		}
	}
	count := func(status string) int {
		n := 0
		matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, m := range matches {
			r, err := j.read(m)
			if err != nil {
				t.Fatal(err)
			}
			if r.Status == status {
				n++
			}
		}
		return n
	}
	now.Add(60)
	if j.Cleanup() != nil || count("expired") != 256 {
		t.Fatalf("first round changed %d records", count("expired"))
	}
	if j.Cleanup() != nil || count("pending") != 0 {
		t.Fatal("second round did not finish")
	}
	os.WriteFile(filepath.Join(dir, strings.Repeat("a", 64)+".json"), []byte("{"), 0o600)
	if err := j.Cleanup(); err == nil {
		t.Fatal("corrupt record ignored")
	}
	j.Close()
	if _, _, err := j.prepare("a", "z", "b", nil, 60, nil); err == nil {
		t.Fatal("closed journal usable")
	}
}

func TestOfflineSendRetryAndReceipt(t *testing.T) {
	plain := newFakeRelay(t).dial(t, "alice", nil)
	if _, err := plain.MessageOffline(context.Background(), "bob", strings.Repeat("ab", 16), []byte("x")); err == nil {
		t.Fatal("offline send without journal")
	}
	r := newFakeRelay(t)
	alice := r.dial(t, "alice", openTestJournal(t, t.TempDir(), nil))
	bob := r.dial(t, "bob", openTestJournal(t, t.TempDir(), nil))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, _ := NewMessageID()
	receipt, err := alice.MessageOffline(ctx, "bob", id, []byte("durable"))
	if err != nil || receipt.Type != "stored" {
		t.Fatalf("send: %v %+v", err, receipt)
	}
	first := nextOf(t, bob, "message")
	if !first.Offline || string(first.Data) != "durable" || first.Expires <= time.Now().Unix() {
		t.Fatalf("delivery: %+v", first)
	}
	// A retry reuses the stored ciphertext and expiry.
	var mu sync.Mutex
	var bodies []Event
	r.setOnText(func(device string, e Event) bool {
		if e.Type == "message" {
			mu.Lock()
			bodies = append(bodies, e)
			mu.Unlock()
		}
		return false
	})
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(bodies) }
	if _, err = alice.MessageOffline(ctx, "bob", id, []byte("durable")); err != nil {
		t.Fatal(err)
	}
	if _, err = alice.MessageOffline(ctx, "bob", id, []byte("changed")); err == nil {
		t.Fatal("same ID with new content accepted")
	}
	redelivered := nextOf(t, bob, "message")
	if redelivered.ID != id || redelivered.Expires != first.Expires {
		t.Fatal("retry changed expiry")
	}
	if err = bob.Acknowledge(ctx, first); err != nil {
		t.Fatal(err)
	}
	receipt, err = alice.MessageOffline(ctx, "bob", id, []byte("durable"))
	if err != nil || receipt.Type != "received" {
		t.Fatalf("receipt: %v %+v", err, receipt)
	}
	sent := count()
	receipt, err = alice.MessageOffline(ctx, "bob", id, []byte("durable"))
	if err != nil || receipt.Type != "received" || count() != sent {
		t.Fatal("received message was sent again")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) < 2 || bodies[0].Body != bodies[1].Body || bodies[0].Expires != bodies[1].Expires || bodies[0].Expires == 0 {
		t.Fatal("retry did not reuse original ciphertext")
	}
}

func TestOfflineRedeliveryAfterLostAckIsDeduplicated(t *testing.T) {
	r := newFakeRelay(t)
	bobJournal := openTestJournal(t, t.TempDir(), nil)
	alice := r.dial(t, "alice", openTestJournal(t, t.TempDir(), nil))
	bob := r.dial(t, "bob", bobJournal)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	acks := make(chan Event, 4)
	dropFirst := true
	r.setOnText(func(device string, e Event) bool {
		if e.Type == "ack" {
			acks <- e
			if dropFirst { // Simulate a lost ACK: the relay never records it.
				dropFirst = false
				r.send(device, Event{Type: "acked", ID: e.ID})
				return true
			}
		}
		return false
	})
	id, _ := NewMessageID()
	if _, err := alice.MessageOffline(ctx, "bob", id, []byte("once")); err != nil {
		t.Fatal(err)
	}
	e := nextOf(t, bob, "message")
	if err := bob.Acknowledge(ctx, e); err != nil {
		t.Fatal(err)
	}
	<-acks
	// Relay redelivers; the SDK re-ACKs automatically and does not deliver again.
	if _, err := alice.MessageOffline(ctx, "bob", id, []byte("once")); err != nil {
		t.Fatal(err)
	}
	select {
	case ack := <-acks:
		if ack.ID != id || ack.From != "alice" {
			t.Fatalf("wrong re-ACK %+v", ack)
		}
	case <-ctx.Done():
		t.Fatal("redelivery not re-ACKed")
	}
	short, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	if extra, err := bob.NextEvent(short); err == nil && extra.Type == "message" {
		t.Fatal("duplicate delivered to the application")
	}
	// Online messages are acknowledged locally only.
	if err := bob.Acknowledge(ctx, Event{Type: "message", ID: strings.Repeat("cd", 16), From: "alice"}); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredOfflineMessageIsAckedNotDelivered(t *testing.T) {
	v := vectors(t)
	r := newFakeRelay(t)
	bob := r.dial(t, "bob", openTestJournal(t, t.TempDir(), nil))
	acked := make(chan string, 1)
	r.setOnText(func(device string, e Event) bool {
		if e.Type == "ack" {
			acked <- e.ID
			return true
		}
		return false
	})
	// The shared vector's authenticated expiry (1234567890) is in the past.
	r.send("bob", Event{Type: "message", ID: v["id"], From: "alice", Body: v["offline_message"], Offline: true})
	select {
	case id := <-acked:
		if id != v["id"] {
			t.Fatal("wrong ack")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expired message not acknowledged")
	}
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if e, err := bob.NextEvent(short); err == nil && e.Type == "message" {
		t.Fatal("expired message delivered")
	}
}

func TestStreamEchoFlowControlAndFinal(t *testing.T) {
	r := newFakeRelay(t)
	alice := r.dial(t, "alice", nil)
	bob := r.dial(t, "bob", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	echoed := make(chan error, 1)
	go func() {
		request := nextOf(t, bob, "stream.open")
		s, err := bob.AcceptStream(ctx, request)
		if err != nil {
			echoed <- err
			return
		}
		for !s.ReceivedFinal() {
			data, err := s.Receive(ctx)
			if err != nil {
				echoed <- err
				return
			}
			if err = s.Send(ctx, data, s.ReceivedFinal()); err != nil {
				echoed <- err
				return
			}
		}
		_, err = s.Receive(ctx)
		if err != io.EOF {
			err = fmt.Errorf("expected EOF after final, got %v", err)
		} else {
			err = nil
		}
		echoed <- err
	}()
	s, err := alice.OpenStream(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 3<<20+12345)
	rand.Read(payload)
	sent := make(chan error, 1)
	go func() { sent <- s.Send(ctx, payload, true) }()
	var received []byte
	for !s.ReceivedFinal() {
		data, err := s.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, data...)
	}
	if err = <-sent; err != nil {
		t.Fatal(err)
	}
	if err = <-echoed; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("echo mismatch")
	}
	if err = s.Send(ctx, nil, true); err == nil {
		t.Fatal("send after final")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Receive(ctx); err == nil {
		t.Fatal("receive after close")
	}
}

func TestStreamCreditPausesSenderAndCloseInterrupts(t *testing.T) {
	r := newFakeRelay(t)
	alice := r.dial(t, "alice", nil)
	bob := r.dial(t, "bob", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan *Stream, 1)
	go func() {
		s, err := bob.AcceptStream(ctx, nextOf(t, bob, "stream.open"))
		if err != nil {
			t.Error(err)
		}
		accepted <- s
	}()
	s, err := alice.OpenStream(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	remote := <-accepted
	for i := range 8 {
		if err = s.Send(ctx, []byte{byte(i)}, false); err != nil {
			t.Fatal(err)
		}
	}
	short, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stop()
	if err = s.Send(short, []byte("ninth"), false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sender did not pause without credit: %v", err)
	}
	if data, err := remote.Receive(ctx); err != nil || data[0] != 0 {
		t.Fatal(err)
	}
	if err = s.Send(ctx, []byte("ninth"), false); err != nil {
		t.Fatalf("credit did not resume sender: %v", err)
	}
	blocked := make(chan error, 1)
	go func() { blocked <- s.Send(ctx, []byte("tenth"), false) }()
	time.Sleep(50 * time.Millisecond)
	remote.Close()
	select {
	case err = <-blocked:
		if err == nil {
			t.Fatal("blocked send succeeded after close")
		}
	case <-ctx.Done():
		t.Fatal("close did not interrupt sender")
	}
	if _, err = remote.Receive(ctx); err == nil {
		t.Fatal("closed stream readable")
	}
}

func TestStreamRejectsReorderAndRejectedOpen(t *testing.T) {
	r := newFakeRelay(t)
	alice := r.dial(t, "alice", nil)
	bob := r.dial(t, "bob", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { bob.RejectStream(ctx, nextOf(t, bob, "stream.open")) }()
	if _, err := alice.OpenStream(ctx, "bob"); err == nil {
		t.Fatal("rejected stream opened")
	}
	accepted := make(chan *Stream, 1)
	go func() {
		s, _ := bob.AcceptStream(ctx, nextOf(t, bob, "stream.open"))
		accepted <- s
	}()
	s, err := alice.OpenStream(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	remote := <-accepted
	// Inject a duplicate of sequence 0 behind the real one.
	if err = s.Send(ctx, []byte("a"), false); err != nil {
		t.Fatal(err)
	}
	if _, err = remote.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	remote.enqueue(streamFrame{sequence: 0, data: make([]byte, 20)})
	if _, err = remote.Receive(ctx); err == nil {
		t.Fatal("duplicate/reordered record accepted")
	}
	if _, err = s.Receive(ctx); err == nil {
		t.Fatal("peer stream not closed after rejection")
	}
}

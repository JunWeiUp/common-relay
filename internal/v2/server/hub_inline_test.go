package server_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
)

// callCounter classifies the device's box HTTP calls.
type callCounter struct {
	mu    sync.Mutex
	calls map[string]int // list | download | ack1 | ackBatch | other
}

func (c *callCounter) RoundTrip(r *http.Request) (*http.Response, error) {
	kind := "other"
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/items"):
		kind = "list"
	case r.Method == http.MethodGet && strings.Contains(p, "/items/"):
		kind = "download"
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/items/ack"):
		kind = "ackBatch"
	case r.Method == http.MethodDelete && strings.Contains(p, "/items/"):
		kind = "ack1"
	}
	c.mu.Lock()
	c.calls[kind]++
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func (c *callCounter) take() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.calls
	c.calls = map[string]int{}
	return out
}

func (c *callCounter) get(kind string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[kind]
}

func TestHubInlineDeliveryBatchAckAndFallbacks(t *testing.T) {
	e := newInlineEnv(t)
	counter := &callCounter{calls: map[string]int{}}
	desk, err := v2client.New(v2client.Config{
		BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.tokens["bob"], AllowLocal: true,
		HTTPClient: &http.Client{Transport: counter, Timeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := v2client.NewHub(desk)
	var mu sync.Mutex
	got := map[string]int{} // payload -> deliveries
	var failNext atomic.Bool
	hub.SubscribeBox("q", "inbox", func(ctx context.Context, item v2client.BoxItem, data []byte) error {
		mu.Lock()
		got[string(data[:min(len(data), 16)])]++
		mu.Unlock()
		if failNext.CompareAndSwap(true, false) {
			return errors.New("handler busy")
		}
		return nil
	})
	deliveries := func(key string) int {
		mu.Lock()
		defer mu.Unlock()
		return got[key]
	}
	hub.Start(context.Background())
	defer hub.Close()
	waitFor(t, "hub connected and drained", func() bool {
		ok, _ := hub.Status()
		return ok && counter.get("list") >= 1
	})
	waitFor(t, "hub registered on the pipe", func() bool { return len(e.srv.Pipe.OnlineDevices("q")) == 1 })
	counter.take()

	queued := func() int { return len(e.list("alice", "q", "inbox")) }

	// 1) Small items: delivered inline, ACKed in one batch, zero list/download.
	for _, s := range []string{"small-1", "small-2", "small-3"} {
		e.put("alice", "q", "inbox", []byte(s))
	}
	waitFor(t, "inline deliveries", func() bool {
		return deliveries("small-1") == 1 && deliveries("small-2") == 1 && deliveries("small-3") == 1
	})
	waitFor(t, "batch ack", func() bool { return queued() == 0 })
	calls := counter.take()
	t.Logf("3 small items: HTTP calls %v", calls)
	if calls["list"] != 0 || calls["download"] != 0 || calls["ack1"] != 0 || calls["ackBatch"] != 1 {
		t.Fatalf("small items must need no list/download and one batch ack, got %v", calls)
	}

	// 2) Large item: old list/download path (ACK via batch endpoint).
	big := append([]byte("big-item--------"), bytes.Repeat([]byte("x"), core.InlineMaxBytes)...)
	e.put("alice", "q", "inbox", big)
	waitFor(t, "large delivery", func() bool { return deliveries("big-item--------") == 1 })
	waitFor(t, "large ack", func() bool { return queued() == 0 })
	calls = counter.take()
	t.Logf("1 large item: HTTP calls %v", calls)
	if calls["download"] != 1 || calls["list"] < 1 || calls["ackBatch"] != 1 {
		t.Fatalf("large item must use list+download, got %v", calls)
	}

	// 3) Handler error on an inline item: not ACKed, redelivered after reconnect.
	failNext.Store(true)
	e.put("alice", "q", "inbox", []byte("flaky-item"))
	waitFor(t, "first attempt", func() bool { return deliveries("flaky-item") == 1 })
	time.Sleep(3 * v2client.AckFlushDelay)
	if queued() != 1 {
		t.Fatal("failed item must stay queued")
	}
	e.srv.Pipe.DisconnectDevice("bob")
	waitFor(t, "redelivery on reconnect", func() bool { return deliveries("flaky-item") == 2 })
	waitFor(t, "ack after redelivery", func() bool { return queued() == 0 })

	// 4) After the reconnect drain, inline delivery resumes.
	waitFor(t, "hub back on the pipe", func() bool { return len(e.srv.Pipe.OnlineDevices("q")) == 1 })
	counter.take()
	e.put("alice", "q", "inbox", []byte("small-4"))
	waitFor(t, "inline after reconnect", func() bool { return deliveries("small-4") == 1 })
	waitFor(t, "ack small-4", func() bool { return queued() == 0 })
	if calls := counter.take(); calls["list"] != 0 || calls["download"] != 0 {
		t.Fatalf("inline should resume after reconnect, got %v", calls)
	}
	for k, n := range got {
		if n != 1 && k != "flaky-item" {
			t.Fatalf("%q delivered %d times", k, n)
		}
	}
}

// TestHubHandlerErrorRetriedOnNextWakeup: a failing inline item is redelivered
// by the drain that the next box.changed triggers, before the newer item.
func TestHubHandlerErrorRetriedOnNextWakeup(t *testing.T) {
	e := newInlineEnv(t)
	desk, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.tokens["bob"], AllowLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	hub := v2client.NewHub(desk)
	var mu sync.Mutex
	var order []string
	var failed atomic.Bool
	hub.SubscribeBox("q", "inbox", func(ctx context.Context, item v2client.BoxItem, data []byte) error {
		mu.Lock()
		order = append(order, string(data))
		mu.Unlock()
		if string(data) == "a" && failed.CompareAndSwap(false, true) {
			return errors.New("first attempt fails")
		}
		return nil
	})
	hub.Start(context.Background())
	defer hub.Close()
	waitFor(t, "hub registered", func() bool { return len(e.srv.Pipe.OnlineDevices("q")) == 1 })
	time.Sleep(50 * time.Millisecond)
	e.put("alice", "q", "inbox", []byte("a"))
	waitFor(t, "first attempt", func() bool { mu.Lock(); defer mu.Unlock(); return len(order) == 1 })
	e.put("alice", "q", "inbox", []byte("b"))
	waitFor(t, "queue drained", func() bool { return len(e.list("alice", "q", "inbox")) == 0 })
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "a,a,b" {
		t.Fatalf("delivery order %v", order)
	}
}

// oldServerTransport answers the batch ACK endpoint like a server that
// predates it (405 text), so the Hub must fall back to per-item DELETE.
type oldServerTransport struct{ deletes atomic.Int32 }

func (o *oldServerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/items/ack") {
		return &http.Response{StatusCode: 405, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
	}
	if r.Method == http.MethodDelete {
		o.deletes.Add(1)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestHubFallsBackToSingleAckOnOldServer(t *testing.T) {
	e := newInlineEnv(t)
	tr := &oldServerTransport{}
	desk, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.tokens["bob"], AllowLocal: true,
		HTTPClient: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	hub := v2client.NewHub(desk)
	var n atomic.Int32
	hub.SubscribeBox("q", "inbox", func(context.Context, v2client.BoxItem, []byte) error { n.Add(1); return nil })
	hub.Start(context.Background())
	defer hub.Close()
	waitFor(t, "hub registered", func() bool { return len(e.srv.Pipe.OnlineDevices("q")) == 1 })
	time.Sleep(50 * time.Millisecond)
	e.put("alice", "q", "inbox", []byte("one"))
	e.put("alice", "q", "inbox", []byte("two"))
	waitFor(t, "acked via DELETE", func() bool { return len(e.list("alice", "q", "inbox")) == 0 })
	if n.Load() != 2 || tr.deletes.Load() != 2 {
		t.Fatalf("handled %d, deletes %d", n.Load(), tr.deletes.Load())
	}
}

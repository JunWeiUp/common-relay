package v2client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// BoxItemHandler processes one item from a queue/ephemeral Box, either inline
// from box.changed (small items, verified against size and SHA-256) or
// downloaded. Returning nil causes the Hub to ACK and delete the item from the
// server (batched, within AckFlushDelay); returning an error leaves it queued
// for redelivery on the next drain.
type BoxItemHandler func(ctx context.Context, item BoxItem, data []byte) error

// ObjectChangeHandler is called whenever an object-mode Box publishes a new version.
type ObjectChangeHandler func(ctx context.Context, spaceID, boxName, key string, version int64)

// RPCHandler answers synchronous RPC requests forwarded over /v2/ws (e.g. mcpedge).
type RPCHandler func(ctx context.Context, payload string) (string, error)

type boxSub struct {
	space   string
	box     string
	handler BoxItemHandler
	// lastSeq and synced are owned by the Hub's connection goroutine.
	lastSeq int64
	synced  bool // last drain reached the end of the Box and nothing failed since
}

type objSub struct {
	space   string
	box     string
	handler ObjectChangeHandler
}

// Hub maintains a single persistent /v2/ws connection for a device (e.g. a local
// hub daemon), combining real-time box.changed wake-ups with cursor-based catch-up
// on reconnect so no module needs its own polling loop or relay.json.
type Hub struct {
	client *Client

	mu        sync.Mutex
	boxSubs   map[string]*boxSub    // space+"/"+box
	objSubs   map[string]*objSub    // space+"/"+box
	rpcSubs   map[string]RPCHandler // space+"/"+topic
	connected bool
	lastErr   string
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// Owned by the connection goroutine (no lock): ACKs waiting for a batch.
	acks       []pendingAck
	noBatchAck bool

	// Keepalive is how often the hub pings the relay (0 = DefaultHubKeepalive).
	// Without traffic, reverse proxies close idle WebSockets; a missing pong also
	// detects a dead connection long before TCP would.
	Keepalive time.Duration
}

// DefaultHubKeepalive stays well under common proxy idle timeouts (60–120s).
const DefaultHubKeepalive = 30 * time.Second

func NewHub(c *Client) *Hub {
	return &Hub{
		client:  c,
		boxSubs: map[string]*boxSub{},
		objSubs: map[string]*objSub{},
		rpcSubs: map[string]RPCHandler{},
	}
}

func (h *Hub) HandleRPC(spaceID, topic string, fn RPCHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rpcSubs[spaceID+"/"+topic] = fn
}

func (h *Hub) SubscribeBox(spaceID, boxName string, fn BoxItemHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.boxSubs[spaceID+"/"+boxName] = &boxSub{space: spaceID, box: boxName, handler: fn}
}

func (h *Hub) SubscribeObject(spaceID, boxName string, fn ObjectChangeHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.objSubs[spaceID+"/"+boxName] = &objSub{space: spaceID, box: boxName, handler: fn}
}

func (h *Hub) Status() (connected bool, lastErr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.connected, h.lastErr
}

func (h *Hub) Start(parent context.Context) {
	h.mu.Lock()
	if h.cancel != nil {
		h.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	h.cancel = cancel
	h.wg.Add(1)
	h.mu.Unlock()

	go func() {
		defer h.wg.Done()
		backoff := time.Second
		for {
			if ctx.Err() != nil {
				return
			}
			err := h.runOnce(ctx)
			h.mu.Lock()
			h.connected = false
			if err != nil && ctx.Err() == nil {
				h.lastErr = err.Error()
			}
			h.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}()
}

func (h *Hub) Close() {
	h.mu.Lock()
	cancel := h.cancel
	h.cancel = nil
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	h.wg.Wait()
}

// HubFeatures is the /v2/ws opt-in sent by the Hub: the server may then inline
// small queue/ephemeral items into box.changed.
const HubFeatures = "box-inline"

// hubReadLimit bounds one /v2/ws frame (the server caps frames at 256 KiB).
const hubReadLimit = 1 << 20

const (
	// AckFlushDelay is how long the Hub collects ACKs of inline-delivered items
	// before sending one batch request.
	AckFlushDelay = 200 * time.Millisecond
	// AckFlushAt flushes the pending ACKs immediately once this many are queued.
	AckFlushAt = 50
)

func (h *Hub) runOnce(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, _, err := websocket.Dial(dialCtx, h.client.WSURL()+"?features="+HubFeatures, &websocket.DialOptions{
		HTTPHeader: h.client.authHeaders(),
	})
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(hubReadLimit)

	h.mu.Lock()
	h.connected = true
	h.lastErr = ""
	h.mu.Unlock()

	// Pending ACKs are flushed whenever this session ends, including on Close
	// (ctx cancelled), so handled items are not redelivered needlessly.
	defer func() {
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		h.flushAcks(fctx)
		fcancel()
	}()

	// Catch up every subscribed queue/ephemeral Box right after connecting.
	h.drainAll(ctx)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	pingErr := make(chan error, 1)
	go func() {
		every := h.Keepalive
		if every <= 0 {
			every = DefaultHubKeepalive
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(connCtx, min(every, 10*time.Second))
				err := conn.Ping(pctx)
				pcancel()
				if err != nil && connCtx.Err() == nil {
					pingErr <- err
					connCancel() // unblock Read and reconnect
					return
				}
			}
		}
	}()

	// The reader only decodes frames; box handling, ACK batching and the
	// subscription cursors all live on this goroutine.
	events := make(chan PipeEvent, 32)
	readErr := make(chan error, 1)
	go func() {
		for {
			kind, data, err := conn.Read(connCtx)
			if err != nil {
				readErr <- err
				return
			}
			if kind != websocket.MessageText {
				continue
			}
			var ev PipeEvent
			if json.Unmarshal(data, &ev) != nil {
				continue
			}
			switch ev.Type {
			case "rpc.req":
				go h.handleRPCReq(ctx, conn, ev)
			case "box.changed":
				select {
				case events <- ev:
				case <-connCtx.Done():
					return
				}
			}
		}
	}()

	var flushTimer *time.Timer
	var flushC <-chan time.Time
	stopTimer := func() {
		if flushTimer != nil {
			flushTimer.Stop()
			flushTimer, flushC = nil, nil
		}
	}
	defer stopTimer()
	for {
		select {
		case ev := <-events:
			h.handleBoxChanged(ctx, ev)
			switch {
			case h.pendingAcks() >= AckFlushAt:
				stopTimer()
				h.flushAcks(ctx)
			case h.pendingAcks() > 0 && flushC == nil:
				flushTimer = time.NewTimer(AckFlushDelay)
				flushC = flushTimer.C
			case h.pendingAcks() == 0:
				stopTimer()
			}
		case <-flushC:
			flushTimer, flushC = nil, nil
			h.flushAcks(ctx)
		case err := <-readErr:
			select {
			case perr := <-pingErr:
				return errors.New("keepalive: " + perr.Error())
			default:
			}
			return err
		}
	}
}

func (h *Hub) handleRPCReq(ctx context.Context, conn *websocket.Conn, ev PipeEvent) {
	h.mu.Lock()
	fn := h.rpcSubs[ev.Space+"/"+ev.Topic]
	h.mu.Unlock()
	res := PipeEvent{Type: "rpc.res", Space: ev.Space, ID: ev.ID, Topic: ev.Topic}
	if fn == nil {
		res.Code = "no_handler"
	} else {
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		body, err := fn(rctx, ev.Body)
		cancel()
		if err != nil {
			res.Code = err.Error()
		} else {
			res.Body = body
		}
	}
	b, _ := json.Marshal(res)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_ = conn.Write(wctx, websocket.MessageText, b)
	cancel()
}

func (h *Hub) drainAll(ctx context.Context) {
	h.mu.Lock()
	subs := make([]*boxSub, 0, len(h.boxSubs))
	for _, s := range h.boxSubs {
		subs = append(subs, s)
	}
	h.mu.Unlock()
	for _, s := range subs {
		h.drainBox(ctx, s)
	}
}

func (h *Hub) handleBoxChanged(ctx context.Context, ev PipeEvent) {
	key := ev.Space + "/" + ev.Box
	h.mu.Lock()
	bs := h.boxSubs[key]
	osub := h.objSubs[key]
	h.mu.Unlock()
	if bs != nil && ev.Event == "item" {
		if ev.Item == nil || !h.handleInline(ctx, bs, ev) {
			h.drainBox(ctx, bs)
		}
	}
	if osub != nil && ev.Event == "object" {
		osub.handler(ctx, ev.Space, ev.Box, ev.Ref, ev.Seq)
	}
}

// handleInline delivers an inline item without any HTTP round trip. It returns
// false when the item cannot be used and the caller must fall back to the
// list/download path.
//
// Inline is only a prefetch, and it is used only when it is provably the next
// item: the subscription is synced (the last drain reached the end of the Box
// and nothing failed since) and the item's seq is exactly lastSeq+1. Anything
// else — a gap (missed or reordered wake-up, another consumer), a failed
// verification — goes through drainBox, which lists everything after lastSeq.
func (h *Hub) handleInline(ctx context.Context, s *boxSub, ev PipeEvent) bool {
	it := ev.Item
	if it.Seq <= s.lastSeq {
		return true // already handled by an earlier drain
	}
	if !s.synced || it.Seq != s.lastSeq+1 || it.ID != ev.Ref || it.SpaceID != s.space || it.BoxName != s.box {
		return false
	}
	data, err := base64.StdEncoding.DecodeString(it.DataB64)
	if err != nil || int64(len(data)) != it.Size {
		return false
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), it.SHA256) {
		return false
	}
	if err := s.handler(ctx, it.BoxItem, data); err != nil {
		// Not ACKed and the cursor stays put: the next wake-up or reconnect
		// drains and redelivers it.
		s.synced = false
		return true
	}
	s.lastSeq = it.Seq
	h.queueAck(s, it.ID, it.Seq)
	return true
}

func (h *Hub) drainBox(ctx context.Context, s *boxSub) {
	s.synced = false
	for {
		items, err := h.client.ListBoxItems(ctx, s.space, s.box, s.lastSeq, 100)
		if err != nil {
			return
		}
		if len(items) == 0 {
			s.synced = true
			return
		}
		for _, it := range items {
			data, err := h.client.DownloadBoxItem(ctx, s.space, s.box, it.ID)
			if err != nil {
				h.flushAcks(ctx)
				return
			}
			if err := s.handler(ctx, it, data); err != nil {
				h.flushAcks(ctx)
				return
			}
			s.lastSeq = it.Seq
			h.queueAck(s, it.ID, it.Seq)
		}
		if !h.flushAcks(ctx) {
			return
		}
	}
}

/* ───────── Batched ACKs ───────── */

type pendingAck struct {
	sub *boxSub
	id  string
	seq int64
}

func (h *Hub) queueAck(s *boxSub, id string, seq int64) {
	h.acks = append(h.acks, pendingAck{sub: s, id: id, seq: seq})
}

func (h *Hub) pendingAcks() int { return len(h.acks) }

// flushAcks sends the queued ACKs, one batch request per Box (per-item DELETE
// against servers without the batch endpoint). If a Box's ACK fails, its
// cursor is rewound to before the first unacknowledged item so a later drain
// redelivers it (at-least-once, as before). It reports whether all succeeded.
func (h *Hub) flushAcks(ctx context.Context) bool {
	if len(h.acks) == 0 {
		return true
	}
	pending := h.acks
	h.acks = nil
	type group struct {
		sub    *boxSub
		ids    []string
		minSeq int64
	}
	var order []*group
	bySub := map[*boxSub]*group{}
	for _, a := range pending {
		g := bySub[a.sub]
		if g == nil {
			g = &group{sub: a.sub, minSeq: a.seq}
			bySub[a.sub] = g
			order = append(order, g)
		}
		g.ids = append(g.ids, a.id)
		g.minSeq = min(g.minSeq, a.seq)
	}
	ok := true
	for _, g := range order {
		if err := h.ackIDs(ctx, g.sub, g.ids); err != nil {
			ok = false
			if g.sub.lastSeq >= g.minSeq {
				g.sub.lastSeq = g.minSeq - 1
			}
			g.sub.synced = false
		}
	}
	return ok
}

func (h *Hub) ackIDs(ctx context.Context, s *boxSub, ids []string) error {
	for len(ids) > 0 {
		n := min(len(ids), MaxAckBatch)
		chunk := ids[:n]
		ids = ids[n:]
		if !h.noBatchAck {
			_, _, err := h.client.AckBoxItems(ctx, s.space, s.box, chunk)
			if err == nil {
				continue
			}
			if !IsUnsupported(err) {
				return err
			}
			h.noBatchAck = true // older server: per-item DELETE from now on
		}
		for _, id := range chunk {
			if err := h.client.AckBoxItem(ctx, s.space, s.box, id); err != nil && !isNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == 404
}

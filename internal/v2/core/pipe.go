package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	MaxPipeMessage    = 256 << 10
	MaxGlobalQueued   = 32 << 20
	PeerOutQueueSize  = 64
	PeerDataQueueSize = 64

	// InlineMaxBytes is the largest stored item that box.changed may carry
	// inline (base64 makes the frame ~4/3 of this plus metadata).
	InlineMaxBytes = 64 << 10
	// PipeFeatureBoxInline is the /v2/ws opt-in (query "features=box-inline" or
	// header "X-Relay-Features: box-inline") for inline box.changed items. Only
	// opted-in peers ever receive the larger frames, so clients with a small
	// WebSocket read limit (e.g. the 32 KiB default of coder/websocket) keep
	// working unchanged.
	PipeFeatureBoxInline = "box-inline"
	// PipeFeatureStreamCredit is the /v2/ws opt-in for explicit stream backpressure
	// hints (stream.credit frames with Seq=0 when the peer data queue is saturated).
	PipeFeatureStreamCredit = "stream-credit"
)

// PipeEvent is the compact JSON envelope carried over /v2/ws.
// Binary frames use a 16-byte stream ID prefix followed by raw encrypted chunk bytes
// for zero-overhead streaming (large folder transfers, tunnels, MCP).
type PipeEvent struct {
	Type    string   `json:"type"` // hello | presence | ping | pong | msg | ack | box.changed | stream.open | stream.accept | stream.close | error
	Space   string   `json:"space,omitempty"`
	ID      string   `json:"id,omitempty"`
	From    string   `json:"from,omitempty"`
	To      string   `json:"to,omitempty"`
	Topic   string   `json:"topic,omitempty"`
	Box     string   `json:"box,omitempty"`
	Event   string   `json:"event,omitempty"`
	Ref     string   `json:"ref,omitempty"`
	Seq     int64    `json:"seq,omitempty"`
	Body    string   `json:"body,omitempty"`
	TTL     int64    `json:"ttl,omitempty"`
	Offline bool     `json:"offline,omitempty"`
	Peers   []string `json:"peers,omitempty"`
	Code    string   `json:"code,omitempty"`
	// Item is set on box.changed (event "item") for opted-in peers when the new
	// item is small enough; it is an optional prefetch of list+download.
	Item *InlineBoxItem `json:"item,omitempty"`
}

type wsPacket struct {
	kind websocket.MessageType
	data []byte
}

type pipePeer struct {
	dev     Device
	spaces  map[string]MemberRole
	inline  bool // opted in to PipeFeatureBoxInline
	credit  bool // opted in to PipeFeatureStreamCredit
	conn    *websocket.Conn
	out     chan wsPacket // high-priority control / messaging frames
	dataOut chan wsPacket // lower-priority binary stream frames (never starves control)
	outMu   sync.Mutex
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	reason  atomic.Value // string: why the server ended this session (first writer wins)
}

func (p *pipePeer) endWith(reason string) {
	p.reason.CompareAndSwap(nil, reason)
	p.cancel()
}

// pendingRPC binds an in-flight RPC to the only device allowed to answer it.
type pendingRPC struct {
	target string
	ch     chan PipeEvent
}

// DefaultRPCTimeout bounds CallRPC when the caller's context has no deadline,
// so an unresponsive target can never pin plugin slots indefinitely.
const DefaultRPCTimeout = 15 * time.Second

type pipeStream struct {
	id    string
	space string
	a, b  *pipePeer
	ready bool
}

// PipeHub manages online device connections, Presence, messages, bounded
// zero-disk streams, and real-time Box wake-up notifications.
type PipeHub struct {
	store      *Store
	mu         sync.Mutex
	peers      map[string]*pipePeer   // deviceID -> active peer (replaces stale session on reconnect)
	streams    map[string]*pipeStream // streamID -> active stream
	rpcs       map[string]pendingRPC  // rpcID -> awaiting response (bound to the target device)
	queued     atomic.Int64
	sessionSeq atomic.Int64

	// OriginPatterns optionally allowlists browser Origins for /v2/ws (host patterns,
	// e.g. "console.example.com"). Requests without an Origin header are always allowed.
	OriginPatterns []string

	// Keepalive is how often the server pings each /v2/ws peer (0 = DefaultPipeKeepalive).
	// Reverse proxies drop idle WebSockets (nginx proxy_read_timeout); a ping/pong
	// round trip keeps both directions busy and reaps dead peers.
	Keepalive time.Duration

	// Metrics, when set, records connects/disconnects for /v2/admin/metrics.
	Metrics *Metrics
}

// DefaultPipeKeepalive stays well under common proxy idle timeouts (60–120s).
const DefaultPipeKeepalive = 30 * time.Second

func NewPipeHub(store *Store) *PipeHub {
	h := &PipeHub{
		store:   store,
		peers:   map[string]*pipePeer{},
		streams: map[string]*pipeStream{},
		rpcs:    map[string]pendingRPC{},
	}
	store.OnBoxChange = h.NotifyBoxChanged
	store.OnBoxItem = h.NotifyBoxItem
	return h
}

// CallRPC dispatches a bounded synchronous RPC request over the target device's
// existing /v2/ws connection (used by plugins like mcpedge to query the target host).
func (h *PipeHub) CallRPC(ctx context.Context, spaceID, targetDeviceID, topic, payload string) (string, error) {
	if targetDeviceID == "" {
		return "", ErrInvalidInput
	}
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultRPCTimeout)
		defer cancel()
	}
	h.mu.Lock()
	target := h.peers[targetDeviceID]
	if target == nil {
		h.mu.Unlock()
		return "", errors.New("target device offline")
	}
	if _, ok := target.spaces[spaceID]; !ok {
		h.mu.Unlock()
		return "", ErrDenied
	}
	id := RandomHex(12)
	ch := make(chan PipeEvent, 1)
	h.rpcs[id] = pendingRPC{target: targetDeviceID, ch: ch}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.rpcs, id)
		h.mu.Unlock()
	}()

	if !h.sendEvent(target, PipeEvent{
		Type: "rpc.req", Space: spaceID, ID: id, Topic: topic, Body: payload,
	}) {
		return "", errors.New("failed to enqueue rpc request")
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		if res.Code != "" {
			return "", errors.New(res.Code)
		}
		return res.Body, nil
	}
}

func (h *PipeHub) OnlineCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.peers)
}

// OnlineDevices returns the currently connected device IDs subscribed to spaceID.
func (h *PipeHub) OnlineDevices(spaceID string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, p := range h.peers {
		if _, ok := p.spaces[spaceID]; ok {
			out = append(out, p.dev.ID)
		}
	}
	return out
}

// OnlineDeviceSet returns a snapshot set of all currently connected device IDs.
func (h *PipeHub) OnlineDeviceSet() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]bool, len(h.peers))
	for id := range h.peers {
		out[id] = true
	}
	return out
}

// DisconnectDevice forcefully terminates an active /v2/ws session (e.g. after removal/disband).
func (h *PipeHub) DisconnectDevice(deviceID string) {
	h.mu.Lock()
	p := h.peers[deviceID]
	h.mu.Unlock()
	if p != nil {
		p.cancel()
	}
}

// NotifyGroupChanged informs online members of spaceID that signed group membership advanced.
func (h *PipeHub) NotifyGroupChanged(spaceID string, revision int) {
	ev := PipeEvent{
		Type:  "group.changed",
		Space: spaceID,
		Seq:   int64(revision),
	}
	b, _ := json.Marshal(ev)
	h.mu.Lock()
	var targets []*pipePeer
	for _, p := range h.peers {
		if _, ok := p.spaces[spaceID]; ok {
			targets = append(targets, p)
		}
	}
	h.mu.Unlock()
	for _, p := range targets {
		h.send(p, websocket.MessageText, b)
	}
}

func (h *PipeHub) send(p *pipePeer, kind websocket.MessageType, data []byte) bool {
	if p == nil {
		return false
	}
	p.outMu.Lock()
	defer p.outMu.Unlock()
	if p.closed {
		return false
	}
	n := int64(len(data))
	if h.queued.Add(n) > MaxGlobalQueued {
		h.queued.Add(-n)
		if kind == websocket.MessageBinary {
			// Backpressure: drop binary stream chunk instead of killing control plane.
			return false
		}
		p.cancel()
		return false
	}
	select {
	case <-p.ctx.Done():
		h.queued.Add(-n)
		return false
	default:
	}
	ch := p.out
	isData := kind == websocket.MessageBinary && p.dataOut != nil
	if isData {
		ch = p.dataOut
	}
	select {
	case ch <- wsPacket{kind: kind, data: data}:
		return true
	default:
		h.queued.Add(-n)
		if !isData {
			p.cancel()
		}
		return false
	}
}

func (h *PipeHub) sendEvent(p *pipePeer, ev PipeEvent) bool {
	b, _ := json.Marshal(ev)
	return h.send(p, websocket.MessageText, b)
}

// sendStreamClose enqueues stream.close behind any already-queued binary stream
// frames on dataOut so a peer never observes stream.close before the final
// encrypted chunks of that stream. Falls back to the control queue if dataOut
// is saturated or uninitialized.
func (h *PipeHub) sendStreamClose(p *pipePeer, ev PipeEvent) bool {
	if p == nil {
		return false
	}
	b, _ := json.Marshal(ev)
	p.outMu.Lock()
	if p.closed {
		p.outMu.Unlock()
		return false
	}
	if p.dataOut != nil {
		n := int64(len(b))
		if h.queued.Add(n) <= MaxGlobalQueued {
			select {
			case p.dataOut <- wsPacket{kind: websocket.MessageText, data: b}:
				p.outMu.Unlock()
				return true
			default:
				h.queued.Add(-n)
			}
		} else {
			h.queued.Add(-n)
		}
	}
	p.outMu.Unlock()
	return h.send(p, websocket.MessageText, b)
}

// NotifyBoxChanged wakes up every online member (including archive_observer) of spaceID.
func (h *PipeHub) NotifyBoxChanged(spaceID, boxName, event, ref string, seqOrVer int64) {
	ev := PipeEvent{
		Type:  "box.changed",
		Space: spaceID,
		Box:   boxName,
		Event: event,
		Ref:   ref,
		Seq:   seqOrVer,
	}
	b, _ := json.Marshal(ev)
	h.mu.Lock()
	var targets []*pipePeer
	for _, p := range h.peers {
		if _, ok := p.spaces[spaceID]; ok {
			targets = append(targets, p)
		}
	}
	h.mu.Unlock()
	for _, p := range targets {
		h.send(p, websocket.MessageText, b)
	}
}

// NotifyBoxItem announces a new queue/ephemeral item. Peers that opted in to
// PipeFeatureBoxInline get the item inline when it is at most InlineMaxBytes,
// the frame fits MaxPipeMessage and their send queue has headroom; everyone
// else (and any fallback) gets the same compact box.changed as before.
func (h *PipeHub) NotifyBoxItem(item BoxItem) {
	ev := PipeEvent{Type: "box.changed", Space: item.SpaceID, Box: item.BoxName, Event: "item", Ref: item.ID, Seq: item.Seq}
	plain, _ := json.Marshal(ev)
	h.mu.Lock()
	var targets []*pipePeer
	wantInline := false
	for _, p := range h.peers {
		if _, ok := p.spaces[item.SpaceID]; ok {
			targets = append(targets, p)
			wantInline = wantInline || p.inline
		}
	}
	h.mu.Unlock()
	var full []byte
	if wantInline && item.Size <= InlineMaxBytes {
		full = h.inlineFrame(ev, item)
	}
	for _, p := range targets {
		if p.inline {
			if full != nil && h.hasInlineRoom(p, len(full)) {
				h.Metrics.Inline(true)
				h.send(p, websocket.MessageText, full)
				continue
			}
			h.Metrics.Inline(false)
		}
		h.send(p, websocket.MessageText, plain)
	}
}

// inlineFrame reads the just-committed blob and builds the inline event, or
// returns nil (plain fallback) if it is gone, changed size, or would exceed
// MaxPipeMessage.
func (h *PipeHub) inlineFrame(ev PipeEvent, item BoxItem) []byte {
	data, err := os.ReadFile(h.store.blobPath(item.ID))
	if err != nil || int64(len(data)) != item.Size {
		return nil
	}
	ev.Item = &InlineBoxItem{BoxItem: item, DataB64: base64.StdEncoding.EncodeToString(data)}
	b, err := json.Marshal(ev)
	if err != nil || len(b) > MaxPipeMessage {
		return nil
	}
	return b
}

// hasInlineRoom keeps inlining from pushing a peer toward the limits that make
// send() drop the session: it requires the peer's queue to be at most half full
// and the global queued bytes to stay under half of MaxGlobalQueued.
func (h *PipeHub) hasInlineRoom(p *pipePeer, n int) bool {
	if len(p.out) >= PeerOutQueueSize/2 {
		return false
	}
	return h.queued.Load()+int64(n) <= MaxGlobalQueued/2
}

// wantsFeature reports whether the /v2/ws request opted in to feature via the
// "features" query parameter or X-Relay-Features header (comma-separated).
func wantsFeature(r *http.Request, feature string) bool {
	for _, list := range append(r.URL.Query()["features"], r.Header.Values("X-Relay-Features")...) {
		for _, f := range strings.Split(list, ",") {
			if strings.EqualFold(strings.TrimSpace(f), feature) {
				return true
			}
		}
	}
	return false
}

func (h *PipeHub) ServeWS(w http.ResponseWriter, r *http.Request, dev Device) {
	spaceIDs, err := h.store.DeviceSpaces(dev.ID)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	spaces := make(map[string]MemberRole, len(spaceIDs))
	for _, sid := range spaceIDs {
		if role, err := h.store.MemberRole(sid, dev.ID); err == nil {
			spaces[sid] = role
		}
	}

	// Native SDK clients send no Origin header; browsers do. Cross-origin browser
	// pages are rejected (same-host only) unless explicitly allowlisted.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.OriginPatterns})
	if err != nil {
		return
	}
	conn.SetReadLimit(MaxPipeMessage)

	ctx, cancel := context.WithCancel(r.Context())
	p := &pipePeer{
		dev:     dev,
		spaces:  spaces,
		inline:  wantsFeature(r, PipeFeatureBoxInline),
		credit:  wantsFeature(r, PipeFeatureStreamCredit),
		conn:    conn,
		out:     make(chan wsPacket, PeerOutQueueSize),
		dataOut: make(chan wsPacket, PeerDataQueueSize),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Replace any stale session for the same device cleanly (zero leak on network switch).
	h.mu.Lock()
	prev := h.peers[dev.ID]
	h.peers[dev.ID] = p
	h.mu.Unlock()
	if prev != nil {
		prev.endWith("replaced")
		_ = prev.conn.Close(websocket.StatusGoingAway, "replaced")
	}
	connectedAt := time.Now()
	h.Metrics.Connect(dev.ID)

	var readErr error
	defer func() {
		cancel()
		reason, _ := p.reason.Load().(string)
		if reason == "" {
			switch {
			case readErr == nil:
				reason = "server_closed"
			case websocket.CloseStatus(readErr) != -1:
				reason = "client_closed"
			default:
				reason = "connection_lost"
			}
		}
		p.outMu.Lock()
		p.closed = true
		p.outMu.Unlock()
		h.mu.Lock()
		if h.peers[dev.ID] == p {
			delete(h.peers, dev.ID)
		}
		_, stillOnline := h.peers[dev.ID]
		h.Metrics.Disconnect(dev.ID, reason, connectedAt, stillOnline)
		for sid, st := range h.streams {
			if st.a == p || st.b == p {
				other := st.a
				if other == p {
					other = st.b
				}
				delete(h.streams, sid)
				if other != nil {
					h.sendStreamClose(other, PipeEvent{Type: "stream.close", Space: st.space, ID: sid})
				}
			}
		}
		h.mu.Unlock()
		h.broadcastPresence(p)
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}()

	// Writer goroutine: strictly prioritizes control/messaging frames (p.out)
	// over binary stream frames (p.dataOut) so high-throughput streams cannot
	// starve keepalives, ACKs, or RPC replies.
	go func() {
		writePkt := func(pkt wsPacket) bool {
			h.queued.Add(-int64(len(pkt.data)))
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Write(wctx, pkt.kind, pkt.data)
			wcancel()
			if err != nil {
				p.endWith("write_failed")
				return false
			}
			return true
		}
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-p.out:
				if !writePkt(pkt) {
					return
				}
				continue
			default:
			}
			select {
			case <-ctx.Done():
				return
			case pkt := <-p.out:
				if !writePkt(pkt) {
					return
				}
			case pkt := <-p.dataOut:
				if !writePkt(pkt) {
					return
				}
			}
		}
	}()

	// Keepalive goroutine: a peer that stops answering pings is disconnected so its
	// presence and streams are released instead of lingering until TCP times out.
	go func() {
		every := h.Keepalive
		if every <= 0 {
			every = DefaultPipeKeepalive
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(ctx, min(every, 10*time.Second))
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					if ctx.Err() == nil {
						p.endWith("keepalive_timeout")
					}
					return
				}
			}
		}
	}()

	h.sendEvent(p, PipeEvent{Type: "hello", From: dev.ID, Seq: h.sessionSeq.Add(1)})
	h.broadcastPresence(p)

	// Flush pending offline messages for each subscribed space.
	for sid := range spaces {
		if msgs, err := h.store.PendingMessages(sid, dev.ID); err == nil {
			for _, m := range msgs {
				h.sendEvent(p, PipeEvent{
					Type: "msg", Space: m.SpaceID, ID: m.ID, From: m.Sender,
					To: m.Recipient, Topic: m.Topic, Body: m.Body, Offline: true,
				})
			}
		}
	}

	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			readErr = err
			return
		}
		if kind == websocket.MessageBinary {
			h.handleBinaryFrame(p, data)
			continue
		}
		var ev PipeEvent
		if json.Unmarshal(data, &ev) != nil {
			h.sendEvent(p, PipeEvent{Type: "error", Code: "bad_json"})
			continue
		}
		h.handleEvent(p, ev)
	}
}

func (h *PipeHub) broadcastPresence(changed *pipePeer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for sid := range changed.spaces {
		var online []string
		var members []*pipePeer
		for _, peer := range h.peers {
			if _, ok := peer.spaces[sid]; ok {
				online = append(online, peer.dev.ID)
				members = append(members, peer)
			}
		}
		ev := PipeEvent{Type: "presence", Space: sid, Peers: online}
		b, _ := json.Marshal(ev)
		for _, peer := range members {
			h.send(peer, websocket.MessageText, b)
		}
	}
}

func (h *PipeHub) handleEvent(p *pipePeer, ev PipeEvent) {
	switch ev.Type {
	case "ping":
		h.sendEvent(p, PipeEvent{Type: "pong", ID: ev.ID})

	case "presence":
		if _, ok := p.spaces[ev.Space]; !ok {
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "forbidden"})
			return
		}
		h.mu.Lock()
		var online []string
		for _, peer := range h.peers {
			if _, ok := peer.spaces[ev.Space]; ok {
				online = append(online, peer.dev.ID)
			}
		}
		h.mu.Unlock()
		h.sendEvent(p, PipeEvent{Type: "presence", Space: ev.Space, ID: ev.ID, Peers: online})

	case "rpc.res":
		if ev.ID == "" {
			return
		}
		h.mu.Lock()
		pending, ok := h.rpcs[ev.ID]
		h.mu.Unlock()
		// Only the device the request was sent to may answer it.
		if ok && pending.target == p.dev.ID {
			select {
			case pending.ch <- ev:
			default:
			}
		}

	case "msg":
		role, ok := p.spaces[ev.Space]
		if !ok || !role.CanWrite() {
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "forbidden"})
			return
		}
		if ev.ID == "" {
			ev.ID = RandomHex(12)
		}
		if _, err := h.store.MemberRole(ev.Space, ev.To); err != nil {
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "unknown_recipient"})
			return
		}
		h.mu.Lock()
		target := h.peers[ev.To]
		h.mu.Unlock()
		if ev.Offline {
			ttl := ev.TTL
			if ttl <= 0 {
				ttl = 86400
			}
			_, err := h.store.PutMessage(Message{
				ID: ev.ID, SpaceID: ev.Space, Sender: p.dev.ID, Recipient: ev.To,
				Topic: ev.Topic, Body: ev.Body, ExpiresAt: time.Now().Unix() + ttl,
			})
			if err != nil {
				h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "storage"})
				return
			}
			if target != nil {
				h.sendEvent(target, PipeEvent{
					Type: "msg", Space: ev.Space, ID: ev.ID, From: p.dev.ID,
					To: ev.To, Topic: ev.Topic, Body: ev.Body, Offline: true,
				})
			}
			h.Metrics.SpaceMsg(ev.Space, true)
			h.sendEvent(p, PipeEvent{Type: "ack", Space: ev.Space, ID: ev.ID, Event: "stored"})
			return
		}
		if target != nil {
			h.sendEvent(target, PipeEvent{
				Type: "msg", Space: ev.Space, ID: ev.ID, From: p.dev.ID,
				To: ev.To, Topic: ev.Topic, Body: ev.Body,
			})
			h.Metrics.SpaceMsg(ev.Space, false)
			h.sendEvent(p, PipeEvent{Type: "ack", Space: ev.Space, ID: ev.ID, Event: "forwarded"})
			return
		}
		h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "offline"})

	case "ack":
		if ev.Space != "" && ev.From != "" && ev.ID != "" {
			_ = h.store.AckMessage(ev.Space, p.dev.ID, ev.From, ev.ID)
			h.mu.Lock()
			sender := h.peers[ev.From]
			h.mu.Unlock()
			if sender != nil {
				h.sendEvent(sender, PipeEvent{Type: "received", Space: ev.Space, ID: ev.ID, From: p.dev.ID})
			}
		}

	case "stream.open":
		role, ok := p.spaces[ev.Space]
		if !ok || !role.CanWrite() || len(ev.ID) != 16 {
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "invalid_stream"})
			return
		}
		h.mu.Lock()
		target := h.peers[ev.To]
		if target == nil {
			h.mu.Unlock()
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "offline"})
			return
		}
		if _, ok := target.spaces[ev.Space]; !ok {
			h.mu.Unlock()
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "forbidden"})
			return
		}
		h.streams[ev.ID] = &pipeStream{id: ev.ID, space: ev.Space, a: p, b: target}
		h.mu.Unlock()
		h.sendEvent(target, PipeEvent{Type: "stream.open", Space: ev.Space, ID: ev.ID, From: p.dev.ID, Topic: ev.Topic, Body: ev.Body})

	case "stream.accept":
		h.mu.Lock()
		st := h.streams[ev.ID]
		if st == nil || st.b != p {
			h.mu.Unlock()
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "unknown_stream"})
			return
		}
		st.ready = true
		origin := st.a
		h.mu.Unlock()
		h.sendEvent(origin, PipeEvent{Type: "stream.accept", Space: st.space, ID: st.id, From: p.dev.ID, Body: ev.Body})

	case "stream.credit":
		if ev.Seq < 0 {
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "invalid_stream"})
			return
		}
		h.mu.Lock()
		st := h.streams[ev.ID]
		var other *pipePeer
		if st != nil && st.ready {
			if st.a == p {
				other = st.b
			} else if st.b == p {
				other = st.a
			}
		}
		h.mu.Unlock()
		if other == nil {
			h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "unknown_stream"})
			return
		}
		h.sendEvent(other, PipeEvent{Type: "stream.credit", Space: st.space, ID: st.id, From: p.dev.ID, Seq: ev.Seq})

	case "stream.close":
		h.mu.Lock()
		st := h.streams[ev.ID]
		var other *pipePeer
		if st != nil && (st.a == p || st.b == p) {
			delete(h.streams, ev.ID)
			if st.a == p {
				other = st.b
			} else {
				other = st.a
			}
		}
		h.mu.Unlock()
		if other != nil {
			h.sendStreamClose(other, PipeEvent{Type: "stream.close", Space: st.space, ID: st.id, From: p.dev.ID})
		}
	}
}

// handleBinaryFrame forwards [16-byte streamID][encrypted chunk] directly to the peer with zero disk I/O.
func (h *PipeHub) handleBinaryFrame(p *pipePeer, frame []byte) {
	if len(frame) < 16 {
		return
	}
	sid := string(frame[:16])
	h.mu.Lock()
	st := h.streams[sid]
	var target *pipePeer
	var spaceID string
	if st != nil && st.ready {
		spaceID = st.space
		if st.a == p {
			target = st.b
		} else if st.b == p {
			target = st.a
		}
	}
	h.mu.Unlock()
	if target != nil {
		if h.send(target, websocket.MessageBinary, frame) {
			h.Metrics.StreamFrame(spaceID, int64(len(frame)))
		} else {
			h.Metrics.StreamDrop(spaceID)
			if p.credit {
				h.sendEvent(p, PipeEvent{Type: "stream.credit", Space: spaceID, ID: sid, Seq: 0})
			}
		}
	}
}

package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	MaxPipeMessage   = 256 << 10
	MaxGlobalQueued  = 32 << 20
	PeerOutQueueSize = 64
)

// PipeEvent is the compact JSON envelope carried over /v2/ws.
// Binary frames use a 16-byte stream ID prefix followed by raw encrypted chunk bytes
// for zero-overhead streaming (SyncApp 512 MiB folder transfers, TunnelApp, MCP).
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
}

type wsPacket struct {
	kind websocket.MessageType
	data []byte
}

type pipePeer struct {
	dev    Device
	spaces map[string]MemberRole
	conn   *websocket.Conn
	out    chan wsPacket
	outMu  sync.Mutex
	closed bool
	ctx    context.Context
	cancel context.CancelFunc
}

type pipeStream struct {
	id    string
	space string
	a, b  *pipePeer
	ready bool
}

// PipeHub manages online device connections, Presence, messages, bounded
// zero-disk streams, and real-time Box wake-up notifications.
type PipeHub struct {
	store   *Store
	mu      sync.Mutex
	peers   map[string]*pipePeer      // deviceID -> active peer (replaces stale session on reconnect)
	streams map[string]*pipeStream    // streamID -> active stream
	rpcs    map[string]chan PipeEvent // rpcID -> awaiting response channel
	queued  atomic.Int64
}

func NewPipeHub(store *Store) *PipeHub {
	h := &PipeHub{
		store:   store,
		peers:   map[string]*pipePeer{},
		streams: map[string]*pipeStream{},
		rpcs:    map[string]chan PipeEvent{},
	}
	store.OnBoxChange = h.NotifyBoxChanged
	return h
}

// CallRPC dispatches a bounded synchronous RPC request over the target device's
// existing /v2/ws connection (used by plugins like mcpedge to query the local Hub).
func (h *PipeHub) CallRPC(ctx context.Context, spaceID, targetDeviceID, topic, payload string) (string, error) {
	if targetDeviceID == "" {
		return "", ErrInvalidInput
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
	h.rpcs[id] = ch
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
		p.cancel()
		return false
	}
	select {
	case <-p.ctx.Done():
		h.queued.Add(-n)
		return false
	default:
	}
	select {
	case p.out <- wsPacket{kind: kind, data: data}:
		return true
	default:
		h.queued.Add(-n)
		p.cancel()
		return false
	}
}

func (h *PipeHub) sendEvent(p *pipePeer, ev PipeEvent) bool {
	b, _ := json.Marshal(ev)
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

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(MaxPipeMessage)

	ctx, cancel := context.WithCancel(r.Context())
	p := &pipePeer{
		dev:    dev,
		spaces: spaces,
		conn:   conn,
		out:    make(chan wsPacket, PeerOutQueueSize),
		ctx:    ctx,
		cancel: cancel,
	}

	// Replace any stale session for the same device cleanly (zero leak on network switch).
	h.mu.Lock()
	prev := h.peers[dev.ID]
	h.peers[dev.ID] = p
	h.mu.Unlock()
	if prev != nil {
		prev.cancel()
		_ = prev.conn.Close(websocket.StatusGoingAway, "replaced")
	}

	defer func() {
		cancel()
		p.outMu.Lock()
		p.closed = true
		p.outMu.Unlock()
		h.mu.Lock()
		if h.peers[dev.ID] == p {
			delete(h.peers, dev.ID)
		}
		for sid, st := range h.streams {
			if st.a == p || st.b == p {
				other := st.a
				if other == p {
					other = st.b
				}
				delete(h.streams, sid)
				if other != nil {
					h.sendEvent(other, PipeEvent{Type: "stream.close", Space: st.space, ID: sid})
				}
			}
		}
		h.mu.Unlock()
		h.broadcastPresence(p)
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}()

	// Writer goroutine.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-p.out:
				h.queued.Add(-int64(len(pkt.data)))
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				err := conn.Write(wctx, pkt.kind, pkt.data)
				wcancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	h.sendEvent(p, PipeEvent{Type: "hello", From: dev.ID})
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
		ch := h.rpcs[ev.ID]
		h.mu.Unlock()
		if ch != nil {
			select {
			case ch <- ev:
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
		if target != nil {
			h.sendEvent(target, PipeEvent{
				Type: "msg", Space: ev.Space, ID: ev.ID, From: p.dev.ID,
				To: ev.To, Topic: ev.Topic, Body: ev.Body,
			})
			h.sendEvent(p, PipeEvent{Type: "ack", Space: ev.Space, ID: ev.ID})
			return
		}
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
			h.sendEvent(p, PipeEvent{Type: "ack", Space: ev.Space, ID: ev.ID})
			return
		}
		h.sendEvent(p, PipeEvent{Type: "error", ID: ev.ID, Code: "offline"})

	case "ack":
		if ev.Space != "" && ev.From != "" && ev.ID != "" {
			_ = h.store.AckMessage(ev.Space, p.dev.ID, ev.From, ev.ID)
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
			h.sendEvent(other, PipeEvent{Type: "stream.close", Space: st.space, ID: st.id, From: p.dev.ID})
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
	if st != nil && st.ready {
		if st.a == p {
			target = st.b
		} else if st.b == p {
			target = st.a
		}
	}
	h.mu.Unlock()
	if target != nil {
		h.send(target, websocket.MessageBinary, frame)
	}
}

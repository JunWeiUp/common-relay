package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/coder/websocket"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MaxMessage = 256 << 10

type Event struct {
	Type         string   `json:"type"`
	ID           string   `json:"id,omitempty"`
	To           string   `json:"to,omitempty"`
	From         string   `json:"from,omitempty"`
	Body         string   `json:"body,omitempty"`
	Offline      bool     `json:"offline,omitempty"`
	TTL          int64    `json:"ttl,omitempty"`
	Expires      int64    `json:"expires,omitempty"`
	Code         string   `json:"code,omitempty"`
	Version      int      `json:"version,omitempty"`
	Revision     int      `json:"revision,omitempty"`
	Sequence     uint64   `json:"sequence,omitempty"`
	Devices      []Device `json:"devices,omitzero"`
	Device       *Device  `json:"identity,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}
type packet struct {
	kind websocket.MessageType
	data []byte
}
type peer struct {
	outMu  sync.Mutex
	closed bool
	d      Device
	ws     *websocket.Conn
	out    chan packet
	ctx    context.Context
	cancel context.CancelFunc
}
type stream struct {
	a, b       *peer
	ready      bool
	seqA, seqB uint64
	ackA, ackB uint64
	deadline   time.Time
}
type Server struct {
	SelfServiceApps                map[string]bool
	Store                          *Store
	mu                             sync.Mutex
	peers                          map[string]*peer
	streams                        map[string]*stream
	queued                         atomic.Int64
	fileLocksMu                    sync.Mutex
	fileLocks                      map[string]*fileLock
	MaxConnections, AppConnections int
	DiskReserve                    uint64
}

func New(s *Store) *Server {
	return &Server{Store: s, peers: map[string]*peer{}, streams: map[string]*stream{}, fileLocks: map[string]*fileLock{}, MaxConnections: 128, AppConnections: 64, DiskReserve: 2 << 30}
}
func key(d Device) string { return d.App + "/" + d.Group + "/" + d.ID }
func (s *Server) presence(d Device, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.peers {
		if p.d.App == d.App && p.d.Group == d.Group && p.d.ID != d.ID {
			s.event(p, Event{Type: kind, Device: &d})
		}
	}
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/relay/v1/ws", s.websocket)
	m.HandleFunc("/relay/v1/group", s.groups)
	m.HandleFunc("/relay/v1/group/", s.groups)
	m.HandleFunc("/relay/v1/enroll/", s.groups)
	m.HandleFunc("/relay/v1/files", s.files)
	m.HandleFunc("/relay/v1/files/", s.files)
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.Store.DB.Ping() != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Write([]byte("ok\n"))
	})
	return m
}
func (s *Server) auth(r *http.Request) (Device, error) {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return Device{}, ErrDenied
	}
	return s.Store.Authenticate(strings.TrimPrefix(v, "Bearer "))
}
func (s *Server) send(p *peer, kind websocket.MessageType, b []byte) bool {
	if p == nil {
		return false
	}
	p.outMu.Lock()
	defer p.outMu.Unlock()
	if p.closed {
		return false
	}
	n := int64(len(b))
	if s.queued.Add(n) > 32<<20 {
		s.queued.Add(-n)
		p.cancel()
		return false
	}
	select {
	case <-p.ctx.Done():
		s.queued.Add(-n)
		return false
	default:
	}
	select {
	case p.out <- packet{kind, b}:
		return true
	default:
		s.queued.Add(-n)
		p.cancel()
		return false
	}
}
func (s *Server) event(p *peer, e Event) bool {
	b, _ := json.Marshal(e)
	return s.send(p, websocket.MessageText, b)
}
func (s *Server) failure(p *peer, id, code string) {
	s.event(p, Event{Type: "error", ID: id, Code: code})
}
func (s *Server) websocket(w http.ResponseWriter, r *http.Request) {
	d, err := s.auth(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	s.mu.Lock()
	count := 0
	for _, p := range s.peers {
		if p.d.App == d.App {
			count++
		}
	}
	if s.peers[key(d)] != nil || len(s.peers) >= s.MaxConnections || count >= s.AppConnections {
		s.mu.Unlock()
		http.Error(w, "capacity or duplicate device", 409)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"common-relay.v1"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		s.mu.Unlock()
		return
	}
	if ws.Subprotocol() != "common-relay.v1" {
		s.mu.Unlock()
		ws.Close(websocket.StatusPolicyViolation, "version required")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	p := &peer{d: d, ws: ws, out: make(chan packet, 32), ctx: ctx, cancel: cancel}
	s.peers[key(d)] = p
	s.mu.Unlock()
	ws.SetReadLimit(MaxMessage + 4096)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-p.out:
				s.queued.Add(-int64(len(item.data)))
				wc, stop := context.WithTimeout(ctx, 30*time.Second)
				e := ws.Write(wc, item.kind, item.data)
				stop()
				if e != nil {
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		ws.CloseNow()
		<-writerDone
		s.mu.Lock()
		delete(s.peers, key(d))
		for id, st := range s.streams {
			if st.a == p || st.b == p {
				other := st.a
				if other == p {
					other = st.b
				}
				s.event(other, Event{Type: "stream.close", ID: id, Code: "peer_offline"})
				delete(s.streams, id)
			}
		}
		s.mu.Unlock()
		s.presence(d, "peer.down")
		p.outMu.Lock()
		defer p.outMu.Unlock()
		p.closed = true
		for {
			select {
			case item := <-p.out:
				s.queued.Add(-int64(len(item.data)))
			default:
				return
			}
		}
	}()
	s.event(p, Event{Type: "welcome", Version: 1, Device: &d, Capabilities: []string{"presence", "message", "stream", "offline", "files"}})
	var revision int
	if err := s.Store.DB.QueryRow("SELECT COALESCE(MAX(revision),0) FROM group_entries WHERE app=? AND grp=?", d.App, d.Group).Scan(&revision); err == nil && revision > 0 {
		s.event(p, Event{Type: "group.changed", Revision: revision})
	}
	s.presence(d, "peer.up")
	s.inbox(p)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		ticks := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.expireStreams(time.Now())
				if _, e := s.Store.Peer(d, d.ID); e != nil {
					cancel()
					return
				}
				ticks++
				if ticks%25 == 0 {
					pc, stop := context.WithTimeout(ctx, 10*time.Second)
					e := ws.Ping(pc)
					stop()
					if e != nil {
						cancel()
						return
					}
					s.inbox(p)
				}
			}
		}
	}()
	for {
		kind, b, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if _, err = s.Store.Peer(d, d.ID); err != nil {
			return
		}
		if kind == websocket.MessageBinary {
			s.binary(p, b)
			continue
		}
		var e Event
		if json.Unmarshal(b, &e) != nil {
			s.failure(p, "", "invalid_json")
			continue
		}
		s.control(p, e)
	}
}
func (s *Server) inbox(p *peer) {
	rows, err := s.Store.DB.Query("SELECT sender,id,body FROM messages m WHERE app=? AND grp=? AND recipient=? AND expires>? AND EXISTS(SELECT 1 FROM devices d WHERE d.app=m.app AND d.grp=m.grp AND d.id=m.sender AND d.revoked=0) ORDER BY expires,id LIMIT 16", p.d.App, p.d.Group, p.d.ID, time.Now().Unix())
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var from, id, body string
		if rows.Scan(&from, &id, &body) == nil {
			s.event(p, Event{Type: "message", ID: id, From: from, Body: body, Offline: true})
		}
	}
}
func (s *Server) control(p *peer, e Event) {
	if e.Type == "peers" {
		s.mu.Lock()
		ds := []Device{}
		for _, q := range s.peers {
			if q.d.App == p.d.App && q.d.Group == p.d.Group && q != p {
				ds = append(ds, q.d)
			}
		}
		s.mu.Unlock()
		s.event(p, Event{Type: "peers", ID: e.ID, Devices: ds})
		return
	}
	if !objectID.MatchString(e.ID) {
		s.failure(p, e.ID, "invalid_id")
		return
	}
	if e.Type == "ack" {
		if err := s.Store.Ack(p.d, e.From, e.ID); err != nil {
			s.failure(p, e.ID, "storage_error")
			return
		}
		s.event(p, Event{Type: "acked", ID: e.ID})
		return
	}
	if e.Type == "stream.accept" || e.Type == "stream.close" || e.Type == "stream.credit" {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := s.streams[e.ID]
		if st == nil || (st.a != p && st.b != p) {
			s.failure(p, e.ID, "unknown_stream")
			return
		}
		if e.Type == "stream.close" {
			s.event(st.a, e)
			s.event(st.b, e)
			delete(s.streams, e.ID)
			return
		}
		if e.Type == "stream.credit" {
			ack, sent, other := &st.ackA, st.seqA, st.a
			if p == st.a {
				ack, sent, other = &st.ackB, st.seqB, st.b
			}
			if !st.ready || e.Sequence < *ack || e.Sequence > sent {
				s.failure(p, e.ID, "invalid_credit")
				return
			}
			*ack = e.Sequence
			s.event(other, Event{Type: "stream.credit", ID: e.ID, Sequence: e.Sequence})
			return
		}
		if st.b != p || st.ready || time.Now().After(st.deadline) {
			s.failure(p, e.ID, "invalid_state")
			return
		}
		if len(e.Body) > 4096 {
			s.failure(p, e.ID, "too_large")
			return
		}
		st.ready = true
		e.From = p.d.ID
		s.event(st.a, e)
		s.event(st.b, Event{Type: "stream.ready", ID: e.ID})
		return
	}
	target, err := s.Store.Peer(p.d, e.To)
	if err != nil || target.ID == p.d.ID {
		s.failure(p, e.ID, "unknown_peer")
		return
	}
	s.mu.Lock()
	q := s.peers[key(target)]
	s.mu.Unlock()
	switch e.Type {
	case "message":
		if len(e.Body) == 0 || len(e.Body) > MaxMessage {
			s.failure(p, e.ID, "too_large")
			return
		}
		state := "forwarded"
		if e.Offline {
			if e.TTL == 0 {
				e.TTL = 86400
			}
			if e.TTL < 1 || e.TTL > 86400 {
				s.failure(p, e.ID, "invalid_ttl")
				return
			}
			if e.Expires != 0 {
				remaining := e.Expires - time.Now().Unix()
				if remaining < 1 || remaining > 86400 {
					s.failure(p, e.ID, "expired_or_invalid_expiry")
					return
				}
				e.TTL = remaining
			}
			state, err = s.Store.PutMessage(p.d, e.To, e.ID, []byte(e.Body), e.TTL, e.Expires)
			if err != nil {
				s.failure(p, e.ID, "storage_or_quota")
				return
			}
		} else if q == nil {
			s.failure(p, e.ID, "peer_offline")
			return
		}
		e.From = p.d.ID
		e.To = ""
		if state != "received" {
			ok := s.event(q, e)
			if !ok && !e.Offline {
				s.failure(p, e.ID, "peer_unavailable")
				return
			}
		}
		s.event(p, Event{Type: state, ID: e.ID})
	case "stream.open":
		if q == nil {
			s.failure(p, e.ID, "peer_offline")
			return
		}
		if e.Offline || len(e.Body) > 4096 {
			s.failure(p, e.ID, "invalid_stream")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.streams[e.ID]; ok {
			s.failure(p, e.ID, "id_conflict")
			return
		}
		n, targetCount := 0, 0
		for id, st := range s.streams {
			if !st.ready && time.Now().After(st.deadline) {
				s.event(st.a, Event{Type: "stream.close", ID: id, Code: "timeout"})
				s.event(st.b, Event{Type: "stream.close", ID: id, Code: "timeout"})
				delete(s.streams, id)
				continue
			}
			if st.a == p || st.b == p {
				n++
			}
			if st.a == q || st.b == q {
				targetCount++
			}
		}
		if n >= 8 || targetCount >= 8 || len(s.streams) >= 256 {
			s.failure(p, e.ID, "capacity")
			return
		}
		s.streams[e.ID] = &stream{a: p, b: q, deadline: time.Now().Add(40 * time.Second)}
		e.From = p.d.ID
		e.To = ""
		s.event(q, e)
	default:
		s.failure(p, e.ID, "unknown_type")
	}
}
func (s *Server) binary(p *peer, b []byte) {
	if len(b) < 26 || len(b) > 65536+25 || b[0] != 1 {
		s.failure(p, "", "invalid_frame")
		return
	}
	id := hex.EncodeToString(b[1:17])
	seq := binary.BigEndian.Uint64(b[17:25])
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[id]
	if st == nil || !st.ready || (p != st.a && p != st.b) {
		s.failure(p, id, "unknown_stream")
		return
	}
	q := st.b
	expected := &st.seqA
	ack := st.ackA
	if p == st.b {
		q = st.a
		expected = &st.seqB
		ack = st.ackB
	}
	if seq != *expected || seq-ack >= 8 {
		s.failure(p, id, "invalid_sequence")
		s.event(st.a, Event{Type: "stream.close", ID: id})
		s.event(st.b, Event{Type: "stream.close", ID: id})
		delete(s.streams, id)
		return
	}
	*expected++
	s.send(q, websocket.MessageBinary, b)
}
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.peers {
		p.cancel()
	}
}

// Called by active connection heartbeats; no streams can outlive all peers.
func (s *Server) expireStreams(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, st := range s.streams {
		if !st.ready && !now.Before(st.deadline) {
			s.event(st.a, Event{Type: "stream.close", ID: id, Code: "timeout"})
			s.event(st.b, Event{Type: "stream.close", ID: id, Code: "timeout"})
			delete(s.streams, id)
		}
	}
}

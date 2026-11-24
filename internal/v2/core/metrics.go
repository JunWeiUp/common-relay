package core

import (
	"sort"
	"sync"
	"time"
)

// Metrics is a small in-memory operational record for /v2/admin/metrics. It is
// reset on restart (StartedAt says when) and strictly bounded: edge counters are
// capped per key count and connection events live in a fixed ring.
type Metrics struct {
	start time.Time

	mu      sync.Mutex
	edge    map[string]*EdgeCounter
	spaces  map[string]*SpaceCounter
	devices map[string]*DeviceConn
	events  []ConnEvent // ring buffer
	next    int
	full    bool

	keepaliveTimeouts int64
	replaced          int64
	boxInline         int64
	boxInlineSkipped  int64
	streamFrames      int64
	streamBytes       int64
	streamDrops       int64
}

const (
	maxEdgeKeys      = 256
	maxSpaceKeys     = 256
	connEventRing    = 500
	edgeOverflowKey  = "*/other"
	spaceOverflowKey = "*/other"
)

// SpaceCounter summarises per-space Pipe message & stream traffic since start.
type SpaceCounter struct {
	MessagesOnline  int64 `json:"messages_online"`
	MessagesOffline int64 `json:"messages_offline"`
	StreamFrames    int64 `json:"stream_frames"`
	StreamBytes     int64 `json:"stream_bytes"`
	StreamDrops     int64 `json:"stream_drops"`
	LastAt          int64 `json:"last_at,omitempty"`
}

// EdgeCounter counts /edge/{plugin}/{mount} requests by outcome.
type EdgeCounter struct {
	Requests   int64 `json:"requests"`
	OK         int64 `json:"ok"`          // 1xx–3xx
	Rejected   int64 `json:"rejected"`    // 401/403/429
	ClientErr  int64 `json:"client_err"`  // other 4xx
	ServerErr  int64 `json:"server_err"`  // 5xx
	LastAt     int64 `json:"last_at"`     // unix seconds
	LastErrAt  int64 `json:"last_err_at"` // unix seconds of the last non-2xx/3xx
	LastStatus int   `json:"last_status"`
}

// DeviceConn summarises one device's /v2/ws sessions since start.
type DeviceConn struct {
	Online         bool   `json:"online"`
	Connects       int64  `json:"connects"`
	Disconnects    int64  `json:"disconnects"`
	Disconnects24h int64  `json:"disconnects_24h"`
	LastConnect    int64  `json:"last_connect,omitempty"`
	LastDisconnect int64  `json:"last_disconnect,omitempty"`
	LastReason     string `json:"last_reason,omitempty"`
}

// ConnEvent is one /v2/ws connect or disconnect.
type ConnEvent struct {
	Device   string `json:"device"`
	At       int64  `json:"at"`
	Kind     string `json:"kind"` // connect | disconnect
	Reason   string `json:"reason,omitempty"`
	Duration int64  `json:"duration,omitempty"` // seconds the session lasted
}

// MetricsSnapshot is the JSON body of /v2/admin/metrics.
type MetricsSnapshot struct {
	StartedAt         int64                   `json:"started_at"`
	UptimeSeconds     int64                   `json:"uptime_seconds"`
	Edge              map[string]EdgeCounter  `json:"edge"`
	Spaces            map[string]SpaceCounter `json:"spaces,omitempty"`
	Devices           map[string]DeviceConn   `json:"devices"`
	KeepaliveTimeouts int64                   `json:"keepalive_timeouts"`
	Replaced          int64                   `json:"replaced"`
	// BoxInline counts box.changed events that carried the item inline;
	// BoxInlineSkipped counts opted-in peers that got a plain wake-up instead
	// (item too large for the frame, blob unreadable, or send queue pressure).
	BoxInline        int64       `json:"box_inline"`
	BoxInlineSkipped int64       `json:"box_inline_skipped"`
	StreamFrames     int64       `json:"stream_frames"`
	StreamBytes      int64       `json:"stream_bytes"`
	StreamDrops      int64       `json:"stream_drops"`
	Recent           []ConnEvent `json:"recent"` // newest first, at most 30
}

func NewMetrics() *Metrics {
	return &Metrics{
		start:   time.Now(),
		edge:    map[string]*EdgeCounter{},
		spaces:  map[string]*SpaceCounter{},
		devices: map[string]*DeviceConn{},
		events:  make([]ConnEvent, connEventRing),
	}
}

// Edge records one edge request. key is "plugin/mount".
func (m *Metrics) Edge(key string, status int) {
	if m == nil {
		return
	}
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.edge[key]
	if c == nil {
		if len(m.edge) >= maxEdgeKeys {
			key = edgeOverflowKey
			c = m.edge[key]
		}
		if c == nil {
			c = &EdgeCounter{}
			m.edge[key] = c
		}
	}
	c.Requests++
	c.LastAt, c.LastStatus = now, status
	switch {
	case status < 400:
		c.OK++
		return
	case status == 401 || status == 403 || status == 429:
		c.Rejected++
	case status < 500:
		c.ClientErr++
	default:
		c.ServerErr++
	}
	c.LastErrAt = now
}

// Inline records one box.changed delivery to an inline-capable peer.
func (m *Metrics) Inline(sent bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if sent {
		m.boxInline++
	} else {
		m.boxInlineSkipped++
	}
}

func (m *Metrics) spaceLocked(spaceID string) *SpaceCounter {
	if spaceID == "" {
		spaceID = spaceOverflowKey
	}
	c := m.spaces[spaceID]
	if c == nil {
		if len(m.spaces) >= maxSpaceKeys {
			spaceID = spaceOverflowKey
			c = m.spaces[spaceID]
		}
		if c == nil {
			c = &SpaceCounter{}
			m.spaces[spaceID] = c
		}
	}
	return c
}

// SpaceMsg records one Pipe message routed within spaceID.
func (m *Metrics) SpaceMsg(spaceID string, offline bool) {
	if m == nil {
		return
	}
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.spaceLocked(spaceID)
	if offline {
		c.MessagesOffline++
	} else {
		c.MessagesOnline++
	}
	c.LastAt = now
}

// StreamFrame records one forwarded binary stream frame.
func (m *Metrics) StreamFrame(spaceID string, n int64) {
	if m == nil {
		return
	}
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamFrames++
	m.streamBytes += n
	c := m.spaceLocked(spaceID)
	c.StreamFrames++
	c.StreamBytes += n
	c.LastAt = now
}

// StreamDrop records one binary stream frame dropped under backpressure.
func (m *Metrics) StreamDrop(spaceID string) {
	if m == nil {
		return
	}
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamDrops++
	c := m.spaceLocked(spaceID)
	c.StreamDrops++
	c.LastAt = now
}

// Connect records a new /v2/ws session.
func (m *Metrics) Connect(device string) {
	if m == nil {
		return
	}
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.device(device)
	d.Online = true
	d.Connects++
	d.LastConnect = now
	m.push(ConnEvent{Device: device, At: now, Kind: "connect"})
}

// Disconnect records the end of a session. stillOnline is true when a newer
// session of the same device replaced this one.
func (m *Metrics) Disconnect(device, reason string, since time.Time, stillOnline bool) {
	if m == nil {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.device(device)
	d.Online = stillOnline
	d.Disconnects++
	d.LastDisconnect, d.LastReason = now.Unix(), reason
	switch reason {
	case "keepalive_timeout":
		m.keepaliveTimeouts++
	case "replaced":
		m.replaced++
	}
	m.push(ConnEvent{Device: device, At: now.Unix(), Kind: "disconnect", Reason: reason, Duration: int64(now.Sub(since).Seconds())})
}

func (m *Metrics) device(id string) *DeviceConn {
	d := m.devices[id]
	if d == nil {
		d = &DeviceConn{}
		m.devices[id] = d
	}
	return d
}

func (m *Metrics) push(ev ConnEvent) {
	m.events[m.next] = ev
	m.next = (m.next + 1) % len(m.events)
	if m.next == 0 {
		m.full = true
	}
}

// Snapshot copies the current counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := MetricsSnapshot{
		StartedAt: m.start.Unix(), UptimeSeconds: int64(now.Sub(m.start).Seconds()),
		Edge: make(map[string]EdgeCounter, len(m.edge)), Spaces: make(map[string]SpaceCounter, len(m.spaces)),
		Devices:           make(map[string]DeviceConn, len(m.devices)),
		KeepaliveTimeouts: m.keepaliveTimeouts, Replaced: m.replaced,
		BoxInline: m.boxInline, BoxInlineSkipped: m.boxInlineSkipped,
		StreamFrames: m.streamFrames, StreamBytes: m.streamBytes, StreamDrops: m.streamDrops,
	}
	for k, v := range m.edge {
		out.Edge[k] = *v
	}
	for k, v := range m.spaces {
		out.Spaces[k] = *v
	}
	n := m.next
	if m.full {
		n = len(m.events)
	}
	evs := make([]ConnEvent, 0, n)
	for i := 0; i < n; i++ {
		evs = append(evs, m.events[(m.next-1-i+len(m.events))%len(m.events)])
	}
	cut := now.Add(-24 * time.Hour).Unix()
	per24 := map[string]int64{}
	for _, ev := range evs {
		if ev.Kind == "disconnect" && ev.At >= cut && ev.Reason != "replaced" {
			per24[ev.Device]++
		}
	}
	for k, v := range m.devices {
		d := *v
		d.Disconnects24h = per24[k]
		out.Devices[k] = d
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].At > evs[j].At })
	if len(evs) > 30 {
		evs = evs[:30]
	}
	out.Recent = evs
	return out
}

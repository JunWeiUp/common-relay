package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Peer is untrusted discovery information, never an update to Identity's pinned keys.
type Peer struct {
	App       string `json:"app"`
	Group     string `json:"group"`
	Device    string `json:"device"`
	PublicKey string `json:"public_key"`
}

type Event struct {
	Type     string `json:"type"`
	ID       string `json:"id,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Body     string `json:"body,omitempty"`
	Offline  bool   `json:"offline,omitempty"`
	TTL      int64  `json:"ttl,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
	Sequence uint64 `json:"sequence,omitempty"`
	Code     string `json:"code,omitempty"`
	Version  int    `json:"version,omitempty"`
	Identity *Peer  `json:"identity,omitempty"`
	Devices  []Peer `json:"devices,omitempty"`
	Revision int    `json:"revision,omitempty"`
	Device   string `json:"device,omitempty"`
	Data     []byte `json:"-"` // Authenticated plaintext, only populated for messages.
}

type Options struct{ AllowLocalTest bool }
type reply struct {
	event Event
	err   error
}
type pending struct {
	expected []string
	result   chan reply
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

// Client owns one connection. Reconnect explicitly; online messages and streams are never replayed.
type Client struct {
	identity *Identity
	journal  *Journal
	scope    string
	conn     *websocket.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	events   chan Event
	mu       sync.Mutex
	failure  error
	pending  map[string]pending
	streams  map[string]*Stream
}

// Dial's context covers the handshake. Close owns the subsequent connection lifetime.
// Without a journal, offline sends fail and offline receipt closes the connection.
func Dial(ctx context.Context, endpoint, token string, identity *Identity, options Options) (*Client, error) {
	return DialJournal(ctx, endpoint, token, identity, nil, options)
}

// DialJournal connects with durable offline state. The journal must stay open until
// the client is closed; reconnect with the same journal (one owner per directory).
// While connected the journal is cleaned hourly; a cleanup failure closes the client.
func DialJournal(ctx context.Context, endpoint, token string, identity *Identity, journal *Journal, options Options) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("invalid relay endpoint")
	}
	local := options.AllowLocalTest && u.Scheme == "ws" && u.Hostname() == "127.0.0.1"
	if identity == nil || (u.Scheme != "wss" && !local) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/relay/v1/ws" {
		return nil, errors.New("a WSS relay endpoint and identity are required")
	}
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("invalid device credential")
	}
	dialCtx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("relay redirects forbidden") }}
	conn, response, err := websocket.Dial(dialCtx, endpoint, &websocket.DialOptions{
		HTTPClient: httpClient, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
		Subprotocols: []string{"common-relay.v1"}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, errors.New("relay handshake failed")
	}
	valid := false
	defer func() {
		if !valid {
			conn.CloseNow()
		}
	}()
	if conn.Subprotocol() != "common-relay.v1" {
		return nil, errors.New("protocol mismatch")
	}
	conn.SetReadLimit(1 << 20)
	kind, raw, err := conn.Read(dialCtx)
	if err != nil {
		return nil, errors.New("welcome read failed")
	}
	var welcome Event
	if kind != websocket.MessageText || json.Unmarshal(raw, &welcome) != nil || welcome.Type != "welcome" || welcome.Version != 1 || welcome.Identity == nil {
		return nil, errors.New("invalid welcome")
	}
	own := welcome.Identity
	if own.App != identity.app || own.Group != identity.group || own.Device != identity.device || own.PublicKey != identity.public {
		return nil, errors.New("welcome identity mismatch")
	}
	scope, _ := json.Marshal([]string{identity.app, identity.group, identity.device})
	lifetime, cancel := context.WithCancel(context.Background())
	c := &Client{identity: identity, journal: journal, scope: string(scope), conn: conn, ctx: lifetime, cancel: cancel, done: make(chan struct{}), events: make(chan Event, 64), pending: make(map[string]pending), streams: make(map[string]*Stream)}
	valid = true
	go c.readLoop()
	if journal != nil {
		go c.cleanupLoop()
	}
	return c, nil
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.failure != nil {
		c.mu.Unlock()
		return
	}
	c.failure = err
	close(c.done)
	streams := c.streams
	c.streams = map[string]*Stream{}
	c.mu.Unlock()
	for _, s := range streams {
		s.abort(errors.New("stream interrupted; do not replay operations"))
	}
	c.cancel()
	c.conn.CloseNow()
}

// Close ends the connection and its streams. It does not close the journal.
func (c *Client) Close() error { c.fail(errors.New("client closed")); return nil }
func (c *Client) Err() error   { c.mu.Lock(); defer c.mu.Unlock(); return c.failure }

// Cleanup runs one bounded journal cleanup round (no-op without a journal).
func (c *Client) Cleanup() error {
	if c.journal == nil {
		return nil
	}
	return c.journal.Cleanup()
}

func (c *Client) cleanupLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			// Never keep acknowledging when durable state can no longer be maintained.
			if err := c.journal.Cleanup(); err != nil {
				c.fail(fmt.Errorf("journal cleanup failed: %w", err))
				return
			}
		}
	}
}

func (c *Client) now() int64 {
	if c.journal != nil {
		return c.journal.clock()
	}
	return time.Now().Unix()
}

// write uses the connection lifetime so caller cancellation never tears a frame.
func (c *Client) write(kind websocket.MessageType, data []byte) error {
	if err := c.Err(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(c.ctx, 45*time.Second)
	defer cancel()
	if err := c.conn.Write(bounded, kind, data); err != nil {
		c.fail(errors.New("relay write failed"))
		return c.Err()
	}
	return nil
}

func (c *Client) send(_ context.Context, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return c.write(websocket.MessageText, data)
}

func newID() (string, error) {
	var data [16]byte
	_, err := rand.Read(data[:])
	return hex.EncodeToString(data[:]), err
}

// NewMessageID returns a random object ID. Persist it to retry one logical offline send.
func NewMessageID() (string, error) { return newID() }

func (c *Client) request(ctx context.Context, event Event, expected ...string) (Event, error) {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	result := make(chan reply, 1)
	c.mu.Lock()
	if c.failure != nil {
		err := c.failure
		c.mu.Unlock()
		return Event{}, err
	}
	if len(c.pending) >= 64 {
		c.mu.Unlock()
		return Event{}, errors.New("too many pending requests")
	}
	if _, ok := c.pending[event.ID]; ok {
		c.mu.Unlock()
		return Event{}, errors.New("request already pending")
	}
	c.pending[event.ID] = pending{expected, result}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, event.ID); c.mu.Unlock() }()
	if err := c.send(bounded, event); err != nil {
		return Event{}, err
	}
	select {
	case r := <-result:
		return r.event, r.err
	case <-bounded.Done():
		return Event{}, bounded.Err()
	case <-c.done:
		return Event{}, c.Err()
	}
}

func (c *Client) Peers(ctx context.Context) ([]Peer, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	event, err := c.request(ctx, Event{Type: "peers", ID: id}, "peers")
	if err != nil {
		return nil, err
	}
	for _, p := range event.Devices {
		if p.App != c.identity.app || p.Group != c.identity.group || !namePattern.MatchString(p.Device) || !keyPattern.MatchString(p.PublicKey) {
			return nil, errors.New("invalid peer scope")
		}
	}
	return event.Devices, nil
}

// Message sends online-only data. Forwarded is a relay queue receipt, not peer delivery.
// Cancellation can stop waiting but cannot undo a message already sent.
func (c *Client) Message(ctx context.Context, to string, data []byte) (Event, error) {
	id, err := newID()
	if err != nil {
		return Event{}, err
	}
	body, err := c.identity.SealMessage(to, id, data)
	if err != nil {
		return Event{}, err
	}
	return c.request(ctx, Event{Type: "message", ID: id, To: to, Body: body}, "forwarded")
}

// MessageOffline sends at-least-once data valid for 24 hours. See MessageOfflineTTL.
func (c *Client) MessageOffline(ctx context.Context, to, id string, data []byte) (Event, error) {
	return c.MessageOfflineTTL(ctx, to, id, data, 24*time.Hour)
}

// MessageOfflineTTL requires a journal. The recipient, content digest, ciphertext and
// fixed absolute expiry (1s..24h, also authenticated in the envelope) are persisted
// before sending. Retry a logical send with the same id: the original ciphertext and
// expiry are reused, a different recipient or content is rejected, and an expired
// message fails instead of being renewed. "stored" means the relay holds it (the
// journal keeps the ciphertext); "received" means the recipient acknowledged it.
func (c *Client) MessageOfflineTTL(ctx context.Context, to, id string, data []byte, ttl time.Duration) (Event, error) {
	if c.journal == nil {
		return Event{}, errors.New("persistent journal required for offline delivery")
	}
	if !objectID.MatchString(id) {
		return Event{}, errors.New("invalid message ID")
	}
	if ttl%time.Second != 0 {
		return Event{}, errors.New("TTL must be whole seconds")
	}
	body, expires, err := c.journal.prepare(c.scope, id, to, data, int64(ttl/time.Second), func(expires int64) (string, error) {
		return c.identity.sealMessage(to, id, data, expires)
	})
	if err != nil {
		return Event{}, err
	}
	if body == "" {
		return Event{Type: "received", ID: id}, nil
	}
	result, err := c.request(ctx, Event{Type: "message", ID: id, To: to, Body: body, Offline: true, Expires: expires}, "stored", "received")
	if err != nil {
		return Event{}, err
	}
	if result.Type == "received" {
		if err = c.journal.complete(c.scope, id); err != nil {
			return Event{}, err
		}
	}
	return result, nil
}

// Acknowledge must be called only after the application durably processed event.
// With a journal the dedupe record is persisted first; offline messages are then
// ACKed so the relay stops redelivering. A redelivery after a lost ACK is re-ACKed
// automatically and not delivered again within 7 days.
func (c *Client) Acknowledge(ctx context.Context, event Event) error {
	if event.Type != "message" || !objectID.MatchString(event.ID) || !namePattern.MatchString(event.From) {
		return errors.New("only received messages can be acknowledged")
	}
	if event.Offline && c.journal == nil {
		return errors.New("persistent journal required for offline acknowledgment")
	}
	if c.journal != nil {
		if err := c.journal.acknowledge(c.scope, event.From, event.ID); err != nil {
			return err
		}
	}
	if !event.Offline {
		return nil
	}
	_, err := c.request(ctx, Event{Type: "ack", ID: event.ID, From: event.From}, "acked")
	return err
}

// NextEvent receives authenticated messages, stream.open requests (accept with
// AcceptStream or decline with RejectStream) and untrusted presence/group.changed notices.
// Queue capacity is 64; a slow consumer closes the connection rather than losing data.
func (c *Client) NextEvent(ctx context.Context) (Event, error) {
	if err := c.Err(); err != nil {
		return Event{}, err
	}
	select {
	case event := <-c.events:
		if err := c.Err(); err != nil {
			return Event{}, err
		}
		return event, nil
	case <-ctx.Done():
		return Event{}, ctx.Err()
	case <-c.done:
		return Event{}, c.Err()
	}
}

func (c *Client) resolve(id string, r reply) bool {
	c.mu.Lock()
	p, ok := c.pending[id]
	c.mu.Unlock()
	if !ok {
		return false
	}
	if r.err == nil && r.event.Type == "error" {
		r.err = fmt.Errorf("relay error: %s", r.event.Code)
	} else if r.err == nil && !slices.Contains(p.expected, r.event.Type) {
		r.err = errors.New("unexpected reply type")
	}
	select {
	case p.result <- r:
	default:
	}
	return true
}

func (c *Client) readLoop() {
	for {
		kind, raw, err := c.conn.Read(c.ctx)
		if err != nil {
			c.fail(errors.New("relay connection closed"))
			return
		}
		if kind == websocket.MessageBinary {
			if err = c.dispatchFrame(raw); err != nil {
				c.fail(err)
				return
			}
			continue
		}
		var e Event
		if kind != websocket.MessageText || json.Unmarshal(raw, &e) != nil {
			c.fail(errors.New("invalid relay frame"))
			return
		}
		switch e.Type {
		case "welcome":
			c.fail(errors.New("repeated welcome"))
			return
		case "stream.credit":
			if s := c.stream(e.ID); s != nil {
				if err = s.credit(e.Sequence); err != nil {
					c.fail(err)
					return
				}
			}
			continue
		case "stream.close":
			if s := c.removeStream(e.ID); s != nil {
				s.abort(errors.New("stream closed by peer or relay"))
			}
			c.resolve(e.ID, reply{err: errors.New("stream closed")})
			continue
		case "stream.open":
			if !objectID.MatchString(e.ID) || !namePattern.MatchString(e.From) || e.Body == "" {
				c.fail(errors.New("invalid stream request"))
				return
			}
		case "message":
			if e.Offline && c.journal == nil {
				c.fail(errors.New("offline reception requires a persistent journal"))
				return
			}
			deliver, err := c.receiveMessage(&e)
			if err != nil {
				c.fail(err)
				return
			}
			if !deliver {
				continue
			}
		case "peer.up", "peer.down", "group.changed":
		default:
			c.resolve(e.ID, reply{event: e})
			continue
		}
		select {
		case c.events <- e:
		default:
			c.fail(errors.New("event receive overflow"))
			return
		}
	}
}

// receiveMessage authenticates e; expired or already acknowledged messages are
// re-ACKed (offline) and not delivered to the application again.
func (c *Client) receiveMessage(e *Event) (bool, error) {
	data, expires, err := c.identity.openMessage(e.From, e.ID, e.Body)
	if err != nil {
		return false, err
	}
	duplicate := false
	if c.journal != nil {
		if duplicate, err = c.journal.contains(c.scope, e.From, e.ID); err != nil {
			return false, err
		}
	}
	if duplicate || (expires != 0 && expires <= c.now()) {
		if e.Offline {
			return false, c.send(c.ctx, Event{Type: "ack", ID: e.ID, From: e.From})
		}
		return false, nil
	}
	e.Data, e.Body, e.Expires = data, "", expires
	return true, nil
}

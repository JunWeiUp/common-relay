package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"github.com/coder/websocket"
)

const (
	streamWindow     = 8  // Unconsumed records per direction allowed by the relay.
	streamQueueLimit = 16 // Local receive buffer; a peer exceeding it is cut off.
)

type streamFrame struct {
	sequence uint64
	data     []byte
}

// Stream is one end-to-end encrypted bidirectional relay stream. Send and Receive
// may run concurrently with each other, but not with themselves. A stream is never
// resumed or replayed: Close, disconnect or an invalid record terminates it. Use a
// final record (Send with final=true, ReceivedFinal) for an authenticated complete end.
type Stream struct {
	client   *Client
	peer, id string
	push     *secretStreamPush
	pull     *secretStreamPull

	mu       sync.Mutex
	tx       uint64 // Records sent.
	acked    uint64 // Records the peer has consumed.
	failure  error
	done     chan struct{}
	credited chan struct{}
	incoming chan streamFrame

	sendMu    sync.Mutex
	sentFinal bool
	receiveMu sync.Mutex
	rx        uint64
}

func newStream(c *Client, peer, id string, push *secretStreamPush) *Stream {
	return &Stream{client: c, peer: peer, id: id, push: push, done: make(chan struct{}), credited: make(chan struct{}, 1), incoming: make(chan streamFrame, streamQueueLimit)}
}

func (s *Stream) ID() string   { return s.id }
func (s *Stream) Peer() string { return s.peer }

// Err reports why the stream ended, or nil while it is open.
func (s *Stream) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.failure }

// abort ends the stream locally; it reports whether this call ended it.
func (s *Stream) abort(err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return false
	}
	s.failure = err
	close(s.done)
	return true
}

func (s *Stream) credit(sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence < s.acked || sequence > s.tx {
		return errors.New("invalid stream credit")
	}
	s.acked = sequence
	select {
	case s.credited <- struct{}{}:
	default:
	}
	return nil
}

// Send encrypts data as records of at most 65519 bytes, pausing while 8 records
// are unconsumed. final marks the last record with the secretstream FINAL tag;
// an empty data slice still sends one record. Cancellation is not a half-close:
// part of data may already have been sent.
func (s *Stream) Send(ctx context.Context, data []byte, final bool) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sentFinal {
		return errors.New("stream already finished")
	}
	for offset := 0; ; {
		end := min(offset+streamRecordPlain, len(data))
		sequence, err := s.reserve(ctx)
		if err != nil {
			return err
		}
		last := final && end == len(data)
		tag := byte(secretStreamTagMessage)
		if last {
			tag = secretStreamTagFinal
		}
		me := s.client.identity.device
		cipher, err := s.push.push(data[offset:end], s.client.identity.streamAAD(me, s.peer, "stream", s.id, sequence), tag)
		if err != nil {
			s.terminate(err)
			return err
		}
		frame := make([]byte, 25+len(cipher))
		frame[0] = 1
		hex.Decode(frame[1:17], []byte(s.id))
		binary.BigEndian.PutUint64(frame[17:25], sequence)
		copy(frame[25:], cipher)
		if err = s.client.write(websocket.MessageBinary, frame); err != nil {
			return err
		}
		s.sentFinal = last
		offset = end
		if offset >= len(data) {
			return nil
		}
	}
}

// reserve waits for credit and claims the next sequence number before writing,
// so a credit for this record can never exceed the local sent count.
func (s *Stream) reserve(ctx context.Context) (uint64, error) {
	for {
		s.mu.Lock()
		if s.failure != nil {
			err := s.failure
			s.mu.Unlock()
			return 0, err
		}
		if s.tx-s.acked < streamWindow {
			sequence := s.tx
			s.tx++
			s.mu.Unlock()
			return sequence, nil
		}
		s.mu.Unlock()
		select {
		case <-s.credited:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
		}
	}
}

func (s *Stream) enqueue(frame streamFrame) bool {
	select {
	case <-s.done:
		return true // Dropped: the stream already ended.
	default:
	}
	select {
	case s.incoming <- frame:
		return true
	default:
		return false
	}
}

// Receive returns the next authenticated record in order, then grants the sender
// one credit. After the FINAL record it returns io.EOF; any later record is an error.
func (s *Stream) Receive(ctx context.Context) ([]byte, error) {
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if err := s.Err(); err != nil {
		return nil, err
	}
	if s.pull.finished {
		select {
		case <-s.incoming:
			err := errors.New("data after final record")
			s.terminate(err)
			return nil, err
		default:
			return nil, io.EOF
		}
	}
	var frame streamFrame
	select {
	case frame = <-s.incoming:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.Err()
	}
	if frame.sequence != s.rx {
		err := errors.New("invalid stream sequence")
		s.terminate(err)
		return nil, err
	}
	plain, err := s.pull.pull(frame.data, s.client.identity.streamAAD(s.peer, s.client.identity.device, "stream", s.id, s.rx))
	if err != nil {
		s.terminate(err)
		return nil, err
	}
	s.rx++
	if err = s.client.send(ctx, Event{Type: "stream.credit", ID: s.id, Sequence: s.rx}); err != nil {
		return nil, err
	}
	return plain, nil
}

// ReceivedFinal reports whether the authenticated FINAL record was received.
func (s *Stream) ReceivedFinal() bool {
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	return s.pull != nil && s.pull.finished
}

// terminate ends the stream locally and tells the relay, which notifies the peer.
func (s *Stream) terminate(err error) {
	if s.abort(err) {
		s.client.removeStream(s.id)
		s.client.send(s.client.ctx, Event{Type: "stream.close", ID: s.id})
	}
}

// Close terminates the stream for both ends. It is not a graceful half-close.
func (s *Stream) Close() error {
	if !s.abort(errors.New("stream closed")) {
		return nil
	}
	s.client.removeStream(s.id)
	if s.client.Err() != nil {
		return nil
	}
	return s.client.send(s.client.ctx, Event{Type: "stream.close", ID: s.id})
}

func (c *Client) stream(id string) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *Client) addStream(s *Stream) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	if _, ok := c.streams[s.id]; ok {
		return errors.New("stream ID already in use")
	}
	c.streams[s.id] = s
	return nil
}

func (c *Client) removeStream(id string) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.streams[id]
	delete(c.streams, id)
	return s
}

func (c *Client) dispatchFrame(raw []byte) error {
	if len(raw) < 25+secretStreamABytes || len(raw) > 25+streamRecordPlain+secretStreamABytes || raw[0] != 1 {
		return errors.New("invalid binary frame")
	}
	id := hex.EncodeToString(raw[1:17])
	s := c.stream(id)
	if s == nil {
		return nil // Late frame for a stream that already ended.
	}
	if !s.enqueue(streamFrame{binary.BigEndian.Uint64(raw[17:25]), raw[25:]}) {
		s.terminate(errors.New("stream receive overflow"))
	}
	return nil
}

// OpenStream asks a pinned peer for a stream and waits for its acceptance.
func (c *Client) OpenStream(ctx context.Context, to string) (*Stream, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	push, err := newSecretStreamPush()
	if err != nil {
		return nil, err
	}
	body, err := c.identity.sealEnvelope(to, "stream.open", id, push.descriptor())
	if err != nil {
		return nil, err
	}
	s := newStream(c, to, id, push)
	if err = c.addStream(s); err != nil {
		return nil, err
	}
	fail := func(err error) (*Stream, error) {
		if s.abort(err) {
			c.removeStream(id)
			c.send(c.ctx, Event{Type: "stream.close", ID: id})
		}
		return nil, err
	}
	result, err := c.request(ctx, Event{Type: "stream.open", ID: id, To: to, Body: body}, "stream.accept")
	if err != nil {
		return fail(err)
	}
	if result.From != "" && result.From != to {
		return fail(errors.New("stream accepted by unexpected device"))
	}
	var descriptor streamDescriptor
	if err = c.identity.openEnvelope(to, "stream.accept", id, result.Body, &descriptor); err != nil {
		return fail(err)
	}
	if s.pull, err = newSecretStreamPull(descriptor); err != nil {
		return fail(err)
	}
	return s, nil
}

// AcceptStream accepts a stream.open event returned by NextEvent.
func (c *Client) AcceptStream(ctx context.Context, event Event) (*Stream, error) {
	if event.Type != "stream.open" {
		return nil, errors.New("not a stream request")
	}
	var descriptor streamDescriptor
	if err := c.identity.openEnvelope(event.From, "stream.open", event.ID, event.Body, &descriptor); err != nil {
		return nil, err
	}
	pull, err := newSecretStreamPull(descriptor)
	if err != nil {
		return nil, err
	}
	push, err := newSecretStreamPush()
	if err != nil {
		return nil, err
	}
	body, err := c.identity.sealEnvelope(event.From, "stream.accept", event.ID, push.descriptor())
	if err != nil {
		return nil, err
	}
	s := newStream(c, event.From, event.ID, push)
	s.pull = pull
	if err = c.addStream(s); err != nil {
		return nil, err
	}
	if _, err = c.request(ctx, Event{Type: "stream.accept", ID: event.ID, Body: body}, "stream.ready"); err != nil {
		if s.abort(err) {
			c.removeStream(event.ID)
			c.send(c.ctx, Event{Type: "stream.close", ID: event.ID})
		}
		return nil, err
	}
	return s, nil
}

// RejectStream declines a stream.open event instead of letting it time out.
func (c *Client) RejectStream(ctx context.Context, event Event) error {
	if event.Type != "stream.open" || !objectID.MatchString(event.ID) {
		return errors.New("not a stream request")
	}
	return c.send(ctx, Event{Type: "stream.close", ID: event.ID})
}

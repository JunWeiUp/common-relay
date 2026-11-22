package v2client

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// BoxItemHandler processes one downloaded item from a queue/ephemeral Box.
// Returning nil causes the Hub to ACK and delete the item from the server.
type BoxItemHandler func(ctx context.Context, item BoxItem, data []byte) error

// ObjectChangeHandler is called whenever an object-mode Box publishes a new version.
type ObjectChangeHandler func(ctx context.Context, spaceID, boxName, key string, version int64)

// RPCHandler answers synchronous RPC requests forwarded over /v2/ws (e.g. mcpedge).
type RPCHandler func(ctx context.Context, payload string) (string, error)

type boxSub struct {
	space   string
	box     string
	handler BoxItemHandler
	lastSeq int64
}

type objSub struct {
	space   string
	box     string
	handler ObjectChangeHandler
}

// Hub maintains a single persistent /v2/ws connection for a device (e.g. hub-daemon
// Hub), combining real-time box.changed wake-ups with cursor-based catch-up
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

func (h *Hub) runOnce(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, _, err := websocket.Dial(dialCtx, h.client.WSURL(), &websocket.DialOptions{
		HTTPHeader: h.client.authHeaders(),
	})
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()

	h.mu.Lock()
	h.connected = true
	h.lastErr = ""
	h.mu.Unlock()

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
				pctx, pcancel := context.WithTimeout(connCtx, every/2+5*time.Second)
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

	for {
		kind, data, err := conn.Read(connCtx)
		if err != nil {
			select {
			case perr := <-pingErr:
				return errors.New("keepalive: " + perr.Error())
			default:
			}
			return err
		}
		if err != nil {
			return err
		}
		if kind != websocket.MessageText {
			continue
		}
		var ev PipeEvent
		if json.Unmarshal(data, &ev) != nil {
			continue
		}
		if ev.Type == "box.changed" {
			h.handleBoxChanged(ctx, ev)
		} else if ev.Type == "rpc.req" {
			go h.handleRPCReq(ctx, conn, ev)
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
		h.drainBox(ctx, bs)
	}
	if osub != nil && ev.Event == "object" {
		osub.handler(ctx, ev.Space, ev.Box, ev.Ref, ev.Seq)
	}
}

func (h *Hub) drainBox(ctx context.Context, s *boxSub) {
	for {
		items, err := h.client.ListBoxItems(ctx, s.space, s.box, s.lastSeq, 100)
		if err != nil || len(items) == 0 {
			return
		}
		for _, it := range items {
			data, err := h.client.DownloadBoxItem(ctx, s.space, s.box, it.ID)
			if err != nil {
				return
			}
			if err := s.handler(ctx, it, data); err != nil {
				return
			}
			if err := h.client.AckBoxItem(ctx, s.space, s.box, it.ID); err != nil {
				return
			}
			s.lastSeq = it.Seq
		}
	}
}

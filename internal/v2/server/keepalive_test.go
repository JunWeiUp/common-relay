package server_test

import (
	"context"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
)

// idleProxy mimics nginx proxy_read_timeout: it drops a connection when the
// upstream (relay) has sent nothing to the client for longer than idle.
type idleProxy struct {
	ln       net.Listener
	accepted atomic.Int32
}

func newIdleProxy(t *testing.T, upstream string, idle time.Duration) *idleProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &idleProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.accepted.Add(1)
			go p.pipe(c, upstream, idle)
		}
	}()
	return p
}

func (p *idleProxy) pipe(c net.Conn, upstream string, idle time.Duration) {
	u, err := net.Dial("tcp", upstream)
	if err != nil {
		_ = c.Close()
		return
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var once sync.Once
	closeAll := func() { once.Do(func() { _ = c.Close(); _ = u.Close() }) }
	go func() { _, _ = io.Copy(u, c); closeAll() }()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := u.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if _, werr := c.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		closeAll()
	}()
	for {
		time.Sleep(idle / 5)
		if time.Since(time.Unix(0, last.Load())) > idle {
			closeAll()
			return
		}
	}
}

func TestPipeKeepaliveSurvivesIdleProxy(t *testing.T) {
	cases := []struct {
		name          string
		server, hub   time.Duration
		wantReconnect bool
	}{
		{"server pings keep idle peers alive", 100 * time.Millisecond, time.Hour, false},
		{"hub pings keep the connection alive", time.Hour, 100 * time.Millisecond, false},
		{"without keepalive the proxy drops it (control)", time.Hour, time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.srv.Pipe.Keepalive = tc.server
			ctx := context.Background()
			admin, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true})
			if err != nil {
				t.Fatal(err)
			}
			_, tok, err := admin.CreateDevice(ctx, "desk", "Desk", strings.Repeat("cd", 32), true)
			if err != nil {
				t.Fatal(err)
			}
			up, _ := url.Parse(e.ts.URL)
			proxy := newIdleProxy(t, up.Host, 300*time.Millisecond)
			c, err := v2client.New(v2client.Config{BaseURL: "http://" + proxy.ln.Addr().String(), AccessPassword: e.access, Token: tok, AllowLocal: true})
			if err != nil {
				t.Fatal(err)
			}
			hub := v2client.NewHub(c)
			hub.Keepalive = tc.hub
			hub.Start(ctx)
			defer hub.Close()

			time.Sleep(1500 * time.Millisecond) // five idle windows
			reconnected := proxy.accepted.Load() > 1
			if reconnected != tc.wantReconnect {
				t.Fatalf("connections through proxy = %d, wantReconnect=%v", proxy.accepted.Load(), tc.wantReconnect)
			}
		})
	}
}

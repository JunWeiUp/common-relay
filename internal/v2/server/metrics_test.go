package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAdminMetricsCountEdgeOutcomesAndDisconnectReasons(t *testing.T) {
	e := newEnv(t)
	seedPersonal(t, e)
	e.srv.Pipe.Keepalive = 100 * time.Millisecond
	ctx := context.Background()
	admin, err := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("m", 40)
	if _, err := admin.UpsertPlugin(ctx, "drop", "inbox", "personal", "", map[string]any{"token": token}, true); err != nil {
		t.Fatal(err)
	}
	post := func(mount, tok string) int {
		req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/edge/drop/"+mount, strings.NewReader("hi"))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "text/plain")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if post("inbox", token) >= 300 || post("inbox", "wrong") != 401 {
		t.Fatal("unexpected drop responses")
	}

	_, devTok, err := admin.CreateDevice(ctx, "phone", "Phone", strings.Repeat("ef", 32), false)
	if err != nil {
		t.Fatal(err)
	}
	dial := func() *websocket.Conn {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+devTok)
		h.Set("Relay-Access", e.access)
		c, _, err := websocket.Dial(ctx, strings.Replace(e.ts.URL, "http", "ws", 1)+"/v2/ws", &websocket.DialOptions{HTTPHeader: h})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	m := func() v2client.Metrics {
		got, err := admin.Metrics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// 1) Client closes cleanly.
	c1 := dial()
	waitFor(t, "connect", func() bool { return m().Devices["phone"].Online })
	_ = c1.Close(websocket.StatusNormalClosure, "")
	waitFor(t, "client_closed", func() bool { return m().Devices["phone"].LastReason == "client_closed" })

	// 2) A second session replaces the first.
	c2 := dial()
	go func() { _, _, _ = c2.Read(ctx) }() // answer pings
	waitFor(t, "second connect", func() bool { return m().Devices["phone"].Connects == 2 })
	c3 := dial()
	waitFor(t, "replaced", func() bool { return m().Replaced == 1 && m().Devices["phone"].Online })

	// 3) A peer that never reads cannot answer pings and is reaped.
	waitFor(t, "keepalive_timeout", func() bool { return m().KeepaliveTimeouts >= 1 })
	_ = c3.CloseNow()
	_ = c2.CloseNow()

	got := m()
	if got.V1 != nil {
		t.Fatalf("a bare v2 server reports no v1 usage: %+v", got.V1)
	}
	drop := got.Edge["drop/inbox"]
	if drop.Requests != 2 || drop.OK != 1 || drop.Rejected != 1 || drop.LastErrAt == 0 {
		t.Fatalf("edge counters = %+v", drop)
	}
	ph := got.Devices["phone"]
	if ph.Disconnects < 3 || ph.Disconnects24h < 2 || got.StartedAt == 0 || len(got.Recent) == 0 {
		t.Fatalf("device metrics = %+v (recent %d)", ph, len(got.Recent))
	}
	if got.Recent[0].At < got.Recent[len(got.Recent)-1].At {
		t.Fatal("recent events must be newest first")
	}
}

func TestEdgeMetricKeysAreBounded(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 400; i++ {
		res, err := http.Get(e.ts.URL + "/edge/drop/random-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26)))
		if err == nil {
			res.Body.Close()
		}
	}
	admin, _ := v2client.New(v2client.Config{BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true})
	got, err := admin.Metrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Edge) > 257 || got.Edge["*/other"].Requests == 0 {
		t.Fatalf("edge keys = %d, overflow = %+v", len(got.Edge), got.Edge["*/other"])
	}
}

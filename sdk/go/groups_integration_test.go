package relay

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGroupsLoopback(t *testing.T) {
	binary, err := filepath.Abs("../../build/common-relay")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(binary); err != nil {
		t.Skip("prebuilt relay unavailable")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	cmd := exec.Command(binary, "serve", "--data", t.TempDir(), "--listen", address, "--disk-reserve", "0", "--self-service-apps", "example")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	base := "http://" + address
	ready := false
	for i := 0; i < 100; i++ {
		r, e := http.Get(base + "/health")
		if e == nil {
			_ = r.Body.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server failed to start")
	}
	secret, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	config := &GroupConfig{URL: "ws://" + address + "/relay/v1/ws", App: "example", Device: "one", SecretKey: secret}
	g, err := NewGroups(config, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewGroups(config, false); err == nil {
		t.Fatal("insecure URL accepted")
	}
	if err = g.PrepareCreate("Devices", "One"); err != nil {
		t.Fatal(err)
	}
	if err = g.Create(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"manual", "auto"} {
		t.Run(mode, func(t *testing.T) {
			inv, e := g.Invite(mode, true)
			if e != nil {
				t.Fatal(e)
			}
			secret, _, e := GenerateKeyPair()
			if e != nil {
				t.Fatal(e)
			}
			c := &GroupConfig{URL: config.URL, App: config.App, Group: config.Group, Device: fmt.Sprintf("peer-%s", mode), SecretKey: secret}
			peer, e := NewGroups(c, true)
			if e != nil {
				t.Fatal(e)
			}
			resolved, e := peer.ResolveInvitation(inv.ShortLink)
			if e != nil {
				t.Fatal(e)
			}
			if e = peer.Join(resolved, "Peer"); e != nil {
				t.Fatal(e)
			}
			if mode == "manual" {
				req, e := g.Pending(inv)
				if e != nil || req == nil {
					t.Fatalf("pending: %v", e)
				}
				if e = g.Approve(inv, *req, false); e != nil {
					t.Fatal(e)
				}
			}
			ok, e := peer.FinishJoin()
			if e != nil || !ok {
				t.Fatalf("finish: %v", e)
			}
			if e = peer.Rename(c.Device, "New name"); e != nil {
				t.Fatal(e)
			}
			if e = peer.PrepareExit(false); e != nil {
				t.Fatal(e)
			}
			if e = peer.Exit(); e != nil {
				t.Fatal(e)
			}
		})
	}
	if err = g.PrepareExit(true); err != nil {
		t.Fatal(err)
	}
	if err = g.Exit(); err != nil {
		t.Fatal(err)
	}
}

package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGroupContextCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	group, e := NewGroups(&GroupConfig{URL: strings.Replace(server.URL, "http://", "ws://", 1) + "/relay/v1/ws", App: "test", Device: "test"}, true)
	if e != nil {
		t.Fatal(e)
	}
	defer group.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- group.WithContext(ctx).call("GET", "/group", nil, "", new(any)) }()
	<-started
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("request survived cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop HTTP request")
	}
}

func TestResolveInvitationHonorsCancellation(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(500) }))
	defer server.Close()
	endpoint := strings.Replace(server.URL, "http://", "ws://", 1) + "/relay/v1/ws"
	group, e := NewGroups(&GroupConfig{URL: endpoint, App: "example"}, true)
	if e != nil {
		t.Fatal(e)
	}
	defer group.Close()
	link, e := invitationMakeLink(GroupInvitation{URL: endpoint, ID: strings.Repeat("a", 32)}, [32]byte{}, "")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = group.WithContext(ctx).ResolveInvitation(link); e == nil {
		t.Fatal("canceled resolution accepted")
	}
	if hits != 0 {
		t.Fatal("canceled resolution contacted relay")
	}
}

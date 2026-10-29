package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGroupsRejectRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; w.Write([]byte(`{}`)) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	g, err := NewGroups(&GroupConfig{URL: strings.Replace(server.URL, "http://", "ws://", 1) + "/relay/v1/ws"}, true)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err = g.call("GET", "/group", nil, "", &out); err == nil || reached {
		t.Fatal("redirect followed")
	}
}

package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUsageTracksAppsKindsAndURLFamily(t *testing.T) {
	f := setup(t)
	f.add("phone", "daily")
	f.add("mac", "bills")

	ws := f.dial("phone")
	waitUsage(t, f.s, func(u UsageSnapshot) bool { return u.Live["daily"] == 1 })

	get := func(h http.Handler, path, id string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+f.tokens[id])
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	get(f.s.Handler(), "/relay/v1/files", "mac")        // v1 URL
	get(f.s.V2FilesHandler(), "/v2/files", "mac")       // v2 URL served by v1 code
	get(f.s.V2GroupHandler(), "/v2/group", "phone")     // v2 group URL
	get(f.s.Handler(), "/relay/v1/enroll/abc", "phone") // unauthenticated enrollment

	u := f.s.Usage.Snapshot()
	find := func(app, kind, family string) int64 {
		for _, r := range u.Rows {
			if r.App == app && r.Kind == kind && r.Family == family {
				return r.Requests
			}
		}
		return 0
	}
	if find("daily", "ws", "v1") != 1 || find("bills", "files", "v1") != 1 || find("bills", "files", "v2") != 1 || find("daily", "group", "v2") != 1 || find("?", "enroll", "v1") != 1 {
		t.Fatalf("usage rows = %+v", u.Rows)
	}
	_ = ws.CloseNow()
	waitUsage(t, f.s, func(u UsageSnapshot) bool { return u.Live["daily"] == 0 })
}

func waitUsage(t *testing.T, s *Server, ok func(UsageSnapshot) bool) {
	t.Helper()
	for i := 0; i < 150; i++ {
		if ok(s.Usage.Snapshot()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("usage never reached the expected state: %+v", s.Usage.Snapshot())
}

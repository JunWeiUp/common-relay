package ledger

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUsageTracksAppsAndKinds(t *testing.T) {
	f := setup(t)
	f.add("phone", "daily")
	f.add("mac", "bills")

	get := func(path, id string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+f.tokens[id])
		f.s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	get("/v2/files", "mac")
	get("/v2/files", "mac")
	get("/v2/group", "phone")
	get("/v2/enroll/abc", "phone") // unauthenticated enrollment

	u := f.s.Usage.Snapshot()
	find := func(app, kind string) int64 {
		for _, r := range u.Rows {
			if r.App == app && r.Kind == kind {
				return r.Requests
			}
		}
		return 0
	}
	if find("bills", "files") != 2 || find("daily", "group") != 1 || find("?", "enroll") != 1 {
		t.Fatalf("usage rows = %+v", u.Rows)
	}
}

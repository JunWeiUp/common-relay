package relay

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Usage records who still calls the v1 server code and through which URL family,
// so v1 can be retired only once nothing depends on it. In memory, bounded by the
// number of (app, kind, family) combinations, reset on restart.
type Usage struct {
	mu   sync.Mutex
	rows map[usageKey]*UsageRow
	live map[string]int // app -> open /relay/v1/ws sessions
}

type usageKey struct{ app, kind, family string }

// UsageRow is one (app, kind, family) counter.
type UsageRow struct {
	App      string `json:"app"`
	Kind     string `json:"kind"`   // ws | files | group | enroll | dav | webhook
	Family   string `json:"family"` // v1 (client used a /relay/v1 URL) | v2 (a /v2 URL served by v1 code)
	Requests int64  `json:"requests"`
	LastAt   int64  `json:"last_at"`
}

// UsageSnapshot is exposed through /v2/admin/metrics.
type UsageSnapshot struct {
	Rows []UsageRow     `json:"rows"`
	Live map[string]int `json:"live_ws"`
}

const maxUsageRows = 512

type v2RewriteKey struct{}

// markV2 tags a request that reached v1 code through a /v2 URL.
func markV2(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), v2RewriteKey{}, true))
}

func usageFamily(r *http.Request) string {
	if v, _ := r.Context().Value(v2RewriteKey{}).(bool); v {
		return "v2"
	}
	return "v1"
}

func usageKind(path string) string {
	switch {
	case strings.HasPrefix(path, "/relay/v1/ws"):
		return "ws"
	case strings.HasPrefix(path, "/relay/v1/files"):
		return "files"
	case strings.HasPrefix(path, "/relay/v1/enroll"):
		return "enroll"
	case strings.HasPrefix(path, "/relay/v1/group"):
		return "group"
	case strings.HasPrefix(path, "/relay/v1/dav"):
		return "dav"
	case strings.HasPrefix(path, "/relay/v1/webhooks"):
		return "webhook"
	}
	return "other"
}

func (u *Usage) record(app string, r *http.Request) {
	if u == nil {
		return
	}
	if app == "" {
		app = "?"
	}
	k := usageKey{app, usageKind(r.URL.Path), usageFamily(r)}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.rows == nil {
		u.rows = map[usageKey]*UsageRow{}
	}
	row := u.rows[k]
	if row == nil {
		if len(u.rows) >= maxUsageRows {
			k.app = "*other"
			row = u.rows[k]
		}
		if row == nil {
			row = &UsageRow{App: k.app, Kind: k.kind, Family: k.family}
			u.rows[k] = row
		}
	}
	row.Requests++
	row.LastAt = time.Now().Unix()
}

func (u *Usage) wsOpen(app string, delta int) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.live == nil {
		u.live = map[string]int{}
	}
	u.live[app] += delta
	if u.live[app] <= 0 {
		delete(u.live, app)
	}
}

// Snapshot copies the counters.
func (u *Usage) Snapshot() UsageSnapshot {
	out := UsageSnapshot{Rows: []UsageRow{}, Live: map[string]int{}}
	if u == nil {
		return out
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, r := range u.rows {
		out.Rows = append(out.Rows, *r)
	}
	for k, v := range u.live {
		out.Live[k] = v
	}
	return out
}

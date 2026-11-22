package relay

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// Usage counts calls into the signed group ledger and file plane per app and
// kind. In memory, bounded by the number of (app, kind) combinations, reset on
// restart; exposed through /v2/admin/metrics.
type Usage struct {
	mu   sync.Mutex
	rows map[usageKey]*UsageRow
}

type usageKey struct{ app, kind string }

// UsageRow is one (app, kind) counter.
type UsageRow struct {
	App      string `json:"app"`
	Kind     string `json:"kind"`   // files | group | enroll
	Family   string `json:"family"` // always "v2": /relay/v1 URLs no longer exist
	Requests int64  `json:"requests"`
	LastAt   int64  `json:"last_at"`
}

// UsageSnapshot is exposed through /v2/admin/metrics.
type UsageSnapshot struct {
	Rows []UsageRow `json:"rows"`
}

const maxUsageRows = 512

func usageKind(path string) string {
	switch {
	case strings.HasPrefix(path, "/v2/files"):
		return "files"
	case strings.HasPrefix(path, "/v2/enroll"):
		return "enroll"
	case strings.HasPrefix(path, "/v2/group"):
		return "group"
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
	k := usageKey{app, usageKind(r.URL.Path)}
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
			row = &UsageRow{App: k.app, Kind: k.kind, Family: "v2"}
			u.rows[k] = row
		}
	}
	row.Requests++
	row.LastAt = time.Now().Unix()
}

// Snapshot copies the counters.
func (u *Usage) Snapshot() UsageSnapshot {
	out := UsageSnapshot{Rows: []UsageRow{}}
	if u == nil {
		return out
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, r := range u.rows {
		out.Rows = append(out.Rows, *r)
	}
	return out
}

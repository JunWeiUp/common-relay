package relay

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Self-service is opt-in per application. A new random namespace cannot claim
// an existing group. Quotas are durable and global, not spoofable forwarding IPs.
func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var in struct {
		Entry     SignedEntry `json:"entry"`
		TokenHash string      `json:"token_hash"`
	}
	if !readGroupJSON(w, r, &in) {
		return
	}
	g, err := in.Entry.state()
	if in.Entry.Authorization != nil || err != nil || !s.SelfServiceApps[g.App] || len(g.Members) != 1 || g.Revision != 1 || g.Previous != "" || g.Invitation != "" || g.RequestHash != "" || strings.TrimSpace(g.Name) == "" || !strings.HasPrefix(g.Group, "g-") || !validHex(strings.TrimPrefix(g.Group, "g-"), 16) || !validHex(in.TokenHash, 32) {
		groupFailure(w, ErrDenied)
		return
	}
	m := g.Members[0]
	if m.Device != in.Entry.Signer || !m.Manager || !in.Entry.verify(m.SigningKey) {
		groupFailure(w, ErrDenied)
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	// A retry succeeds only with the identical root and still-active credential,
	// even if the group has advanced since the first response was lost.
	var raw string
	err = tx.QueryRow("SELECT entry FROM group_entries WHERE app=? AND grp=? AND revision=1", g.App, g.Group).Scan(&raw)
	if err == nil {
		var token string
		var count int
		tx.QueryRow("SELECT count(*) FROM group_creations WHERE app=? AND grp=?", g.App, g.Group).Scan(&count)
		e := SignedEntry{}
		json.Unmarshal([]byte(raw), &e)
		err = tx.QueryRow("SELECT token FROM devices WHERE app=? AND grp=? AND id=? AND revoked=0", g.App, g.Group, m.Device).Scan(&token)
		if count == 1 && err == nil && token == in.TokenHash && e == in.Entry {
			reply(w, in.Entry)
			return
		}
		groupFailure(w, ErrDenied)
		return
	}
	if err != sql.ErrNoRows {
		groupFailure(w, err)
		return
	}
	var existing, total, recent int
	err = tx.QueryRow("SELECT (SELECT count(*) FROM devices WHERE app=? AND grp=?) + (SELECT count(*) FROM group_bootstrap WHERE app=? AND grp=?)", g.App, g.Group, g.App, g.Group).Scan(&existing)
	if err != nil || existing != 0 {
		groupFailure(w, ErrDenied)
		return
	}
	err = tx.QueryRow("SELECT count(*),coalesce(sum(created>?),0) FROM group_creations", time.Now().Add(-time.Hour).Unix()).Scan(&total, &recent)
	if err != nil {
		groupFailure(w, err)
		return
	}
	if total >= 1000 || recent >= 20 {
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "group creation capacity reached; retry later", 429)
		return
	}
	_, err = tx.Exec("INSERT INTO devices(app,grp,id,token,public_key) VALUES(?,?,?,?,?)", g.App, g.Group, m.Device, in.TokenHash, m.PublicKey)
	if err == nil {
		err = insertEntry(tx, in.Entry, g)
	}
	if err == nil {
		_, err = tx.Exec("INSERT INTO group_creations VALUES(?,?,?)", g.App, g.Group, time.Now().Unix())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		groupFailure(w, err)
		return
	}
	reply(w, in.Entry)
}

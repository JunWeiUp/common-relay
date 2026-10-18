package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Exit is a signed transition. A revoked token may only acknowledge the exact
// previously committed exit, so a lost response never traps the local client.
func (s *Server) exitGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var e SignedEntry
	if !readGroupJSON(w, r, &e) {
		return
	}
	g, err := e.state()
	if err != nil {
		groupFailure(w, ErrDenied)
		return
	}
	if _, present := g.member(e.Signer); present {
		groupFailure(w, ErrDenied)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.WriteHeader(401)
		return
	}
	var d Device
	var revoked int
	err = s.Store.DB.QueryRow("SELECT app,grp,id,public_key,revoked FROM devices WHERE token=?", hashToken(strings.TrimPrefix(auth, "Bearer "))).Scan(&d.App, &d.Group, &d.ID, &d.PublicKey, &revoked)
	if err != nil || d.App != g.App || d.Group != g.Group || d.ID != e.Signer {
		w.WriteHeader(401)
		return
	}
	if revoked != 0 {
		var raw string
		var saved SignedEntry
		err = s.Store.DB.QueryRow("SELECT entry FROM group_entries WHERE app=? AND grp=? AND revision=?", d.App, d.Group, g.Revision).Scan(&raw)
		if err == nil && json.Unmarshal([]byte(raw), &saved) == nil && saved == e {
			reply(w, e)
			return
		}
		w.WriteHeader(401)
		return
	}
	raw, _ := json.Marshal(e)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	s.changeGroup(w, r, d)
}

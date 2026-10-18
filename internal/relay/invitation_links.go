package relay

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// A compact link carries a 256-bit encryption key in its fragment. Only an
// independently derived read credential reaches this endpoint. The relay stores
// an authenticated ciphertext, never the manager/delegate private keys.
func (s *Server) publishInvitationLink(w http.ResponseWriter, r *http.Request, d Device) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/relay/v1/group/invitations/"), "/link")
	if !objectID.MatchString(id) {
		w.WriteHeader(404)
		return
	}
	var in struct {
		ReadHash string `json:"read_hash"`
		Packet   string `json:"packet"`
	}
	if !readGroupJSON(w, r, &in) {
		return
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(in.Packet)
	if err != nil || len(raw) < 40 || len(raw) > 16384 || !validHex(in.ReadHash, 32) {
		w.WriteHeader(400)
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	_, g, err := latest(tx, d.App, d.Group)
	m, ok := g.member(d.ID)
	if err != nil || !ok || !m.Manager || g.Closed {
		groupFailure(w, ErrDenied)
		return
	}
	var request, approved string
	err = tx.QueryRow("SELECT request,approved FROM group_invites WHERE id=? AND app=? AND grp=? AND owner=? AND expires>?", id, d.App, d.Group, d.ID, time.Now().Unix()).Scan(&request, &approved)
	if err != nil {
		groupFailure(w, err)
		return
	}
	var hash, packet string
	err = tx.QueryRow("SELECT read_hash,packet FROM group_invite_links WHERE id=?", id).Scan(&hash, &packet)
	if err == nil {
		if hash == in.ReadHash && packet == in.Packet {
			reply(w, map[string]bool{"published": true})
			return
		}
		http.Error(w, "invitation link is immutable", 409)
		return
	}
	if err != sql.ErrNoRows {
		groupFailure(w, err)
		return
	}
	if request != "" || approved != "" {
		http.Error(w, "invitation already claimed", 409)
		return
	}
	_, err = tx.Exec("INSERT INTO group_invite_links VALUES(?,?,?)", id, in.ReadHash, in.Packet)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		groupFailure(w, err)
		return
	}
	reply(w, map[string]bool{"published": true})
}

func (s *Server) readInvitationLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/relay/v1/enroll/"), "/link")
	if !objectID.MatchString(id) {
		w.WriteHeader(404)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "InvitationLink ") || !validHex(strings.TrimPrefix(auth, "InvitationLink "), 32) {
		groupFailure(w, ErrDenied)
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	var app, group, owner, packet string
	err = tx.QueryRow(`SELECT i.app,i.grp,i.owner,l.packet FROM group_invite_links l JOIN group_invites i ON i.id=l.id WHERE i.id=? AND l.read_hash=? AND i.expires>? AND i.approved=''`, id, hashToken(strings.TrimPrefix(auth, "InvitationLink ")), time.Now().Unix()).Scan(&app, &group, &owner, &packet)
	if err != nil {
		groupFailure(w, err)
		return
	}
	_, g, err := latest(tx, app, group)
	m, ok := g.member(owner)
	if err != nil || !ok || !m.Manager || g.Closed {
		groupFailure(w, ErrDenied)
		return
	}
	reply(w, map[string]any{"version": 1, "packet": packet})
}

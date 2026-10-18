package relay

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The delegate private key travels only in the trusted QR/link. The relay sees
// its public key and signed membership changes, never a key that can forge one.
type AdmissionGrant struct {
	Version        int    `json:"version"`
	Purpose        string `json:"purpose"`
	Mode           string `json:"mode"`
	App            string `json:"app"`
	Group          string `json:"group"`
	Invitation     string `json:"invitation"`
	Expires        int64  `json:"expires"`
	SecretHash     string `json:"secret_hash"`
	DelegateKey    string `json:"delegate_key"`
	AnchorRevision int    `json:"anchor_revision"`
	AnchorHash     string `json:"anchor_hash"`
}

func validateGrant(e *SignedEntry, owner Member, state GroupState) (AdmissionGrant, error) {
	var g AdmissionGrant
	if e == nil || e.Authorization != nil || !owner.Manager || e.Signer != owner.Device || !e.verify(owner.SigningKey) {
		return g, ErrDenied
	}
	b, err := e.bytes()
	if err != nil || json.Unmarshal(b, &g) != nil || g.Version != 1 || g.Purpose != "common-relay/admission/v1" || g.Mode != "auto" || g.App != state.App || g.Group != state.Group || !objectID.MatchString(g.Invitation) || !validHex(g.DelegateKey, 32) || !validHex(g.SecretHash, 32) || !validHex(g.AnchorHash, 32) || g.AnchorRevision < 1 || g.AnchorRevision > state.Revision || g.Expires <= 0 {
		return g, ErrDenied
	}
	return g, nil
}

// Validate the exact transition, not just a delegated signature. Delegation
// permits one new ordinary member; it cannot rename, upgrade, remove or close.
func validateAutoTransition(current, entry SignedEntry) (GroupState, error) {
	old, err := current.state()
	if err != nil {
		return old, err
	}
	next, err := entry.state()
	if err != nil {
		return next, err
	}
	owner, ok := old.member(entry.Signer)
	grant, err := validateGrant(entry.Authorization, owner, old)
	b, _ := current.bytes()
	if !ok || err != nil || old.Closed || next.Closed || next.App != old.App || next.Group != old.Group || next.Name != old.Name || next.Revision != old.Revision+1 || next.Previous != digest(b) || next.Invitation != grant.Invitation || !validHex(next.RequestHash, 32) || !entry.verify(grant.DelegateKey) || len(next.Members) != len(old.Members)+1 {
		return next, ErrDenied
	}
	if old.Revision == grant.AnchorRevision && digest(b) != grant.AnchorHash {
		return next, ErrDenied
	}
	for _, m := range old.Members {
		n, ok := next.member(m.Device)
		if !ok || n != m {
			return next, ErrDenied
		}
	}
	for _, m := range next.Members {
		if _, ok := old.member(m.Device); !ok && m.Manager {
			return next, ErrDenied
		}
	}
	return next, nil
}

func (s *Server) autoEnroll(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/relay/v1/enroll/"), "/auto")
	if !objectID.MatchString(id) {
		w.WriteHeader(404)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var entry SignedEntry
	if r.Method == "POST" && !readGroupJSON(w, r, &entry) {
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	var app, group, owner, token, request, approved, grantRaw string
	err = tx.QueryRow(`SELECT i.app,i.grp,i.owner,i.token_hash,i.request,i.approved,a.grant_entry FROM group_invites i JOIN group_invite_grants a ON a.id=i.id WHERE i.id=? AND i.expires>?`, id, time.Now().Unix()).Scan(&app, &group, &owner, &token, &request, &approved, &grantRaw)
	if err != nil {
		groupFailure(w, err)
		return
	}
	auth := r.Header.Get("Authorization")
	if token == "" || !strings.HasPrefix(auth, "Claim ") || hashToken(strings.TrimPrefix(auth, "Claim ")) != token {
		groupFailure(w, ErrDenied)
		return
	}
	current, old, err := latest(tx, app, group)
	manager, ok := old.member(owner)
	var grantEntry SignedEntry
	if err != nil || !ok || old.Closed || json.Unmarshal([]byte(grantRaw), &grantEntry) != nil {
		groupFailure(w, ErrDenied)
		return
	}
	grant, err := validateGrant(&grantEntry, manager, old)
	if err != nil || grant.Expires <= time.Now().Unix() {
		groupFailure(w, ErrDenied)
		return
	}
	if approved != "" {
		// A consumed invitation cannot restore access after the joiner is removed.
		var active int
		err = tx.QueryRow("SELECT count(*) FROM devices WHERE app=? AND grp=? AND token=? AND revoked=0", app, group, token).Scan(&active)
		if err != nil || active != 1 {
			groupFailure(w, ErrDenied)
			return
		}
	}
	if r.Method == "GET" {
		after := grant.AnchorRevision - 1
		if r.URL.Query().Has("after") {
			after, err = strconv.Atoi(r.URL.Query().Get("after"))
			if err != nil || after < grant.AnchorRevision-1 {
				w.WriteHeader(400)
				return
			}
		}
		revision := old.Revision
		var result *SignedEntry
		if approved != "" {
			result = &SignedEntry{}
			if json.Unmarshal([]byte(approved), result) != nil {
				w.WriteHeader(500)
				return
			}
			g, e := result.state()
			if e != nil {
				w.WriteHeader(500)
				return
			}
			revision = g.Revision
		}
		if after > revision {
			w.WriteHeader(400)
			return
		}
		rows, e := tx.Query("SELECT entry FROM group_entries WHERE app=? AND grp=? AND revision>? AND revision<=? ORDER BY revision LIMIT 64", app, group, after, revision)
		if e != nil {
			groupFailure(w, e)
			return
		}
		entries := []SignedEntry{}
		for rows.Next() {
			var raw string
			var se SignedEntry
			if rows.Scan(&raw) != nil || json.Unmarshal([]byte(raw), &se) != nil {
				rows.Close()
				w.WriteHeader(500)
				return
			}
			entries = append(entries, se)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			groupFailure(w, e)
			return
		}
		reply(w, map[string]any{"entries": entries, "revision": revision, "entry": result})
		return
	}
	raw, _ := json.Marshal(entry)
	if approved != "" {
		if approved == string(raw) {
			reply(w, entry)
		} else {
			http.Error(w, "invitation already used", 409)
		}
		return
	}
	if old.Revision >= 4096 {
		http.Error(w, "membership history capacity", 507)
		return
	}
	if entry.Authorization == nil || entry.Authorization.Authorization != nil || entry.Authorization.Payload != grantEntry.Payload || entry.Authorization.Signature != grantEntry.Signature || entry.Authorization.Signer != grantEntry.Signer {
		groupFailure(w, ErrDenied)
		return
	}
	// Concurrency is an explicit rebase; a stale signed proposal is never replayed.
	candidate, e := entry.state()
	b, _ := current.bytes()
	if e == nil && (candidate.Previous != digest(b) || candidate.Revision != old.Revision+1) {
		http.Error(w, "stale revision", 409)
		return
	}
	next, err := validateAutoTransition(current, entry)
	var req SignedEntry
	var join JoinRequest
	if err != nil || json.Unmarshal([]byte(request), &req) != nil {
		groupFailure(w, ErrDenied)
		return
	}
	rb, e := req.bytes()
	if e != nil || json.Unmarshal(rb, &join) != nil || next.RequestHash != digest(rb) || next.Invitation != id {
		groupFailure(w, ErrDenied)
		return
	}
	actual, ok := next.member(join.Member.Device)
	if !ok || actual != join.Member || actual.Manager {
		groupFailure(w, ErrDenied)
		return
	}
	var used int
	err = tx.QueryRow("SELECT count(*) FROM devices WHERE app=? AND grp=? AND id=?", app, group, actual.Device).Scan(&used)
	if err != nil || used != 0 {
		http.Error(w, "device ID cannot be reused", 409)
		return
	}
	_, err = tx.Exec("INSERT INTO devices(app,grp,id,token,public_key) VALUES(?,?,?,?,?)", app, group, actual.Device, token, actual.PublicKey)
	if err == nil {
		err = insertEntry(tx, entry, next)
	}
	if err == nil {
		_, err = tx.Exec("UPDATE group_invites SET approved=? WHERE id=?", string(raw), id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		groupFailure(w, err)
		return
	}
	s.mu.Lock()
	for _, p := range s.peers {
		if p.d.App == app && p.d.Group == group {
			s.event(p, Event{Type: "group.changed", Revision: next.Revision})
		}
	}
	s.mu.Unlock()
	reply(w, entry)
}

func isAutoInvite(tx *sql.Tx, id string) (bool, error) {
	var n int
	err := tx.QueryRow("SELECT count(*) FROM group_invite_grants WHERE id=?", id).Scan(&n)
	if err != nil {
		return false, err
	}
	return n != 0, nil
}

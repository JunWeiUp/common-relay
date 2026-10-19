package relay

// Group membership is a client-signed, append-only chain. The relay authorizes
// operations but cannot manufacture a trusted device key on behalf of a client.
import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Member struct {
	Device     string `json:"device"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	SigningKey string `json:"signing_key"`
	Manager    bool   `json:"manager"`
}
type GroupState struct {
	Closed      bool     `json:"closed,omitempty"`
	Name        string   `json:"name,omitempty"`
	Version     int      `json:"version"`
	App         string   `json:"app"`
	Group       string   `json:"group"`
	Revision    int      `json:"revision"`
	Previous    string   `json:"previous"`
	Members     []Member `json:"members"`
	Invitation  string   `json:"invitation"`
	RequestHash string   `json:"request_hash"`
}
type SignedEntry struct {
	Payload       string       `json:"payload"`
	Signature     string       `json:"signature"`
	Signer        string       `json:"signer"`
	Authorization *SignedEntry `json:"authorization,omitempty"`
}
type JoinRequest struct {
	Version    int    `json:"version"`
	App        string `json:"app"`
	Group      string `json:"group"`
	Invitation string `json:"invitation"`
	Member     Member `json:"member"`
	TokenHash  string `json:"token_hash"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && s == strings.ToLower(s)
}
func (e SignedEntry) bytes() ([]byte, error) {
	// Strict still skips CR/LF, which the SDK decoders reject.
	b, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(b) > 32768 || strings.ContainsAny(e.Payload, "\r\n") {
		return nil, ErrDenied
	}
	return b, nil
}
func (e SignedEntry) verify(key string) bool {
	b, err := e.bytes()
	pk, pe := hex.DecodeString(key)
	sig, se := hex.DecodeString(e.Signature)
	return err == nil && pe == nil && se == nil && len(pk) == 32 && ed25519.Verify(pk, b, sig)
}
func (e SignedEntry) state() (GroupState, error) {
	var g GroupState
	b, err := e.bytes()
	if err != nil {
		return g, err
	}
	if err = decodeStrict(b, stateSchema, &g); err != nil {
		return g, err
	}
	if len(g.Name) > 128 || (g.Name != "" && strings.TrimSpace(g.Name) == "") || g.Version != 1 || !identifier.MatchString(g.App) || !identifier.MatchString(g.Group) || g.Revision < 1 || (!g.Closed && len(g.Members) < 1) || (g.Closed && len(g.Members) != 0) || len(g.Members) > 32 {
		return g, ErrDenied
	}
	seen := map[string]bool{}
	managers := 0
	for _, m := range g.Members {
		if !identifier.MatchString(m.Device) || seen[m.Device] || !validHex(m.PublicKey, 32) || (!validHex(m.SigningKey, 32) && m.SigningKey != "") || len(m.Name) > 128 || strings.TrimSpace(m.Name) == "" || (m.Manager && m.SigningKey == "") {
			return g, ErrDenied
		}
		seen[m.Device] = true
		if m.Manager {
			managers++
		}
	}
	if !g.Closed && managers == 0 {
		return g, ErrDenied
	}
	return g, nil
}
func (g GroupState) member(id string) (Member, bool) {
	for _, m := range g.Members {
		if m.Device == id {
			return m, true
		}
	}
	return Member{}, false
}
func (s *Store) initGroups() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS group_creations(app TEXT NOT NULL,grp TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(app,grp));
 CREATE TABLE IF NOT EXISTS group_entries(app TEXT NOT NULL,grp TEXT NOT NULL,revision INTEGER NOT NULL,entry TEXT NOT NULL,PRIMARY KEY(app,grp,revision));
 CREATE TABLE IF NOT EXISTS group_bootstrap(token_hash TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS group_invites(id TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,owner TEXT NOT NULL,secret_hash TEXT NOT NULL,expires INTEGER NOT NULL,request TEXT NOT NULL DEFAULT '',token_hash TEXT NOT NULL DEFAULT '',approved TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS group_invite_grants(id TEXT PRIMARY KEY REFERENCES group_invites(id) ON DELETE CASCADE,grant_entry TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS group_invite_links(id TEXT PRIMARY KEY REFERENCES group_invites(id) ON DELETE CASCADE,read_hash TEXT NOT NULL,packet TEXT NOT NULL);`)
	return e
}

// Bootstrap is an explicit administrator capability, never an ordinary device token.
func (s *Store) GroupBootstrap(app, group, secret string) error {
	if !identifier.MatchString(app) || !identifier.MatchString(group) || len(secret) < 32 {
		return ErrDenied
	}
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM group_entries WHERE app=? AND grp=?", app, group).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return errors.New("group already initialized")
	}
	_, err := s.DB.Exec("INSERT INTO group_bootstrap VALUES(?,?,?,?)", hashToken(secret), app, group, time.Now().Add(10*time.Minute).Unix())
	return err
}

// CheckGroups reports stored records that the strict payload rules would
// reject, so an upgrade can be verified against existing data first.
func (s *Store) CheckGroups() ([]string, error) {
	rows, err := s.DB.Query("SELECT app,grp,revision,entry FROM group_entries ORDER BY app,grp,revision")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bad []string
	for rows.Next() {
		var app, group, raw string
		var revision int
		var e SignedEntry
		var grant AdmissionGrant
		if err = rows.Scan(&app, &group, &revision, &raw); err != nil {
			return nil, err
		}
		err = json.Unmarshal([]byte(raw), &e)
		if err == nil {
			_, err = e.state()
		}
		if err == nil && e.Authorization != nil {
			var b []byte
			if b, err = e.Authorization.bytes(); err == nil {
				err = decodeStrict(b, grantSchema, &grant)
			}
		}
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s/%s@%d", app, group, revision))
		}
	}
	return bad, rows.Err()
}
func latest(tx *sql.Tx, app, group string) (SignedEntry, GroupState, error) {
	var e SignedEntry
	var raw string
	err := tx.QueryRow("SELECT entry FROM group_entries WHERE app=? AND grp=? ORDER BY revision DESC LIMIT 1", app, group).Scan(&raw)
	if err != nil {
		return e, GroupState{}, err
	}
	if err = json.Unmarshal([]byte(raw), &e); err != nil {
		return e, GroupState{}, err
	}
	g, err := e.state()
	return e, g, err
}
func insertEntry(tx *sql.Tx, e SignedEntry, g GroupState) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO group_entries VALUES(?,?,?,?)", g.App, g.Group, g.Revision, string(raw))
	return err
}
func readGroupJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid request", 400)
		return false
	}
	return true
}
func groupFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrDenied) {
		http.Error(w, "not authorized", 403)
	} else if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "not found or expired", 404)
	} else {
		http.Error(w, "membership conflict; refresh and retry", 409)
	}
}
func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/relay/v1/group/exit" {
		s.exitGroup(w, r)
		return
	}
	if r.URL.Path == "/relay/v1/group/create" {
		s.createGroup(w, r)
		return
	}
	if r.URL.Path == "/relay/v1/group/bootstrap" {
		s.bootstrap(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/relay/v1/enroll/") {
		if strings.HasSuffix(r.URL.Path, "/link") {
			s.readInvitationLink(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/auto") {
			s.autoEnroll(w, r)
			return
		}
		s.enroll(w, r)
		return
	}
	d, err := s.auth(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.URL.Path == "/relay/v1/group" && r.Method == "GET" {
		s.groupList(w, r, d)
		return
	}
	if r.URL.Path == "/relay/v1/group" && r.Method == "PUT" {
		s.changeGroup(w, r, d)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/relay/v1/group/invitations") {
		if strings.HasSuffix(r.URL.Path, "/link") {
			s.publishInvitationLink(w, r, d)
			return
		}
		s.invitation(w, r, d)
		return
	}
	http.NotFound(w, r)
}
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
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
	m, ok := g.member(in.Entry.Signer)
	if in.Entry.Authorization != nil || err != nil || !ok || !m.Manager || !in.Entry.verify(m.SigningKey) || g.Revision != 1 || g.Previous != "" || g.Invitation != "" || !validHex(in.TokenHash, 32) {
		groupFailure(w, ErrDenied)
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bootstrap ")
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	var app, group string
	err = tx.QueryRow("SELECT app,grp FROM group_bootstrap WHERE token_hash=? AND expires>?", hashToken(secret), time.Now().Unix()).Scan(&app, &group)
	if err != nil || app != g.App || group != g.Group {
		groupFailure(w, ErrDenied)
		return
	}
	if previous, _, lookupErr := latest(tx, g.App, g.Group); lookupErr == nil {
		var token string
		tokenErr := tx.QueryRow("SELECT token FROM devices WHERE app=? AND grp=? AND id=? AND revoked=0", g.App, g.Group, m.Device).Scan(&token)
		if previous == in.Entry && tokenErr == nil && token == in.TokenHash {
			reply(w, in.Entry)
			return
		}
		groupFailure(w, ErrDenied)
		return
	} else if lookupErr != sql.ErrNoRows {
		groupFailure(w, lookupErr)
		return
	}
	// Existing devices must retain their keys; bootstrap cannot silently remove them.
	rows, err := tx.Query("SELECT id,public_key FROM devices WHERE app=? AND grp=? AND revoked=0", g.App, g.Group)
	if err != nil {
		groupFailure(w, err)
		return
	}
	existing := map[string]string{}
	for rows.Next() {
		var id, pk string
		if err = rows.Scan(&id, &pk); err != nil {
			break
		}
		existing[id] = pk
	}
	rows.Close()
	if err != nil {
		groupFailure(w, err)
		return
	}
	for id, pk := range existing {
		v, found := g.member(id)
		if !found || v.PublicKey != pk {
			groupFailure(w, ErrDenied)
			return
		}
	}
	for _, v := range g.Members {
		if v.Device != m.Device {
			if existing[v.Device] != v.PublicKey || v.Manager || v.SigningKey != "" {
				groupFailure(w, ErrDenied)
				return
			}
		}
	}
	if _, ok = existing[m.Device]; !ok {
		_, err = tx.Exec("INSERT INTO devices(app,grp,id,token,public_key) VALUES(?,?,?,?,?)", g.App, g.Group, m.Device, in.TokenHash, m.PublicKey)
	} else {
		var token string
		err = tx.QueryRow("SELECT token FROM devices WHERE app=? AND grp=? AND id=?", g.App, g.Group, m.Device).Scan(&token)
		if token != in.TokenHash {
			err = ErrDenied
		}
	}
	if err == nil {
		err = insertEntry(tx, in.Entry, g)
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
func (s *Server) groupList(w http.ResponseWriter, r *http.Request, d Device) {
	after, err := strconv.Atoi(r.URL.Query().Get("after"))
	if r.URL.Query().Get("after") == "" {
		after = 0
		err = nil
	}
	if err != nil || after < 0 {
		w.WriteHeader(400)
		return
	}
	rows, err := s.Store.DB.Query("SELECT entry FROM group_entries WHERE app=? AND grp=? AND revision>? ORDER BY revision LIMIT 64", d.App, d.Group, after)
	if err != nil {
		groupFailure(w, err)
		return
	}
	entries := []SignedEntry{}
	for rows.Next() {
		var raw string
		var e SignedEntry
		if rows.Scan(&raw) != nil || json.Unmarshal([]byte(raw), &e) != nil {
			rows.Close()
			w.WriteHeader(500)
			return
		}
		entries = append(entries, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		groupFailure(w, err)
		return
	}
	var count int
	s.Store.DB.QueryRow("SELECT count(*) FROM group_entries WHERE app=? AND grp=?", d.App, d.Group).Scan(&count)
	if count == 0 {
		http.Error(w, "group management not initialized", 404)
		return
	}
	online := []string{}
	s.mu.Lock()
	for _, p := range s.peers {
		if p.d.App == d.App && p.d.Group == d.Group {
			online = append(online, p.d.ID)
		}
	}
	s.mu.Unlock()
	reply(w, map[string]any{"entries": entries, "online": online, "revision": count})
}
func (s *Server) invitation(w http.ResponseWriter, r *http.Request, d Device) {
	var input struct {
		SecretHash string       `json:"secret_hash"`
		Mode       string       `json:"mode"`
		Grant      *SignedEntry `json:"grant"`
	}
	if r.Method == "POST" && !readGroupJSON(w, r, &input) {
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	current, g, err := latest(tx, d.App, d.Group)
	m, ok := g.member(d.ID)
	if err != nil || !ok || !m.Manager {
		groupFailure(w, ErrDenied)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/relay/v1/group/invitations")
	if path == "" && r.Method == "POST" {
		if !validHex(input.SecretHash, 32) {
			w.WriteHeader(400)
			return
		}
		_, err = tx.Exec("DELETE FROM group_invites WHERE expires<=?", time.Now().Unix())
		if err != nil {
			groupFailure(w, err)
			return
		}
		var n int
		err = tx.QueryRow("SELECT count(*) FROM group_invites WHERE app=? AND grp=?", d.App, d.Group).Scan(&n)
		if err != nil || n >= 16 {
			http.Error(w, "invitation capacity", 429)
			return
		}
		id := RandomID()
		expires := time.Now().Add(10 * time.Minute).Unix()
		if input.Mode == "" {
			input.Mode = "manual"
		}
		if input.Mode != "manual" && input.Mode != "auto" || input.Mode == "manual" && input.Grant != nil {
			groupFailure(w, ErrDenied)
			return
		}
		if input.Mode == "auto" {
			grant, e := validateGrant(input.Grant, m, g)
			b, _ := current.bytes()
			if e != nil || grant.SecretHash != input.SecretHash || grant.Expires <= time.Now().Unix() || grant.Expires > expires || grant.AnchorRevision != g.Revision || grant.AnchorHash != digest(b) {
				groupFailure(w, ErrDenied)
				return
			}
			id, expires = grant.Invitation, grant.Expires
		}
		_, err = tx.Exec("INSERT INTO group_invites(id,app,grp,owner,secret_hash,expires) VALUES(?,?,?,?,?,?)", id, d.App, d.Group, d.ID, input.SecretHash, expires)
		if err == nil && input.Grant != nil {
			raw, _ := json.Marshal(input.Grant)
			_, err = tx.Exec("INSERT INTO group_invite_grants VALUES(?,?)", id, string(raw))
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			groupFailure(w, err)
			return
		}
		reply(w, map[string]any{"id": id, "expires": expires, "mode": input.Mode})
		return
	}
	id := strings.TrimPrefix(path, "/")
	if !objectID.MatchString(id) {
		w.WriteHeader(404)
		return
	}
	var raw, approved string
	err = tx.QueryRow("SELECT request,approved FROM group_invites WHERE id=? AND app=? AND grp=? AND owner=? AND expires>?", id, d.App, d.Group, d.ID, time.Now().Unix()).Scan(&raw, &approved)
	if err != nil {
		groupFailure(w, err)
		return
	}
	if r.Method == "DELETE" {
		_, err = tx.Exec("DELETE FROM group_invites WHERE id=?", id)
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			groupFailure(w, err)
			return
		}
		reply(w, map[string]bool{"cancelled": true})
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	var req any
	if raw != "" {
		if json.Unmarshal([]byte(raw), &req) != nil {
			w.WriteHeader(500)
			return
		}
	}
	reply(w, map[string]any{"request": req, "approved": approved != ""})
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/relay/v1/enroll/")
	if !objectID.MatchString(id) {
		w.WriteHeader(404)
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
	var app, group, owner, secret, request, token, approved string
	err = tx.QueryRow("SELECT app,grp,owner,secret_hash,request,token_hash,approved FROM group_invites WHERE id=? AND expires>?", id, time.Now().Unix()).Scan(&app, &group, &owner, &secret, &request, &token, &approved)
	if err != nil {
		groupFailure(w, err)
		return
	}
	_, g, err := latest(tx, app, group)
	m, ok := g.member(owner)
	if err != nil || !ok || !m.Manager {
		groupFailure(w, ErrDenied)
		return
	}
	auth := r.Header.Get("Authorization")
	if r.Method == "POST" {
		if !strings.HasPrefix(auth, "Invitation ") || hashToken(strings.TrimPrefix(auth, "Invitation ")) != secret {
			groupFailure(w, ErrDenied)
			return
		}
		b, e := entry.bytes()
		var j JoinRequest
		if entry.Authorization != nil || e != nil || decodeStrict(b, requestSchema, &j) != nil || j.Version != 1 || j.App != app || j.Group != group || j.Invitation != id || j.Member.Manager || !identifier.MatchString(j.Member.Device) || j.Member.Device != entry.Signer || !validHex(j.Member.PublicKey, 32) || !validHex(j.Member.SigningKey, 32) || !validHex(j.TokenHash, 32) || len(j.Member.Name) > 128 || strings.TrimSpace(j.Member.Name) == "" || !entry.verify(j.Member.SigningKey) {
			groupFailure(w, ErrDenied)
			return
		}
		raw, _ := json.Marshal(entry)
		if request != "" {
			if request != string(raw) {
				http.Error(w, "invitation already claimed", 409)
				return
			}
			reply(w, map[string]bool{"pending": approved == ""})
			return
		}
		legacy, exists := g.member(j.Member.Device)
		if exists && (legacy.SigningKey != "" || legacy.PublicKey != j.Member.PublicKey) {
			http.Error(w, "device already enrolled", 409)
			return
		}
		var used int
		err = tx.QueryRow("SELECT count(*) FROM devices WHERE app=? AND grp=? AND id=?", app, group, j.Member.Device).Scan(&used)
		if err != nil || (used != 0 && !exists) {
			http.Error(w, "device ID cannot be reused", 409)
			return
		}
		_, err = tx.Exec("UPDATE group_invites SET request=?,token_hash=? WHERE id=?", string(raw), j.TokenHash, id)
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			groupFailure(w, err)
			return
		}
		reply(w, map[string]bool{"pending": true})
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	if token == "" || !strings.HasPrefix(auth, "Claim ") || hashToken(strings.TrimPrefix(auth, "Claim ")) != token {
		groupFailure(w, ErrDenied)
		return
	}
	var result any
	if approved != "" {
		if json.Unmarshal([]byte(approved), &result) != nil {
			w.WriteHeader(500)
			return
		}
	}
	reply(w, map[string]any{"entry": result})
}
func (s *Server) changeGroup(w http.ResponseWriter, r *http.Request, d Device) {
	var e SignedEntry
	if !readGroupJSON(w, r, &e) {
		return
	}
	if e.Authorization != nil {
		groupFailure(w, ErrDenied)
		return
	}
	g, err := e.state()
	if err != nil || g.App != d.App || g.Group != d.Group || e.Signer != d.ID {
		groupFailure(w, ErrDenied)
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		groupFailure(w, err)
		return
	}
	defer tx.Rollback()
	oldEntry, old, err := latest(tx, d.App, d.Group)
	actor, ok := old.member(d.ID)
	if err != nil || !ok || old.Closed || !e.verify(actor.SigningKey) {
		groupFailure(w, ErrDenied)
		return
	}
	b, _ := oldEntry.bytes()
	if old.Revision >= 4096 && len(g.Members) >= len(old.Members) {
		http.Error(w, "membership history capacity", 507)
		return
	}
	if g.Name != old.Name || g.Revision != old.Revision+1 || g.Previous != digest(b) {
		http.Error(w, "stale revision", 409)
		return
	}
	added := []Member{}
	removed := []Member{}
	upgrade := false
	renamed := []Member{}
	for _, m := range g.Members {
		prev, found := old.member(m.Device)
		if !found {
			added = append(added, m)
		} else if m != prev {
			sameIdentity := prev
			sameIdentity.Name = m.Name
			if sameIdentity == m && prev.Name != m.Name {
				renamed = append(renamed, m)
				continue
			}
			if prev.SigningKey == "" && m.SigningKey != "" && m.PublicKey == prev.PublicKey {
				added = append(added, m)
				upgrade = true
			} else {
				groupFailure(w, ErrDenied)
				return
			}
		}
	}
	for _, m := range old.Members {
		if _, found := g.member(m.Device); !found {
			removed = append(removed, m)
		}
	}
	raw, _ := json.Marshal(e)
	if len(renamed) == 1 && len(added) == 0 && len(removed) == 0 && g.Invitation == "" && g.RequestHash == "" && (actor.Manager || renamed[0].Device == d.ID) {
		// Display-only change is carried by the signed entry.
	} else if len(renamed) != 0 {
		groupFailure(w, ErrDenied)
		return
	} else if g.Closed && actor.Manager && len(g.Members) == 0 && g.Invitation == "" && g.RequestHash == "" {
		_, err = tx.Exec("UPDATE devices SET revoked=1 WHERE app=? AND grp=?", d.App, d.Group)
		if err == nil {
			_, err = tx.Exec("DELETE FROM group_invites WHERE app=? AND grp=?", d.App, d.Group)
		}
	} else if actor.Manager && len(added) == 1 && len(removed) == 0 {
		if automatic, e := isAutoInvite(tx, g.Invitation); e != nil || automatic {
			groupFailure(w, ErrDenied)
			return
		}
		var req, owner, approved string
		err = tx.QueryRow("SELECT request,owner,approved FROM group_invites WHERE id=? AND app=? AND grp=? AND expires>?", g.Invitation, d.App, d.Group, time.Now().Unix()).Scan(&req, &owner, &approved)
		var se SignedEntry
		var j JoinRequest
		if err != nil || owner != d.ID || approved != "" || json.Unmarshal([]byte(req), &se) != nil {
			groupFailure(w, ErrDenied)
			return
		}
		rb, er := se.bytes()
		if er != nil || decodeStrict(rb, requestSchema, &j) != nil || g.RequestHash != digest(rb) {
			groupFailure(w, ErrDenied)
			return
		}
		m := added[0]
		expected := j.Member
		expected.Manager = m.Manager
		if m != expected {
			groupFailure(w, ErrDenied)
			return
		}
		if upgrade {
			var token string
			err = tx.QueryRow("SELECT token FROM devices WHERE app=? AND grp=? AND id=? AND revoked=0", d.App, d.Group, m.Device).Scan(&token)
			if err == nil && token != j.TokenHash {
				err = ErrDenied
			}
		} else {
			_, err = tx.Exec("INSERT INTO devices(app,grp,id,token,public_key) VALUES(?,?,?,?,?)", d.App, d.Group, m.Device, j.TokenHash, m.PublicKey)
		}
		if err == nil {
			_, err = tx.Exec("UPDATE group_invites SET approved=? WHERE id=?", string(raw), g.Invitation)
		}
	} else if len(removed) == 1 && len(added) == 0 && g.Invitation == "" && g.RequestHash == "" && (actor.Manager || removed[0].Device == d.ID) {
		_, err = tx.Exec("UPDATE devices SET revoked=1 WHERE app=? AND grp=? AND id=?", d.App, d.Group, removed[0].Device)
		if err == nil {
			_, err = tx.Exec("DELETE FROM group_invites WHERE app=? AND grp=? AND owner=?", d.App, d.Group, removed[0].Device)
		}
	} else {
		groupFailure(w, ErrDenied)
		return
	}
	if err == nil {
		err = insertEntry(tx, e, g)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		groupFailure(w, err)
		return
	}
	s.mu.Lock()
	for _, m := range removed {
		if p := s.peers[key(Device{App: d.App, Group: d.Group, ID: m.Device})]; p != nil {
			p.cancel()
		}
	}
	for _, p := range s.peers {
		if p.d.App == d.App && p.d.Group == d.Group {
			s.event(p, Event{Type: "group.changed", Revision: g.Revision})
		}
	}
	s.mu.Unlock()
	reply(w, e)
}

package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type GroupMember struct {
	Device     string `json:"device"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	SigningKey string `json:"signing_key"`
	Manager    bool   `json:"manager"`
}
type GroupState struct {
	Closed      bool          `json:"closed,omitempty"`
	Name        string        `json:"name,omitempty"`
	Version     int           `json:"version"`
	App         string        `json:"app"`
	Group       string        `json:"group"`
	Revision    int           `json:"revision"`
	Previous    string        `json:"previous"`
	Members     []GroupMember `json:"members"`
	Invitation  string        `json:"invitation"`
	RequestHash string        `json:"request_hash"`
}
type GroupEntry struct {
	Payload       string      `json:"payload"`
	Signature     string      `json:"signature"`
	Signer        string      `json:"signer"`
	Authorization *GroupEntry `json:"authorization,omitempty"`
}
type GroupRequest struct {
	Version    int         `json:"version"`
	App        string      `json:"app"`
	Group      string      `json:"group"`
	Invitation string      `json:"invitation"`
	Member     GroupMember `json:"member"`
	TokenHash  string      `json:"token_hash"`
}
type GroupGrant struct {
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
type GroupInvitation struct {
	Version        int         `json:"version"`
	Mode           string      `json:"mode,omitempty"`
	URL            string      `json:"url"`
	App            string      `json:"app"`
	Group          string      `json:"group"`
	ID             string      `json:"id"`
	Expires        int64       `json:"expires"`
	Secret         string      `json:"secret"`
	Manager        GroupMember `json:"manager"`
	Grant          *GroupEntry `json:"grant,omitempty"`
	DelegateSecret string      `json:"delegate_secret,omitempty"`
	ShortLink      string      `json:"short_link,omitempty"`
}
type GroupPendingJoin struct {
	Invitation GroupInvitation `json:"invitation"`
	Request    GroupEntry      `json:"request"`
	AutoEntry  *GroupEntry     `json:"auto_entry,omitempty"`
}
type GroupConfig struct {
	URL           string            `json:"url"`
	App           string            `json:"app"`
	Group         string            `json:"group,omitempty"`
	Device        string            `json:"device"`
	SecretKey     string            `json:"secret_key"`
	Token         string            `json:"token,omitempty"`
	PublicKey     string            `json:"public_key,omitempty"`
	TrustedPeers  map[string]string `json:"trusted_peers,omitempty"`
	GroupEntry    *GroupEntry       `json:"group_entry,omitempty"`
	PendingCreate *GroupEntry       `json:"pending_create,omitempty"`
	PendingJoin   *GroupPendingJoin `json:"pending_join,omitempty"`
	PendingExit   *GroupEntry       `json:"pending_exit,omitempty"`
}

func groupErr() error             { return errors.New("invalid group entry") }
func groupDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func groupRandom(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func groupBytes(e GroupEntry) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(b) > 32768 || base64.StdEncoding.EncodeToString(b) != e.Payload {
		return nil, groupErr()
	}
	return b, nil
}
func groupDecode(e GroupEntry, schema map[string]payloadField, v any) error {
	b, err := groupBytes(e)
	if err != nil || !payloadStrict(b, schema) {
		return groupErr()
	}
	return json.Unmarshal(b, v)
}
func groupSign(v any, secret, device string) (GroupEntry, error) {
	var e GroupEntry
	k, err := decodeKey(secret)
	if err != nil {
		return e, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return e, err
	}
	e = GroupEntry{Payload: base64.StdEncoding.EncodeToString(b), Signature: hex.EncodeToString(ed25519.Sign(groupSigningKey(k), b)), Signer: device}
	return e, nil
}
func groupVerify(e GroupEntry, key string) error {
	b, err := groupBytes(e)
	k, er := hex.DecodeString(key)
	sig, es := hex.DecodeString(e.Signature)
	if err != nil || er != nil || es != nil || len(k) != 32 || len(sig) != 64 || !ed25519.Verify(k, b, sig) {
		return groupErr()
	}
	return nil
}
func groupState(e GroupEntry) (GroupState, error) {
	var s GroupState
	if err := groupDecode(e, payloadStateSchema, &s); err != nil {
		return s, err
	}
	if s.Version != 1 || !namePattern.MatchString(s.App) || !namePattern.MatchString(s.Group) || s.Revision < 1 || len(s.Name) > 128 || (s.Name != "" && strings.TrimSpace(s.Name) == "") || len(s.Members) > 32 || (s.Closed && len(s.Members) != 0) || (!s.Closed && len(s.Members) == 0) {
		return s, groupErr()
	}
	seen := map[string]bool{}
	managers := 0
	for _, m := range s.Members {
		if !namePattern.MatchString(m.Device) || seen[m.Device] || !keyPattern.MatchString(m.PublicKey) || (m.SigningKey != "" && !keyPattern.MatchString(m.SigningKey)) || (m.Manager && m.SigningKey == "") || len(m.Name) > 128 || strings.TrimSpace(m.Name) == "" {
			return s, groupErr()
		}
		seen[m.Device] = true
		if m.Manager {
			managers++
		}
	}
	if !s.Closed && managers == 0 {
		return s, groupErr()
	}
	return s, nil
}
func groupMember(s GroupState, id string) (GroupMember, bool) {
	for _, m := range s.Members {
		if m.Device == id {
			return m, true
		}
	}
	return GroupMember{}, false
}
func groupGrant(e *GroupEntry, owner GroupMember, s GroupState) (GroupGrant, error) {
	var g GroupGrant
	if e == nil || e.Authorization != nil || !owner.Manager || e.Signer != owner.Device || groupVerify(*e, owner.SigningKey) != nil || groupDecode(*e, payloadGrantSchema, &g) != nil || g.Version != 1 || g.Purpose != "common-relay/admission/v1" || g.Mode != "auto" || g.App != s.App || g.Group != s.Group || g.AnchorRevision < 1 || g.AnchorRevision > s.Revision || g.Expires <= 0 || !objectID.MatchString(g.Invitation) || !keyPattern.MatchString(g.SecretHash) || !keyPattern.MatchString(g.DelegateKey) || !keyPattern.MatchString(g.AnchorHash) {
		return g, groupErr()
	}
	return g, nil
}

// VerifyGroupAdvance verifies a signed membership transition against a trusted entry.
func VerifyGroupAdvance(current, entry GroupEntry) error {
	old, err := groupState(current)
	if err != nil {
		return err
	}
	next, err := groupState(entry)
	if err != nil {
		return err
	}
	actor, ok := groupMember(old, entry.Signer)
	b, _ := groupBytes(current)
	if !ok || old.Closed || next.App != old.App || next.Group != old.Group || next.Name != old.Name || next.Revision != old.Revision+1 || next.Previous != groupDigest(b) {
		return groupErr()
	}
	if entry.Authorization != nil {
		grant, err := groupGrant(entry.Authorization, actor, old)
		if err != nil || groupVerify(entry, grant.DelegateKey) != nil || next.Closed || next.Invitation != grant.Invitation || !keyPattern.MatchString(next.RequestHash) || len(next.Members) != len(old.Members)+1 || (old.Revision == grant.AnchorRevision && groupDigest(b) != grant.AnchorHash) {
			return groupErr()
		}
		for _, m := range old.Members {
			n, ok := groupMember(next, m.Device)
			if !ok || n != m {
				return groupErr()
			}
		}
		for _, m := range next.Members {
			if _, ok := groupMember(old, m.Device); !ok && m.Manager {
				return groupErr()
			}
		}
		return nil
	}
	if groupVerify(entry, actor.SigningKey) != nil {
		return groupErr()
	}
	added, removed, renamed := 0, 0, 0
	renamedID := ""
	for _, m := range next.Members {
		prev, ok := groupMember(old, m.Device)
		if !ok {
			added++
			continue
		}
		if m != prev {
			tmp := prev
			tmp.Name = m.Name
			if tmp == m {
				renamed++
				renamedID = m.Device
			} else if prev.SigningKey == "" && m.SigningKey != "" && prev.PublicKey == m.PublicKey {
				added++
			} else {
				return groupErr()
			}
		}
	}
	removedID := ""
	for _, m := range old.Members {
		if _, ok := groupMember(next, m.Device); !ok {
			removed++
			removedID = m.Device
		}
	}
	empty := next.Invitation == "" && next.RequestHash == ""
	if renamed > 0 {
		if renamed == 1 && added == 0 && removed == 0 && empty && (actor.Manager || renamedID == entry.Signer) {
			return nil
		}
		return groupErr()
	}
	if next.Closed && actor.Manager && len(next.Members) == 0 && empty || actor.Manager && added == 1 && removed == 0 && next.Invitation != "" && next.RequestHash != "" || removed == 1 && added == 0 && empty && (actor.Manager || removedID == entry.Signer) {
		return nil
	}
	return fmt.Errorf("%w: unauthorized transition", groupErr())
}

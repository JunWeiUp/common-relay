package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

const invitationPurpose = "common-relay/invitation-link/v1"

func invitationToken(key [32]byte) string {
	h := sha256.New()
	h.Write([]byte("common-relay/invitation-link/read/v1\x00"))
	h.Write(key[:])
	return hex.EncodeToString(h.Sum(nil))
}
func invitationSeal(inv GroupInvitation, key [32]byte, nonce [24]byte) (string, error) {
	raw, err := json.Marshal(struct {
		Version    int             `json:"version"`
		Purpose    string          `json:"purpose"`
		Invitation GroupInvitation `json:"invitation"`
	}{1, invitationPurpose, inv})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(secretbox.Seal(nonce[:], raw, &nonce, &key)), nil
}
func invitationOpen(packet string, key [32]byte) (GroupInvitation, error) {
	var result GroupInvitation
	raw, err := base64.StdEncoding.Strict().DecodeString(packet)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != packet || len(raw) < 40 || len(raw) > 16384 {
		return result, errors.New("invalid invitation packet")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	plain, ok := secretbox.Open(nil, raw[24:], &nonce, &key)
	if !ok {
		return result, errors.New("invalid invitation packet")
	}
	var v struct {
		Version    int             `json:"version"`
		Purpose    string          `json:"purpose"`
		Invitation GroupInvitation `json:"invitation"`
	}
	if json.Unmarshal(plain, &v) != nil || v.Version != 1 || v.Purpose != invitationPurpose {
		return result, errors.New("invalid invitation packet scope")
	}
	return v.Invitation, nil
}
func invitationMakeLink(inv GroupInvitation, key [32]byte) (string, error) {
	u, err := url.Parse(inv.URL)
	id, e := hex.DecodeString(inv.ID)
	if err != nil || u.Host == "" || e != nil || len(id) != 16 {
		return "", errors.New("invalid invitation")
	}
	return "common-relay://" + u.Host + "/i/" + base64.RawURLEncoding.EncodeToString(id) + "#" + base64.RawURLEncoding.EncodeToString(key[:]), nil
}
func invitationParseLink(text string, local bool) (string, string, [32]byte, error) {
	var key [32]byte
	bad := errors.New("invalid compact invitation")
	if len(text) > 2048 {
		return "", "", key, bad
	}
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "common-relay" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || !strings.HasPrefix(u.Path, "/i/") || u.RawPath != "" || u.RawFragment != "" {
		return "", "", key, bad
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(u.Path, "/i/"))
	if err != nil || len(id) != 16 || base64.RawURLEncoding.EncodeToString(id) != u.Path[3:] {
		return "", "", key, bad
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(u.Fragment)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != u.Fragment {
		return "", "", key, bad
	}
	copy(key[:], b)
	scheme := "wss"
	if local && u.Hostname() == "127.0.0.1" {
		scheme = "ws"
	}
	return scheme + "://" + u.Host + "/relay/v1/ws", hex.EncodeToString(id), key, nil
}

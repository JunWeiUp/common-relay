package relay

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInvitationLinkVectors(t *testing.T) {
	b, err := os.ReadFile("../../protocol/v2/invitation-link-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Invitation                          GroupInvitation `json:"invitation"`
		Key, Nonce, Packet, ReadToken, Link string
		AccessPassword                      string   `json:"access_password"`
		LinkWithPassword                    string   `json:"link_with_password"`
		InvalidLinkSuffixes                 []string `json:"invalid_link_suffixes"`
		InvalidLinks                        []string `json:"invalid_links"`
		PacketPlaintext                     string   `json:"packet_plaintext"`
		ReadHash                            string   `json:"read_hash"`
		LinkLength                          int      `json:"link_length"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	_ = json.Unmarshal(m["read_token"], &v.ReadToken)
	kb, err := hex.DecodeString(v.Key)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := hex.DecodeString(v.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	var nonce [24]byte
	copy(key[:], kb)
	copy(nonce[:], nb)
	opened, err := invitationOpen(v.Packet, key)
	if err != nil || !reflect.DeepEqual(opened, v.Invitation) {
		t.Fatalf("open: %v", err)
	}
	packet, err := invitationSeal(v.Invitation, key, nonce)
	if err != nil || packet != v.Packet {
		t.Fatalf("seal mismatch: %v", err)
	}
	if invitationToken(key) != v.ReadToken || groupDigest([]byte(v.ReadToken)) != v.ReadHash {
		t.Fatal("token mismatch")
	}
	if plain, ok := secretbox.Open(nil, mustB64(t, v.Packet)[24:], &nonce, &key); !ok || string(plain) != v.PacketPlaintext {
		t.Fatal("packet plaintext mismatch")
	}
	link, err := invitationMakeLink(v.Invitation, key, "")
	if err != nil || link != v.Link || len(link) != v.LinkLength || !strings.Contains(link, "/v2/i/") {
		t.Fatal("link mismatch")
	}
	u, id, k, pw, err := invitationParseLink(link, false)
	if err != nil || u != v.Invitation.URL || id != v.Invitation.ID || k != key || pw != "" {
		t.Fatal("parse mismatch")
	}
	if v.AccessPassword == "" || v.LinkWithPassword == "" || len(v.InvalidLinkSuffixes) == 0 {
		t.Fatal("access password vectors missing")
	}
	withPassword, err := invitationMakeLink(v.Invitation, key, v.AccessPassword)
	if err != nil || withPassword != v.LinkWithPassword {
		t.Fatal("link with password mismatch")
	}
	u, id, k, pw, err = invitationParseLink(withPassword, false)
	if err != nil || u != v.Invitation.URL || id != v.Invitation.ID || k != key || pw != v.AccessPassword {
		t.Fatal("parse with password mismatch")
	}
	for _, suffix := range v.InvalidLinkSuffixes {
		if _, _, _, _, err = invitationParseLink(link+suffix, false); err == nil {
			t.Fatalf("invalid suffix %q accepted", suffix)
		}
	}
	legacy := v.Invitation
	legacy.URL = "wss://relay.example.com/relay/v1/ws"
	if _, err = invitationMakeLink(legacy, key, ""); err == nil {
		t.Fatal("retired v1 relay URL accepted by link builder")
	}
	if _, err = NewGroups(&GroupConfig{URL: legacy.URL}, false); err == nil {
		t.Fatal("retired v1 relay URL accepted by groups")
	}
	if _, err = invitationMakeLink(v.Invitation, key, "bad pass"); err == nil {
		t.Fatal("invalid password accepted by link builder")
	}
	if _, err = invitationOpen(v.Packet, [32]byte{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = invitationOpen(v.Packet[:len(v.Packet)-8]+"AAAAAAAA", key); err == nil {
		t.Fatal("tampered packet accepted")
	}
	if len(v.InvalidLinks) == 0 {
		t.Fatal("invalid_links missing")
	}
	for _, s := range v.InvalidLinks {
		if _, _, _, _, err = invitationParseLink(s, false); err == nil {
			t.Fatalf("invalid link %q accepted", s)
		}
	}
}

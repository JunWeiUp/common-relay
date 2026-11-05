package relay

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestInvitationLinkVectors(t *testing.T) {
	b, err := os.ReadFile("../../protocol/invitation-link-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Invitation                          GroupInvitation `json:"invitation"`
		Key, Nonce, Packet, ReadToken, Link string
		AccessPassword                      string   `json:"access_password"`
		LinkWithPassword                    string   `json:"link_with_password"`
		InvalidLinkSuffixes                 []string `json:"invalid_link_suffixes"`
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
	if invitationToken(key) != v.ReadToken {
		t.Fatal("token mismatch")
	}
	link, err := invitationMakeLink(v.Invitation, key, "")
	if err != nil || link != v.Link {
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
	if _, err = invitationMakeLink(v.Invitation, key, "bad pass"); err == nil {
		t.Fatal("invalid password accepted by link builder")
	}
	if _, err = invitationOpen(v.Packet, [32]byte{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = invitationOpen(v.Packet[:len(v.Packet)-8]+"AAAAAAAA", key); err == nil {
		t.Fatal("tampered packet accepted")
	}
	for _, s := range []string{link + "=", strings.Replace(link, "/i/", "/other/", 1), strings.Replace(link, "relay.example.com", "user@relay.example.com", 1), strings.Replace(link, "#", "?x=1#", 1)} {
		if _, _, _, _, err = invitationParseLink(s, false); err == nil {
			t.Fatal("invalid link accepted")
		}
	}
}

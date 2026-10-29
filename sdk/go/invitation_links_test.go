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
	link, err := invitationMakeLink(v.Invitation, key)
	if err != nil || link != v.Link {
		t.Fatal("link mismatch")
	}
	u, id, k, err := invitationParseLink(link, false)
	if err != nil || u != v.Invitation.URL || id != v.Invitation.ID || k != key {
		t.Fatal("parse mismatch")
	}
	if _, err = invitationOpen(v.Packet, [32]byte{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = invitationOpen(v.Packet[:len(v.Packet)-8]+"AAAAAAAA", key); err == nil {
		t.Fatal("tampered packet accepted")
	}
	for _, s := range []string{link + "=", strings.Replace(link, "/i/", "/other/", 1), strings.Replace(link, "relay.example.com", "user@relay.example.com", 1), strings.Replace(link, "#", "?x=1#", 1)} {
		if _, _, _, err = invitationParseLink(s, false); err == nil {
			t.Fatal("invalid link accepted")
		}
	}
}

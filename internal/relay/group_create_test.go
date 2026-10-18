package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSelfServiceCreationBoundaries(t *testing.T) {
	f := setup(t)
	pk, sk, _ := ed25519.GenerateKey(nil)
	m := Member{Device: "phone", Name: "Phone", PublicKey: strings.Repeat("01", 32), SigningKey: hex.EncodeToString(pk), Manager: true}
	g := GroupState{Name: "我的设备", Version: 1, App: "example", Group: "g-" + RandomID(), Revision: 1, Members: []Member{m}}
	token := RandomID() + RandomID()
	send := func(state GroupState, tokenHash string) int {
		code, _ := groupRequest(t, f, "POST", "/relay/v1/group/create", "", map[string]any{"entry": groupSigned(t, state, m.Device, sk), "token_hash": tokenHash})
		return code
	}
	if send(g, hashToken(token)) != 403 {
		t.Fatal("must opt in")
	}
	f.s.SelfServiceApps = map[string]bool{"example": true}
	if send(g, hashToken(token)) != 200 || send(g, hashToken(token)) != 200 {
		t.Fatal("create/retry")
	}
	if _, err := f.s.Store.Authenticate(token); err != nil {
		t.Fatal(err)
	}
	if send(g, hashToken("different")) != 403 {
		t.Fatal("retry changed token")
	}
	altered := g
	altered.Name = "Changed"
	if send(altered, hashToken(token)) != 403 {
		t.Fatal("retry changed root")
	}
	old := g
	old.Group = "g-" + RandomID()
	if err := f.s.Store.AddDevice(Device{App: old.App, Group: old.Group, ID: "old", PublicKey: m.PublicKey}, RandomID()+RandomID()); err != nil {
		t.Fatal(err)
	}
	if send(old, hashToken(RandomID())) != 403 {
		t.Fatal("claimed legacy group")
	}
	invalid := g
	invalid.Group = "personal"
	if send(invalid, hashToken(RandomID())) != 403 {
		t.Fatal("nonrandom namespace")
	}
	invalid = g
	invalid.Group = "g-" + RandomID()
	invalid.Members = append(invalid.Members, Member{Device: "other", Name: "Other", PublicKey: m.PublicKey})
	if send(invalid, hashToken(RandomID())) != 403 {
		t.Fatal("preloaded other member")
	}
	for i := 0; i < 19; i++ {
		g.Group = "g-" + RandomID()
		if code := send(g, hashToken(RandomID())); code != 200 {
			t.Fatalf("capacity %d: %d", i, code)
		}
	}
	g.Group = "g-" + RandomID()
	if send(g, hashToken(RandomID())) != 429 {
		t.Fatal("quota not enforced")
	}
}

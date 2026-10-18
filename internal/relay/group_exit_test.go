package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedExitAndDisband(t *testing.T) {
	f := setup(t)
	pk, sk, _ := ed25519.GenerateKey(nil)
	bp, bk, _ := ed25519.GenerateKey(nil)
	a := Member{Device: "owner", Name: "Owner", PublicKey: strings.Repeat("01", 32), SigningKey: hex.EncodeToString(pk), Manager: true}
	b := Member{Device: "phone", Name: "Phone", PublicKey: strings.Repeat("02", 32), SigningKey: hex.EncodeToString(bp)}
	g := GroupState{Version: 1, App: "example", Group: "exit-test", Revision: 1, Members: []Member{a, b}}
	root := groupSigned(t, g, a.Device, sk)
	raw, _ := json.Marshal(root)
	at, bt := RandomID(), RandomID()
	for _, item := range []struct {
		m     Member
		token string
	}{{a, at}, {b, bt}} {
		if err := f.s.Store.AddDevice(Device{App: g.App, Group: g.Group, ID: item.m.Device, PublicKey: item.m.PublicKey}, item.token); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.Store.DB.Exec("INSERT INTO group_entries VALUES(?,?,?,?)", g.App, g.Group, 1, string(raw)); err != nil {
		t.Fatal(err)
	}
	rename := g
	rename.Members = append([]Member(nil), g.Members...)
	rename.Revision++
	rootBytes, _ := root.bytes()
	rename.Previous = digest(rootBytes)
	rename.Members[0].Name = "Not allowed"
	denied := groupSigned(t, rename, b.Device, bk)
	if code, _ := groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+bt, denied); code != 403 {
		t.Fatalf("ordinary rename other: %d", code)
	}
	rename.Members[0] = a
	rename.Members[1].Name = "My phone"
	renamed := groupSigned(t, rename, b.Device, bk)
	if code, _ := groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+bt, renamed); code != 200 {
		t.Fatalf("self rename: %d", code)
	}
	g = rename
	root = renamed
	b.Name = "My phone"
	next := g
	next.Revision = g.Revision + 1
	bytes, _ := root.bytes()
	next.Previous = digest(bytes)
	next.Members = []Member{}
	next.Closed = true
	req := groupSigned(t, next, b.Device, bk)
	if code, _ := groupRequest(t, f, "POST", "/relay/v1/group/exit", "Bearer "+bt, req); code != 403 {
		t.Fatalf("ordinary disband: %d", code)
	}
	next.Closed = false
	next.Members = []Member{b}
	req = groupSigned(t, next, a.Device, sk)
	if code, _ := groupRequest(t, f, "POST", "/relay/v1/group/exit", "Bearer "+at, req); code != 403 {
		t.Fatalf("last manager exit: %d", code)
	}
	next.Members = []Member{a}
	req = groupSigned(t, next, b.Device, bk)
	for i := 0; i < 2; i++ {
		if code, _ := groupRequest(t, f, "POST", "/relay/v1/group/exit", "Bearer "+bt, req); code != 200 {
			t.Fatalf("leave/retry: %d", code)
		}
	}
	if _, err := f.s.Store.Authenticate(bt); err == nil {
		t.Fatal("leaver still authorized")
	}
	closed := next
	closed.Revision++
	bytes, _ = req.bytes()
	closed.Previous = digest(bytes)
	closed.Members = []Member{}
	closed.Closed = true
	end := groupSigned(t, closed, a.Device, sk)
	for i := 0; i < 2; i++ {
		if code, _ := groupRequest(t, f, "POST", "/relay/v1/group/exit", "Bearer "+at, end); code != 200 {
			t.Fatalf("disband/retry: %d", code)
		}
	}
	if _, err := f.s.Store.Authenticate(at); err == nil {
		t.Fatal("manager still authorized")
	}
	if code, _ := groupRequest(t, f, "POST", "/relay/v1/group/exit", "Bearer "+bt, end); code != 401 {
		t.Fatal("foreign token acknowledged exit")
	}
}

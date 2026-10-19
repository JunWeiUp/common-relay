package relay

import (
	"encoding/json"
	"os"
	"testing"
)

type strictVectors struct {
	Initial  SignedEntry `json:"initial"`
	Approved SignedEntry `json:"approved"`
	Strict   struct {
		Valid       []strictCase `json:"valid"`
		Invalid     []strictCase `json:"invalid"`
		InvalidAuto []strictCase `json:"invalid_auto"`
	} `json:"strict_payload"`
}
type strictCase struct {
	Case  string      `json:"case"`
	Entry SignedEntry `json:"entry"`
}

func loadStrictVectors(t *testing.T) strictVectors {
	t.Helper()
	raw, err := os.ReadFile("../../protocol/group-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v strictVectors
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Strict.Valid) == 0 || len(v.Strict.Invalid) == 0 || len(v.Strict.InvalidAuto) == 0 {
		t.Fatal("missing strict payload vectors")
	}
	return v
}

func TestStrictPayloadVectors(t *testing.T) {
	v := loadStrictVectors(t)
	for _, c := range v.Strict.Valid {
		if _, err := c.Entry.state(); err != nil || !c.Entry.verify(phoneSigningKey) {
			t.Fatalf("%s rejected", c.Case)
		}
	}
	for _, c := range v.Strict.Invalid {
		if _, err := c.Entry.state(); err == nil {
			t.Errorf("%s accepted", c.Case)
		}
	}
	for _, c := range v.Strict.InvalidAuto {
		if _, err := validateAutoTransition(v.Initial, c.Entry); err == nil {
			t.Errorf("%s accepted", c.Case)
		}
	}
	for _, s := range []string{`{"version":9007199254740992}`, `{"version":-1}`, `{"version":1}x`, "{\"version\":1,\"name\":\"\x01\"}"} {
		if strictPayload([]byte(s), map[string]field{"version": {'i', true}, "name": {'s', false}}) {
			t.Errorf("accepted %q", s)
		}
	}
	if !strictPayload([]byte(` { "version" : 9007199254740991 } `), map[string]field{"version": {'i', true}}) {
		t.Error("rejected largest safe integer")
	}
}

// A member may rename itself, so the relay must refuse ambiguous renames
// before they become part of the chain every client has to verify.
func TestChangeGroupRejectsAmbiguousPayload(t *testing.T) {
	v := loadStrictVectors(t)
	f := setup(t)
	initial, _ := json.Marshal(v.Initial)
	approved, _ := json.Marshal(v.Approved)
	token := RandomID() + RandomID()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO group_entries VALUES('example','vectors',1,?)", []any{string(initial)}},
		{"INSERT INTO group_entries VALUES('example','vectors',2,?)", []any{string(approved)}},
		{"INSERT INTO devices(app,grp,id,token,public_key) VALUES('example','vectors','phone',?,'ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59')", []any{hashToken(token)}},
	} {
		if _, err := f.s.Store.DB.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range v.Strict.Invalid {
		if status, _ := groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+token, c.Entry); status == 200 {
			t.Errorf("%s stored", c.Case)
		}
	}
	if bad, err := f.s.Store.CheckGroups(); err != nil || len(bad) != 0 {
		t.Fatalf("check: %v %v", bad, err)
	}
	if status, body := groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+token, v.Strict.Valid[0].Entry); status != 200 {
		t.Fatalf("valid rename: %d %s", status, body)
	}
	raw, _ := json.Marshal(v.Strict.Invalid[0].Entry)
	if _, err := f.s.Store.DB.Exec("INSERT INTO group_entries VALUES('example','vectors',4,?)", string(raw)); err != nil {
		t.Fatal(err)
	}
	if bad, err := f.s.Store.CheckGroups(); err != nil || len(bad) != 1 || bad[0] != "example/vectors@4" {
		t.Fatalf("check missed stored entry: %v %v", bad, err)
	}
}

const phoneSigningKey = "7be9c6f9a7247a5531a40e0883aa93e2246c034f94d031008b56205d78950753"

package ledger

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAutomaticAdmissionVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../protocol/v2/group-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Initial SignedEntry `json:"initial"`
		Auto    struct {
			Approved SignedEntry `json:"approved"`
			Invalid  []struct {
				Case  string      `json:"case"`
				Entry SignedEntry `json:"entry"`
			} `json:"invalid"`
		} `json:"auto_admission"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if _, err = validateAutoTransition(vectors.Initial, vectors.Auto.Approved); err != nil {
		t.Fatal(err)
	}
	for _, test := range vectors.Auto.Invalid {
		t.Run(test.Case, func(t *testing.T) {
			if _, err := validateAutoTransition(vectors.Initial, test.Entry); err == nil {
				t.Fatal("accepted unauthorized delegated transition")
			}
		})
	}
	if _, err = validateAutoTransition(vectors.Auto.Approved, vectors.Auto.Approved); err == nil {
		t.Fatal("accepted replay")
	}
}

func TestInviteGrantAndLinkCascadeWithInvitation(t *testing.T) {
	f := setup(t)
	db := f.s.Store.DB
	if _, err := db.Exec("INSERT INTO v2_ledger_invites(id,app,grp,owner,secret_hash,expires) VALUES('old','example','test','mac','hash',123)"); err != nil {
		t.Fatal(err)
	}
	var count int
	if _, err := db.Exec("INSERT INTO v2_ledger_invite_grants VALUES('old','{}'); INSERT INTO v2_ledger_invite_links VALUES('old','hash','ciphertext'); DELETE FROM v2_ledger_invites WHERE id='old'"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM v2_ledger_invite_links").Scan(&count); err != nil || count != 0 {
		t.Fatal("link not revoked with invitation", err)
	}
	if err := db.QueryRow("SELECT count(*) FROM v2_ledger_invite_grants").Scan(&count); err != nil || count != 0 {
		t.Fatal("grant not revoked with invitation", err)
	}
}

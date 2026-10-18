package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAutomaticAdmissionVectors(t *testing.T) {
	raw, err := os.ReadFile("../../protocol/group-vectors.json")
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

func TestInviteGrantSchemaUpgradeAndCascade(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the previous schema. Reopening must upgrade without replacing data.
	if _, err = s.DB.Exec("DROP TABLE group_invite_links; DROP TABLE group_invite_grants; INSERT INTO group_invites(id,app,grp,owner,secret_hash,expires) VALUES('old','example','test','mac','hash',123)"); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM group_invites WHERE id='old'").Scan(&count); err != nil || count != 1 {
		t.Fatal("legacy invite lost", err)
	}
	if _, err = s.DB.Exec("INSERT INTO group_invite_grants VALUES('old','{}'); INSERT INTO group_invite_links VALUES('old','hash','ciphertext'); DELETE FROM group_invites WHERE id='old'"); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM group_invite_links").Scan(&count); err != nil || count != 0 {
		t.Fatal("link not revoked with invitation", err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM group_invite_grants").Scan(&count); err != nil || count != 0 {
		t.Fatal("grant not revoked with invitation", err)
	}
}

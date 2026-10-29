package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestGroupVectors(t *testing.T) {
	b, err := os.ReadFile("../../protocol/group-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Config                                                                                                              GroupConfig `json:"config"`
		Manager                                                                                                             GroupMember `json:"manager"`
		NewMember                                                                                                           GroupMember `json:"new_member"`
		Initial, Request, Approved, Removed, SelfService, Left, Disbanded, UnauthorizedDisband, Renamed, UnauthorizedRename GroupEntry
		Auto                                                                                                                struct {
			Grant, Approved GroupEntry
			Invalid         []struct {
				Case  string
				Entry GroupEntry
			}
		} `json:"auto_admission"`
		Strict struct {
			Valid, Invalid, InvalidAuto []struct {
				Case  string
				Entry GroupEntry
			} `json:"-"`
		} `json:"-"`
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for key, dst := range map[string]*GroupEntry{"self_service": &v.SelfService, "unauthorized_disband": &v.UnauthorizedDisband, "unauthorized_rename": &v.UnauthorizedRename} {
		if err = json.Unmarshal(raw[key], dst); err != nil {
			t.Fatal(err)
		}
	}
	k, err := decodeKey(v.Config.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(groupSigningKey(k).Public().(ed25519.PublicKey)) != v.Manager.SigningKey {
		t.Fatal("signing derivation mismatch")
	}
	if groupVerify(v.Initial, v.Manager.SigningKey) != nil || groupVerify(v.Request, v.NewMember.SigningKey) != nil {
		t.Fatal("signature mismatch")
	}
	s, err := groupState(v.SelfService)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := groupMember(s, v.SelfService.Signer)
	if !ok || groupVerify(v.SelfService, m.SigningKey) != nil {
		t.Fatal("self service signature")
	}
	for _, tc := range []struct {
		name      string
		old, next GroupEntry
		valid     bool
	}{{"approved", v.Initial, v.Approved, true}, {"removed", v.Approved, v.Removed, true}, {"left", v.Approved, v.Left, true}, {"disbanded", v.Approved, v.Disbanded, true}, {"renamed", v.Approved, v.Renamed, true}, {"unauthorized_disband", v.Approved, v.UnauthorizedDisband, false}, {"unauthorized_rename", v.Approved, v.UnauthorizedRename, false}, {"broken_chain", v.Initial, v.Removed, false}, {"auto", v.Initial, v.Auto.Approved, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if (VerifyGroupAdvance(tc.old, tc.next) == nil) != tc.valid {
				t.Fatal("unexpected result")
			}
		})
	}
	for _, tc := range v.Auto.Invalid {
		t.Run("auto/"+tc.Case, func(t *testing.T) {
			if VerifyGroupAdvance(v.Initial, tc.Entry) == nil {
				t.Fatal("accepted invalid")
			}
		})
	}
	var sections map[string]json.RawMessage
	if err = json.Unmarshal(raw["strict_payload"], &sections); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid", "invalid", "invalid_auto"} {
		var cases []struct {
			Case  string
			Entry GroupEntry
		}
		if err = json.Unmarshal(sections[name], &cases); err != nil {
			t.Fatal(err)
		}
		for _, tc := range cases {
			t.Run("strict/"+name+"/"+tc.Case, func(t *testing.T) {
				old := v.Approved
				if name == "invalid_auto" {
					old = v.Initial
				}
				if (VerifyGroupAdvance(old, tc.Entry) == nil) != (name == "valid") {
					t.Fatal("unexpected result")
				}
			})
		}
	}
}

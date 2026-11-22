package ledger

import (
	"encoding/json"
	"fmt"
)

// Problem names one ledger row that fails verification.
type Problem struct {
	Where  string `json:"where"` // app/group@revision
	Reason string `json:"reason"`
}

// CheckReport summarizes `common-relay check`.
type CheckReport struct {
	Groups        int       `json:"groups"`
	Entries       int       `json:"entries"`
	Devices       int       `json:"devices"`
	ActiveDevices int       `json:"active_devices"`
	Files         int       `json:"files"`
	Imported      bool      `json:"legacy_imported"`
	Problems      []Problem `json:"problems"`
}

// Check verifies every stored entry against the strict payload rules, that each
// row's payload names its own app/group/revision, that revisions run 1..n
// without gaps and that every entry links to the digest of its predecessor.
func (s *Store) Check() (CheckReport, error) {
	rep := CheckReport{Problems: []Problem{}}
	rows, err := s.DB.Query("SELECT app,grp,revision,entry FROM v2_ledger_entries ORDER BY app,grp,revision")
	if err != nil {
		return rep, err
	}
	defer rows.Close()
	var curApp, curGroup, prevDigest string
	prevRevision := 0
	for rows.Next() {
		var app, group, raw string
		var revision int
		if err = rows.Scan(&app, &group, &revision, &raw); err != nil {
			return rep, err
		}
		rep.Entries++
		if app != curApp || group != curGroup {
			rep.Groups++
			curApp, curGroup, prevDigest, prevRevision = app, group, "", 0
		}
		where := fmt.Sprintf("%s/%s@%d", app, group, revision)
		bad := func(reason string) { rep.Problems = append(rep.Problems, Problem{where, reason}) }
		if revision != prevRevision+1 {
			bad(fmt.Sprintf("revision gap after %d", prevRevision))
		}
		prevRevision = revision
		var e SignedEntry
		var g GroupState
		var b []byte
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			bad("entry is not JSON")
			prevDigest = ""
			continue
		}
		if b, err = e.bytes(); err == nil {
			g, err = e.state()
		}
		if err != nil {
			bad("strict payload rules")
			prevDigest = ""
			continue
		}
		if e.Authorization != nil {
			var grant AdmissionGrant
			ab, aerr := e.Authorization.bytes()
			if aerr != nil || decodeStrict(ab, grantSchema, &grant) != nil {
				bad("authorization violates strict payload rules")
			}
		}
		if g.App != app || g.Group != group || g.Revision != revision {
			bad("payload app/group/revision differs from its row")
		}
		if revision == 1 && g.Previous != "" {
			bad("root entry has a previous digest")
		}
		if revision > 1 && prevDigest != "" && g.Previous != prevDigest {
			bad("previous digest does not match the preceding entry")
		}
		prevDigest = digest(b)
	}
	if err = rows.Err(); err != nil {
		return rep, err
	}
	rows.Close()
	_ = s.DB.QueryRow(`SELECT count(*), COALESCE(SUM(revoked=0),0) FROM v2_ledger_devices`).Scan(&rep.Devices, &rep.ActiveDevices)
	_ = s.DB.QueryRow(`SELECT count(*) FROM v2_ledger_files`).Scan(&rep.Files)
	rep.Imported = s.imported()
	return rep, nil
}

// CheckGroups lists the rows (app/group@revision) that fail Check.
func (s *Store) CheckGroups() ([]string, error) {
	rep, err := s.Check()
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range rep.Problems {
		if !seen[p.Where] {
			seen[p.Where] = true
			out = append(out, p.Where)
		}
	}
	return out, nil
}

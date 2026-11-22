package ledger

import (
	"database/sql"
	"encoding/json"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
)

// mirrorTx writes group state g into the v2 space tables inside tx (the same
// transaction that commits the signed entry). The mirror runs in a savepoint:
// if it cannot be applied (for instance the group ID is an admin-owned space)
// the signed ledger still commits, exactly as before the stores were merged,
// and the reason is logged. It reports whether the mirror was applied.
func mirrorTx(tx *sql.Tx, g GroupState, removed []Member) bool {
	if _, err := tx.Exec(`SAVEPOINT ledger_mirror`); err != nil {
		logProjection(g, err)
		return false
	}
	err := func() error {
		var members []core.ManagedMember
		if !g.Closed {
			for _, m := range g.Members {
				var tokenHash string
				err := tx.QueryRow("SELECT token_hash FROM v2_ledger_devices WHERE app=? AND grp=? AND id=? AND revoked=0", g.App, g.Group, m.Device).Scan(&tokenHash)
				if err == sql.ErrNoRows {
					continue // legacy member without an active credential
				}
				if err != nil {
					return err
				}
				members = append(members, core.ManagedMember{ID: m.Device, Name: m.Name, PublicKey: m.PublicKey, TokenHash: tokenHash, Manager: m.Manager})
			}
		}
		ids := make([]string, 0, len(removed))
		for _, m := range removed {
			ids = append(ids, m.Device)
		}
		return core.SyncManagedGroupTx(tx, g.Group, g.App, g.Name, members, ids, g.Closed)
	}()
	if err != nil {
		_, _ = tx.Exec(`ROLLBACK TO ledger_mirror`)
		_, _ = tx.Exec(`RELEASE ledger_mirror`)
		logProjection(g, err)
		return false
	}
	if _, err := tx.Exec(`RELEASE ledger_mirror`); err != nil {
		logProjection(g, err)
		return false
	}
	return true
}

// mirrorAllTx re-applies the latest state of every open group. It runs after
// the legacy import and at startup, healing spaces an administrator removed.
func mirrorAllTx(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT entry FROM v2_ledger_entries ge WHERE revision = (SELECT MAX(revision) FROM v2_ledger_entries WHERE app = ge.app AND grp = ge.grp) ORDER BY app, grp`)
	if err != nil {
		return err
	}
	var states []GroupState
	for rows.Next() {
		var raw string
		var e SignedEntry
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if json.Unmarshal([]byte(raw), &e) != nil {
			continue
		}
		if g, err := e.state(); err == nil && !g.Closed {
			states = append(states, g)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, g := range states {
		mirrorTx(tx, g, nil)
	}
	return nil
}

// MirrorAll re-applies every open group's membership to its v2 space.
func (s *Store) MirrorAll() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := mirrorAllTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

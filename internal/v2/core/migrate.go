package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// SchemaVersion is the relay_v2.db schema version this binary understands.
// Migrations are ordered and each runs exactly once, tracked by PRAGMA user_version.
const SchemaVersion = 4

// migrations[i] upgrades the schema from version i to i+1.
var migrations = []func(tx *sql.Tx) error{
	// 0 → 1: v2_spaces.app (databases created before the app namespace existed).
	func(tx *sql.Tx) error {
		return addColumnIfMissing(tx, "v2_spaces", "app", `TEXT NOT NULL DEFAULT ''`)
	},
	// 1 → 2: provenance. Rows projected from v1 signed groups are tagged so the
	// sync path can never merge into (or take over) spaces/devices it does not own.
	func(tx *sql.Tx) error {
		if err := addColumnIfMissing(tx, "v2_spaces", "managed_by", `TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		if err := addColumnIfMissing(tx, "v2_devices", "managed_by", `TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		// Legacy projected spaces are the strict_e2e spaces carrying an app namespace
		// (the admin API cannot set app).
		if _, err := tx.Exec(`UPDATE v2_spaces SET managed_by='v1:'||app
			WHERE managed_by='' AND app<>'' AND trust_level='strict_e2e'`); err != nil {
			return err
		}
		// Non-admin devices whose memberships include a projected space belong to
		// the first such group.
		_, err := tx.Exec(`UPDATE v2_devices SET managed_by = (
				SELECT sp.managed_by||':'||sp.id FROM v2_space_members m
				JOIN v2_spaces sp ON sp.id=m.space_id
				WHERE m.device_id=v2_devices.id AND sp.managed_by<>''
				ORDER BY m.added_at, sp.id LIMIT 1)
			WHERE managed_by='' AND is_admin=0 AND EXISTS (
				SELECT 1 FROM v2_space_members m JOIN v2_spaces sp ON sp.id=m.space_id
				WHERE m.device_id=v2_devices.id AND sp.managed_by<>'')`)
		return err
	},
	// 2 → 3: write-only plugin secrets, config versioning, idempotency receipts.
	func(tx *sql.Tx) error {
		if err := addColumnIfMissing(tx, "v2_plugin_bindings", "secrets_json", `TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		if err := addColumnIfMissing(tx, "v2_plugin_bindings", "config_version", `INTEGER NOT NULL DEFAULT 1`); err != nil {
			return err
		}
		if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS v2_plugin_receipts (
			binding_id TEXT NOT NULL REFERENCES v2_plugin_bindings(id) ON DELETE CASCADE,
			key TEXT NOT NULL,
			item_id TEXT NOT NULL,
			seq INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (binding_id, key)
		)`); err != nil {
			return err
		}
		// Move legacy secret keys out of config_json. They stay plaintext in the
		// (not yet keyed) secrets column here; Store.sealPendingSecrets encrypts
		// them on open once the secrets key is loaded.
		rows, err := tx.Query(`SELECT id, config_json FROM v2_plugin_bindings`)
		if err != nil {
			return err
		}
		type mv struct{ id, pub, sec string }
		var moves []mv
		for rows.Next() {
			var id, raw string
			if err := rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return err
			}
			pub, sec := splitLegacySecrets(raw)
			if sec != "" {
				moves = append(moves, mv{id, pub, sec})
			}
		}
		rows.Close()
		for _, m := range moves {
			if _, err := tx.Exec(`UPDATE v2_plugin_bindings SET config_json=?, secrets_json=? WHERE id=?`, m.pub, legacyPlainPrefix+m.sec, m.id); err != nil {
				return err
			}
		}
		return nil
	},
	// 3 → 4: O(1) quota accounting. Triggers keep per-space byte counters exact
	// for every insert/delete, including FK cascades.
	func(tx *sql.Tx) error {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS v2_usage (space_id TEXT PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0)`,
			`DELETE FROM v2_usage`,
			`INSERT INTO v2_usage(space_id, bytes)
			   SELECT space_id, SUM(sz) FROM (
			     SELECT space_id, size AS sz FROM v2_box_items
			     UNION ALL SELECT space_id, size FROM v2_box_objects
			     UNION ALL SELECT space_id, length(body) FROM v2_messages
			   ) GROUP BY space_id`,
		}
		for _, t := range []struct{ table, size string }{
			{"v2_box_items", "size"}, {"v2_box_objects", "size"}, {"v2_messages", "length(%s.body)"},
		} {
			sz := func(row string) string {
				if strings.Contains(t.size, "%s") {
					return fmt.Sprintf(t.size, row)
				}
				return row + "." + t.size
			}
			stmts = append(stmts,
				fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS %[1]s_usage_ins AFTER INSERT ON %[1]s BEGIN
					INSERT INTO v2_usage(space_id, bytes) VALUES (NEW.space_id, %[2]s)
					ON CONFLICT(space_id) DO UPDATE SET bytes = bytes + %[2]s; END`, t.table, sz("NEW")),
				fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS %[1]s_usage_del AFTER DELETE ON %[1]s BEGIN
					UPDATE v2_usage SET bytes = bytes - %[2]s WHERE space_id = OLD.space_id; END`, t.table, sz("OLD")),
			)
		}
		for _, q := range stmts {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		return nil
	},
}

const legacyPlainPrefix = "plain:"

func migrate(db *sql.DB) error {
	var ver int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	if ver > SchemaVersion {
		return fmt.Errorf("relay_v2.db schema version %d is newer than this binary (%d); refusing to start", ver, SchemaVersion)
	}
	for ; ver < SchemaVersion; ver++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := migrations[ver](tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate relay_v2.db %d→%d: %w", ver, ver+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, ver+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func addColumnIfMissing(tx *sql.Tx, table, column, decl string) error {
	rows, err := tx.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	_, err = tx.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, decl))
	return err
}

// legacySecretKeys are the config keys earlier releases stored inline.
var legacySecretKeys = []string{"token_sha256", "hmac_secret"}

func splitLegacySecrets(raw string) (pub string, sec string) {
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil || m == nil {
		return raw, ""
	}
	secrets := map[string]any{}
	for _, k := range legacySecretKeys {
		if v, ok := m[k]; ok {
			secrets[k] = v
			delete(m, k)
		}
	}
	if len(secrets) == 0 {
		return raw, ""
	}
	p, _ := json.Marshal(m)
	s, _ := json.Marshal(secrets)
	return string(p), string(s)
}

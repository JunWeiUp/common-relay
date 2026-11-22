package ledger

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LegacyImportSetting marks (in v2_settings) that <data>/relay.db was imported.
const LegacyImportSetting = "ledger_legacy_import"

// LegacyDB is the database of releases before the single store. It is read
// once and then left on disk untouched, together with <data>/files/, as a backup.
const LegacyDB = "relay.db"

// ImportResult describes one legacy import.
type ImportResult struct {
	Source     string `json:"source"`
	At         int64  `json:"at"`
	Groups     int    `json:"groups"`
	Entries    int    `json:"entries"`
	Devices    int    `json:"devices"`
	Invites    int    `json:"invites"`
	Bootstrap  int    `json:"bootstrap"`
	Creations  int    `json:"creations"`
	Files      int    `json:"files"`
	Payloads   int    `json:"payloads"`
	Skipped    bool   `json:"-"` // nothing to do (no relay.db, or already imported)
	SkipReason string `json:"-"`
}

func (s *Store) imported() bool {
	var v string
	return s.DB.QueryRow(`SELECT value FROM v2_settings WHERE key=?`, LegacyImportSetting).Scan(&v) == nil
}

// legacyTable lists the columns copied from relay.db; the v2_ledger_* tables
// have the same columns in the same order (devices.token became token_hash).
type legacyTable struct {
	from, to, cols string
	required       bool
}

var legacyTables = []legacyTable{
	{"devices", "v2_ledger_devices", "app,grp,id,token,public_key,revoked", true},
	{"group_entries", "v2_ledger_entries", "app,grp,revision,entry", false},
	{"group_creations", "v2_ledger_creations", "app,grp,created", false},
	{"group_bootstrap", "v2_ledger_bootstrap", "token_hash,app,grp,expires", false},
	{"group_invites", "v2_ledger_invites", "id,app,grp,owner,secret_hash,expires,request,token_hash,approved", false},
	{"group_invite_grants", "v2_ledger_invite_grants", "id,grant_entry", false},
	{"group_invite_links", "v2_ledger_invite_links", "id,read_hash,packet", false},
	{"files", "v2_ledger_files", "id,app,grp,sender,recipient,size,offset,metadata,digest,state,expires", false},
}

// ImportLegacy copies the ledger and file plane of <data>/relay.db (and the
// payloads in <data>/files/) into the v2 store in one transaction, then mirrors
// every open group into its v2 space (merging with the rows the old projection
// created: same device ID and token hash, admin devices untouched). It is a
// no-op when relay.db is absent or the import already completed. On any error
// nothing is committed and copied payloads are removed.
func (s *Store) ImportLegacy() (ImportResult, error) {
	res := ImportResult{Source: LegacyDB}
	src := filepath.Join(s.Dir, LegacyDB)
	if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
		res.Skipped, res.SkipReason = true, "no relay.db"
		return res, nil
	} else if err != nil {
		return res, err
	}
	if s.imported() {
		res.Skipped, res.SkipReason = true, "already imported"
		return res, nil
	}
	legacy, err := sql.Open("sqlite", "file:"+src+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return res, err
	}
	defer legacy.Close()
	legacy.SetMaxOpenConns(1)
	present := map[string]bool{}
	names, err := legacy.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return res, fmt.Errorf("read %s: %w", LegacyDB, err)
	}
	for names.Next() {
		var n string
		if err := names.Scan(&n); err != nil {
			names.Close()
			return res, err
		}
		present[n] = true
	}
	names.Close()

	// Read everything first (production holds a few hundred rows); the v2 store
	// has a single connection, so the copy below never interleaves two databases.
	data := map[string][][]any{}
	for _, t := range legacyTables {
		if !present[t.from] {
			if t.required {
				return res, fmt.Errorf("%s has no %s table", LegacyDB, t.from)
			}
			continue
		}
		rows, err := legacy.Query(fmt.Sprintf(`SELECT %s FROM %s`, t.cols, t.from))
		if err != nil {
			return res, fmt.Errorf("read %s.%s: %w", LegacyDB, t.from, err)
		}
		n := len(strings.Split(t.cols, ","))
		for rows.Next() {
			vals := make([]any, n)
			ptrs := make([]any, n)
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return res, err
			}
			data[t.from] = append(data[t.from], vals)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return res, err
		}
	}
	legacy.Close()

	var copied []string
	fail := func(err error) (ImportResult, error) {
		for _, p := range copied {
			_ = os.Remove(p)
		}
		return res, fmt.Errorf("import %s: %w", LegacyDB, err)
	}
	// Payloads are copied (never moved) before the commit; a failed commit removes them.
	for _, row := range data["files"] {
		id, _ := row[0].(string)
		if !objectID.MatchString(id) {
			return fail(fmt.Errorf("invalid file id %q", id))
		}
		from := filepath.Join(s.Dir, "files", id)
		to := filepath.Join(FilesDir(s.Dir), id)
		ok, err := copyPayload(from, to)
		if err != nil {
			return fail(err)
		}
		if ok {
			copied = append(copied, to)
			res.Payloads++
		}
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	var marker int
	if err := tx.QueryRow(`SELECT count(*) FROM v2_settings WHERE key=?`, LegacyImportSetting).Scan(&marker); err != nil {
		return fail(err)
	}
	if marker != 0 {
		res.Skipped, res.SkipReason = true, "already imported"
		copied = nil // rows exist: keep their payloads
		return res, nil
	}
	for _, t := range legacyTables {
		rows := data[t.from]
		if len(rows) == 0 {
			continue
		}
		cols := t.cols
		if t.from == "devices" {
			cols = strings.Replace(cols, ",token,", ",token_hash,", 1)
		}
		ph := strings.TrimSuffix(strings.Repeat("?,", len(rows[0])), ",")
		stmt, err := tx.Prepare(fmt.Sprintf(`INSERT INTO %s(%s) VALUES(%s)`, t.to, cols, ph))
		if err != nil {
			return fail(err)
		}
		for _, r := range rows {
			if _, err := stmt.Exec(r...); err != nil {
				stmt.Close()
				return fail(fmt.Errorf("%s → %s: %w", t.from, t.to, err))
			}
		}
		stmt.Close()
	}
	if err := mirrorAllTx(tx); err != nil {
		return fail(err)
	}
	res.Entries = len(data["group_entries"])
	res.Devices = len(data["devices"])
	res.Invites = len(data["group_invites"])
	res.Bootstrap = len(data["group_bootstrap"])
	res.Creations = len(data["group_creations"])
	res.Files = len(data["files"])
	if err := tx.QueryRow(`SELECT count(*) FROM (SELECT DISTINCT app,grp FROM v2_ledger_entries)`).Scan(&res.Groups); err != nil {
		return fail(err)
	}
	res.At = time.Now().Unix()
	summary, _ := json.Marshal(res)
	if _, err := tx.Exec(`INSERT INTO v2_settings(key,value,updated_at) VALUES(?,?,?)`, LegacyImportSetting, string(summary), res.At); err != nil {
		return fail(err)
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	return res, nil
}

// copyPayload copies from → to through a temporary file (0600, fsync, rename).
// A missing source is not an error: the row then behaves as a lost upload.
func copyPayload(from, to string) (bool, error) {
	in, err := os.Open(from)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(to), ".import-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0o600); err == nil {
		if _, err = io.Copy(tmp, in); err == nil {
			err = tmp.Sync()
		}
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), to)
}

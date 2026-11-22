package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/ledger"
	_ "modernc.org/sqlite"
)

// backupPrefix names snapshot directories so pruning never touches anything else.
const backupPrefix = "common-relay-"

// backupDatabases are copied with VACUUM INTO: a transactionally consistent
// snapshot taken while the service keeps running (WAL readers do not block it).
// relay_v2.db is the single store; relay.db is the pre-merge database, kept
// only while it still exists on disk (it is read once, then never written).
var backupDatabases = []string{"relay_v2.db", "relay.db"}

// backupFiles and backupDirs are copied as-is: blobs/ (v2 blobs and, under
// blobs/files/, ledger file payloads) and the legacy files/ directory if present.
// Finished blobs are immutable, so hard links are used when the target shares a
// filesystem and the snapshot then costs almost no space. Ledger payloads grow
// in place while uploading, so mutableDirs are always copied, never linked.
var (
	backupFiles = []string{"plugin-secrets.key"}
	backupDirs  = []string{"blobs", "files"}
	mutableDirs = map[string]bool{filepath.Join("blobs", "files"): true}
)

// runBackup writes <out>/common-relay-<UTC timestamp>/ and keeps the newest keep
// snapshots. It returns the new snapshot path.
func runBackup(dataDir, outDir string, keep int, now time.Time) (string, error) {
	if dataDir == "" || outDir == "" {
		return "", errors.New("backup needs --data and --out")
	}
	if abs, _ := filepath.Abs(outDir); strings.HasPrefix(abs+string(os.PathSeparator), mustAbs(dataDir)+string(os.PathSeparator)) {
		return "", errors.New("--out must not be inside --data")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", err
	}
	name := backupPrefix + now.UTC().Format("20060102T150405Z")
	final := filepath.Join(outDir, name)
	tmp := final + ".partial"
	_ = os.RemoveAll(tmp)
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return "", err
	}
	fail := func(err error) (string, error) { _ = os.RemoveAll(tmp); return "", err }

	for _, db := range backupDatabases {
		src := filepath.Join(dataDir, db)
		if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := vacuumInto(src, filepath.Join(tmp, db)); err != nil {
			return fail(fmt.Errorf("snapshot %s: %w", db, err))
		}
	}
	for _, f := range backupFiles {
		if err := copyFile(filepath.Join(dataDir, f), filepath.Join(tmp, f), false); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(err)
		}
	}
	for _, d := range backupDirs {
		if err := copyTree(filepath.Join(dataDir, d), filepath.Join(tmp, d), d); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(err)
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		return fail(err)
	}
	if keep > 0 {
		if err := pruneBackups(outDir, keep); err != nil {
			return final, err
		}
	}
	return final, nil
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func vacuumInto(src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+src+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`VACUUM INTO ?`, dst); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return err
	}
	var res string
	check, err := sql.Open("sqlite", "file:"+dst+"?mode=ro")
	if err != nil {
		return err
	}
	defer check.Close()
	if err := check.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("integrity_check: %s", res)
	}
	return nil
}

// copyTree copies src (the data-dir relative path name) into dst.
func copyTree(src, dst, name string) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(p, target, !mutableDirs[filepath.Dir(filepath.Join(name, rel))])
	})
}

func copyFile(src, dst string, allowLink bool) error {
	if allowLink {
		if err := os.Link(src, dst); err == nil {
			return nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func pruneBackups(outDir string, keep int) error {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return err
	}
	var snaps []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), backupPrefix) && !strings.HasSuffix(e.Name(), ".partial") {
			snaps = append(snaps, e.Name())
		}
	}
	sort.Strings(snaps) // timestamp names sort chronologically
	for len(snaps) > keep {
		if err := os.RemoveAll(filepath.Join(outDir, snaps[0])); err != nil {
			return err
		}
		snaps = snaps[1:]
	}
	return nil
}

// schemaReport tells deploy tooling whether a new binary will migrate the data
// (and therefore whether a rollback must restore the pre-deploy snapshot).
// ledger_imported is 1 once a legacy relay.db has been merged into relay_v2.db.
func schemaReport(dataDir string) (map[string]int, error) {
	out := map[string]int{"binary_v2": v2core.SchemaVersion, "data_v2": 0, "ledger_imported": 0}
	p := filepath.Join(dataDir, "relay_v2.db")
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	db, err := sql.Open("sqlite", "file:"+p+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return nil, err
	}
	out["data_v2"] = v
	var n int
	if db.QueryRow(`SELECT count(*) FROM v2_settings WHERE key=?`, ledger.LegacyImportSetting).Scan(&n) == nil && n > 0 {
		out["ledger_imported"] = 1
	}
	return out, nil
}

func printJSON(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}

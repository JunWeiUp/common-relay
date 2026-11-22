package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
)

func TestBackupSnapshotsLiveStoreAndPrunes(t *testing.T) {
	data := t.TempDir()
	st, err := v2core.OpenStore(data)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateSpace("personal", "Personal", v2core.TrustBridgeAllowed); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "blobs", "ab"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(data, "plugin-secrets.key"), []byte("k"), 0o600)
	// Ledger payloads grow in place while uploading: they must be copied, not linked.
	if err := os.MkdirAll(filepath.Join(data, "blobs", "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "blobs", "files", "f1"), []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Keep writing while snapshots are taken: VACUUM INTO must not block or tear.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = st.CreateSpace("s"+strings.Repeat("x", i%5)+string(rune('a'+i%26)), "", v2core.TrustBridgeAllowed)
			time.Sleep(time.Millisecond)
		}
	}()

	out := t.TempDir()
	base := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	var last string
	for i := 0; i < 4; i++ {
		p, err := runBackup(data, out, 3, base.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	close(stop)
	<-done

	entries, _ := os.ReadDir(out)
	if len(entries) != 3 || !strings.HasSuffix(last, "common-relay-20261122T030000Z") {
		t.Fatalf("kept %d snapshots, last %s", len(entries), last)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(last, "relay_v2.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM v2_spaces WHERE id='personal'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("snapshot content: n=%d err=%v", n, err)
	}
	if b, err := os.ReadFile(filepath.Join(last, "blobs", "ab")); err != nil || string(b) != "payload" {
		t.Fatalf("blob copy: %q %v", b, err)
	}
	src, _ := os.Stat(filepath.Join(data, "blobs", "files", "f1"))
	if fi, err := os.Stat(filepath.Join(last, "blobs", "files", "f1")); err != nil || os.SameFile(src, fi) {
		t.Fatalf("ledger payload must be an independent copy: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(last, "relay_v2.db")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot db perm: %v %v", fi, err)
	}
	rep, err := schemaReport(last)
	if err != nil || rep["data_v2"] != v2core.SchemaVersion || rep["binary_v2"] != v2core.SchemaVersion || rep["ledger_imported"] != 0 {
		t.Fatalf("schema report = %v %v", rep, err)
	}
	if _, err := runBackup(data, filepath.Join(data, "inside"), 1, base); err == nil {
		t.Fatal("--out inside --data must be refused")
	}
}

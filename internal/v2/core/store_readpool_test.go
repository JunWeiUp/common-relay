package core

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// within fails the test if fn does not return before d (a blocked read would
// otherwise hang the whole package).
func within(t *testing.T, d time.Duration, what string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s blocked for %v behind an open write transaction", what, d)
	}
}

func TestReadPoolNotBlockedByOpenWriteTx(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.RDB == nil || st.RDB == st.DB {
		t.Fatal("store must open a separate read pool")
	}
	_, token, err := st.CreateDevice("dev-a", "A", strings.Repeat("ab", 32), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSpace("sp", "Space", TrustStrictE2E); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetSpaceMember("sp", "dev-a", RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateBox(Box{SpaceID: "sp", Name: "q", Mode: ModeQueue}); err != nil {
		t.Fatal(err)
	}
	item, err := st.PutBoxItem("sp", "q", "dev-a", "", "", 0, strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Hold the single writer connection with an uncommitted write, exactly like a
	// slow import or ledger transaction would.
	tx, err := st.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO v2_spaces(id,name,trust_level,created_at) VALUES('pending','',?,0)`, string(TrustStrictE2E)); err != nil {
		t.Fatal(err)
	}

	const limit = 3 * time.Second
	within(t, limit, "Status", func() error {
		s, err := st.Status(0, nil)
		if err == nil && (s.Spaces != 1 || s.PendingItems != 1) {
			t.Errorf("status must show committed state only: %+v", s)
		}
		return err
	})
	within(t, limit, "ListSpaces", func() error {
		sp, err := st.ListSpaces()
		if err == nil && len(sp) != 1 {
			t.Errorf("uncommitted space leaked into reader: %+v", sp)
		}
		return err
	})
	within(t, limit, "ListBoxItems", func() error {
		items, err := st.ListBoxItems("sp", "q", 0, 10)
		if err == nil && (len(items) != 1 || items[0].ID != item.ID) {
			t.Errorf("items = %+v", items)
		}
		return err
	})
	within(t, limit, "AuthenticateDevice", func() error { _, err := st.AuthenticateDevice(token); return err })
	within(t, limit, "MemberRole", func() error { _, err := st.MemberRole("sp", "dev-a"); return err })
	within(t, limit, "OpenBoxItem", func() error {
		f, _, err := st.OpenBoxItem("sp", "q", item.ID)
		if err == nil {
			f.Close()
		}
		return err
	})

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Read-your-writes across pools: a committed write is visible to the next read.
	sp, err := st.ListSpaces()
	if err != nil || len(sp) != 2 {
		t.Fatalf("committed write not visible to reader: %v %+v", err, sp)
	}
	if err := st.AckBoxItem("sp", "q", item.ID); err != nil {
		t.Fatal(err)
	}
	if items, _ := st.ListBoxItems("sp", "q", 0, 10); len(items) != 0 {
		t.Fatalf("ack not visible to reader: %+v", items)
	}
}

func TestReadPoolIsReadOnly(t *testing.T) {
	// URI-significant characters in the data directory must be escaped in the DSN.
	st, err := OpenStore(filepath.Join(t.TempDir(), "data dir #1 ?x=%20"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RDB.Exec(`INSERT INTO v2_settings(key,value,updated_at) VALUES('x','y',0)`); err == nil {
		t.Fatal("read pool accepted a write")
	}
	if _, err := st.SetSetting("k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, _, ok, err := st.GetSetting("k"); err != nil || !ok || v != "v" {
		t.Fatalf("setting via reader: %q %v %v", v, ok, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.RDB.Ping(); err == nil {
		t.Fatal("Close must close the read pool")
	}
	if err := st.DB.Ping(); err == nil {
		t.Fatal("Close must close the writer")
	}
	// Reopening works (WAL was checkpointed by the writer closing last).
	st2, err := OpenStore(st.Dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
}

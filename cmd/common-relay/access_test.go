package main

import (
	"testing"

	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
)

func TestResolveAccessHashSingleSourceOfTruth(t *testing.T) {
	st, err := v2core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fileA, fileB, admin := v2core.HashSecret("a"), v2core.HashSecret("b"), v2core.HashSecret("admin")

	if h, src, _, _ := resolveAccessHash(st, fileA); h != fileA || src != "file" {
		t.Fatalf("fresh = %s %s", h, src)
	}
	// Admin rotation wins while the file is unchanged.
	st.SetSetting("access_hash", admin)
	if h, src, _, _ := resolveAccessHash(st, fileA); h != admin || src != "db" {
		t.Fatalf("after admin rotation = %s %s", h, src)
	}
	// Operator edits the file: the file wins and becomes the stored value.
	if h, src, _, _ := resolveAccessHash(st, fileB); h != fileB || src != "file" {
		t.Fatalf("after file edit = %s %s", h, src)
	}
	if h, _, _, _ := resolveAccessHash(st, fileB); h != fileB {
		t.Fatalf("restart after file edit = %s", h)
	}
}

func TestResolveAccessHashUpgradeKeepsAdminRotation(t *testing.T) {
	st, err := v2core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	admin := v2core.HashSecret("admin")
	st.SetSetting("access_hash", admin) // set by an older release, no access_file_seen
	if h, src, _, _ := resolveAccessHash(st, v2core.HashSecret("old-file")); h != admin || src != "db" {
		t.Fatalf("upgrade must keep admin rotation, got %s %s", h, src)
	}
}

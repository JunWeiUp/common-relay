package core

import (
	"testing"
)

func TestSyncManagedGroupLifecycleAndAdminSafety(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	// Seed an admin device to verify SyncManagedGroup never revokes or overwrites admin.
	adminPub := RandomHex(32)
	_, adminTok, err := store.CreateDevice("admin-dev", "Admin", adminPub, true)
	if err != nil {
		t.Fatalf("CreateDevice admin: %v", err)
	}

	tokA := RandomHex(32)
	tokB := RandomHex(32)
	pubA := RandomHex(32)
	pubB := RandomHex(32)
	groupID := "g-" + RandomHex(16)

	// 1. Create group with device A.
	if err := store.SyncManagedGroup(groupID, "My Devices", []ManagedMember{
		{ID: "dev-a", Name: "Mac", PublicKey: pubA, TokenHash: HashSecret(tokA)},
	}, nil, false); err != nil {
		t.Fatalf("SyncManagedGroup create: %v", err)
	}
	devA, err := store.AuthenticateDevice(tokA)
	if err != nil || devA.ID != "dev-a" {
		t.Fatalf("AuthenticateDevice(tokA): dev=%+v err=%v", devA, err)
	}
	roleA, err := store.MemberRole(groupID, "dev-a")
	if err != nil || roleA != RoleMember {
		t.Fatalf("MemberRole(dev-a): role=%q err=%v", roleA, err)
	}

	// 2. Add device B.
	if err := store.SyncManagedGroup(groupID, "My Devices", []ManagedMember{
		{ID: "dev-a", Name: "Mac", PublicKey: pubA, TokenHash: HashSecret(tokA)},
		{ID: "dev-b", Name: "Phone", PublicKey: pubB, TokenHash: HashSecret(tokB)},
	}, nil, false); err != nil {
		t.Fatalf("SyncManagedGroup add B: %v", err)
	}
	if _, err := store.AuthenticateDevice(tokB); err != nil {
		t.Fatalf("AuthenticateDevice(tokB): %v", err)
	}

	// 3. Remove device B -> B revoked, A still active.
	if err := store.SyncManagedGroup(groupID, "My Devices", []ManagedMember{
		{ID: "dev-a", Name: "Mac", PublicKey: pubA, TokenHash: HashSecret(tokA)},
	}, []string{"dev-b"}, false); err != nil {
		t.Fatalf("SyncManagedGroup remove B: %v", err)
	}
	if _, err := store.AuthenticateDevice(tokB); err == nil {
		t.Fatal("expected removed dev-b to be rejected")
	}
	if _, err := store.AuthenticateDevice(tokA); err != nil {
		t.Fatalf("expected dev-a still active: %v", err)
	}

	// 4. Disband group -> A also revoked; admin untouched.
	if err := store.SyncManagedGroup(groupID, "My Devices", nil, []string{"admin-dev"}, true); err != nil {
		t.Fatalf("SyncManagedGroup disband: %v", err)
	}
	if _, err := store.AuthenticateDevice(tokA); err == nil {
		t.Fatal("expected disbanded dev-a to be rejected")
	}
	if _, err := store.AuthenticateDevice(adminTok); err != nil {
		t.Fatalf("expected admin-dev untouched: %v", err)
	}
}

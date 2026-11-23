package core

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSyncNeverMergesIntoForeignSpacesOrDevices(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Admin-created space with the same ID as a v1 group must not be taken over.
	if _, err := st.CreateSpace("g-0123456789abcdef", "Admin", TrustBridgeAllowed); err != nil {
		t.Fatal(err)
	}
	tok := RandomHex(32)
	m := []ManagedMember{{ID: "phone", Name: "P", PublicKey: RandomHex(32), TokenHash: HashSecret(tok)}}
	if err := st.SyncManagedGroupWithApp("g-0123456789abcdef", "app-a", "G", m, nil, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("sync into admin space = %v, want ErrConflict", err)
	}

	// Two apps with the same group ID: the second projection is refused.
	if err := st.SyncManagedGroupWithApp("g-1111111111111111", "app-a", "G", m, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SyncManagedGroupWithApp("g-1111111111111111", "app-b", "G", m, nil, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-app sync = %v, want ErrConflict", err)
	}

	// An admin-created device ID is never overwritten by a projection.
	_, adminTok, err := st.CreateDevice("desktop-1", "Desktop", RandomHex(32), false)
	if err != nil {
		t.Fatal(err)
	}
	before := SyncConflicts.Load()
	evil := RandomHex(32)
	if err := st.SyncManagedGroupWithApp("g-2222222222222222", "app-a", "G", []ManagedMember{
		{ID: "desktop-1", Name: "hijack", PublicKey: RandomHex(32), TokenHash: HashSecret(evil)},
	}, nil, false); err != nil {
		t.Fatal(err)
	}
	if SyncConflicts.Load() != before+1 {
		t.Fatal("conflict must be counted")
	}
	if _, err := st.AuthenticateDevice(evil); err == nil {
		t.Fatal("projected token must not replace an admin device token")
	}
	if _, err := st.AuthenticateDevice(adminTok); err != nil {
		t.Fatalf("admin device token broken: %v", err)
	}
	// Removing it via the projection must not revoke it either.
	if err := st.SyncManagedGroupWithApp("g-2222222222222222", "app-a", "G", nil, []string{"desktop-1"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthenticateDevice(adminTok); err != nil {
		t.Fatalf("projection revoked a foreign device: %v", err)
	}
}

func TestUsageCountersTrackInsertsAndDeletes(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateSpace("s1", "S", TrustBridgeAllowed); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureBox(Box{SpaceID: "s1", Name: "q", Mode: ModeQueue}); err != nil {
		t.Fatal(err)
	}
	it, err := st.PutBoxItem("s1", "q", "x", "text/plain", "", 0, io.Reader(strings.NewReader("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := st.UsedBytes(); n != 5 {
		t.Fatalf("used after put = %d", n)
	}
	if err := st.AckBoxItem("s1", "q", it.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.UsedBytes(); n != 0 {
		t.Fatalf("used after ack = %d", n)
	}
}

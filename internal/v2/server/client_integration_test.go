package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
)

func TestV2ClientAndRelayHubEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Admin client configures spaces, hub device, and plugins via v2client.
	admin, err := v2client.New(v2client.Config{
		BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, deskTok, err := admin.CreateDevice(ctx, "hub-host", "Hub Host", fakePubKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	_, vaultTok, err := admin.CreateDevice(ctx, "vault-dev", "Vault Device", fakePubKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CreateSpace(ctx, "personal", "Personal", "bridge_allowed"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CreateSpace(ctx, "vault", "VaultApp", "strict_e2e"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SetSpaceMember(ctx, "personal", "hub-host", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SetSpaceMember(ctx, "vault", "vault-dev", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SetSpaceMember(ctx, "vault", "hub-host", "archive_observer"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CreateBox(ctx, "vault", v2client.Box{Name: "vault", Mode: "object", KeepVersions: 5}); err != nil {
		t.Fatal(err)
	}

	dropSecret := "shortcuts-drop-token-1234567890"
	if _, err := admin.UpsertPlugin(ctx, "drop", "quick", "personal", "drop/quick", map[string]any{
		"token_sha256": v2client.HashSecret(dropSecret),
	}, true); err != nil {
		t.Fatal(err)
	}

	// Start RelayHub (single connection handling both personal Drop queue & vault archive_observer).
	deskClient, err := v2client.New(v2client.Config{
		BaseURL: e.ts.URL, AccessPassword: e.access, Token: deskTok, AllowLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := v2client.NewHub(deskClient)

	dropGot := make(chan string, 1)
	hub.SubscribeBox("personal", "drop/quick", func(ctx context.Context, item v2client.BoxItem, data []byte) error {
		dropGot <- string(data)
		return nil
	})

	vaultArchived := make(chan string, 1)
	hub.SubscribeObject("vault", "vault", func(ctx context.Context, spaceID, boxName, key string, version int64) {
		raw, _, ver, err := deskClient.GetBoxObject(ctx, spaceID, boxName, key)
		if err == nil && ver == version {
			vaultArchived <- string(raw)
		}
	})

	hub.Start(ctx)
	defer hub.Close()

	// Wait until Hub is connected.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := hub.Status(); ok {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if ok, lastErr := hub.Status(); !ok {
		t.Fatalf("hub failed to connect: %s", lastErr)
	}

	// 1. Trigger external Drop POST -> Hub wakes up in real time, delivers bytes, and ACKs!
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/edge/drop/quick?name=note.md", strings.NewReader("hello from shortcut"))
	req.Header.Set("Authorization", "Bearer "+dropSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("drop POST = %v %v", resp, err)
	}
	resp.Body.Close()

	select {
	case got := <-dropGot:
		if got != "hello from shortcut" {
			t.Fatalf("unexpected drop payload: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for hub drop delivery")
	}

	// 2. Vault client writes new encrypted object -> Hub archive_observer auto-fetches ciphertext!
	vaultClient, err := v2client.New(v2client.Config{
		BaseURL: e.ts.URL, AccessPassword: e.access, Token: vaultTok, AllowLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultClient.PutBoxObject(ctx, "vault", "vault", "main.enc", "application/octet-stream", "none", strings.NewReader("VAULT_OPAQUE_CIPHERTEXT_V1")); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-vaultArchived:
		if got != "VAULT_OPAQUE_CIPHERTEXT_V1" {
			t.Fatalf("unexpected vault archived bytes: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for archive_observer wake-up")
	}
}

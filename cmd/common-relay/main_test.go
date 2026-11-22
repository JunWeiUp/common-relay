package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JunWeiUp/common-relay/internal/v2/ledger"
)

func TestInvalidInvocationDoesNotCreateStore(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	for _, command := range [][]string{{"typo"}, {"check", "extra"}, {"serve", "--help"}, {"serve"}} {
		t.Run(command[0], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			os.Args = append([]string{"common-relay", command[0], "--data", dir}, command[1:]...)
			err := run()
			if err == nil {
				t.Fatal("expected argument error or help")
			}
			if command[0] == "serve" && len(command) > 1 && !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("expected help: %v", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("invalid invocation touched data directory: %v", err)
			}
		})
	}
}

func TestServeRequiresV2AdminHash(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	tmp := t.TempDir()
	access := filepath.Join(tmp, "access")
	if err := os.WriteFile(access, []byte(ledger.AccessPasswordHash("correct-horse-1")), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, "must-not-exist")
	for _, removed := range [][]string{{"device-add"}, {"device-revoke"}, {"import-v1"}} {
		os.Args = append([]string{"common-relay"}, removed...)
		if err := run(); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("%s: %v", removed[0], err)
		}
	}
	os.Args = []string{"common-relay", "serve", "--data", dir, "--access-password-file", access}
	if err := run(); err == nil || !strings.Contains(err.Error(), "--v2-admin-hash-file") {
		t.Fatalf("serve without v2 admin hash: %v", err)
	}
	os.Args = []string{"common-relay", "serve", "--data", dir, "--access-password-file", access, "--webhook-config", "x"}
	if err := run(); err == nil {
		t.Fatal("removed --webhook-config flag accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("serve touched data directory: %v", err)
	}
}

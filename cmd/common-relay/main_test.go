package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidInvocationDoesNotCreateStore(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	for _, command := range [][]string{{"typo"}, {"check", "extra"}, {"serve", "--help"}} {
		t.Run(command[0], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			os.Args = append([]string{"common-relay", command[0], "--data", dir}, command[1:]...)
			err := run()
			if err == nil {
				t.Fatal("expected argument error or help")
			}
			if command[0] == "serve" && !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("expected help: %v", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("invalid invocation touched data directory: %v", err)
			}
		})
	}
}

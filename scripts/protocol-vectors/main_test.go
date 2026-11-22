package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestVectorsUpToDate fails when protocol/v2 differs from what the generator emits.
func TestVectorsUpToDate(t *testing.T) {
	dir := filepath.Join("..", "..", "protocol", "v2")
	files, err := Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run go run ./scripts/protocol-vectors", name)
		}
	}
}

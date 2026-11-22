package relay

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestGroupEntryHashVectors checks payload hashing, signature verification and
// the previous-hash chain links of protocol/v2/group-vectors.json.
func TestGroupEntryHashVectors(t *testing.T) {
	b, err := os.ReadFile("../../protocol/v2/group-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	entry := func(path string) GroupEntry {
		parts := strings.Split(path, ".")
		cur := doc
		for _, p := range parts[:len(parts)-1] {
			next := map[string]json.RawMessage{}
			if err := json.Unmarshal(cur[p], &next); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			cur = next
		}
		var e GroupEntry
		if err := json.Unmarshal(cur[parts[len(parts)-1]], &e); err != nil || e.Payload == "" {
			t.Fatalf("%s: missing entry", path)
		}
		return e
	}
	var h struct {
		Cases []struct {
			Entry          string `json:"entry"`
			PayloadSHA256  string `json:"payload_sha256"`
			VerifyKey      string `json:"verify_key"`
			SignatureValid bool   `json:"signature_valid"`
		} `json:"cases"`
		Links []struct{ Base, Next string } `json:"links"`
	}
	if err = json.Unmarshal(doc["entry_hashes"], &h); err != nil || len(h.Cases) == 0 || len(h.Links) == 0 {
		t.Fatalf("entry_hashes missing: %v", err)
	}
	for _, c := range h.Cases {
		e := entry(c.Entry)
		payload, err := groupBytes(e)
		if err != nil || groupDigest(payload) != c.PayloadSHA256 {
			t.Fatalf("%s: payload hash mismatch", c.Entry)
		}
		if (groupVerify(e, c.VerifyKey) == nil) != c.SignatureValid {
			t.Fatalf("%s: signature validity under %s", c.Entry, c.VerifyKey[:8])
		}
	}
	for _, l := range h.Links {
		base, _ := groupBytes(entry(l.Base))
		next, err := groupState(entry(l.Next))
		if err != nil || next.Previous != groupDigest(base) {
			t.Fatalf("%s.previous != sha256(%s): %v", l.Next, l.Base, err)
		}
	}
}

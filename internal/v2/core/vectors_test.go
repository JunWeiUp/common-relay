package core

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestProtocolVectors pins the server's secret hashing, trust matrix and binary
// stream framing to protocol/v2/vectors.json (shared with every SDK).
func TestProtocolVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../protocol/v2/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		HashSecret []struct{ Input, SHA256 string } `json:"hash_secret"`
		Frame      struct {
			StreamID string `json:"stream_id"`
			Payload  string `json:"payload_utf8"`
			FrameHex string `json:"frame_hex"`
		} `json:"binary_stream_frame"`
		Trust []struct {
			Space, Plugin TrustLevel
			Allowed       bool
		} `json:"trust_matrix"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.HashSecret) == 0 || len(v.Trust) != 9 {
		t.Fatal("vectors missing")
	}
	for _, c := range v.HashSecret {
		if HashSecret(c.Input) != c.SHA256 {
			t.Fatalf("HashSecret(%q)", c.Input)
		}
	}
	for _, c := range v.Trust {
		if c.Space.Allows(c.Plugin) != c.Allowed {
			t.Fatalf("%s allows %s != %v", c.Space, c.Plugin, c.Allowed)
		}
	}
	frame, _ := hex.DecodeString(v.Frame.FrameHex)
	if len(v.Frame.StreamID) != 16 || string(frame[:16]) != v.Frame.StreamID || string(frame[16:]) != v.Frame.Payload {
		t.Fatal("binary stream frame")
	}
}

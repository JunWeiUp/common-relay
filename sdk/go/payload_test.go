package relay

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestPayloadStrictVectors(t *testing.T) {
	raw, err := os.ReadFile("../../protocol/group-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(root["strict_payload"], &sections); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"valid", "invalid"} {
		var entries []struct {
			Case  string `json:"case"`
			Entry struct {
				Payload string `json:"payload"`
			} `json:"entry"`
		}
		if err := json.Unmarshal(sections[key], &entries); err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Case == "base64_newline" {
				continue
			}
			t.Run(key+"/"+e.Case, func(t *testing.T) {
				b, err := base64.StdEncoding.DecodeString(e.Entry.Payload)
				if err != nil {
					t.Fatal(err)
				}
				if got := payloadStrict(b, payloadStateSchema); got != (key == "valid") {
					t.Errorf("got %v", got)
				}
			})
		}
	}
}

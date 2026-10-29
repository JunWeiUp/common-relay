package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type libsodiumStreamVector struct {
	Key     string `json:"key"`
	Header  string `json:"header"`
	Records []struct {
		Plain  string `json:"plain"`
		AAD    string `json:"aad"`
		Tag    byte   `json:"tag"`
		Cipher string `json:"cipher"`
	} `json:"records"`
}

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testdata/secretstream-libsodium.json was produced by PyNaCl (libsodium) with
// MESSAGE, PUSH, REKEY and FINAL tags, so this also exercises rekeying.
func TestSecretStreamMatchesLibsodium(t *testing.T) {
	raw, err := os.ReadFile("testdata/secretstream-libsodium.json")
	if err != nil {
		t.Fatal(err)
	}
	var v libsodiumStreamVector
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// Re-encrypt with the same key/header: output must be byte-identical.
	push := &secretStreamPush{}
	copy(push.key[:], unhexT(t, v.Key))
	copy(push.header[:], unhexT(t, v.Header))
	if err = push.state.init(push.key[:], push.header[:]); err != nil {
		t.Fatal(err)
	}
	var pullState secretStreamState
	if err = pullState.init(unhexT(t, v.Key), unhexT(t, v.Header)); err != nil {
		t.Fatal(err)
	}
	for i, r := range v.Records {
		out, err := push.push(unhexT(t, r.Plain), unhexT(t, r.AAD), r.Tag)
		if err != nil || hex.EncodeToString(out) != r.Cipher {
			t.Fatalf("record %d differs from libsodium: %v", i, err)
		}
	}
	// Relay pull accepts only MESSAGE/FINAL, so check the full libsodium
	// sequence with a raw state and the relay pull on the descriptor vector.
	pull := &secretStreamPull{state: pullState}
	for i, r := range v.Records {
		plain, err := pull.pull(unhexT(t, r.Cipher), unhexT(t, r.AAD))
		if r.Tag == secretStreamTagPush || r.Tag == secretStreamTagRekey {
			if err == nil {
				t.Fatalf("record %d: accepted unsupported tag", i)
			}
			// Authenticated but rejected tags do not advance state; replay manually.
			var block [64]byte
			c := unhexT(t, r.Cipher)
			block[0] = c[0]
			pull.state.cipher(1).XORKeyStream(block[:], block[:])
			block[0] = c[0]
			mac := pull.state.mac(unhexT(t, r.AAD), block[:], c[1:len(c)-16])
			pull.state.advance(r.Tag, mac)
			continue
		}
		if err != nil || !bytes.Equal(plain, unhexT(t, r.Plain)) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if !pull.finished {
		t.Fatal("final tag not observed")
	}
	if _, err = pull.pull(unhexT(t, v.Records[0].Cipher), nil); err == nil {
		t.Fatal("accepted data after final")
	}
}

func TestSecretStreamRejectsTamperReorderAndDuplicate(t *testing.T) {
	push, err := newSecretStreamPush()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := push.push([]byte("one"), []byte("a0"), secretStreamTagMessage)
	b, _ := push.push(bytes.Repeat([]byte{7}, streamRecordPlain), []byte("a1"), secretStreamTagFinal)
	if _, err = push.push(nil, nil, secretStreamTagMessage); err == nil {
		t.Fatal("push after final")
	}
	if _, err = push.push(make([]byte, streamRecordPlain+1), nil, 0); err == nil {
		t.Fatal("oversize accepted")
	}
	open := func() *secretStreamPull {
		p, err := newSecretStreamPull(push.descriptor())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := open()
	if _, err = p.pull(b, []byte("a1")); err == nil {
		t.Fatal("reorder accepted")
	}
	tampered := append([]byte(nil), a...)
	tampered[2] ^= 1
	if _, err = p.pull(tampered, []byte("a0")); err == nil {
		t.Fatal("tamper accepted")
	}
	if _, err = p.pull(a, []byte("wrong")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
	if got, err := p.pull(a, []byte("a0")); err != nil || string(got) != "one" {
		t.Fatalf("valid record rejected: %v", err)
	}
	if _, err = p.pull(a, []byte("a0")); err == nil {
		t.Fatal("duplicate accepted")
	}
	if got, err := p.pull(b, []byte("a1")); err != nil || len(got) != streamRecordPlain || !p.finished {
		t.Fatalf("final rejected: %v", err)
	}
	if _, err = newSecretStreamPull(streamDescriptor{Key: "00", Header: push.descriptor().Header}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestSecretStreamCounterWrapRekeys(t *testing.T) {
	var s secretStreamState
	if err := s.init(make([]byte, 32), make([]byte, 24)); err != nil {
		t.Fatal(err)
	}
	s.nonce[0], s.nonce[1], s.nonce[2], s.nonce[3] = 0xff, 0xff, 0xff, 0xff
	before := s.key
	s.advance(secretStreamTagMessage, [16]byte{})
	if s.key == before || s.nonce[0] != 1 {
		t.Fatal("counter wrap did not rekey")
	}
}

package v2client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func readVectors(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("../../../protocol/v2/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestHashSecretVectors(t *testing.T) {
	var v struct {
		HashSecret []struct{ Input, SHA256 string } `json:"hash_secret"`
	}
	readVectors(t, "vectors.json", &v)
	if len(v.HashSecret) == 0 {
		t.Fatal("hash_secret vectors missing")
	}
	for _, c := range v.HashSecret {
		if got := HashSecret(c.Input); got != c.SHA256 {
			t.Fatalf("HashSecret(%q) = %s, want %s", c.Input, got, c.SHA256)
		}
	}
}

func TestSealedVectors(t *testing.T) {
	var v struct {
		ContentType     string `json:"content_type"`
		RecipientPublic string `json:"recipient_public"`
		RecipientSecret string `json:"recipient_private"`
		WrongPublic     string `json:"wrong_public"`
		WrongSecret     string `json:"wrong_private"`
		Valid           []struct {
			Name            string `json:"name"`
			PlaintextHex    *string
			PlaintextLength int    `json:"plaintext_length"`
			PlaintextSHA256 string `json:"plaintext_sha256"`
			SealedB64       string `json:"sealed_b64"`
		} `json:"valid"`
		Invalid []struct {
			Name, Base, Op, Hex string
			Length, Offset      int
		} `json:"invalid"`
	}
	readVectors(t, "sealed-vectors.json", &v)
	if v.ContentType != SealedContentType {
		t.Fatal("content type mismatch")
	}
	pub, _ := ParsePublicKey(v.RecipientPublic)
	priv, _ := ParsePrivateKey(v.RecipientSecret)
	sealed := map[string][]byte{}
	for _, c := range v.Valid {
		b, err := base64.StdEncoding.DecodeString(c.SealedB64)
		if err != nil || !IsSealed(b) {
			t.Fatalf("%s: bad vector", c.Name)
		}
		plain, err := OpenSealed(b, pub, priv)
		sum := sha256.Sum256(plain)
		if err != nil || len(plain) != c.PlaintextLength || hex.EncodeToString(sum[:]) != c.PlaintextSHA256 {
			t.Fatalf("%s: open mismatch: %v", c.Name, err)
		}
		sealed[c.Name] = b
	}
	if len(sealed) < 3 || len(v.Invalid) == 0 {
		t.Fatal("sealed vectors missing")
	}
	for _, c := range v.Invalid {
		b := append([]byte(nil), sealed[c.Base]...)
		switch c.Op {
		case "truncate":
			b = b[:c.Length]
		case "append":
			x, _ := hex.DecodeString(c.Hex)
			b = append(b, x...)
		case "flip":
			b[c.Offset] ^= 1
		default:
			t.Fatalf("%s: unknown op %q", c.Name, c.Op)
		}
		if _, err := OpenSealed(b, pub, priv); err == nil {
			t.Fatalf("%s: opened", c.Name)
		}
	}
	wp, _ := ParsePublicKey(v.WrongPublic)
	ws, _ := ParsePrivateKey(v.WrongSecret)
	if _, err := OpenSealed(sealed["hello"], wp, ws); err == nil {
		t.Fatal("wrong key opened hello")
	}
	if !bytes.Equal(sealed["empty"][:4], []byte("CRS1")) {
		t.Fatal("magic")
	}
}

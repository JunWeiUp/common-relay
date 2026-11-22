package v2client

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestSealedRoundTripSizes(t *testing.T) {
	pubHex, privHex, err := GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ParsePublicKey(pubHex)
	priv, _ := ParsePublicKey(privHex)
	for _, n := range []int{0, 1, sealedChunkSize - 1, sealedChunkSize, sealedChunkSize + 1, 3*sealedChunkSize + 7} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		r, err := SealStream(pub, bytes.NewReader(plain))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if !IsSealed(sealed) {
			t.Fatalf("n=%d: missing magic", n)
		}
		got, err := OpenSealed(sealed, pub, priv)
		if err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("n=%d: mismatch", n)
		}
	}
}

func TestSealedDetectsTruncationAndWrongKey(t *testing.T) {
	pubHex, privHex, _ := GenerateSealKeyPair()
	pub, _ := ParsePublicKey(pubHex)
	priv, _ := ParsePublicKey(privHex)
	plain := bytes.Repeat([]byte("x"), 2*sealedChunkSize+5)
	r, _ := SealStream(pub, bytes.NewReader(plain))
	sealed, _ := io.ReadAll(r)

	// Drop the final frame: the remaining last frame lacks the final bit.
	cut := sealed[:len(sealed)-(4+5+secretboxOverheadForTest)]
	if _, err := OpenSealed(cut, pub, priv); err == nil {
		t.Fatal("truncated payload must fail")
	}
	otherPubHex, otherPrivHex, _ := GenerateSealKeyPair()
	op, _ := ParsePublicKey(otherPubHex)
	ok, _ := ParsePublicKey(otherPrivHex)
	if _, err := OpenSealed(sealed, op, ok); err == nil {
		t.Fatal("wrong key must fail")
	}
}

const secretboxOverheadForTest = 16

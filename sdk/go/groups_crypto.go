package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// groupSigningKey derives a signing key separate from the encryption key.
func groupSigningKey(secret [32]byte) ed25519.PrivateKey {
	h := sha256.New()
	h.Write([]byte("common-relay/group-signing/v1\x00"))
	h.Write(secret[:])
	return ed25519.NewKeyFromSeed(h.Sum(nil))
}

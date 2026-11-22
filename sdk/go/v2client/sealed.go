package v2client

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Sealed bridge payloads ("crs1") let bridge plugins (Webhook, Drop, WebDAV queue)
// encrypt plaintext they receive over TLS to a recipient X25519 public key
// before it touches relay disk. Only the holder of the matching private key
// (e.g. the local Hub) can open it; the relay keeps no decryption key.
//
// Wire format:
//
//	magic "CRS1" (4)
//	sealed content key: box.SealAnonymous(32-byte key) (80)
//	nonce prefix (16)
//	frames: uint32 BE ciphertext length || secretbox(chunk, prefix||uint64 BE counter)
//
// The final frame sets the counter's high bit, so truncation is detected.
// SealedContentType is the Box item content type of sealed bridge payloads; the
// original content type is kept in item meta "content_type".
const SealedContentType = "application/vnd.common-relay.sealed"

const (
	SealedScheme    = "crs1"
	sealedMagic     = "CRS1"
	sealedChunkSize = 64 << 10
	sealedKeyLen    = 32 + box.AnonymousOverhead
	finalFrameBit   = uint64(1) << 63
)

var ErrSealedCorrupt = errors.New("sealed payload corrupt or truncated")

// ParsePublicKey decodes a 64-char hex X25519 public key.
func ParsePublicKey(hexKey string) (*[32]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("public key must be 64 hex characters")
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

// ParsePrivateKey parses a 64-hex X25519 private key (same encoding as public keys).
func ParsePrivateKey(hexKey string) (*[32]byte, error) {
	k, err := ParsePublicKey(hexKey)
	if err != nil {
		return nil, errors.New("private key must be 64 hex characters")
	}
	return k, nil
}

// GenerateSealKeyPair creates a fresh X25519 key pair for sealed bridge payloads.
func GenerateSealKeyPair() (publicHex, privateHex string, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub[:]), hex.EncodeToString(priv[:]), nil
}

// SealStream returns a reader producing the sealed encoding of src for recipient.
func SealStream(recipient *[32]byte, src io.Reader) (io.Reader, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	sealedKey, err := box.SealAnonymous(nil, key[:], recipient, rand.Reader)
	if err != nil {
		return nil, err
	}
	var prefix [16]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, err
	}
	header := make([]byte, 0, 4+sealedKeyLen+16)
	header = append(header, sealedMagic...)
	header = append(header, sealedKey...)
	header = append(header, prefix[:]...)
	return &sealReader{src: bufio.NewReaderSize(src, sealedChunkSize), key: key, prefix: prefix, pending: header}, nil
}

type sealReader struct {
	src     *bufio.Reader
	key     [32]byte
	prefix  [16]byte
	counter uint64
	pending []byte
	done    bool
	err     error
}

func (s *sealReader) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		s.fill()
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *sealReader) fill() {
	chunk := make([]byte, sealedChunkSize)
	n, err := io.ReadFull(s.src, chunk)
	final := false
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		final = true
	case err != nil:
		s.err = err
		return
	default:
		// Peek to learn whether this full chunk is the last one.
		if _, perr := s.src.Peek(1); errors.Is(perr, io.EOF) {
			final = true
		} else if perr != nil {
			s.err = perr
			return
		}
	}
	ctr := s.counter
	if final {
		ctr |= finalFrameBit
		s.done = true
	}
	s.counter++
	nonce := frameNonce(s.prefix, ctr)
	ct := secretbox.Seal(nil, chunk[:n], &nonce, &s.key)
	frame := make([]byte, 4, 4+len(ct))
	binary.BigEndian.PutUint32(frame, uint32(len(ct)))
	s.pending = append(frame, ct...)
}

func frameNonce(prefix [16]byte, ctr uint64) [24]byte {
	var n [24]byte
	copy(n[:16], prefix[:])
	binary.BigEndian.PutUint64(n[16:], ctr)
	return n
}

// IsSealed reports whether data starts with the sealed-payload magic.
func IsSealed(head []byte) bool {
	return len(head) >= 4 && string(head[:4]) == sealedMagic
}

// OpenSealed decrypts a complete sealed payload with the recipient key pair.
func OpenSealed(sealed []byte, publicKey, privateKey *[32]byte) ([]byte, error) {
	if len(sealed) < 4+sealedKeyLen+16 || !IsSealed(sealed) {
		return nil, ErrSealedCorrupt
	}
	rawKey, ok := box.OpenAnonymous(nil, sealed[4:4+sealedKeyLen], publicKey, privateKey)
	if !ok || len(rawKey) != 32 {
		return nil, ErrSealedCorrupt
	}
	var key [32]byte
	copy(key[:], rawKey)
	var prefix [16]byte
	copy(prefix[:], sealed[4+sealedKeyLen:4+sealedKeyLen+16])
	rest := sealed[4+sealedKeyLen+16:]
	var out []byte
	for ctr := uint64(0); ; ctr++ {
		if len(rest) < 4 {
			return nil, ErrSealedCorrupt
		}
		l := int(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if l < secretbox.Overhead || l > sealedChunkSize+secretbox.Overhead || l > len(rest) {
			return nil, ErrSealedCorrupt
		}
		frame := rest[:l]
		rest = rest[l:]
		last := len(rest) == 0
		c := ctr
		if last {
			c |= finalFrameBit
		}
		nonce := frameNonce(prefix, c)
		plain, ok := secretbox.Open(nil, frame, &nonce, &key)
		if !ok {
			return nil, ErrSealedCorrupt
		}
		out = append(out, plain...)
		if last {
			return out, nil
		}
	}
}

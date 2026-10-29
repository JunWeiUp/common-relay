package relay

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // Needed for libsodium's secretstream construction.
)

// libsodium crypto_secretstream_xchacha20poly1305, implemented on x/crypto
// primitives and checked against libsodium output (testdata, PyNaCl interop).
const (
	secretStreamHeaderBytes = 24
	secretStreamKeyBytes    = 32
	secretStreamABytes      = 17
	secretStreamTagMessage  = 0x00
	secretStreamTagPush     = 0x01
	secretStreamTagRekey    = 0x02
	secretStreamTagFinal    = secretStreamTagPush | secretStreamTagRekey
	// Relay records carry at most 65519 plaintext bytes (65536 ciphertext bytes).
	streamRecordPlain = 65519
)

var secretStreamPad [16]byte

type secretStreamState struct {
	key   [32]byte
	nonce [12]byte // 4-byte little-endian counter followed by the 8-byte inonce.
}

func (s *secretStreamState) init(key, header []byte) error {
	if len(key) != secretStreamKeyBytes || len(header) != secretStreamHeaderBytes {
		return errors.New("invalid secretstream key or header")
	}
	sub, err := chacha20.HChaCha20(key, header[:16])
	if err != nil {
		return err
	}
	copy(s.key[:], sub)
	s.resetCounter()
	copy(s.nonce[4:], header[16:24])
	return nil
}

func (s *secretStreamState) resetCounter() {
	clear(s.nonce[:4])
	s.nonce[0] = 1
}

func (s *secretStreamState) cipher(counter uint32) *chacha20.Cipher {
	c, err := chacha20.NewUnauthenticatedCipher(s.key[:], s.nonce[:])
	if err != nil {
		panic(err) // Key and nonce sizes are fixed.
	}
	c.SetCounter(counter)
	return c
}

func (s *secretStreamState) rekey() {
	var buffer [40]byte
	copy(buffer[:32], s.key[:])
	copy(buffer[32:], s.nonce[4:])
	s.cipher(0).XORKeyStream(buffer[:], buffer[:])
	copy(s.key[:], buffer[:32])
	copy(s.nonce[4:], buffer[32:])
	clear(buffer[:])
	s.resetCounter()
}

// mac computes the record tag over aad, the encrypted tag block and ciphertext.
func (s *secretStreamState) mac(aad, block, ciphertext []byte) [16]byte {
	var polyKey [32]byte
	var first [64]byte
	s.cipher(0).XORKeyStream(first[:], first[:])
	copy(polyKey[:], first[:32])
	clear(first[:])
	m := poly1305.New(&polyKey)
	clear(polyKey[:])
	m.Write(aad)
	m.Write(secretStreamPad[:(0x10-len(aad))&0xf])
	m.Write(block)
	m.Write(ciphertext)
	// libsodium pads with (0x10 - sizeof block + mlen) & 0xf; keep that exact quirk.
	m.Write(secretStreamPad[:(0x10-64+len(ciphertext))&0xf])
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(64+len(ciphertext)))
	m.Write(lengths[:])
	var tag [16]byte
	m.Sum(tag[:0])
	return tag
}

func (s *secretStreamState) advance(tag byte, mac [16]byte) {
	for i := range 8 {
		s.nonce[4+i] ^= mac[i]
	}
	counter := binary.LittleEndian.Uint32(s.nonce[:4]) + 1
	binary.LittleEndian.PutUint32(s.nonce[:4], counter)
	if tag&secretStreamTagRekey != 0 || counter == 0 {
		s.rekey()
	}
}

type secretStreamPush struct {
	state    secretStreamState
	key      [32]byte
	header   [24]byte
	finished bool
}

func newSecretStreamPush() (*secretStreamPush, error) {
	p := &secretStreamPush{}
	if _, err := rand.Read(p.key[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(p.header[:]); err != nil {
		return nil, err
	}
	return p, p.state.init(p.key[:], p.header[:])
}

// streamDescriptor is the sealed {"key","header"} value; the key never leaves an envelope.
type streamDescriptor struct {
	Key    string `json:"key"`
	Header string `json:"header"`
}

func (p *secretStreamPush) descriptor() streamDescriptor {
	return streamDescriptor{Key: hex.EncodeToString(p.key[:]), Header: hex.EncodeToString(p.header[:])}
}

func (p *secretStreamPush) push(plain, aad []byte, tag byte) ([]byte, error) {
	if p.finished {
		return nil, errors.New("stream already finished")
	}
	if len(plain) > streamRecordPlain {
		return nil, errors.New("stream record too large")
	}
	var block [64]byte
	block[0] = tag
	p.state.cipher(1).XORKeyStream(block[:], block[:])
	out := make([]byte, 1+len(plain)+16)
	out[0] = block[0]
	p.state.cipher(2).XORKeyStream(out[1:1+len(plain)], plain)
	mac := p.state.mac(aad, block[:], out[1:1+len(plain)])
	copy(out[1+len(plain):], mac[:])
	p.state.advance(tag, mac)
	p.finished = tag == secretStreamTagFinal
	return out, nil
}

type secretStreamPull struct {
	state    secretStreamState
	finished bool
}

func newSecretStreamPull(d streamDescriptor) (*secretStreamPull, error) {
	key, err := hex.DecodeString(d.Key)
	if err != nil || len(d.Key) != 64 || hex.EncodeToString(key) != d.Key {
		return nil, errors.New("invalid stream descriptor")
	}
	header, err := hex.DecodeString(d.Header)
	if err != nil || len(d.Header) != 48 || hex.EncodeToString(header) != d.Header {
		return nil, errors.New("invalid stream descriptor")
	}
	p := &secretStreamPull{}
	return p, p.state.init(key, header)
}

// pull authenticates before decrypting and leaves state untouched on failure.
// Only MESSAGE and FINAL records are valid for relay streams and files.
func (p *secretStreamPull) pull(ciphertext, aad []byte) ([]byte, error) {
	if p.finished {
		return nil, errors.New("data after final record")
	}
	if len(ciphertext) < secretStreamABytes || len(ciphertext) > streamRecordPlain+secretStreamABytes {
		return nil, errors.New("invalid stream record size")
	}
	size := len(ciphertext) - secretStreamABytes
	var block [64]byte
	block[0] = ciphertext[0]
	p.state.cipher(1).XORKeyStream(block[:], block[:])
	tag := block[0]
	block[0] = ciphertext[0]
	body := ciphertext[1 : 1+size]
	mac := p.state.mac(aad, block[:], body)
	if subtle.ConstantTimeCompare(mac[:], ciphertext[1+size:]) != 1 {
		return nil, errors.New("stream record authentication failed")
	}
	if tag != secretStreamTagMessage && tag != secretStreamTagFinal {
		return nil, errors.New("unsupported stream tag")
	}
	plain := make([]byte, size)
	p.state.cipher(2).XORKeyStream(plain, body)
	p.state.advance(tag, mac)
	p.finished = tag == secretStreamTagFinal
	return plain, nil
}

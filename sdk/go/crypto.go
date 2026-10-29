// Package relay implements Common Relay v1 encrypted messages, presence,
// durable offline delivery, bidirectional streams and encrypted files.
package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var objectID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var keyPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// Identity holds a local key and a copy of the out-of-band pinned trust map.
type Identity struct {
	app, group, device string
	secret             [32]byte
	public             string
	trusted            map[string][32]byte
}

func decodeKey(value string) ([32]byte, error) {
	var key [32]byte
	if !keyPattern.MatchString(value) {
		return key, errors.New("expected a 32-byte lowercase hex key")
	}
	raw, err := hex.DecodeString(value)
	copy(key[:], raw)
	return key, err
}

// GenerateKeyPair generates local Curve25519 keys. Never send secretKey to the relay.
func GenerateKeyPair() (secretKey, publicKey string, err error) {
	public, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(secret[:]), hex.EncodeToString(public[:]), nil
}

func NewIdentity(app, group, device, secretKey string, trustedPeers map[string]string) (*Identity, error) {
	if !namePattern.MatchString(app) || !namePattern.MatchString(group) || !namePattern.MatchString(device) {
		return nil, errors.New("invalid identity name")
	}
	secret, err := decodeKey(secretKey)
	if err != nil {
		return nil, err
	}
	public, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	identity := &Identity{app: app, group: group, device: device, secret: secret, public: hex.EncodeToString(public), trusted: make(map[string][32]byte)}
	for name, raw := range trustedPeers {
		peer, err := decodeKey(raw)
		if err != nil {
			return nil, err
		}
		if _, err = curve25519.X25519(secret[:], peer[:]); err != nil {
			return nil, errors.New("invalid peer key")
		}
		identity.trusted[name] = peer
	}
	return identity, nil
}

func (i *Identity) PublicKey() string { return i.public }
func (i *Identity) context(from, to, id string) []any {
	return i.kindContext(from, to, "message", id)
}
func (i *Identity) kindContext(from, to, kind, id string) []any {
	return []any{float64(1), i.app, i.group, from, to, kind, id}
}

// streamAAD is the whitespace-free UTF-8 JSON [1,app,group,from,to,kind,id,sequence].
func (i *Identity) streamAAD(from, to, kind, id string, sequence uint64) []byte {
	raw, err := json.Marshal([]any{1, i.app, i.group, from, to, kind, id, sequence})
	if err != nil {
		panic(err) // Only strings and integers.
	}
	return raw
}

// sealEnvelope encrypts {"context":[...],"value":value} for a pinned peer.
func (i *Identity) sealEnvelope(to, kind, id string, value any) (string, error) {
	if !objectID.MatchString(id) {
		return "", errors.New("invalid object ID")
	}
	peer, ok := i.trusted[to]
	if !ok {
		return "", errors.New("untrusted peer")
	}
	plain, err := json.Marshal(map[string]any{"context": i.kindContext(i.device, to, kind, id), "value": value})
	if err != nil {
		return "", err
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", err
	}
	body := base64.StdEncoding.EncodeToString(box.Seal(nonce[:], plain, &nonce, &peer, &i.secret))
	if len(body) > 262144 {
		return "", errors.New("encrypted envelope exceeds 256 KiB")
	}
	return body, nil
}

// openEnvelope authenticates a pinned sender and the exact routing context.
func (i *Identity) openEnvelope(from, kind, id, body string, value any) error {
	if !objectID.MatchString(id) {
		return errors.New("invalid object ID")
	}
	peer, ok := i.trusted[from]
	if !ok {
		return errors.New("untrusted peer")
	}
	raw, err := decodeBase64(body)
	if err != nil {
		return err
	}
	if len(raw) < 40 {
		return errors.New("truncated envelope")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	plain, ok := box.Open(nil, raw[24:], &nonce, &peer, &i.secret)
	if !ok {
		return errors.New("envelope authentication failed")
	}
	var envelope struct {
		Context []any           `json:"context"`
		Value   json.RawMessage `json:"value"`
	}
	if !utf8.Valid(plain) || json.Unmarshal(plain, &envelope) != nil || len(envelope.Value) == 0 || string(envelope.Value) == "null" {
		return errors.New("invalid envelope JSON")
	}
	if !reflect.DeepEqual(envelope.Context, i.kindContext(from, i.device, kind, id)) {
		return errors.New("authenticated context mismatch")
	}
	if json.Unmarshal(envelope.Value, value) != nil {
		return errors.New("invalid envelope value")
	}
	return nil
}

func decodeBase64(value string) ([]byte, error) {
	if len(value) > 262144 {
		return nil, errors.New("envelope too large")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("invalid base64")
	}
	return raw, nil
}

func (i *Identity) SealMessage(to, id string, data []byte) (string, error) {
	return i.sealMessage(to, id, data, 0)
}

// sealMessage adds the authenticated absolute expiry used by offline delivery.
func (i *Identity) sealMessage(to, id string, data []byte, expires int64) (string, error) {
	if !objectID.MatchString(id) || len(data) > 192000 {
		return "", errors.New("invalid ID or message too large")
	}
	value := map[string]any{"data": base64.StdEncoding.EncodeToString(data)}
	if expires != 0 {
		value["expires"] = expires
	}
	return i.sealEnvelope(to, "message", id, value)
}

// OpenMessage authenticates a message and rejects expired offline envelopes.
func (i *Identity) OpenMessage(from, id, body string) ([]byte, error) {
	data, expires, err := i.openMessage(from, id, body)
	if err == nil && expires != 0 && expires <= time.Now().Unix() {
		return nil, errors.New("invalid or expired message")
	}
	return data, err
}

// openMessage returns the authenticated expiry (0 when absent) without judging it.
func (i *Identity) openMessage(from, id, body string) ([]byte, int64, error) {
	var value struct {
		Data    *string         `json:"data"`
		Expires json.RawMessage `json:"expires"`
	}
	if err := i.openEnvelope(from, "message", id, body, &value); err != nil {
		return nil, 0, err
	}
	var expiry int64
	if len(value.Expires) > 0 {
		if string(value.Expires) == "null" || json.Unmarshal(value.Expires, &expiry) != nil || expiry <= 0 || expiry > 9007199254740991 {
			return nil, 0, errors.New("invalid message expiry")
		}
	}
	if value.Data == nil {
		return nil, 0, errors.New("missing message data")
	}
	data, err := decodeBase64(*value.Data)
	return data, expiry, err
}

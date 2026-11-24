// Package core implements the minimal, business-agnostic kernel primitives of
// Common Relay v2: Identity & Space, Pipe, and Box.
package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// TrustLevel locks the security boundary of a Space at creation time.
// It can never be downgraded after creation.
type TrustLevel string

const (
	// TrustStrictE2E forbids any plaintext bridge plugin from binding to this Space.
	// Used by strict end-to-end encrypted apps.
	TrustStrictE2E TrustLevel = "strict_e2e"

	// TrustClientEncrypted allows opaque client-encrypted passthrough plugins
	// (such as bidirectional WebDAV for encrypted backups or synced vaults).
	TrustClientEncrypted TrustLevel = "client_encrypted"

	// TrustBridgeAllowed allows server-bridged ingress plugins (WebDAV queue, Webhook, Drop)
	// that receive plaintext over TLS and encrypt/enqueue it for the target Space.
	TrustBridgeAllowed TrustLevel = "bridge_allowed"
)

func (t TrustLevel) Valid() bool {
	return t == TrustStrictE2E || t == TrustClientEncrypted || t == TrustBridgeAllowed
}

// Allows reports whether a Space with level t permits binding a plugin that
// requires pluginTrust. strict_e2e only permits strict_e2e; client_encrypted
// permits strict_e2e and client_encrypted; bridge_allowed permits all.
func (t TrustLevel) Allows(pluginTrust TrustLevel) bool {
	rank := func(l TrustLevel) int {
		switch l {
		case TrustStrictE2E:
			return 0
		case TrustClientEncrypted:
			return 1
		case TrustBridgeAllowed:
			return 2
		default:
			return 99
		}
	}
	return t.Valid() && pluginTrust.Valid() && rank(pluginTrust) <= rank(t)
}

// MemberRole defines a Device's permissions inside a Space.
type MemberRole string

const (
	RoleAdmin           MemberRole = "admin"
	RoleMember          MemberRole = "member"
	RoleArchiveObserver MemberRole = "archive_observer" // Read-only ciphertext access to Box(object) & box.changed
)

func (r MemberRole) Valid() bool {
	return r == RoleAdmin || r == RoleMember || r == RoleArchiveObserver
}

func (r MemberRole) CanWrite() bool {
	return r == RoleAdmin || r == RoleMember
}

// BoxMode determines the storage & lifecycle semantics of a Box.
type BoxMode string

const (
	// ModeQueue is an inbox: monotonic seq, cursor catch-up, deleted on ACK.
	ModeQueue BoxMode = "queue"

	// ModeObject is a versioned opaque object store with ETag/CAS optimistic locking
	// and bounded version retention (e.g. encrypted vault sync, bidirectional WebDAV).
	ModeObject BoxMode = "object"

	// ModeEphemeral is a TTL-bounded large blob transfer box (up to 512 MiB, e.g. offline file transfer).
	ModeEphemeral BoxMode = "ephemeral"
)

func (m BoxMode) Valid() bool {
	return m == ModeQueue || m == ModeObject || m == ModeEphemeral
}

var (
	ErrDenied        = errors.New("denied")
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrQuota         = errors.New("quota exceeded")
	ErrInvalidInput  = errors.New("invalid input")
	ErrTrustBoundary = errors.New("space trust level forbids this plugin")
)

var (
	identRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)
	boxRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$`)
)

func ValidIdent(s string) bool { return identRe.MatchString(s) }
func ValidBoxName(s string) bool {
	if !boxRe.MatchString(s) {
		return false
	}
	for i := 0; i < len(s)-1; i++ {
		if (s[i] == '.' && s[i+1] == '.') || (s[i] == '/' && s[i+1] == '/') {
			return false
		}
	}
	if s[len(s)-1] == '/' {
		return false
	}
	// "items"/"objects" segments are reserved for /v2/spaces/{s}/boxes/{box}/items|objects routing.
	for _, seg := range strings.Split(s, "/") {
		if seg == "items" || seg == "objects" {
			return false
		}
	}
	return true
}

func RandomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func HashSecret(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

type Device struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IsAdmin   bool   `json:"is_admin"`
	Revoked   bool   `json:"revoked"`
	CreatedAt int64  `json:"created_at"`
}

type SpaceMemberView struct {
	DeviceID string     `json:"device_id"`
	Name     string     `json:"name"`
	Role     MemberRole `json:"role"`
	Online   bool       `json:"online"`
}

type SpaceBoxView struct {
	Name      string  `json:"name"`
	Mode      BoxMode `json:"mode"`
	Items     int64   `json:"items"`
	Objects   int64   `json:"objects"`
	UsedBytes int64   `json:"used_bytes"`
}

type Space struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	App        string     `json:"app,omitempty"`
	TrustLevel TrustLevel `json:"trust_level"`
	CreatedAt  int64      `json:"created_at"`
	// ManagedBy names the projection that owns this space ("v1:<app>" for
	// signed device groups); empty for admin-created spaces.
	ManagedBy  string            `json:"managed_by,omitempty"`
	Governance string            `json:"governance,omitempty"` // "signed_ledger" | "admin_managed"
	QuotaBytes int64             `json:"quota_bytes,omitempty"`
	UsedBytes  int64             `json:"used_bytes,omitempty"`
	Members    []SpaceMemberView `json:"members,omitempty"`
	Boxes      []SpaceBoxView    `json:"boxes,omitempty"`
}

type SpaceMember struct {
	SpaceID  string     `json:"space_id"`
	DeviceID string     `json:"device_id"`
	Role     MemberRole `json:"role"`
	AddedAt  int64      `json:"added_at"`
}

type Box struct {
	SpaceID      string  `json:"space_id"`
	Name         string  `json:"name"`
	Mode         BoxMode `json:"mode"`
	MaxBytes     int64   `json:"max_bytes"`
	KeepVersions int     `json:"keep_versions"`
	TTLSec       int64   `json:"ttl_sec"`
	NextSeq      int64   `json:"next_seq"`
}

type BoxItem struct {
	ID          string `json:"id"`
	SpaceID     string `json:"space_id"`
	BoxName     string `json:"box_name"`
	Seq         int64  `json:"seq"`
	Sender      string `json:"sender"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
	MetaJSON    string `json:"meta_json"`
	ExpiresAt   int64  `json:"expires_at"`
	CreatedAt   int64  `json:"created_at"`
}

// InlineBoxItem is a queue/ephemeral item carried inside box.changed for
// peers that opted in (see PipeFeatureBoxInline). It is only a prefetch: the
// item stays queued until the consumer ACKs it exactly as before.
type InlineBoxItem struct {
	BoxItem
	DataB64 string `json:"data_b64"` // standard base64 of the stored bytes
}

type BoxObject struct {
	SpaceID     string `json:"space_id"`
	BoxName     string `json:"box_name"`
	Key         string `json:"key"`
	Version     int64  `json:"version"`
	ETag        string `json:"etag"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	MetaJSON    string `json:"meta_json"`
	BlobID      string `json:"-"`
	CreatedAt   int64  `json:"created_at"`
}

type Message struct {
	ID        string `json:"id"`
	SpaceID   string `json:"space_id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Topic     string `json:"topic"`
	Body      string `json:"body"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

type PluginBindingSummary struct {
	TargetDevice string   `json:"target_device,omitempty"`
	TargetOnline bool     `json:"target_online,omitempty"`
	PublicBase   string   `json:"public_base,omitempty"`
	Tag          string   `json:"tag,omitempty"`
	HasHMAC      bool     `json:"has_hmac,omitempty"`
	HasToken     bool     `json:"has_token,omitempty"`
	CORSOrigins  []string `json:"cors_origins,omitempty"`
}

type PluginAccountView struct {
	ScopeKey string `json:"scope_key"`
	Username string `json:"username"`
	Mode     string `json:"mode"`
}

type PluginBinding struct {
	ID         string `json:"id"`
	PluginID   string `json:"plugin_id"`
	Mount      string `json:"mount"`
	SpaceID    string `json:"space_id"`
	BoxName    string `json:"box_name"`
	ConfigJSON string `json:"config_json"` // public (non-secret) config only on admin reads
	Enabled    bool   `json:"enabled"`
	UpdatedAt  int64  `json:"updated_at"`
	// ConfigVersion increases on every update; pass it back as if_version for
	// optimistic concurrency.
	ConfigVersion int64 `json:"config_version"`
	// SecretKeys lists which write-only secret fields are set (values never returned).
	SecretKeys []string              `json:"secret_keys,omitempty"`
	Sealed     bool                  `json:"sealed"` // bridge payloads sealed to seal_public_key at rest
	Summary    *PluginBindingSummary `json:"summary,omitempty"`
	Accounts   []PluginAccountView   `json:"accounts,omitempty"`

	SecretsJSON string `json:"-"` // stored (encrypted) secrets column
}

type PluginAccount struct {
	BindingID  string `json:"binding_id"`
	ScopeKey   string `json:"scope_key"`
	Username   string `json:"username"`
	SecretHash string `json:"-"`
	Mode       string `json:"mode"`
	MetaJSON   string `json:"meta_json"`
	UpdatedAt  int64  `json:"updated_at"`
}

type StatusSnapshot struct {
	Spaces        int              `json:"spaces"`
	Devices       int              `json:"devices"`
	Boxes         int              `json:"boxes"`
	PendingItems  int              `json:"pending_items"`
	StoredObjects int              `json:"stored_objects"`
	UsedBytes     int64            `json:"used_bytes"`
	GlobalQuota   int64            `json:"global_quota"`
	OnlinePeers   int              `json:"online_peers"`
	SyncConflicts int64            `json:"sync_conflicts"`
	Plugins       []string         `json:"plugins"`
	BySpaceBytes  map[string]int64 `json:"by_space_bytes"`
}

// Package v2client is the official Go client and RelayHub runtime for Common Relay v2.
// It talks cleanly to the Device Kernel Plane (/v2/*) and Admin Control Plane (/v2/admin/*)
// with zero external dependencies beyond coder/websocket and the Go standard library.
package v2client

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("relay v2 http %d: %s", e.Status, e.Msg)
}

// HashSecret returns the lowercase 64-char hex SHA-256 of a plaintext secret.
// Plaintext passwords/tokens are never sent to Admin endpoints; only hashes cross the wire.
func HashSecret(plain string) string {
	h := sha256.Sum256([]byte(plain))
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

type Space struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	TrustLevel string `json:"trust_level"` // strict_e2e | client_encrypted | bridge_allowed
	CreatedAt  int64  `json:"created_at"`
}

type SpaceMember struct {
	SpaceID  string `json:"space_id"`
	DeviceID string `json:"device_id"`
	Role     string `json:"role"` // admin | member | archive_observer
	AddedAt  int64  `json:"added_at"`
}

type Box struct {
	SpaceID      string `json:"space_id"`
	Name         string `json:"name"`
	Mode         string `json:"mode"` // queue | object | ephemeral
	MaxBytes     int64  `json:"max_bytes"`
	KeepVersions int    `json:"keep_versions"`
	TTLSec       int64  `json:"ttl_sec"`
	NextSeq      int64  `json:"next_seq"`
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

type BoxObject struct {
	SpaceID     string `json:"space_id"`
	BoxName     string `json:"box_name"`
	Key         string `json:"key"`
	Version     int64  `json:"version"`
	ETag        string `json:"etag"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	MetaJSON    string `json:"meta_json"`
	CreatedAt   int64  `json:"created_at"`
}

type PluginBinding struct {
	ID         string `json:"id"`
	PluginID   string `json:"plugin_id"`
	Mount      string `json:"mount"`
	SpaceID    string `json:"space_id"`
	BoxName    string `json:"box_name"`
	ConfigJSON string `json:"config_json"`
	Enabled    bool   `json:"enabled"`
	UpdatedAt  int64  `json:"updated_at"`
}

type PluginAccount struct {
	BindingID string `json:"binding_id"`
	ScopeKey  string `json:"scope_key"`
	Username  string `json:"username"`
	Mode      string `json:"mode"`
	MetaJSON  string `json:"meta_json"`
	UpdatedAt int64  `json:"updated_at"`
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
	Plugins       []string         `json:"plugins"`
	BySpaceBytes  map[string]int64 `json:"by_space_bytes"`
}

type PipeEvent struct {
	Type    string   `json:"type"`
	Space   string   `json:"space,omitempty"`
	ID      string   `json:"id,omitempty"`
	From    string   `json:"from,omitempty"`
	To      string   `json:"to,omitempty"`
	Topic   string   `json:"topic,omitempty"`
	Box     string   `json:"box,omitempty"`
	Event   string   `json:"event,omitempty"`
	Ref     string   `json:"ref,omitempty"`
	Seq     int64    `json:"seq,omitempty"`
	Body    string   `json:"body,omitempty"`
	TTL     int64    `json:"ttl,omitempty"`
	Offline bool     `json:"offline,omitempty"`
	Peers   []string `json:"peers,omitempty"`
	Code    string   `json:"code,omitempty"`
}

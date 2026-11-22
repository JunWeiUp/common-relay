// Package v2client is the official Go client and RelayHub runtime for Common Relay v2.
// It talks cleanly to the Device Kernel Plane (/v2/*) and Admin Control Plane (/v2/admin/*)
// with zero external dependencies beyond coder/websocket and the Go standard library.
package v2client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("relay v2 http %d: %s", e.Status, e.Msg)
}

// IsUnsupported reports that the server predates an endpoint (e.g. PATCH
// /v2/admin/plugins/{id}/{mount}): it answers a plain-text 404/405 instead of a
// JSON error. Callers can then fall back to the older PUT API.
func IsUnsupported(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Status == 405 || ae.Status == 501 || (ae.Status == 404 && !strings.HasPrefix(ae.Msg, "{"))
}

// HashSecret returns the lowercase 64-char hex SHA-256 of a plaintext secret.
// Legacy helper for secret_sha256 fields. Newer endpoints accept plaintext over
// TLS (e.g. "token", "password") so the server can hash with salt/scrypt.
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

type SpaceMemberView struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Role     string `json:"role"` // admin | member | archive_observer
	Online   bool   `json:"online"`
}

type SpaceBoxView struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"` // queue | object | ephemeral
	Items     int64  `json:"items"`
	Objects   int64  `json:"objects"`
	UsedBytes int64  `json:"used_bytes"`
}

type Space struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	App        string `json:"app,omitempty"`
	TrustLevel string `json:"trust_level"` // strict_e2e | client_encrypted | bridge_allowed
	CreatedAt  int64  `json:"created_at"`
	// ManagedBy names the projection that owns this space ("v1:<app>" for
	// signed device groups); empty for admin-created spaces.
	ManagedBy string            `json:"managed_by,omitempty"`
	UsedBytes int64             `json:"used_bytes,omitempty"`
	Members   []SpaceMemberView `json:"members,omitempty"`
	Boxes     []SpaceBoxView    `json:"boxes,omitempty"`
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
	ID         string                `json:"id"`
	PluginID   string                `json:"plugin_id"`
	Mount      string                `json:"mount"`
	SpaceID    string                `json:"space_id"`
	BoxName    string                `json:"box_name"`
	ConfigJSON string                `json:"config_json"`
	Enabled    bool                  `json:"enabled"`
	UpdatedAt  int64                 `json:"updated_at"`
	Summary    *PluginBindingSummary `json:"summary,omitempty"`
	Accounts   []PluginAccountView   `json:"accounts,omitempty"`
	// ConfigVersion increments on every change; pass it as IfVersion for
	// optimistic concurrency. Zero on servers older than the PATCH API.
	ConfigVersion int64 `json:"config_version,omitempty"`
	// SecretKeys lists write-only secret keys currently set (values never returned).
	SecretKeys []string `json:"secret_keys,omitempty"`
	// Sealed reports that bridged payloads are sealed (crs1) to seal_public_key.
	Sealed bool `json:"sealed,omitempty"`
}

// PluginFieldSpec describes one config key a plugin accepts.
type PluginFieldSpec struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PluginInfo is one registered plugin with its config schema.
type PluginInfo struct {
	ID            string            `json:"id"`
	RequiredTrust string            `json:"required_trust"`
	Schema        []PluginFieldSpec `json:"schema,omitempty"`
}

// PluginPatch is a partial binding update. Nil fields are unchanged; a Config
// entry with a nil value deletes that key. Secret keys are write-only: send a
// plaintext "token" to rotate a Bearer token (it is hashed server-side).
type PluginPatch struct {
	SpaceID   *string        `json:"space_id,omitempty"`
	BoxName   *string        `json:"box_name,omitempty"`
	Enabled   *bool          `json:"enabled,omitempty"`
	Config    map[string]any `json:"config,omitempty"`
	IfVersion int64          `json:"if_version,omitempty"`
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

type AccessPasswordInfo struct {
	Configured      bool     `json:"configured"`
	Source          string   `json:"source"`
	HashPrefix      string   `json:"hash_prefix"`
	UpdatedAt       int64    `json:"updated_at"`
	SelfServiceAll  bool     `json:"self_service_all"`
	SelfServiceApps []string `json:"self_service_apps,omitempty"`
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

// EdgeCounter counts /edge/{plugin}/{mount} requests by outcome.
type EdgeCounter struct {
	Requests   int64 `json:"requests"`
	OK         int64 `json:"ok"`
	Rejected   int64 `json:"rejected"` // 401/403/429
	ClientErr  int64 `json:"client_err"`
	ServerErr  int64 `json:"server_err"`
	LastAt     int64 `json:"last_at"`
	LastErrAt  int64 `json:"last_err_at"`
	LastStatus int   `json:"last_status"`
}

// DeviceConn summarises one device's /v2/ws sessions since the relay started.
type DeviceConn struct {
	Online         bool   `json:"online"`
	Connects       int64  `json:"connects"`
	Disconnects    int64  `json:"disconnects"`
	Disconnects24h int64  `json:"disconnects_24h"` // excludes "replaced"
	LastConnect    int64  `json:"last_connect,omitempty"`
	LastDisconnect int64  `json:"last_disconnect,omitempty"`
	LastReason     string `json:"last_reason,omitempty"` // keepalive_timeout | replaced | client_closed | connection_lost | write_failed | server_closed
}

// ConnEvent is one /v2/ws connect or disconnect.
type ConnEvent struct {
	Device   string `json:"device"`
	At       int64  `json:"at"`
	Kind     string `json:"kind"`
	Reason   string `json:"reason,omitempty"`
	Duration int64  `json:"duration,omitempty"`
}

// Metrics is the relay's in-memory operational record (reset on restart).
type Metrics struct {
	StartedAt         int64                  `json:"started_at"`
	UptimeSeconds     int64                  `json:"uptime_seconds"`
	Edge              map[string]EdgeCounter `json:"edge"` // "plugin/mount"
	Devices           map[string]DeviceConn  `json:"devices"`
	KeepaliveTimeouts int64                  `json:"keepalive_timeouts"`
	Replaced          int64                  `json:"replaced"`
	Recent            []ConnEvent            `json:"recent"`

	// V1 is filled from the response's "v1" section when the relay still runs
	// the legacy v1 server; nil otherwise.
	V1 *V1Usage `json:"-"`
}

// V1UsageRow counts calls into the legacy v1 server code by app, kind and URL family.
type V1UsageRow struct {
	App      string `json:"app"`
	Kind     string `json:"kind"`   // ws | files | group | enroll | dav | webhook
	Family   string `json:"family"` // v1 = client used a /relay/v1 URL; v2 = a /v2 URL served by v1 code
	Requests int64  `json:"requests"`
	LastAt   int64  `json:"last_at"`
}

// V1Usage tells which apps still depend on v1 and whether they are connected now.
type V1Usage struct {
	Rows   []V1UsageRow   `json:"rows"`
	LiveWS map[string]int `json:"live_ws"`
}

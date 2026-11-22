// Package plugin defines the thin, standardized extension interface for
// Common Relay v2 edge protocol adapters (WebDAV, Webhook, Drop, MCP-Edge, etc.).
//
// A plugin declares what it is (ID, required Space trust), what configuration
// it accepts (ConfigSchema, with secret fields marked), and how to validate /
// normalize that configuration (ValidateConfig). The Host owns everything that
// must behave identically across plugins:
//
//   - binding persistence with write-only, encrypted secret fields and
//     optimistic-concurrency config versions (merge or replace updates);
//   - per-source authentication-failure limiting (one client cannot lock out
//     the others);
//   - bounded RPC calls and sealed (recipient-encrypted) bridge writes;
//   - lifecycle (Init/Close) and one-time EdgeHandler construction.
package plugin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
)

// Plugin is implemented by every edge protocol adapter under internal/v2/plugins/*.
type Plugin interface {
	ID() string
	// RequiredTrust declares the minimum Space TrustLevel required to bind this plugin.
	// The kernel enforces Space.TrustLevel.Allows(RequiredTrust()) before persisting any binding.
	RequiredTrust() core.TrustLevel
	// EdgeHandler serves external protocol requests mounted at /edge/<id>/.
	// It is called once, at registration.
	EdgeHandler(host *Host) http.Handler
}

// FieldSpec documents one configuration field of a plugin binding.
type FieldSpec struct {
	Key         string `json:"key"`
	Type        string `json:"type"` // string | int | bool | string_list | hex64
	Description string `json:"description,omitempty"`
	// Secret fields are write-only: stored encrypted, never returned by the admin
	// API, kept when an update omits them, cleared only by an explicit null.
	Secret   bool `json:"secret,omitempty"`
	Required bool `json:"required,omitempty"`
}

// Configurable plugins declare and validate their binding configuration.
// ValidateConfig receives the merged (public + secret) config and may normalize
// it in place (for example hashing a plaintext "token" into "token_sha256").
type Configurable interface {
	ConfigSchema() []FieldSpec
	ValidateConfig(cfg map[string]any) error
}

// Lifecycle plugins get Init at registration and Close at shutdown.
type Lifecycle interface {
	Init(host *Host) error
	Close() error
}

// SealPublicKeyField is the common bridge-plugin config key naming the X25519
// public key (hex) that queue payloads are sealed to before reaching disk.
const SealPublicKeyField = "seal_public_key"

// BridgeSchema is shared by plugins that write plaintext ingress into queue Boxes.
var BridgeSchema = FieldSpec{
	Key: SealPublicKeyField, Type: "hex64",
	Description: "X25519 public key of the consumer; payloads are sealed (crs1) before touching relay disk",
}

// Host is the narrow capability bridge passed to plugins so they never touch
// raw core internals or bypass Space trust boundaries.
type Host struct {
	store    *core.Store
	pipe     *core.PipeHub
	mu       sync.RWMutex
	plugins  map[string]Plugin
	handlers map[string]http.Handler

	// TrustedProxies are the peer addresses whose X-Forwarded-For / X-Real-IP
	// headers are honored when identifying the client (default: loopback).
	TrustedProxies []string

	authCache *verifyCache
}

func NewHost(store *core.Store, pipe *core.PipeHub) *Host {
	return &Host{
		store:     store,
		pipe:      pipe,
		plugins:   map[string]Plugin{},
		handlers:  map[string]http.Handler{},
		authCache: newVerifyCache(512, 10*time.Minute),
	}
}

// Store exposes the kernel store for plugin-internal bookkeeping (receipts).
func (h *Host) Store() *core.Store { return h.store }

// CallRPC forwards a request to targetDeviceID over its /v2/ws pipe, bounded by
// timeout (core.DefaultRPCTimeout when zero).
func (h *Host) CallRPC(ctx context.Context, spaceID, targetDeviceID, topic, payload string) (string, error) {
	return h.CallRPCTimeout(ctx, 0, spaceID, targetDeviceID, topic, payload)
}

func (h *Host) CallRPCTimeout(ctx context.Context, timeout time.Duration, spaceID, targetDeviceID, topic, payload string) (string, error) {
	if h.pipe == nil {
		return "", errors.New("pipe unavailable")
	}
	if timeout <= 0 {
		timeout = core.DefaultRPCTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return h.pipe.CallRPC(ctx, spaceID, targetDeviceID, topic, payload)
}

func (h *Host) Register(p Plugin) error {
	if p == nil || !core.ValidIdent(p.ID()) || !p.RequiredTrust().Valid() {
		return core.ErrInvalidInput
	}
	h.mu.Lock()
	if _, exists := h.plugins[p.ID()]; exists {
		h.mu.Unlock()
		return core.ErrConflict
	}
	h.mu.Unlock()
	if lc, ok := p.(Lifecycle); ok {
		if err := lc.Init(h); err != nil {
			return fmt.Errorf("init plugin %s: %w", p.ID(), err)
		}
	}
	handler := p.EdgeHandler(h)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.plugins[p.ID()] = p
	h.handlers[p.ID()] = handler
	return nil
}

// Close shuts down all Lifecycle plugins.
func (h *Host) Close() {
	h.mu.RLock()
	list := make([]Plugin, 0, len(h.plugins))
	for _, p := range h.plugins {
		list = append(list, p)
	}
	h.mu.RUnlock()
	for _, p := range list {
		if lc, ok := p.(Lifecycle); ok {
			_ = lc.Close()
		}
	}
}

func (h *Host) Get(id string) (Plugin, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p, ok := h.plugins[id]
	return p, ok
}

// Handler returns the edge handler built at registration.
func (h *Host) Handler(id string) (http.Handler, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hd, ok := h.handlers[id]
	return hd, ok
}

func (h *Host) IDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.plugins))
	for id := range h.plugins {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// PluginInfo is the admin-visible description of a registered plugin.
type PluginInfo struct {
	ID            string      `json:"id"`
	RequiredTrust string      `json:"required_trust"`
	Schema        []FieldSpec `json:"schema,omitempty"`
}

func (h *Host) Infos() []PluginInfo {
	out := []PluginInfo{}
	for _, id := range h.IDs() {
		p, _ := h.Get(id)
		info := PluginInfo{ID: id, RequiredTrust: string(p.RequiredTrust())}
		if c, ok := p.(Configurable); ok {
			info.Schema = c.ConfigSchema()
		}
		out = append(out, info)
	}
	return out
}

func (h *Host) secretKeySet(p Plugin) map[string]bool {
	set := map[string]bool{}
	if c, ok := p.(Configurable); ok {
		for _, f := range c.ConfigSchema() {
			if f.Secret {
				set[f.Key] = true
			}
		}
		return set
	}
	return nil // unknown plugin schema: fall back to name heuristics
}

// IsSecretKey reports whether key is a secret field for plugin p.
func (h *Host) IsSecretKey(p Plugin, key string) bool {
	if set := h.secretKeySet(p); set != nil {
		return set[key]
	}
	lk := strings.ToLower(key)
	for _, needle := range []string{"secret", "token", "password", "hash", "key"} {
		if strings.Contains(lk, needle) && lk != SealPublicKeyField {
			return true
		}
	}
	return false
}

/* ───────── Plugin Bindings (Trust-Boundary Enforced) ───────── */

// BindingUpdate describes an admin change to one (plugin, mount) binding.
// Nil pointer fields keep their current value when the binding exists.
type BindingUpdate struct {
	PluginID string
	Mount    string
	SpaceID  *string
	BoxName  *string
	Enabled  *bool
	// Config carries public and secret keys together; the plugin schema decides
	// which is which. A JSON null value deletes the key.
	Config map[string]any
	// ReplacePublic replaces all public config keys (PUT semantics). Secrets are
	// always merged: omitted secret keys are kept.
	ReplacePublic bool
	// IfVersion, when > 0, must equal the stored config_version (else ErrConflict).
	IfVersion int64
}

var ErrVersionMismatch = fmt.Errorf("%w: config_version mismatch", core.ErrConflict)

// SaveBinding applies an update atomically after trust-boundary checks and
// plugin validation, returning the stored binding (public view).
func (h *Host) SaveBinding(u BindingUpdate) (core.PluginBinding, error) {
	p, ok := h.Get(u.PluginID)
	if !ok {
		return core.PluginBinding{}, core.ErrNotFound
	}
	if !core.ValidIdent(u.Mount) {
		return core.PluginBinding{}, core.ErrInvalidInput
	}
	tx, err := h.store.DB.Begin()
	if err != nil {
		return core.PluginBinding{}, err
	}
	defer tx.Rollback()

	cur, exists, err := scanBinding(tx.QueryRow(bindingSelect+` WHERE plugin_id=? AND mount=?`, u.PluginID, u.Mount))
	if err != nil {
		return core.PluginBinding{}, err
	}
	if u.IfVersion > 0 && (!exists || cur.ConfigVersion != u.IfVersion) {
		return core.PluginBinding{}, ErrVersionMismatch
	}
	b := cur
	if !exists {
		b = core.PluginBinding{ID: core.RandomHex(12), PluginID: u.PluginID, Mount: u.Mount, Enabled: true}
	}
	if u.SpaceID != nil {
		b.SpaceID = strings.TrimSpace(*u.SpaceID)
	}
	if u.BoxName != nil {
		b.BoxName = strings.TrimSpace(*u.BoxName)
	}
	if u.Enabled != nil {
		b.Enabled = *u.Enabled
	}
	if !core.ValidIdent(b.SpaceID) {
		return core.PluginBinding{}, core.ErrInvalidInput
	}
	if b.BoxName != "" && !core.ValidBoxName(b.BoxName) {
		return core.PluginBinding{}, core.ErrInvalidInput
	}
	// The store has a single SQLite connection: every read inside this
	// transaction must go through tx, never h.store.DB.
	var trust string
	if err := tx.QueryRow(`SELECT trust_level FROM v2_spaces WHERE id=?`, b.SpaceID).Scan(&trust); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.PluginBinding{}, core.ErrNotFound
		}
		return core.PluginBinding{}, err
	}
	if !core.TrustLevel(trust).Allows(p.RequiredTrust()) {
		return core.PluginBinding{}, core.ErrTrustBoundary
	}

	public := map[string]any{}
	if exists && !u.ReplacePublic {
		_ = json.Unmarshal([]byte(cur.ConfigJSON), &public)
	}
	secrets, err := h.store.OpenSecrets(cur.SecretsJSON)
	if err != nil {
		return core.PluginBinding{}, err
	}
	for k, v := range u.Config {
		target := public
		if h.IsSecretKey(p, k) || k == "token" {
			target = secrets
		}
		if v == nil {
			delete(target, k)
		} else {
			target[k] = v
		}
	}
	merged := make(map[string]any, len(public)+len(secrets))
	for k, v := range public {
		merged[k] = v
	}
	for k, v := range secrets {
		merged[k] = v
	}
	// A plaintext "token" is never stored: it is hashed into token_sha256.
	if t, ok := merged["token"]; ok {
		delete(merged, "token")
		ts, _ := t.(string)
		ts = strings.TrimSpace(ts)
		if len(ts) < MinBearerTokenLen || len(ts) > 256 {
			return core.PluginBinding{}, fmt.Errorf("%w: token must be %d-256 characters", core.ErrInvalidInput, MinBearerTokenLen)
		}
		merged["token_sha256"] = core.HashSecret(ts)
	}
	if err := validateSealKey(merged); err != nil {
		return core.PluginBinding{}, err
	}
	if c, ok := p.(Configurable); ok {
		if err := c.ValidateConfig(merged); err != nil {
			return core.PluginBinding{}, fmt.Errorf("%w: %v", core.ErrInvalidInput, err)
		}
	}
	// Re-split after normalization (ValidateConfig may add/remove keys).
	public, secrets = map[string]any{}, map[string]any{}
	for k, v := range merged {
		if h.IsSecretKey(p, k) {
			secrets[k] = v
		} else {
			public[k] = v
		}
	}
	pubJSON, err := json.Marshal(public)
	if err != nil {
		return core.PluginBinding{}, core.ErrInvalidInput
	}
	sealed, err := h.store.SealSecrets(secrets)
	if err != nil {
		return core.PluginBinding{}, err
	}
	b.ConfigJSON = string(pubJSON)
	b.SecretsJSON = sealed
	b.ConfigVersion = cur.ConfigVersion + 1
	b.UpdatedAt = time.Now().Unix()
	en := 0
	if b.Enabled {
		en = 1
	}
	if _, err := tx.Exec(
		`INSERT INTO v2_plugin_bindings(id,plugin_id,mount,space_id,box_name,config_json,secrets_json,config_version,enabled,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(plugin_id,mount) DO UPDATE SET
		   space_id=excluded.space_id, box_name=excluded.box_name, config_json=excluded.config_json,
		   secrets_json=excluded.secrets_json, config_version=excluded.config_version,
		   enabled=excluded.enabled, updated_at=excluded.updated_at`,
		b.ID, b.PluginID, b.Mount, b.SpaceID, b.BoxName, b.ConfigJSON, b.SecretsJSON, b.ConfigVersion, en, b.UpdatedAt,
	); err != nil {
		return core.PluginBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return core.PluginBinding{}, err
	}
	return h.publicView(b, secrets), nil
}

// UpsertBinding keeps the original replace-style API: public config is replaced,
// secrets omitted from ConfigJSON are kept.
func (h *Host) UpsertBinding(b core.PluginBinding) (core.PluginBinding, error) {
	cfg := map[string]any{}
	if strings.TrimSpace(b.ConfigJSON) != "" {
		if err := json.Unmarshal([]byte(b.ConfigJSON), &cfg); err != nil {
			return core.PluginBinding{}, core.ErrInvalidInput
		}
	}
	en := b.Enabled
	return h.SaveBinding(BindingUpdate{
		PluginID: b.PluginID, Mount: b.Mount, SpaceID: &b.SpaceID, BoxName: &b.BoxName,
		Enabled: &en, Config: cfg, ReplacePublic: true,
	})
}

func validateSealKey(cfg map[string]any) error {
	v, ok := cfg[SealPublicKeyField]
	if !ok {
		return nil
	}
	s, _ := v.(string)
	if _, err := v2client.ParsePublicKey(s); err != nil {
		return fmt.Errorf("%w: %s must be 64 hex characters", core.ErrInvalidInput, SealPublicKeyField)
	}
	return nil
}

func (h *Host) publicView(b core.PluginBinding, secrets map[string]any) core.PluginBinding {
	b.SecretKeys = b.SecretKeys[:0]
	for k := range secrets {
		b.SecretKeys = append(b.SecretKeys, k)
	}
	sort.Strings(b.SecretKeys)
	var pub map[string]any
	if json.Unmarshal([]byte(b.ConfigJSON), &pub) == nil {
		_, b.Sealed = pub[SealPublicKeyField]
	}
	b.SecretsJSON = ""
	return b
}

const bindingSelect = `SELECT id,plugin_id,mount,space_id,box_name,config_json,secrets_json,config_version,enabled,updated_at FROM v2_plugin_bindings`

type rowScanner interface{ Scan(dest ...any) error }

func scanBinding(row rowScanner) (core.PluginBinding, bool, error) {
	var b core.PluginBinding
	var en int
	err := row.Scan(&b.ID, &b.PluginID, &b.Mount, &b.SpaceID, &b.BoxName, &b.ConfigJSON, &b.SecretsJSON, &b.ConfigVersion, &en, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return core.PluginBinding{}, false, nil
	}
	if err != nil {
		return core.PluginBinding{}, false, err
	}
	b.Enabled = en != 0
	return b, true, nil
}

// GetBinding returns the public view of a binding regardless of enabled state
// (admin use).
func (h *Host) GetBinding(pluginID, mount string) (core.PluginBinding, error) {
	b, ok, err := scanBinding(h.store.Reader().QueryRow(bindingSelect+` WHERE plugin_id=? AND mount=?`, pluginID, mount))
	if err != nil {
		return core.PluginBinding{}, err
	}
	if !ok {
		return core.PluginBinding{}, core.ErrNotFound
	}
	secrets, err := h.store.OpenSecrets(b.SecretsJSON)
	if err != nil {
		return core.PluginBinding{}, err
	}
	return h.publicView(b, secrets), nil
}

// LookupBinding resolves an enabled binding for edge traffic. Its ConfigJSON is
// the merged (public + decrypted secret) configuration.
func (h *Host) LookupBinding(pluginID, mount string) (core.PluginBinding, core.Space, error) {
	b, ok, err := scanBinding(h.store.Reader().QueryRow(bindingSelect+` WHERE plugin_id=? AND mount=?`, pluginID, mount))
	if err != nil {
		return core.PluginBinding{}, core.Space{}, err
	}
	if !ok {
		return core.PluginBinding{}, core.Space{}, core.ErrNotFound
	}
	if !b.Enabled {
		return core.PluginBinding{}, core.Space{}, core.ErrDenied
	}
	secrets, err := h.store.OpenSecrets(b.SecretsJSON)
	if err != nil {
		return core.PluginBinding{}, core.Space{}, err
	}
	merged := map[string]any{}
	_ = json.Unmarshal([]byte(b.ConfigJSON), &merged)
	for k, v := range secrets {
		merged[k] = v
	}
	if raw, err := json.Marshal(merged); err == nil {
		b.ConfigJSON = string(raw)
	}
	b.SecretsJSON = ""
	_, b.Sealed = merged[SealPublicKeyField]
	sp, err := h.store.GetSpace(b.SpaceID)
	if err != nil {
		return core.PluginBinding{}, core.Space{}, err
	}
	return b, sp, nil
}

// ListBindings returns public views (no secret values).
func (h *Host) ListBindings(pluginID string) ([]core.PluginBinding, error) {
	var rows *sql.Rows
	var err error
	if pluginID == "" {
		rows, err = h.store.Reader().Query(bindingSelect + ` ORDER BY plugin_id, mount`)
	} else {
		rows, err = h.store.Reader().Query(bindingSelect+` WHERE plugin_id=? ORDER BY mount`, pluginID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.PluginBinding{}
	for rows.Next() {
		b, _, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		secrets, err := h.store.OpenSecrets(b.SecretsJSON)
		if err != nil {
			secrets = map[string]any{}
		}
		out = append(out, h.publicView(b, secrets))
	}
	return out, rows.Err()
}

func (h *Host) DeleteBinding(pluginID, mount string) error {
	res, err := h.store.DB.Exec(`DELETE FROM v2_plugin_bindings WHERE plugin_id=? AND mount=?`, pluginID, mount)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

/* ───────── Plugin Scoped Accounts (salted, slow password hashes) ───────── */

// UpsertAccount stores an account from a pre-computed legacy SHA-256 hash.
// Prefer UpsertAccountPassword, which stores a salted scrypt hash.
func (h *Host) UpsertAccount(bindingID, scopeKey, username, secretHash, mode, metaJSON string) (core.PluginAccount, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(secretHash))
	if err != nil || len(raw) != 32 {
		return core.PluginAccount{}, core.ErrInvalidInput
	}
	return h.upsertAccount(bindingID, scopeKey, username, hex.EncodeToString(raw), mode, metaJSON)
}

// MinBearerTokenLen is enforced for plaintext bearer tokens submitted to the
// admin API. Edges still accept >=16 characters for pre-existing hashed tokens.
const MinBearerTokenLen = 32

// MinAccountPasswordLen is enforced for plaintext account passwords.
const MinAccountPasswordLen = 16

// UpsertAccountPassword hashes password with scrypt and a random salt.
func (h *Host) UpsertAccountPassword(bindingID, scopeKey, username, password, mode, metaJSON string) (core.PluginAccount, error) {
	if len(password) < MinAccountPasswordLen || len(password) > 256 {
		return core.PluginAccount{}, core.ErrInvalidInput
	}
	enc, err := hashPassword(password)
	if err != nil {
		return core.PluginAccount{}, err
	}
	return h.upsertAccount(bindingID, scopeKey, username, enc, mode, metaJSON)
}

func (h *Host) upsertAccount(bindingID, scopeKey, username, stored, mode, metaJSON string) (core.PluginAccount, error) {
	if bindingID == "" || strings.TrimSpace(scopeKey) == "" || strings.TrimSpace(username) == "" {
		return core.PluginAccount{}, core.ErrInvalidInput
	}
	if mode == "" {
		mode = string(core.ModeQueue)
	}
	if metaJSON == "" {
		metaJSON = "{}"
	}
	now := time.Now().Unix()
	_, err := h.store.DB.Exec(
		`INSERT INTO v2_plugin_accounts(binding_id,scope_key,username,secret_hash,mode,meta_json,updated_at)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(binding_id,scope_key) DO UPDATE SET
		   username=excluded.username, secret_hash=excluded.secret_hash, mode=excluded.mode,
		   meta_json=excluded.meta_json, updated_at=excluded.updated_at`,
		bindingID, scopeKey, username, stored, mode, metaJSON, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return core.PluginAccount{}, core.ErrConflict
		}
		return core.PluginAccount{}, err
	}
	h.authCache.purge(bindingID)
	return core.PluginAccount{
		BindingID: bindingID, ScopeKey: scopeKey, Username: username,
		SecretHash: stored, Mode: mode, MetaJSON: metaJSON, UpdatedAt: now,
	}, nil
}

func (h *Host) AuthAccount(bindingID, username, plainSecret string) (core.PluginAccount, error) {
	var a core.PluginAccount
	err := h.store.Reader().QueryRow(
		`SELECT binding_id,scope_key,username,secret_hash,mode,meta_json,updated_at
		 FROM v2_plugin_accounts WHERE binding_id=? AND username=?`,
		bindingID, username,
	).Scan(&a.BindingID, &a.ScopeKey, &a.Username, &a.SecretHash, &a.Mode, &a.MetaJSON, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return core.PluginAccount{}, core.ErrDenied
	}
	if err != nil {
		return core.PluginAccount{}, err
	}
	// Slow hashes are verified once per (account, secret, stored hash) and cached.
	ck := cacheKey(bindingID, username, plainSecret, a.SecretHash)
	if h.authCache.hit(ck) {
		return a, nil
	}
	if !verifyStoredSecret(plainSecret, a.SecretHash) {
		return core.PluginAccount{}, core.ErrDenied
	}
	h.authCache.put(bindingID, ck)
	return a, nil
}

func (h *Host) ListAccounts(bindingID string) ([]core.PluginAccount, error) {
	rows, err := h.store.Reader().Query(
		`SELECT binding_id,scope_key,username,secret_hash,mode,meta_json,updated_at
		 FROM v2_plugin_accounts WHERE binding_id=? ORDER BY scope_key`,
		bindingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.PluginAccount{}
	for rows.Next() {
		var a core.PluginAccount
		if err := rows.Scan(&a.BindingID, &a.ScopeKey, &a.Username, &a.SecretHash, &a.Mode, &a.MetaJSON, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (h *Host) DeleteAccount(bindingID, scopeKey string) error {
	res, err := h.store.DB.Exec(`DELETE FROM v2_plugin_accounts WHERE binding_id=? AND scope_key=?`, bindingID, scopeKey)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return core.ErrNotFound
	}
	h.authCache.purge(bindingID)
	return nil
}

/* ───────── Controlled Kernel Box Operations for Plugins ───────── */

func (h *Host) EnsureBox(b core.Box) (core.Box, error) { return h.store.EnsureBox(b) }

func (h *Host) PutQueueItem(spaceID, boxName, sender, contentType, metaJSON string, body io.Reader) (core.BoxItem, error) {
	return h.store.PutBoxItem(spaceID, boxName, sender, contentType, metaJSON, 0, body)
}

// SealedContentType marks queue items whose body is a crs1 sealed payload.
const SealedContentType = "application/vnd.common-relay.sealed"

// PutBridgedItem enqueues plaintext ingress for binding b. When the binding has
// a seal_public_key, the body is sealed to it while streaming, so plaintext never
// reaches relay disk; the original content type is kept in meta.content_type.
// binding must come from LookupBinding (merged config).
func (h *Host) PutBridgedItem(b core.PluginBinding, boxName, sender, contentType string, meta map[string]any, body io.Reader) (core.BoxItem, error) {
	if meta == nil {
		meta = map[string]any{}
	}
	var cfg struct {
		SealPublicKey string `json:"seal_public_key"`
	}
	_ = json.Unmarshal([]byte(b.ConfigJSON), &cfg)
	if cfg.SealPublicKey != "" {
		pub, err := v2client.ParsePublicKey(cfg.SealPublicKey)
		if err != nil {
			return core.BoxItem{}, core.ErrInvalidInput
		}
		sealedBody, err := v2client.SealStream(pub, body)
		if err != nil {
			return core.BoxItem{}, err
		}
		meta["sealed"] = v2client.SealedScheme
		meta["content_type"] = contentType
		body = sealedBody
		contentType = SealedContentType
	}
	raw, _ := json.Marshal(meta)
	return h.store.PutBoxItem(b.SpaceID, boxName, sender, contentType, string(raw), 0, body)
}

func (h *Host) PutObject(spaceID, boxName, key, contentType, metaJSON, expectedETag string, body io.Reader) (core.BoxObject, error) {
	return h.store.PutBoxObject(spaceID, boxName, key, contentType, metaJSON, expectedETag, body)
}

func (h *Host) OpenObject(spaceID, boxName, key string) (*os.File, core.BoxObject, error) {
	return h.store.OpenBoxObject(spaceID, boxName, key, 0)
}

func (h *Host) ListObjects(spaceID, boxName, prefix string) ([]core.BoxObject, error) {
	return h.store.ListBoxObjects(spaceID, boxName, prefix)
}

func (h *Host) DeleteObject(spaceID, boxName, key string) error {
	return h.store.DeleteBoxObject(spaceID, boxName, key)
}

/* ───────── Client identity & failure limiting ───────── */

// ClientIP returns the requesting client's address. Forwarding headers are only
// honored when the direct peer is a trusted proxy (loopback by default).
func (h *Host) ClientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if h.trustedProxy(peer) {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			return v
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return peer
}

func (h *Host) trustedProxy(peer string) bool {
	if len(h.TrustedProxies) == 0 {
		ip := net.ParseIP(peer)
		return ip != nil && ip.IsLoopback()
	}
	for _, p := range h.TrustedProxies {
		if p == peer {
			return true
		}
	}
	return false
}

// SourceKey scopes failure limiting to (binding, client). A misbehaving client
// is throttled without locking legitimate senders out of the same mount.
func (h *Host) SourceKey(bindingID string, r *http.Request) string {
	return bindingID + "|" + h.ClientIP(r)
}

/* ───────── Shared Security Helpers ───────── */

func SecretMatchesHash(plain, hexHash string) bool {
	if len(plain) == 0 || len(hexHash) != 64 {
		return false
	}
	got := core.HashSecret(plain)
	return subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(hexHash))) == 1
}

// FailLimiter tracks failed authentication attempts per key with a sliding window.
type FailLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	state  map[string]*failBucket
}

type failBucket struct {
	count int
	since time.Time
}

const maxLimiterKeys = 4096

func NewFailLimiter(limit int, window time.Duration) *FailLimiter {
	return &FailLimiter{limit: limit, window: window, state: map[string]*failBucket{}}
}

func (l *FailLimiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.state[key]
	if b == nil {
		return false
	}
	if time.Since(b.since) > l.window {
		delete(l.state, key)
		return false
	}
	return b.count >= l.limit
}

func (l *FailLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.state) >= maxLimiterKeys {
		for k, v := range l.state {
			if now.Sub(v.since) > l.window {
				delete(l.state, k)
			}
		}
	}
	b := l.state[key]
	if b == nil || now.Sub(b.since) > l.window {
		if len(l.state) < maxLimiterKeys {
			l.state[key] = &failBucket{count: 1, since: now}
		}
		return
	}
	b.count++
}

func (l *FailLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, key)
}

/* ───────── verification cache ───────── */

type verifyCache struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	byID map[string]map[string]time.Time // bindingID -> cacheKey -> expiry
	n    int
}

func newVerifyCache(max int, ttl time.Duration) *verifyCache {
	return &verifyCache{max: max, ttl: ttl, byID: map[string]map[string]time.Time{}}
}

func cacheKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *verifyCache) hit(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.byID {
		if exp, ok := m[key]; ok {
			return time.Now().Before(exp)
		}
	}
	return false
}

func (c *verifyCache) put(bindingID, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n >= c.max {
		c.byID = map[string]map[string]time.Time{}
		c.n = 0
	}
	m := c.byID[bindingID]
	if m == nil {
		m = map[string]time.Time{}
		c.byID[bindingID] = m
	}
	if _, ok := m[key]; !ok {
		c.n++
	}
	m[key] = time.Now().Add(c.ttl)
}

func (c *verifyCache) purge(bindingID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n -= len(c.byID[bindingID])
	delete(c.byID, bindingID)
}

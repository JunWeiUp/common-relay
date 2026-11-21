// Package plugin defines the thin, standardized extension interface for
// Common Relay v2 edge protocol adapters (WebDAV, Webhook, Drop, MCP-Edge, etc.).
package plugin

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
)

// Plugin is implemented by every edge protocol adapter under internal/v2/plugins/*.
type Plugin interface {
	ID() string
	// RequiredTrust declares the minimum Space TrustLevel required to bind this plugin.
	// The kernel enforces Space.TrustLevel.Allows(RequiredTrust()) before persisting any binding.
	RequiredTrust() core.TrustLevel
	// EdgeHandler serves external protocol requests mounted at /edge/<id>/.
	EdgeHandler(host *Host) http.Handler
}

// Host is the narrow capability bridge passed to plugins so they never touch
// raw core internals or bypass Space trust boundaries.
type Host struct {
	store   *core.Store
	pipe    *core.PipeHub
	mu      sync.RWMutex
	plugins map[string]Plugin
}

func NewHost(store *core.Store, pipe *core.PipeHub) *Host {
	return &Host{
		store:   store,
		pipe:    pipe,
		plugins: map[string]Plugin{},
	}
}

func (h *Host) CallRPC(ctx context.Context, spaceID, targetDeviceID, topic, payload string) (string, error) {
	if h.pipe == nil {
		return "", errors.New("pipe unavailable")
	}
	return h.pipe.CallRPC(ctx, spaceID, targetDeviceID, topic, payload)
}

func (h *Host) Register(p Plugin) error {
	if p == nil || !core.ValidIdent(p.ID()) || !p.RequiredTrust().Valid() {
		return core.ErrInvalidInput
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.plugins[p.ID()]; exists {
		return core.ErrConflict
	}
	h.plugins[p.ID()] = p
	return nil
}

func (h *Host) Get(id string) (Plugin, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p, ok := h.plugins[id]
	return p, ok
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

/* ───────── Plugin Bindings (Trust-Boundary Enforced) ───────── */

func (h *Host) UpsertBinding(b core.PluginBinding) (core.PluginBinding, error) {
	p, ok := h.Get(b.PluginID)
	if !ok {
		return core.PluginBinding{}, core.ErrNotFound
	}
	if !core.ValidIdent(b.Mount) || !core.ValidIdent(b.SpaceID) {
		return core.PluginBinding{}, core.ErrInvalidInput
	}
	if b.BoxName != "" && !core.ValidBoxName(b.BoxName) {
		return core.PluginBinding{}, core.ErrInvalidInput
	}
	sp, err := h.store.GetSpace(b.SpaceID)
	if err != nil {
		return core.PluginBinding{}, err
	}
	if !sp.TrustLevel.Allows(p.RequiredTrust()) {
		return core.PluginBinding{}, core.ErrTrustBoundary
	}
	if b.ConfigJSON == "" {
		b.ConfigJSON = "{}"
	}
	now := time.Now().Unix()
	en := 0
	if b.Enabled {
		en = 1
	}

	// Reuse existing binding ID on (plugin_id, mount) update.
	var existingID string
	err = h.store.DB.QueryRow(`SELECT id FROM v2_plugin_bindings WHERE plugin_id=? AND mount=?`, b.PluginID, b.Mount).Scan(&existingID)
	if err == nil {
		b.ID = existingID
	} else if errors.Is(err, sql.ErrNoRows) {
		if b.ID == "" {
			b.ID = core.RandomHex(12)
		}
	} else {
		return core.PluginBinding{}, err
	}

	_, err = h.store.DB.Exec(
		`INSERT INTO v2_plugin_bindings(id,plugin_id,mount,space_id,box_name,config_json,enabled,updated_at)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(plugin_id,mount) DO UPDATE SET
		   space_id=excluded.space_id, box_name=excluded.box_name, config_json=excluded.config_json,
		   enabled=excluded.enabled, updated_at=excluded.updated_at`,
		b.ID, b.PluginID, b.Mount, b.SpaceID, b.BoxName, b.ConfigJSON, en, now,
	)
	if err != nil {
		return core.PluginBinding{}, err
	}
	b.UpdatedAt = now
	return b, nil
}

func (h *Host) LookupBinding(pluginID, mount string) (core.PluginBinding, core.Space, error) {
	var b core.PluginBinding
	var en int
	err := h.store.DB.QueryRow(
		`SELECT id,plugin_id,mount,space_id,box_name,config_json,enabled,updated_at
		 FROM v2_plugin_bindings WHERE plugin_id=? AND mount=?`,
		pluginID, mount,
	).Scan(&b.ID, &b.PluginID, &b.Mount, &b.SpaceID, &b.BoxName, &b.ConfigJSON, &en, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return core.PluginBinding{}, core.Space{}, core.ErrNotFound
	}
	if err != nil {
		return core.PluginBinding{}, core.Space{}, err
	}
	b.Enabled = en != 0
	if !b.Enabled {
		return core.PluginBinding{}, core.Space{}, core.ErrDenied
	}
	sp, err := h.store.GetSpace(b.SpaceID)
	if err != nil {
		return core.PluginBinding{}, core.Space{}, err
	}
	return b, sp, nil
}

func (h *Host) ListBindings(pluginID string) ([]core.PluginBinding, error) {
	var rows *sql.Rows
	var err error
	if pluginID == "" {
		rows, err = h.store.DB.Query(`SELECT id,plugin_id,mount,space_id,box_name,config_json,enabled,updated_at FROM v2_plugin_bindings ORDER BY plugin_id, mount`)
	} else {
		rows, err = h.store.DB.Query(`SELECT id,plugin_id,mount,space_id,box_name,config_json,enabled,updated_at FROM v2_plugin_bindings WHERE plugin_id=? ORDER BY mount`, pluginID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.PluginBinding{}
	for rows.Next() {
		var b core.PluginBinding
		var en int
		if err := rows.Scan(&b.ID, &b.PluginID, &b.Mount, &b.SpaceID, &b.BoxName, &b.ConfigJSON, &en, &b.UpdatedAt); err != nil {
			return nil, err
		}
		b.Enabled = en != 0
		out = append(out, b)
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

/* ───────── Plugin Scoped Accounts (SHA-256 Secret Hashes Only) ───────── */

func (h *Host) UpsertAccount(bindingID, scopeKey, username, secretHash, mode, metaJSON string) (core.PluginAccount, error) {
	if bindingID == "" || strings.TrimSpace(scopeKey) == "" || strings.TrimSpace(username) == "" {
		return core.PluginAccount{}, core.ErrInvalidInput
	}
	raw, err := hex.DecodeString(strings.TrimSpace(secretHash))
	if err != nil || len(raw) != 32 {
		return core.PluginAccount{}, core.ErrInvalidInput
	}
	normHash := hex.EncodeToString(raw)
	if mode == "" {
		mode = string(core.ModeQueue)
	}
	if metaJSON == "" {
		metaJSON = "{}"
	}
	now := time.Now().Unix()
	_, err = h.store.DB.Exec(
		`INSERT INTO v2_plugin_accounts(binding_id,scope_key,username,secret_hash,mode,meta_json,updated_at)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(binding_id,scope_key) DO UPDATE SET
		   username=excluded.username, secret_hash=excluded.secret_hash, mode=excluded.mode,
		   meta_json=excluded.meta_json, updated_at=excluded.updated_at`,
		bindingID, scopeKey, username, normHash, mode, metaJSON, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return core.PluginAccount{}, core.ErrConflict
		}
		return core.PluginAccount{}, err
	}
	return core.PluginAccount{
		BindingID: bindingID, ScopeKey: scopeKey, Username: username,
		SecretHash: normHash, Mode: mode, MetaJSON: metaJSON, UpdatedAt: now,
	}, nil
}

func (h *Host) AuthAccount(bindingID, username, plainSecret string) (core.PluginAccount, error) {
	var a core.PluginAccount
	err := h.store.DB.QueryRow(
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
	if !SecretMatchesHash(plainSecret, a.SecretHash) {
		return core.PluginAccount{}, core.ErrDenied
	}
	return a, nil
}

func (h *Host) ListAccounts(bindingID string) ([]core.PluginAccount, error) {
	rows, err := h.store.DB.Query(
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
	return nil
}

/* ───────── Controlled Kernel Box Operations for Plugins ───────── */

func (h *Host) EnsureBox(b core.Box) (core.Box, error) { return h.store.EnsureBox(b) }

func (h *Host) PutQueueItem(spaceID, boxName, sender, contentType, metaJSON string, body io.Reader) (core.BoxItem, error) {
	return h.store.PutBoxItem(spaceID, boxName, sender, contentType, metaJSON, 0, body)
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
	b := l.state[key]
	if b == nil || now.Sub(b.since) > l.window {
		l.state[key] = &failBucket{count: 1, since: now}
		return
	}
	b.count++
}

func (l *FailLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, key)
}

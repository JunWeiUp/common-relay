package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	DefaultSpaceQuota  = 2 << 30 // 2 GiB
	DefaultGlobalQuota = 8 << 30 // 8 GiB
	DefaultBoxMaxBytes = 64 << 20
	HardBoxMaxBytes    = 512 << 20 // 512 MiB (covers SyncApp folder transfers)
)

// Store persists v2 metadata in SQLite WAL and opaque blobs in <dir>/blobs/.
//
// It holds two pools on the same database file:
//   - DB is the single writer connection. Every write, and every read that is
//     part of a write (inside a *sql.Tx, or a read-then-write sequence that must
//     see its own uncommitted state), goes through DB or the tx.
//   - RDB is a read-only pool (mode=ro, query_only) for pure reads. In WAL mode
//     readers never wait for the writer and always see the latest committed
//     state, so a read issued after a write commits observes it. Code holding
//     an open transaction must never query RDB: it would not see the tx's own
//     writes.
type Store struct {
	DB          *sql.DB
	RDB         *sql.DB
	Dir         string
	SpaceQuota  int64
	GlobalQuota int64
	OnBoxChange func(spaceID, boxName, event, ref string, seqOrVer int64)
	// OnBoxItem, when set, replaces OnBoxChange(..., "item", ...) for new queue/
	// ephemeral items so the pipe can inline small items into box.changed.
	OnBoxItem func(item BoxItem)

	// DiskReserve is the minimum free space (bytes) that must remain on the data
	// volume after any write. Zero disables the check.
	DiskReserve uint64

	secretKey *[32]byte
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "relay_v2.db")
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	// Per-connection pragmas live in the DSN so they survive a pool reconnect.
	db, err := sql.Open("sqlite", sqliteDSN(abs, "busy_timeout(5000)", "foreign_keys(1)"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	schema := `
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS v2_devices (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL,
	token_hash TEXT UNIQUE NOT NULL,
	is_admin INTEGER NOT NULL DEFAULT 0,
	revoked INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_spaces (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	app TEXT NOT NULL DEFAULT '',
	trust_level TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_space_members (
	space_id TEXT NOT NULL REFERENCES v2_spaces(id) ON DELETE CASCADE,
	device_id TEXT NOT NULL REFERENCES v2_devices(id) ON DELETE CASCADE,
	role TEXT NOT NULL,
	added_at INTEGER NOT NULL,
	PRIMARY KEY (space_id, device_id)
);

CREATE TABLE IF NOT EXISTS v2_boxes (
	space_id TEXT NOT NULL REFERENCES v2_spaces(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	mode TEXT NOT NULL,
	max_bytes INTEGER NOT NULL,
	keep_versions INTEGER NOT NULL DEFAULT 10,
	ttl_sec INTEGER NOT NULL DEFAULT 0,
	next_seq INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (space_id, name)
);

CREATE TABLE IF NOT EXISTS v2_box_items (
	id TEXT PRIMARY KEY,
	space_id TEXT NOT NULL,
	box_name TEXT NOT NULL,
	seq INTEGER NOT NULL,
	sender TEXT NOT NULL,
	size INTEGER NOT NULL,
	sha256 TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	meta_json TEXT NOT NULL DEFAULT '{}',
	expires_at INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	FOREIGN KEY (space_id, box_name) REFERENCES v2_boxes(space_id, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS v2_box_items_seq ON v2_box_items(space_id, box_name, seq);

CREATE TABLE IF NOT EXISTS v2_box_objects (
	space_id TEXT NOT NULL,
	box_name TEXT NOT NULL,
	obj_key TEXT NOT NULL,
	version INTEGER NOT NULL,
	etag TEXT NOT NULL,
	size INTEGER NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	meta_json TEXT NOT NULL DEFAULT '{}',
	blob_id TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (space_id, box_name, obj_key, version),
	FOREIGN KEY (space_id, box_name) REFERENCES v2_boxes(space_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS v2_messages (
	space_id TEXT NOT NULL REFERENCES v2_spaces(id) ON DELETE CASCADE,
	sender TEXT NOT NULL,
	recipient TEXT NOT NULL,
	id TEXT NOT NULL,
	topic TEXT NOT NULL DEFAULT '',
	body TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (space_id, sender, id)
);
CREATE INDEX IF NOT EXISTS v2_messages_inbox ON v2_messages(space_id, recipient, expires_at);

CREATE TABLE IF NOT EXISTS v2_plugin_bindings (
	id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL,
	mount TEXT NOT NULL,
	space_id TEXT NOT NULL REFERENCES v2_spaces(id) ON DELETE CASCADE,
	box_name TEXT NOT NULL DEFAULT '',
	config_json TEXT NOT NULL DEFAULT '{}',
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL,
	UNIQUE (plugin_id, mount)
);

CREATE TABLE IF NOT EXISTS v2_plugin_accounts (
	binding_id TEXT NOT NULL REFERENCES v2_plugin_bindings(id) ON DELETE CASCADE,
	scope_key TEXT NOT NULL,
	username TEXT NOT NULL,
	secret_hash TEXT NOT NULL,
	mode TEXT NOT NULL DEFAULT 'queue',
	meta_json TEXT NOT NULL DEFAULT '{}',
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (binding_id, scope_key),
	UNIQUE (binding_id, username)
);

CREATE TABLE IF NOT EXISTS v2_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(dbPath, 0o600)
	// The reader is opened after the writer switched the file to WAL, so the
	// -wal/-shm files exist and read-only connections can use them.
	rdb, err := sql.Open("sqlite", sqliteDSN(abs, "busy_timeout(5000)", "query_only(1)")+"&mode=ro")
	if err != nil {
		db.Close()
		return nil, err
	}
	rdb.SetMaxOpenConns(ReadPoolSize)
	rdb.SetMaxIdleConns(ReadPoolSize)
	if err := rdb.Ping(); err != nil {
		rdb.Close()
		db.Close()
		return nil, err
	}
	closeAll := func() { rdb.Close(); db.Close() }
	st := &Store{
		DB:          db,
		RDB:         rdb,
		Dir:         dir,
		SpaceQuota:  DefaultSpaceQuota,
		GlobalQuota: DefaultGlobalQuota,
	}
	if st.secretKey, err = loadOrCreateSecretKey(filepath.Join(dir, "plugin-secrets.key")); err != nil {
		closeAll()
		return nil, err
	}
	if err := st.sealPendingSecrets(); err != nil {
		closeAll()
		return nil, err
	}
	st.SweepOrphanBlobs()
	return st, nil
}

// ReadPoolSize bounds concurrent read-only SQLite connections.
const ReadPoolSize = 4

// sqliteDSN builds a file: URI (path escaped) with one _pragma per argument.
func sqliteDSN(absPath string, pragmas ...string) string {
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	return (&url.URL{Scheme: "file", Path: absPath, RawQuery: q.Encode()}).String()
}

// Close closes the read pool first (so the writer, closing last, can checkpoint
// and remove the WAL), then the writer.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.RDB != nil {
		err = s.RDB.Close()
	}
	if s.DB != nil {
		if werr := s.DB.Close(); werr != nil {
			err = werr
		}
	}
	return err
}

// Reader returns the read-only pool, falling back to the writer for stores
// built without one.
func (s *Store) Reader() *sql.DB {
	if s.RDB != nil {
		return s.RDB
	}
	return s.DB
}

// GetSetting reads a persisted runtime setting from v2_settings.
func (s *Store) GetSetting(key string) (string, int64, bool, error) {
	var val string
	var updatedAt int64
	err := s.Reader().QueryRow(`SELECT value, updated_at FROM v2_settings WHERE key=?`, key).Scan(&val, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return val, updatedAt, true, nil
}

// SetSetting atomically upserts a runtime setting into v2_settings.
func (s *Store) SetSetting(key, value string) (int64, error) {
	if strings.TrimSpace(key) == "" {
		return 0, ErrInvalidInput
	}
	now := time.Now().Unix()
	_, err := s.DB.Exec(
		`INSERT INTO v2_settings(key, value, updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, now,
	)
	return now, err
}

func (s *Store) blobPath(blobID string) string {
	return filepath.Join(s.Dir, "blobs", blobID)
}

// writeBlob streams r to a unique 0600 file in blobs/, returning blobID, size, and SHA-256 hex.
func (s *Store) writeBlob(r io.Reader, maxBytes int64) (blobID string, size int64, digest string, err error) {
	if maxBytes <= 0 || maxBytes > HardBoxMaxBytes {
		maxBytes = HardBoxMaxBytes
	}
	blobDir := filepath.Join(s.Dir, "blobs")
	f, err := os.CreateTemp(blobDir, ".blob-*")
	if err != nil {
		return "", 0, "", err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		f.Close()
		return "", 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, maxBytes+1))
	if err == nil && n > maxBytes {
		err = ErrQuota
	}
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return "", 0, "", err
	}
	blobID = RandomHex(16)
	if err = os.Rename(tmp, s.blobPath(blobID)); err != nil {
		return "", 0, "", err
	}
	keep = true
	return blobID, n, hex.EncodeToString(h.Sum(nil)), nil
}

// UsedBytes returns the bytes held by all v2 spaces (O(1) via v2_usage).
func (s *Store) UsedBytes() (int64, error) {
	var n int64
	err := s.Reader().QueryRow(`SELECT COALESCE(SUM(bytes),0) FROM v2_usage`).Scan(&n)
	return n, err
}

func (s *Store) checkQuotaTx(tx *sql.Tx, spaceID string, extra int64) error {
	if extra < 0 {
		return ErrInvalidInput
	}
	// v2_usage is maintained by triggers (see migrate.go), so this is O(1). It
	// also counts signed-ledger file transfers, so the global quota spans the
	// whole data directory.
	var globalUsed, spaceUsed int64
	q := `SELECT COALESCE(SUM(bytes), 0), COALESCE(SUM(CASE WHEN space_id=? THEN bytes ELSE 0 END), 0) FROM v2_usage`
	if err := tx.QueryRow(q, spaceID).Scan(&globalUsed, &spaceUsed); err != nil {
		return err
	}
	if s.SpaceQuota > 0 && spaceUsed+extra > s.SpaceQuota {
		return ErrQuota
	}
	if s.GlobalQuota > 0 && globalUsed+extra > s.GlobalQuota {
		return ErrQuota
	}
	if s.DiskReserve > 0 && !diskHasRoom(s.Dir, s.DiskReserve) {
		return ErrQuota
	}
	return nil
}

/* ───────── Devices ───────── */

func (s *Store) CreateDevice(id, name, pubKey string, isAdmin bool) (Device, string, error) {
	if !ValidIdent(id) || len(pubKey) != 64 {
		return Device{}, "", ErrInvalidInput
	}
	if _, err := hex.DecodeString(pubKey); err != nil {
		return Device{}, "", ErrInvalidInput
	}
	token := RandomHex(32)
	now := time.Now().Unix()
	adm := 0
	if isAdmin {
		adm = 1
	}
	_, err := s.DB.Exec(
		`INSERT INTO v2_devices(id,name,public_key,token_hash,is_admin,revoked,created_at) VALUES(?,?,?,?,?,0,?)`,
		id, strings.TrimSpace(name), strings.ToLower(pubKey), HashSecret(token), adm, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
			return Device{}, "", ErrConflict
		}
		return Device{}, "", err
	}
	return Device{ID: id, Name: strings.TrimSpace(name), PublicKey: strings.ToLower(pubKey), IsAdmin: isAdmin, CreatedAt: now}, token, nil
}

func (s *Store) AuthenticateDevice(token string) (Device, error) {
	if len(token) < 32 {
		return Device{}, ErrDenied
	}
	var d Device
	var adm, rev int
	err := s.Reader().QueryRow(
		`SELECT id,name,public_key,is_admin,revoked,created_at FROM v2_devices WHERE token_hash=? AND revoked=0`,
		HashSecret(token),
	).Scan(&d.ID, &d.Name, &d.PublicKey, &adm, &rev, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrDenied
	}
	if err != nil {
		return Device{}, err
	}
	d.IsAdmin = adm != 0
	d.Revoked = rev != 0
	return d, nil
}

func (s *Store) RevokeDevice(id string) error {
	res, err := s.DB.Exec(`UPDATE v2_devices SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.Reader().Query(`SELECT id,name,public_key,is_admin,revoked,created_at FROM v2_devices ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		var adm, rev int
		if err := rows.Scan(&d.ID, &d.Name, &d.PublicKey, &adm, &rev, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.IsAdmin, d.Revoked = adm != 0, rev != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

/* ───────── Spaces & Membership ───────── */

func (s *Store) CreateSpace(id, name string, trust TrustLevel) (Space, error) {
	if !ValidIdent(id) || !trust.Valid() {
		return Space{}, ErrInvalidInput
	}
	now := time.Now().Unix()
	_, err := s.DB.Exec(`INSERT INTO v2_spaces(id,name,trust_level,created_at) VALUES(?,?,?,?)`, id, strings.TrimSpace(name), string(trust), now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
			return Space{}, ErrConflict
		}
		return Space{}, err
	}
	return Space{ID: id, Name: strings.TrimSpace(name), TrustLevel: trust, CreatedAt: now}, nil
}

func (s *Store) GetSpace(id string) (Space, error) {
	var sp Space
	var tl string
	err := s.Reader().QueryRow(`SELECT id,name,app,trust_level,created_at,managed_by FROM v2_spaces WHERE id=?`, id).Scan(&sp.ID, &sp.Name, &sp.App, &tl, &sp.CreatedAt, &sp.ManagedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Space{}, ErrNotFound
	}
	if err != nil {
		return Space{}, err
	}
	sp.TrustLevel = TrustLevel(tl)
	return sp, nil
}

func (s *Store) ListSpaces() ([]Space, error) {
	rows, err := s.Reader().Query(`SELECT id,name,app,trust_level,created_at,managed_by FROM v2_spaces ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Space{}
	for rows.Next() {
		var sp Space
		var tl string
		if err := rows.Scan(&sp.ID, &sp.Name, &sp.App, &tl, &sp.CreatedAt, &sp.ManagedBy); err != nil {
			return nil, err
		}
		sp.TrustLevel = TrustLevel(tl)
		out = append(out, sp)
	}
	return out, rows.Err()
}

// ListAllSpaceMembers returns active (non-revoked) members grouped by space_id.
func (s *Store) ListAllSpaceMembers() (map[string][]SpaceMemberView, error) {
	rows, err := s.Reader().Query(`
		SELECT m.space_id, m.device_id, d.name, m.role
		FROM v2_space_members m
		JOIN v2_devices d ON d.id = m.device_id
		WHERE d.revoked = 0
		ORDER BY m.space_id, CASE WHEN m.role='admin' THEN 0 ELSE 1 END, m.added_at, d.name, m.device_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]SpaceMemberView{}
	for rows.Next() {
		var sid, role string
		var mv SpaceMemberView
		if err := rows.Scan(&sid, &mv.DeviceID, &mv.Name, &role); err != nil {
			return nil, err
		}
		mv.Role = MemberRole(role)
		out[sid] = append(out[sid], mv)
	}
	return out, rows.Err()
}

// ListAllBoxesWithStats returns every Box grouped by space_id along with live item/object counts and byte totals.
func (s *Store) ListAllBoxesWithStats() (map[string][]SpaceBoxView, error) {
	rows, err := s.Reader().Query(`
		SELECT
			b.space_id,
			b.name,
			b.mode,
			COALESCE(i.cnt, 0) AS item_cnt,
			COALESCE(o.cnt, 0) AS obj_cnt,
			COALESCE(i.sz, 0) + COALESCE(o.sz, 0) AS used_bytes
		FROM v2_boxes b
		LEFT JOIN (
			SELECT space_id, box_name, COUNT(*) AS cnt, COALESCE(SUM(size), 0) AS sz
			FROM v2_box_items
			GROUP BY space_id, box_name
		) i ON i.space_id = b.space_id AND i.box_name = b.name
		LEFT JOIN (
			SELECT space_id, box_name, COUNT(DISTINCT obj_key) AS cnt, COALESCE(SUM(size), 0) AS sz
			FROM v2_box_objects
			GROUP BY space_id, box_name
		) o ON o.space_id = b.space_id AND o.box_name = b.name
		ORDER BY b.space_id, b.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]SpaceBoxView{}
	for rows.Next() {
		var sid, mode string
		var bv SpaceBoxView
		if err := rows.Scan(&sid, &bv.Name, &mode, &bv.Items, &bv.Objects, &bv.UsedBytes); err != nil {
			return nil, err
		}
		bv.Mode = BoxMode(mode)
		out[sid] = append(out[sid], bv)
	}
	return out, rows.Err()
}

// SpaceUsedBytes returns total stored bytes per space across box items, objects, and offline messages.
func (s *Store) SpaceUsedBytes() (map[string]int64, error) {
	rows, err := s.Reader().Query(`SELECT space_id, bytes FROM v2_usage WHERE bytes <> 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var sid string
		var n int64
		if err := rows.Scan(&sid, &n); err != nil {
			return nil, err
		}
		out[sid] = n
	}
	return out, rows.Err()
}

func (s *Store) SetSpaceMember(spaceID, deviceID string, role MemberRole) (SpaceMember, error) {
	if !role.Valid() {
		return SpaceMember{}, ErrInvalidInput
	}
	now := time.Now().Unix()
	_, err := s.DB.Exec(
		`INSERT INTO v2_space_members(space_id,device_id,role,added_at) VALUES(?,?,?,?)
		 ON CONFLICT(space_id,device_id) DO UPDATE SET role=excluded.role`,
		spaceID, deviceID, string(role), now,
	)
	if err != nil {
		return SpaceMember{}, fmt.Errorf("set member: %w", err)
	}
	return SpaceMember{SpaceID: spaceID, DeviceID: deviceID, Role: role, AddedAt: now}, nil
}

func (s *Store) MemberRole(spaceID, deviceID string) (MemberRole, error) {
	var role string
	err := s.Reader().QueryRow(`SELECT role FROM v2_space_members WHERE space_id=? AND device_id=?`, spaceID, deviceID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrDenied
	}
	if err != nil {
		return "", err
	}
	return MemberRole(role), nil
}

func (s *Store) DeviceSpaces(deviceID string) ([]string, error) {
	rows, err := s.Reader().Query(`SELECT space_id FROM v2_space_members WHERE device_id=? ORDER BY space_id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

/* ───────── Messages (Offline Queue with TTL) ───────── */

func (s *Store) PutMessage(m Message) (bool, error) {
	if m.ID == "" || !ValidIdent(m.SpaceID) || m.Sender == "" || m.Recipient == "" {
		return false, ErrInvalidInput
	}
	now := time.Now().Unix()
	if m.CreatedAt == 0 {
		m.CreatedAt = now
	}
	if m.ExpiresAt <= now {
		m.ExpiresAt = now + 86400
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := s.checkQuotaTx(tx, m.SpaceID, int64(len(m.Body))); err != nil {
		return false, err
	}
	res, err := tx.Exec(
		`INSERT OR IGNORE INTO v2_messages(space_id,sender,recipient,id,topic,body,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		m.SpaceID, m.Sender, m.Recipient, m.ID, m.Topic, m.Body, m.ExpiresAt, m.CreatedAt,
	)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) PendingMessages(spaceID, recipient string) ([]Message, error) {
	now := time.Now().Unix()
	rows, err := s.Reader().Query(
		`SELECT id,space_id,sender,recipient,topic,body,expires_at,created_at FROM v2_messages WHERE space_id=? AND recipient=? AND expires_at>? ORDER BY created_at, id LIMIT 256`,
		spaceID, recipient, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.SpaceID, &m.Sender, &m.Recipient, &m.Topic, &m.Body, &m.ExpiresAt, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) AckMessage(spaceID, recipient, sender, id string) error {
	_, err := s.DB.Exec(`DELETE FROM v2_messages WHERE space_id=? AND recipient=? AND sender=? AND id=?`, spaceID, recipient, sender, id)
	return err
}

/* ───────── Status Snapshot ───────── */

func (s *Store) Status(onlinePeers int, plugins []string) (StatusSnapshot, error) {
	st := StatusSnapshot{
		GlobalQuota:  s.GlobalQuota,
		OnlinePeers:  onlinePeers,
		Plugins:      plugins,
		BySpaceBytes: map[string]int64{},
	}
	_ = s.Reader().QueryRow(`SELECT count(*) FROM v2_spaces`).Scan(&st.Spaces)
	_ = s.Reader().QueryRow(`SELECT count(*) FROM v2_devices WHERE revoked=0`).Scan(&st.Devices)
	_ = s.Reader().QueryRow(`SELECT count(*) FROM v2_boxes`).Scan(&st.Boxes)
	_ = s.Reader().QueryRow(`SELECT count(*) FROM v2_box_items`).Scan(&st.PendingItems)
	_ = s.Reader().QueryRow(`SELECT count(*) FROM v2_box_objects`).Scan(&st.StoredObjects)

	rows, err := s.Reader().Query(`SELECT space_id, bytes FROM v2_usage WHERE bytes <> 0`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sid string
			var n int64
			if rows.Scan(&sid, &n) == nil {
				st.BySpaceBytes[sid] = n
				st.UsedBytes += n
			}
		}
	}
	return st, nil
}

// ManagedSpaceOwner is the provenance tag for spaces that mirror signed device
// groups of app (internal/v2/ledger). Devices carry ManagedSpaceOwner(app)+":"+group.
// The "v1:" prefix is historical and kept: existing rows and admin tools use it.
func ManagedSpaceOwner(app string) string { return "v1:" + strings.TrimSpace(app) }

// SyncConflicts counts group members skipped because their device ID or token
// already belonged to another identity (exposed for logs/metrics).
var SyncConflicts atomic.Int64

// ManagedMember describes one active member of a signed device group mirrored into a v2 Space.
type ManagedMember struct {
	ID        string
	Name      string
	PublicKey string
	TokenHash string
	Manager   bool
}

// SyncManagedGroup mirrors a verified group state (without app namespace); see SyncManagedGroupTx.
func (s *Store) SyncManagedGroup(spaceID, name string, members []ManagedMember, removed []string, closed bool) error {
	return s.SyncManagedGroupWithApp(spaceID, "", name, members, removed, closed)
}

// SyncManagedGroupWithApp runs SyncManagedGroupTx in its own transaction.
func (s *Store) SyncManagedGroupWithApp(spaceID, app, name string, members []ManagedMember, removed []string, closed bool) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := SyncManagedGroupTx(tx, spaceID, app, name, members, removed, closed); err != nil {
		return err
	}
	return tx.Commit()
}

// SyncManagedGroupTx writes a cryptographically verified signed-group state into
// v2_spaces, v2_devices and v2_space_members inside the caller's transaction (the
// ledger commits the signed entry in the same one), so group members authenticate
// natively on /v2/ws. Admin devices and unrelated spaces are never altered.
func SyncManagedGroupTx(tx *sql.Tx, spaceID, app, name string, members []ManagedMember, removed []string, closed bool) error {
	if !ValidIdent(spaceID) {
		return ErrInvalidInput
	}
	now := time.Now().Unix()

	appNorm := strings.TrimSpace(app)
	owner := ManagedSpaceOwner(appNorm)
	devOwner := owner + ":" + spaceID

	// Provenance guard: only ever touch a space this exact (app, group) created.
	// A same-named admin space or another app's group is never merged.
	var curOwner string
	switch err := tx.QueryRow(`SELECT managed_by FROM v2_spaces WHERE id=?`, spaceID).Scan(&curOwner); {
	case errors.Is(err, sql.ErrNoRows):
		if closed {
			return nil
		}
		if _, err := tx.Exec(
			`INSERT INTO v2_spaces(id, name, app, trust_level, created_at, managed_by) VALUES(?,?,?,?,?,?)`,
			spaceID, strings.TrimSpace(name), appNorm, string(TrustStrictE2E), now, owner,
		); err != nil {
			return err
		}
	case err != nil:
		return err
	case curOwner != owner:
		return fmt.Errorf("%w: space %s is owned by %q, refusing group %q", ErrConflict, spaceID, curOwner, owner)
	default:
		if _, err := tx.Exec(`UPDATE v2_spaces SET name=? WHERE id=?`, strings.TrimSpace(name), spaceID); err != nil {
			return err
		}
	}
	active := make(map[string]struct{}, len(members))
	for _, m := range members {
		if !ValidIdent(m.ID) || len(m.PublicKey) != 64 || len(m.TokenHash) != 64 {
			continue
		}
		if _, err := hex.DecodeString(m.PublicKey); err != nil {
			continue
		}
		if _, err := hex.DecodeString(m.TokenHash); err != nil {
			continue
		}
		var devManagedBy string
		err := tx.QueryRow(`SELECT managed_by FROM v2_devices WHERE id=?`, m.ID).Scan(&devManagedBy)
		if err == sql.ErrNoRows {
			if _, err := tx.Exec(
				`INSERT INTO v2_devices(id, name, public_key, token_hash, is_admin, revoked, created_at, managed_by) VALUES(?,?,?,?,0,0,?,?)`,
				m.ID, strings.TrimSpace(m.Name), strings.ToLower(m.PublicKey), strings.ToLower(m.TokenHash), now, devOwner,
			); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					// Token hash already belongs to another device: skip, never steal.
					SyncConflicts.Add(1)
					continue
				}
				return err
			}
		} else if err != nil {
			return err
		} else if devManagedBy != devOwner {
			// Device ID is owned by an admin-created device or by another group's
			// projection. Overwriting its token would hijack (or break) that identity.
			SyncConflicts.Add(1)
			continue
		} else if _, err := tx.Exec(
			`UPDATE v2_devices SET name=?, public_key=?, token_hash=?, revoked=0 WHERE id=? AND managed_by=?`,
			strings.TrimSpace(m.Name), strings.ToLower(m.PublicKey), strings.ToLower(m.TokenHash), m.ID, devOwner,
		); err != nil {
			return err
		}
		active[m.ID] = struct{}{}
		role := RoleMember
		if m.Manager {
			role = RoleAdmin
		}
		if _, err := tx.Exec(
			`INSERT INTO v2_space_members(space_id, device_id, role, added_at) VALUES(?,?,?,?)
			 ON CONFLICT(space_id, device_id) DO UPDATE SET role=excluded.role`,
			spaceID, m.ID, string(role), now,
		); err != nil {
			return err
		}
	}

	toRemove := append([]string(nil), removed...)
	if closed {
		rows, err := tx.Query(`SELECT device_id FROM v2_space_members WHERE space_id=?`, spaceID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var devID string
			if rows.Scan(&devID) == nil {
				toRemove = append(toRemove, devID)
			}
		}
		rows.Close()
	}

	seen := map[string]struct{}{}
	for _, devID := range toRemove {
		if _, stillActive := active[devID]; stillActive && !closed {
			continue
		}
		if _, dup := seen[devID]; dup {
			continue
		}
		seen[devID] = struct{}{}
		if _, err := tx.Exec(`DELETE FROM v2_space_members WHERE space_id=? AND device_id=?`, spaceID, devID); err != nil {
			return err
		}
		var remaining int
		if err := tx.QueryRow(`SELECT count(*) FROM v2_space_members WHERE device_id=?`, devID).Scan(&remaining); err == nil && remaining == 0 {
			// Only revoke identities this group projection owns.
			_, _ = tx.Exec(`UPDATE v2_devices SET revoked=1 WHERE id=? AND is_admin=0 AND managed_by=?`, devID, devOwner)
		}
	}
	return nil
}

package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
type Store struct {
	DB          *sql.DB
	Dir         string
	SpaceQuota  int64
	GlobalQuota int64
	OnBoxChange func(spaceID, boxName, event, ref string, seqOrVer int64)
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "relay_v2.db")
	db, err := sql.Open("sqlite", dbPath)
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
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(dbPath, 0o600)
	return &Store{
		DB:          db,
		Dir:         dir,
		SpaceQuota:  DefaultSpaceQuota,
		GlobalQuota: DefaultGlobalQuota,
	}, nil
}

func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
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

func (s *Store) checkQuotaTx(tx *sql.Tx, spaceID string, extra int64) error {
	if extra < 0 {
		return ErrInvalidInput
	}
	var globalUsed, spaceUsed int64
	q := `SELECT COALESCE(SUM(sz), 0), COALESCE(SUM(CASE WHEN space_id=? THEN sz ELSE 0 END), 0)
	      FROM (
	        SELECT space_id, size AS sz FROM v2_box_items
	        UNION ALL
	        SELECT space_id, size AS sz FROM v2_box_objects
	        UNION ALL
	        SELECT space_id, length(body) AS sz FROM v2_messages
	      )`
	if err := tx.QueryRow(q, spaceID).Scan(&globalUsed, &spaceUsed); err != nil {
		return err
	}
	if s.SpaceQuota > 0 && spaceUsed+extra > s.SpaceQuota {
		return ErrQuota
	}
	if s.GlobalQuota > 0 && globalUsed+extra > s.GlobalQuota {
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
	err := s.DB.QueryRow(
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
	rows, err := s.DB.Query(`SELECT id,name,public_key,is_admin,revoked,created_at FROM v2_devices ORDER BY created_at, id`)
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
	err := s.DB.QueryRow(`SELECT id,name,trust_level,created_at FROM v2_spaces WHERE id=?`, id).Scan(&sp.ID, &sp.Name, &tl, &sp.CreatedAt)
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
	rows, err := s.DB.Query(`SELECT id,name,trust_level,created_at FROM v2_spaces ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Space{}
	for rows.Next() {
		var sp Space
		var tl string
		if err := rows.Scan(&sp.ID, &sp.Name, &tl, &sp.CreatedAt); err != nil {
			return nil, err
		}
		sp.TrustLevel = TrustLevel(tl)
		out = append(out, sp)
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
	err := s.DB.QueryRow(`SELECT role FROM v2_space_members WHERE space_id=? AND device_id=?`, spaceID, deviceID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrDenied
	}
	if err != nil {
		return "", err
	}
	return MemberRole(role), nil
}

func (s *Store) DeviceSpaces(deviceID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT space_id FROM v2_space_members WHERE device_id=? ORDER BY space_id`, deviceID)
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
	rows, err := s.DB.Query(
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
	_ = s.DB.QueryRow(`SELECT count(*) FROM v2_spaces`).Scan(&st.Spaces)
	_ = s.DB.QueryRow(`SELECT count(*) FROM v2_devices WHERE revoked=0`).Scan(&st.Devices)
	_ = s.DB.QueryRow(`SELECT count(*) FROM v2_boxes`).Scan(&st.Boxes)
	_ = s.DB.QueryRow(`SELECT count(*) FROM v2_box_items`).Scan(&st.PendingItems)
	_ = s.DB.QueryRow(`SELECT count(*) FROM v2_box_objects`).Scan(&st.StoredObjects)

	rows, err := s.DB.Query(`
		SELECT space_id, COALESCE(SUM(sz), 0) FROM (
			SELECT space_id, size AS sz FROM v2_box_items
			UNION ALL
			SELECT space_id, size AS sz FROM v2_box_objects
			UNION ALL
			SELECT space_id, length(body) AS sz FROM v2_messages
		) GROUP BY space_id`)
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

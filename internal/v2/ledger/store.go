// Package ledger hosts the client-signed device-group ledger (/v2/group,
// /v2/enroll) and the resumable end-to-end encrypted file plane (/v2/files).
//
// All state lives in the v2 store (relay_v2.db, tables v2_ledger_*; file
// payloads in <data>/blobs/files/). A group's membership is written to
// v2_spaces / v2_space_members / v2_devices in the same transaction that
// appends its signed entry, so ledger devices authenticate on /v2/ws natively.
package ledger

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var objectID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var ErrDenied = errors.New("denied")
var ErrQuota = errors.New("quota exceeded")

// Device is one per-group credential (v2_ledger_devices). The same device ID may
// exist in several groups with distinct tokens, which is why ledger credentials
// are keyed by (app, group, id) rather than living only in v2_devices.
type Device struct {
	App       string `json:"app"`
	Group     string `json:"group"`
	ID        string `json:"device"`
	PublicKey string `json:"public_key"`
}

// Store is the ledger's view of the v2 store.
type Store struct {
	V2                    *core.Store
	DB                    *sql.DB
	Dir                   string // data directory (disk-reserve checks)
	AppQuota, GlobalQuota int64
}

// FilesDir holds ledger file payloads, one file per transfer ID.
func FilesDir(dataDir string) string { return filepath.Join(dataDir, "blobs", "files") }

// Open prepares the ledger on an opened v2 store (schema comes from core migrations).
func Open(v2 *core.Store) (*Store, error) {
	if err := os.MkdirAll(FilesDir(v2.Dir), 0o700); err != nil {
		return nil, err
	}
	return &Store{V2: v2, DB: v2.DB, Dir: v2.Dir, AppQuota: 2 << 30, GlobalQuota: 5 << 30}, nil
}

func RandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// UsedBytes returns the bytes currently reserved by ledger file transfers.
func (s *Store) UsedBytes() (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COALESCE(SUM(size),0) FROM v2_ledger_files`).Scan(&n)
	return n, err
}

func (s *Store) Authenticate(token string) (Device, error) {
	var d Device
	if len(token) < 32 {
		return d, ErrDenied
	}
	err := s.DB.QueryRow("SELECT app,grp,id,public_key FROM v2_ledger_devices WHERE token_hash=? AND revoked=0", hashToken(token)).Scan(&d.App, &d.Group, &d.ID, &d.PublicKey)
	return d, err
}
func (s *Store) Peer(d Device, id string) (Device, error) {
	var p Device
	err := s.DB.QueryRow("SELECT app,grp,id,public_key FROM v2_ledger_devices WHERE app=? AND grp=? AND id=? AND revoked=0", d.App, d.Group, id).Scan(&p.App, &p.Group, &p.ID, &p.PublicKey)
	return p, err
}

// quota bounds ledger file bytes per app (AppQuota) and all stored bytes of the
// data directory (GlobalQuota, from v2_usage which also counts ledger files).
func (s *Store) quota(tx *sql.Tx, app string, extra int64) error {
	var a, g int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size),0) FROM v2_ledger_files WHERE app=?`, app).Scan(&a); err != nil {
		return err
	}
	if err := tx.QueryRow(`SELECT COALESCE(SUM(bytes),0) FROM v2_usage`).Scan(&g); err != nil {
		return err
	}
	if extra < 0 || a+extra > s.AppQuota || g+extra > s.GlobalQuota {
		return ErrQuota
	}
	return nil
}

// GroupBootstrap is an explicit administrator capability, never an ordinary device token.
func (s *Store) GroupBootstrap(app, group, secret string) error {
	if !identifier.MatchString(app) || !identifier.MatchString(group) || len(secret) < 32 {
		return ErrDenied
	}
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM v2_ledger_entries WHERE app=? AND grp=?", app, group).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return errors.New("group already initialized")
	}
	_, err := s.DB.Exec("INSERT INTO v2_ledger_bootstrap VALUES(?,?,?,?)", hashToken(secret), app, group, time.Now().Add(10*time.Minute).Unix())
	return err
}

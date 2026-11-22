package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"regexp"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var objectID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var ErrDenied = errors.New("denied")
var ErrQuota = errors.New("quota exceeded")

type Device struct {
	App       string `json:"app"`
	Group     string `json:"group"`
	ID        string `json:"device"`
	PublicKey string `json:"public_key"`
}
type Store struct {
	DB                    *sql.DB
	Dir                   string
	AppQuota, GlobalQuota int64
	// ExternalUsage reports bytes held by the co-located v2 store so the global
	// quota bounds the whole data directory. It must not touch this DB (it is
	// called inside ledger transactions on a single-connection pool).
	ExternalUsage func() int64
}

// UsedBytes returns the bytes currently held by stored files.
func (s *Store) UsedBytes() (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COALESCE(SUM(size),0) FROM files`).Scan(&n)
	return n, err
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
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "relay.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// Tables of the removed v1 transport (messages, receipts, webdav_*, webhook_receipts)
	// stay untouched in existing databases; nothing creates or reads them any more.
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS devices(app TEXT NOT NULL, grp TEXT NOT NULL, id TEXT NOT NULL, token TEXT UNIQUE NOT NULL, public_key TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(app,grp,id));
 CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,size INTEGER NOT NULL,offset INTEGER NOT NULL DEFAULT 0,metadata TEXT NOT NULL,digest TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'uploading',expires INTEGER NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	os.Chmod(filepath.Join(dir, "relay.db"), 0600)
	store := &Store{DB: db, Dir: dir, AppQuota: 2 << 30, GlobalQuota: 5 << 30}
	if err := store.initGroups(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}
func (s *Store) Authenticate(token string) (Device, error) {
	var d Device
	if len(token) < 32 {
		return d, ErrDenied
	}
	err := s.DB.QueryRow("SELECT app,grp,id,public_key FROM devices WHERE token=? AND revoked=0", hashToken(token)).Scan(&d.App, &d.Group, &d.ID, &d.PublicKey)
	return d, err
}
func (s *Store) Peer(d Device, id string) (Device, error) {
	var p Device
	err := s.DB.QueryRow("SELECT app,grp,id,public_key FROM devices WHERE app=? AND grp=? AND id=? AND revoked=0", d.App, d.Group, id).Scan(&p.App, &p.Group, &p.ID, &p.PublicKey)
	return p, err
}
func (s *Store) quota(tx *sql.Tx, app string, extra int64) error {
	var ext int64
	if s.ExternalUsage != nil {
		ext = s.ExternalUsage()
	}
	return quota(tx, app, extra, s.AppQuota, s.GlobalQuota-ext)
}

func quota(tx *sql.Tx, app string, extra, appMax, globalMax int64) error {
	var a, g int64
	err := tx.QueryRow(`SELECT COALESCE(SUM(n),0),COALESCE(SUM(CASE WHEN app=? THEN n ELSE 0 END),0) FROM (SELECT app,size AS n FROM files)`, app).Scan(&g, &a)
	if err != nil {
		return err
	}
	if extra < 0 || a+extra > appMax || g+extra > globalMax {
		return ErrQuota
	}
	return nil
}

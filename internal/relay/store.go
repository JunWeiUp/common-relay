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
	"time"
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
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS devices(app TEXT NOT NULL, grp TEXT NOT NULL, id TEXT NOT NULL, token TEXT UNIQUE NOT NULL, public_key TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(app,grp,id));
 CREATE TABLE IF NOT EXISTS messages(app TEXT NOT NULL, grp TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(app,grp,sender,id));
 CREATE INDEX IF NOT EXISTS inbox ON messages(app,grp,recipient,expires);
 CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,size INTEGER NOT NULL,offset INTEGER NOT NULL DEFAULT 0,metadata TEXT NOT NULL,digest TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'uploading',expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS receipts(app TEXT NOT NULL,grp TEXT NOT NULL,sender TEXT NOT NULL,id TEXT NOT NULL,recipient TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(app,grp,sender,id));`)
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
func (s *Store) unmanaged(d Device) error {
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM group_entries WHERE app=? AND grp=?", d.App, d.Group).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("managed group: use signed group API")
	}
	return nil
}
func (s *Store) AddDevice(d Device, token string) error {
	if err := s.unmanaged(d); err != nil {
		return err
	}
	if !identifier.MatchString(d.App) || !identifier.MatchString(d.Group) || !identifier.MatchString(d.ID) || len(token) < 32 || len(d.PublicKey) != 64 {
		return errors.New("invalid device")
	}
	if _, err := hex.DecodeString(d.PublicKey); err != nil {
		return err
	}
	result, err := s.DB.Exec("INSERT INTO devices(app,grp,id,token,public_key) SELECT ?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM group_entries WHERE app=? AND grp=?)", d.App, d.Group, d.ID, hashToken(token), d.PublicKey, d.App, d.Group)
	if err == nil {
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			return ErrDenied
		}
	}
	return err
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
func (s *Store) Revoke(d Device) error {
	if err := s.unmanaged(d); err != nil {
		return err
	}
	_, err := s.DB.Exec("UPDATE devices SET revoked=1 WHERE app=? AND grp=? AND id=? AND NOT EXISTS(SELECT 1 FROM group_entries WHERE app=? AND grp=?)", d.App, d.Group, d.ID, d.App, d.Group)
	return err
}
func quota(tx *sql.Tx, app string, extra, appMax, globalMax int64) error {
	var a, g int64
	err := tx.QueryRow(`SELECT COALESCE(SUM(n),0),COALESCE(SUM(CASE WHEN app=? THEN n ELSE 0 END),0) FROM (SELECT app,size AS n FROM files UNION ALL SELECT app,length(body) AS n FROM messages)`, app).Scan(&g, &a)
	if err != nil {
		return err
	}
	if extra < 0 || a+extra > appMax || g+extra > globalMax {
		return ErrQuota
	}
	return nil
}
func (s *Store) PutMessage(d Device, to, id string, body []byte, ttl int64, absoluteExpiry ...int64) (string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var oldTo string
	var old []byte
	err = tx.QueryRow("SELECT recipient,body FROM messages WHERE app=? AND grp=? AND sender=? AND id=?", d.App, d.Group, d.ID, id).Scan(&oldTo, &old)
	if err == nil {
		if oldTo != to || string(old) != string(body) {
			return "", errors.New("id conflict")
		}
		return "stored", nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	var receiptTo string
	err = tx.QueryRow("SELECT recipient FROM receipts WHERE app=? AND grp=? AND sender=? AND id=?", d.App, d.Group, d.ID, id).Scan(&receiptTo)
	if err == nil {
		if receiptTo != to {
			return "", errors.New("id conflict")
		}
		return "received", nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	if err = quota(tx, d.App, int64(len(body)), s.AppQuota, s.GlobalQuota); err != nil {
		return "", err
	}
	expires := time.Now().Unix() + ttl
	if len(absoluteExpiry) > 0 && absoluteExpiry[0] != 0 {
		expires = absoluteExpiry[0]
	}
	if expires <= time.Now().Unix() {
		return "", errors.New("message expired")
	}
	_, err = tx.Exec("INSERT INTO messages VALUES(?,?,?,?,?,?,?)", d.App, d.Group, d.ID, to, id, body, expires)
	if err != nil {
		return "", err
	}
	return "stored", tx.Commit()
}
func (s *Store) Ack(d Device, from, id string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT OR IGNORE INTO receipts SELECT app,grp,sender,id,recipient,expires FROM messages WHERE app=? AND grp=? AND recipient=? AND sender=? AND id=?`, d.App, d.Group, d.ID, from, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM messages WHERE app=? AND grp=? AND recipient=? AND sender=? AND id=?", d.App, d.Group, d.ID, from, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

/* ───────── Encrypted plugin secrets (secrets_json) ───────── */

// Plugin secrets (token hashes, HMAC keys) live in v2_plugin_bindings.secrets_json,
// sealed with a per-installation key kept in <data>/plugin-secrets.key (0600).
// A copied relay_v2.db alone does not reveal HMAC keys; keep the key file out of
// routine database backups (or back it up separately).
const secretsPrefix = "sb1:"

func loadOrCreateSecretKey(path string) (*[32]byte, error) {
	var key [32]byte
	if raw, err := os.ReadFile(path); err == nil {
		dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(dec) != 32 {
			return nil, errors.New("plugin-secrets.key is corrupt")
		}
		copy(key[:], dec)
		return &key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key[:]) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return &key, f.Close()
}

// SealSecrets encrypts a plugin secrets map for storage.
func (s *Store) SealSecrets(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	out := secretbox.Seal(nonce[:], plain, &nonce, s.secretKey)
	return secretsPrefix + base64.StdEncoding.EncodeToString(out), nil
}

// OpenSecrets decrypts a stored secrets_json value. Empty input yields an empty map.
func (s *Store) OpenSecrets(stored string) (map[string]any, error) {
	out := map[string]any{}
	switch {
	case stored == "":
		return out, nil
	case strings.HasPrefix(stored, legacyPlainPrefix):
		err := json.Unmarshal([]byte(strings.TrimPrefix(stored, legacyPlainPrefix)), &out)
		return out, err
	case strings.HasPrefix(stored, secretsPrefix):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretsPrefix))
		if err != nil || len(raw) < 24+secretbox.Overhead {
			return nil, errors.New("plugin secrets corrupt")
		}
		var nonce [24]byte
		copy(nonce[:], raw[:24])
		plain, ok := secretbox.Open(nil, raw[24:], &nonce, s.secretKey)
		if !ok {
			return nil, errors.New("plugin secrets cannot be decrypted (wrong plugin-secrets.key?)")
		}
		err = json.Unmarshal(plain, &out)
		return out, err
	default:
		return nil, errors.New("plugin secrets in unknown format")
	}
}

// sealPendingSecrets encrypts secrets that a migration moved out of config_json.
func (s *Store) sealPendingSecrets() error {
	rows, err := s.DB.Query(`SELECT id, secrets_json FROM v2_plugin_bindings WHERE secrets_json LIKE 'plain:%'`)
	if err != nil {
		return err
	}
	type pending struct{ id, raw string }
	var list []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.raw); err != nil {
			rows.Close()
			return err
		}
		list = append(list, p)
	}
	rows.Close()
	for _, p := range list {
		m, err := s.OpenSecrets(p.raw)
		if err != nil {
			return err
		}
		sealed, err := s.SealSecrets(m)
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(`UPDATE v2_plugin_bindings SET secrets_json=? WHERE id=?`, sealed, p.id); err != nil {
			return err
		}
	}
	return nil
}

/* ───────── Disk reserve ───────── */

func diskHasRoom(dir string, reserve uint64) bool {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return false
	}
	return uint64(st.Bavail)*uint64(st.Bsize) >= reserve
}

/* ───────── Orphan blob recovery ───────── */

// SweepOrphanBlobs removes blob files no metadata row references. Blobs are
// renamed into place before their transaction commits, so a crash in between
// leaves an unreferenced file; this runs at startup and from the periodic sweep.
// Files younger than a minute are skipped to avoid racing in-flight writes.
func (s *Store) SweepOrphanBlobs() (removed int) {
	dir := filepath.Join(s.Dir, "blobs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	cutoff := time.Now().Add(-time.Minute)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".part") {
			if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff.Add(-time.Hour)) {
				if !strings.HasSuffix(name, ".part") {
					_ = os.Remove(filepath.Join(dir, name))
				}
			}
			continue
		}
		if info, err := e.Info(); err != nil || info.ModTime().After(cutoff) {
			continue
		}
		var one int
		err := s.DB.QueryRow(`SELECT 1 FROM v2_box_items WHERE id=? UNION ALL SELECT 1 FROM v2_box_objects WHERE blob_id=? LIMIT 1`, name, name).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			if os.Remove(filepath.Join(dir, name)) == nil {
				removed++
			}
		}
	}
	return removed
}

/* ───────── Plugin idempotency receipts ───────── */

// ReceiptTTL bounds how long Idempotency-Key receipts are remembered.
const ReceiptTTL = 7 * 24 * time.Hour

// LookupReceipt returns the item a previous delivery with the same key created.
func (s *Store) LookupReceipt(bindingID, key string) (itemID string, seq int64, ok bool, err error) {
	err = s.DB.QueryRow(`SELECT item_id, seq FROM v2_plugin_receipts WHERE binding_id=? AND key=? AND created_at>?`,
		bindingID, key, time.Now().Add(-ReceiptTTL).Unix()).Scan(&itemID, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	return itemID, seq, err == nil, err
}

// SaveReceipt records an accepted delivery. A concurrent duplicate loses with ErrConflict.
func (s *Store) SaveReceipt(bindingID, key, itemID string, seq int64) error {
	_, err := s.DB.Exec(`INSERT INTO v2_plugin_receipts(binding_id,key,item_id,seq,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(binding_id,key) DO UPDATE SET item_id=excluded.item_id, seq=excluded.seq, created_at=excluded.created_at
		WHERE v2_plugin_receipts.created_at <= ?`,
		bindingID, key, itemID, seq, time.Now().Unix(), time.Now().Add(-ReceiptTTL).Unix())
	return err
}

func (s *Store) sweepReceipts() {
	_, _ = s.DB.Exec(`DELETE FROM v2_plugin_receipts WHERE created_at<=?`, time.Now().Add(-ReceiptTTL).Unix())
}

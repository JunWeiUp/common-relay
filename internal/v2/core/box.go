package core

import (
	"database/sql"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

/* ───────── Box Management ───────── */

func (s *Store) CreateBox(b Box) (Box, error) {
	if !ValidIdent(b.SpaceID) || !ValidBoxName(b.Name) || !b.Mode.Valid() {
		return Box{}, ErrInvalidInput
	}
	if b.MaxBytes <= 0 {
		if b.Mode == ModeEphemeral {
			b.MaxBytes = HardBoxMaxBytes
		} else {
			b.MaxBytes = DefaultBoxMaxBytes
		}
	}
	if b.MaxBytes > HardBoxMaxBytes {
		return Box{}, ErrInvalidInput
	}
	if b.KeepVersions <= 0 {
		b.KeepVersions = 10
	}
	if b.Mode == ModeEphemeral && b.TTLSec <= 0 {
		b.TTLSec = 86400 // 24h default for SyncApp offline file transfers
	}
	_, err := s.DB.Exec(
		`INSERT INTO v2_boxes(space_id,name,mode,max_bytes,keep_versions,ttl_sec,next_seq) VALUES(?,?,?,?,?,?,0)`,
		b.SpaceID, b.Name, string(b.Mode), b.MaxBytes, b.KeepVersions, b.TTLSec,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
			return Box{}, ErrConflict
		}
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return Box{}, ErrNotFound
		}
		return Box{}, err
	}
	return b, nil
}

func (s *Store) EnsureBox(b Box) (Box, error) {
	existing, err := s.GetBox(b.SpaceID, b.Name)
	if err == nil {
		if existing.Mode != b.Mode {
			return Box{}, ErrConflict
		}
		return existing, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Box{}, err
	}
	return s.CreateBox(b)
}

func (s *Store) GetBox(spaceID, name string) (Box, error) {
	var b Box
	var mode string
	err := s.Reader().QueryRow(
		`SELECT space_id,name,mode,max_bytes,keep_versions,ttl_sec,next_seq FROM v2_boxes WHERE space_id=? AND name=?`,
		spaceID, name,
	).Scan(&b.SpaceID, &b.Name, &mode, &b.MaxBytes, &b.KeepVersions, &b.TTLSec, &b.NextSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return Box{}, ErrNotFound
	}
	if err != nil {
		return Box{}, err
	}
	b.Mode = BoxMode(mode)
	return b, nil
}

func (s *Store) ListBoxes(spaceID string) ([]Box, error) {
	rows, err := s.Reader().Query(
		`SELECT space_id,name,mode,max_bytes,keep_versions,ttl_sec,next_seq FROM v2_boxes WHERE space_id=? ORDER BY name`,
		spaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Box{}
	for rows.Next() {
		var b Box
		var mode string
		if err := rows.Scan(&b.SpaceID, &b.Name, &mode, &b.MaxBytes, &b.KeepVersions, &b.TTLSec, &b.NextSeq); err != nil {
			return nil, err
		}
		b.Mode = BoxMode(mode)
		out = append(out, b)
	}
	return out, rows.Err()
}

/* ───────── Queue & Ephemeral Items ───────── */

func (s *Store) PutBoxItem(spaceID, boxName, sender, contentType, metaJSON string, ttlOverride int64, body io.Reader) (BoxItem, error) {
	box, err := s.GetBox(spaceID, boxName)
	if err != nil {
		return BoxItem{}, err
	}
	if box.Mode != ModeQueue && box.Mode != ModeEphemeral {
		return BoxItem{}, ErrInvalidInput
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if metaJSON == "" {
		metaJSON = "{}"
	}
	blobID, size, digest, err := s.writeBlob(body, box.MaxBytes)
	if err != nil {
		return BoxItem{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(s.blobPath(blobID))
		}
	}()

	now := time.Now().Unix()
	var expiresAt int64
	ttl := box.TTLSec
	if ttlOverride > 0 {
		ttl = ttlOverride
	}
	if ttl > 0 {
		expiresAt = now + ttl
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return BoxItem{}, err
	}
	defer tx.Rollback()
	if err := s.checkQuotaTx(tx, spaceID, size); err != nil {
		return BoxItem{}, err
	}
	if _, err := tx.Exec(`UPDATE v2_boxes SET next_seq = next_seq + 1 WHERE space_id=? AND name=?`, spaceID, boxName); err != nil {
		return BoxItem{}, err
	}
	var seq int64
	if err := tx.QueryRow(`SELECT next_seq FROM v2_boxes WHERE space_id=? AND name=?`, spaceID, boxName).Scan(&seq); err != nil {
		return BoxItem{}, err
	}
	_, err = tx.Exec(
		`INSERT INTO v2_box_items(id,space_id,box_name,seq,sender,size,sha256,content_type,meta_json,expires_at,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		blobID, spaceID, boxName, seq, sender, size, digest, contentType, metaJSON, expiresAt, now,
	)
	if err != nil {
		return BoxItem{}, err
	}
	if err := tx.Commit(); err != nil {
		return BoxItem{}, err
	}
	committed = true

	item := BoxItem{
		ID: blobID, SpaceID: spaceID, BoxName: boxName, Seq: seq, Sender: sender,
		Size: size, SHA256: digest, ContentType: contentType, MetaJSON: metaJSON,
		ExpiresAt: expiresAt, CreatedAt: now,
	}
	if s.OnBoxItem != nil {
		s.OnBoxItem(item)
	} else if s.OnBoxChange != nil {
		s.OnBoxChange(spaceID, boxName, "item", item.ID, item.Seq)
	}
	return item, nil
}

func (s *Store) ListBoxItems(spaceID, boxName string, afterSeq int64, limit int) ([]BoxItem, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	now := time.Now().Unix()
	rows, err := s.Reader().Query(
		`SELECT id,space_id,box_name,seq,sender,size,sha256,content_type,meta_json,expires_at,created_at
		 FROM v2_box_items
		 WHERE space_id=? AND box_name=? AND seq>? AND (expires_at=0 OR expires_at>?)
		 ORDER BY seq ASC LIMIT ?`,
		spaceID, boxName, afterSeq, now, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BoxItem{}
	for rows.Next() {
		var it BoxItem
		if err := rows.Scan(&it.ID, &it.SpaceID, &it.BoxName, &it.Seq, &it.Sender, &it.Size, &it.SHA256, &it.ContentType, &it.MetaJSON, &it.ExpiresAt, &it.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) OpenBoxItem(spaceID, boxName, itemID string) (*os.File, BoxItem, error) {
	var it BoxItem
	now := time.Now().Unix()
	err := s.Reader().QueryRow(
		`SELECT id,space_id,box_name,seq,sender,size,sha256,content_type,meta_json,expires_at,created_at
		 FROM v2_box_items WHERE id=? AND space_id=? AND box_name=?`,
		itemID, spaceID, boxName,
	).Scan(&it.ID, &it.SpaceID, &it.BoxName, &it.Seq, &it.Sender, &it.Size, &it.SHA256, &it.ContentType, &it.MetaJSON, &it.ExpiresAt, &it.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, BoxItem{}, ErrNotFound
	}
	if err != nil {
		return nil, BoxItem{}, err
	}
	if it.ExpiresAt > 0 && it.ExpiresAt <= now {
		return nil, BoxItem{}, ErrNotFound
	}
	f, err := os.Open(s.blobPath(it.ID))
	if err != nil {
		return nil, BoxItem{}, ErrNotFound
	}
	return f, it, nil
}

func (s *Store) AckBoxItem(spaceID, boxName, itemID string) error {
	res, err := s.DB.Exec(`DELETE FROM v2_box_items WHERE id=? AND space_id=? AND box_name=?`, itemID, spaceID, boxName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	_ = os.Remove(s.blobPath(itemID))
	return nil
}

// MaxAckBatch bounds the item IDs accepted by one AckBoxItems call.
const MaxAckBatch = 200

// AckBoxItems deletes several items of one queue/ephemeral Box in a single
// transaction. IDs that are not (or no longer) in this Box — already acked,
// expired, or belonging to another Box/Space — are returned in missing and are
// not an error, so retrying a batch is idempotent and never reveals whether an
// ID exists elsewhere.
func (s *Store) AckBoxItems(spaceID, boxName string, ids []string) (acked, missing []string, err error) {
	if len(ids) == 0 || len(ids) > MaxAckBatch {
		return nil, nil, ErrInvalidInput
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`DELETE FROM v2_box_items WHERE id=? AND space_id=? AND box_name=?`)
	if err != nil {
		return nil, nil, err
	}
	defer stmt.Close()
	acked, missing = []string{}, []string{}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		res, err := stmt.Exec(id, spaceID, boxName)
		if err != nil {
			return nil, nil, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			acked = append(acked, id)
		} else {
			missing = append(missing, id)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	for _, id := range acked {
		_ = os.Remove(s.blobPath(id))
	}
	return acked, missing, nil
}

/* ───────── Versioned Objects (CAS Optimistic Locking) ───────── */

// PutBoxObject writes a new version of key inside an object-mode Box.
// If expectedETag != "", it enforces CAS (returning ErrConflict if current ETag differs).
// If expectedETag == "none", it succeeds only when key does not yet exist.
func (s *Store) PutBoxObject(spaceID, boxName, key, contentType, metaJSON, expectedETag string, body io.Reader) (BoxObject, error) {
	box, err := s.GetBox(spaceID, boxName)
	if err != nil {
		return BoxObject{}, err
	}
	if box.Mode != ModeObject {
		return BoxObject{}, ErrInvalidInput
	}
	key = strings.Trim(key, "/")
	if key == "" || len(key) > 512 || strings.Contains(key, "..") {
		return BoxObject{}, ErrInvalidInput
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if metaJSON == "" {
		metaJSON = "{}"
	}
	blobID, size, digest, err := s.writeBlob(body, box.MaxBytes)
	if err != nil {
		return BoxObject{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(s.blobPath(blobID))
		}
	}()

	tx, err := s.DB.Begin()
	if err != nil {
		return BoxObject{}, err
	}
	defer tx.Rollback()

	var curVer int64
	var curETag string
	err = tx.QueryRow(
		`SELECT version, etag FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? ORDER BY version DESC LIMIT 1`,
		spaceID, boxName, key,
	).Scan(&curVer, &curETag)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return BoxObject{}, err
	}
	if expectedETag != "" {
		cleanWant := strings.Trim(expectedETag, `"`)
		if cleanWant == "none" {
			if curVer > 0 {
				return BoxObject{}, ErrConflict
			}
		} else if curVer == 0 || curETag != cleanWant {
			return BoxObject{}, ErrConflict
		}
	}
	if err := s.checkQuotaTx(tx, spaceID, size); err != nil {
		return BoxObject{}, err
	}

	nextVer := curVer + 1
	now := time.Now().Unix()
	_, err = tx.Exec(
		`INSERT INTO v2_box_objects(space_id,box_name,obj_key,version,etag,size,content_type,meta_json,blob_id,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		spaceID, boxName, key, nextVer, digest, size, contentType, metaJSON, blobID, now,
	)
	if err != nil {
		return BoxObject{}, err
	}

	// Prune older versions beyond keep_versions.
	var staleBlobs []string
	if box.KeepVersions > 0 {
		cutoff := nextVer - int64(box.KeepVersions)
		if cutoff > 0 {
			rows, err := tx.Query(
				`SELECT blob_id FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? AND version<=?`,
				spaceID, boxName, key, cutoff,
			)
			if err != nil {
				return BoxObject{}, err
			}
			for rows.Next() {
				var bid string
				if rows.Scan(&bid) == nil {
					staleBlobs = append(staleBlobs, bid)
				}
			}
			rows.Close()
			if _, err := tx.Exec(
				`DELETE FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? AND version<=?`,
				spaceID, boxName, key, cutoff,
			); err != nil {
				return BoxObject{}, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return BoxObject{}, err
	}
	committed = true
	for _, bid := range staleBlobs {
		_ = os.Remove(s.blobPath(bid))
	}

	obj := BoxObject{
		SpaceID: spaceID, BoxName: boxName, Key: key, Version: nextVer,
		ETag: digest, Size: size, ContentType: contentType, MetaJSON: metaJSON,
		BlobID: blobID, CreatedAt: now,
	}
	if s.OnBoxChange != nil {
		s.OnBoxChange(spaceID, boxName, "object", key, nextVer)
	}
	return obj, nil
}

// OpenBoxObject opens the latest version (when version <= 0) or a specific version of key.
func (s *Store) OpenBoxObject(spaceID, boxName, key string, version int64) (*os.File, BoxObject, error) {
	key = strings.Trim(key, "/")
	var o BoxObject
	var err error
	if version <= 0 {
		err = s.Reader().QueryRow(
			`SELECT space_id,box_name,obj_key,version,etag,size,content_type,meta_json,blob_id,created_at
			 FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? ORDER BY version DESC LIMIT 1`,
			spaceID, boxName, key,
		).Scan(&o.SpaceID, &o.BoxName, &o.Key, &o.Version, &o.ETag, &o.Size, &o.ContentType, &o.MetaJSON, &o.BlobID, &o.CreatedAt)
	} else {
		err = s.Reader().QueryRow(
			`SELECT space_id,box_name,obj_key,version,etag,size,content_type,meta_json,blob_id,created_at
			 FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? AND version=?`,
			spaceID, boxName, key, version,
		).Scan(&o.SpaceID, &o.BoxName, &o.Key, &o.Version, &o.ETag, &o.Size, &o.ContentType, &o.MetaJSON, &o.BlobID, &o.CreatedAt)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, BoxObject{}, ErrNotFound
	}
	if err != nil {
		return nil, BoxObject{}, err
	}
	f, err := os.Open(s.blobPath(o.BlobID))
	if err != nil {
		return nil, BoxObject{}, ErrNotFound
	}
	return f, o, nil
}

// ListBoxObjects returns the latest version of every key matching prefix (empty = all).
func (s *Store) ListBoxObjects(spaceID, boxName, prefix string) ([]BoxObject, error) {
	prefix = strings.Trim(prefix, "/")
	rows, err := s.Reader().Query(
		`SELECT o.space_id,o.box_name,o.obj_key,o.version,o.etag,o.size,o.content_type,o.meta_json,o.blob_id,o.created_at
		 FROM v2_box_objects o
		 INNER JOIN (
		   SELECT obj_key, MAX(version) AS mv FROM v2_box_objects WHERE space_id=? AND box_name=? GROUP BY obj_key
		 ) m ON o.obj_key = m.obj_key AND o.version = m.mv
		 WHERE o.space_id=? AND o.box_name=?
		 ORDER BY o.obj_key ASC`,
		spaceID, boxName, spaceID, boxName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BoxObject{}
	for rows.Next() {
		var o BoxObject
		if err := rows.Scan(&o.SpaceID, &o.BoxName, &o.Key, &o.Version, &o.ETag, &o.Size, &o.ContentType, &o.MetaJSON, &o.BlobID, &o.CreatedAt); err != nil {
			return nil, err
		}
		if prefix != "" && o.Key != prefix && !strings.HasPrefix(o.Key, prefix+"/") {
			continue
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) ListObjectVersions(spaceID, boxName, key string) ([]BoxObject, error) {
	key = strings.Trim(key, "/")
	rows, err := s.Reader().Query(
		`SELECT space_id,box_name,obj_key,version,etag,size,content_type,meta_json,blob_id,created_at
		 FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? ORDER BY version DESC`,
		spaceID, boxName, key,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BoxObject{}
	for rows.Next() {
		var o BoxObject
		if err := rows.Scan(&o.SpaceID, &o.BoxName, &o.Key, &o.Version, &o.ETag, &o.Size, &o.ContentType, &o.MetaJSON, &o.BlobID, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) DeleteBoxObject(spaceID, boxName, key string) error {
	key = strings.Trim(key, "/")
	rows, err := s.DB.Query(`SELECT blob_id FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=?`, spaceID, boxName, key)
	if err != nil {
		return err
	}
	var blobs []string
	for rows.Next() {
		var bid string
		if rows.Scan(&bid) == nil {
			blobs = append(blobs, bid)
		}
	}
	rows.Close()
	if len(blobs) == 0 {
		return ErrNotFound
	}
	if _, err := s.DB.Exec(`DELETE FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=?`, spaceID, boxName, key); err != nil {
		return err
	}
	for _, bid := range blobs {
		_ = os.Remove(s.blobPath(bid))
	}
	if s.OnBoxChange != nil {
		s.OnBoxChange(spaceID, boxName, "object_deleted", key, 0)
	}
	return nil
}

// SweepExpired physically deletes expired ephemeral items and expired offline messages.
func (s *Store) SweepExpired() (removedItems int, removedMsgs int) {
	now := time.Now().Unix()
	rows, err := s.DB.Query(`SELECT id FROM v2_box_items WHERE expires_at>0 AND expires_at<=?`, now)
	if err == nil {
		var ids []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			if _, err := s.DB.Exec(`DELETE FROM v2_box_items WHERE id=?`, id); err == nil {
				_ = os.Remove(s.blobPath(id))
				removedItems++
			}
		}
	}
	if res, err := s.DB.Exec(`DELETE FROM v2_messages WHERE expires_at<=?`, now); err == nil {
		n, _ := res.RowsAffected()
		removedMsgs = int(n)
	}
	s.sweepReceipts()
	s.SweepOrphanBlobs()
	return removedItems, removedMsgs
}

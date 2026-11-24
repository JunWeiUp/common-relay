package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultUploadTTLSec is the lifetime of an incomplete chunked Box upload.
	DefaultUploadTTLSec = 24 * 3600
	// MaxUploadTTLSec caps incomplete upload retention.
	MaxUploadTTLSec = 7 * 24 * 3600
)

// BoxUpload tracks an in-progress resumable chunked upload into a Box.
type BoxUpload struct {
	ID          string `json:"id"`
	SpaceID     string `json:"space_id"`
	BoxName     string `json:"box_name"`
	Key         string `json:"key,omitempty"`
	Sender      string `json:"sender,omitempty"`
	TotalSize   int64  `json:"total_size"`
	Offset      int64  `json:"offset"`
	ContentType string `json:"content_type"`
	MetaJSON    string `json:"meta_json"`
	ExpiresAt   int64  `json:"expires_at"`
	CreatedAt   int64  `json:"created_at"`
}

func (s *Store) uploadPartPath(id string) string {
	return filepath.Join(s.Dir, "blobs", "up_"+id+".part")
}

// CreateBoxUpload reserves quota and creates a resumable chunked upload session
// targeting either a queue/ephemeral Box (objKey == "") or an object Box.
func (s *Store) CreateBoxUpload(spaceID, boxName, sender, objKey, contentType, metaJSON string, totalSize, ttlSec int64) (BoxUpload, error) {
	box, err := s.GetBox(spaceID, boxName)
	if err != nil {
		return BoxUpload{}, err
	}
	if totalSize <= 0 || totalSize > box.MaxBytes {
		return BoxUpload{}, ErrQuota
	}
	objKey = strings.Trim(objKey, "/")
	switch box.Mode {
	case ModeQueue, ModeEphemeral:
		if objKey != "" {
			return BoxUpload{}, ErrInvalidInput
		}
	case ModeObject:
		if objKey == "" || len(objKey) > 512 || strings.Contains(objKey, "..") {
			return BoxUpload{}, ErrInvalidInput
		}
	default:
		return BoxUpload{}, ErrInvalidInput
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if metaJSON == "" {
		metaJSON = "{}"
	}
	if ttlSec <= 0 {
		ttlSec = DefaultUploadTTLSec
	}
	if ttlSec > MaxUploadTTLSec {
		ttlSec = MaxUploadTTLSec
	}

	id := RandomHex(16)
	now := time.Now().Unix()
	expiresAt := now + ttlSec

	tx, err := s.DB.Begin()
	if err != nil {
		return BoxUpload{}, err
	}
	defer tx.Rollback()
	if err := s.checkQuotaTx(tx, spaceID, totalSize); err != nil {
		return BoxUpload{}, err
	}
	_, err = tx.Exec(
		`INSERT INTO v2_box_uploads(id,space_id,box_name,obj_key,sender,total_size,offset,meta_json,content_type,digest,expires_at,created_at)
		 VALUES(?,?,?,?,?,?,0,?,?,'',?,?)`,
		id, spaceID, boxName, objKey, sender, totalSize, metaJSON, contentType, expiresAt, now,
	)
	if err != nil {
		return BoxUpload{}, err
	}
	f, err := os.OpenFile(s.uploadPartPath(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return BoxUpload{}, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(s.uploadPartPath(id))
		return BoxUpload{}, err
	}
	if err := tx.Commit(); err != nil {
		_ = os.Remove(s.uploadPartPath(id))
		return BoxUpload{}, err
	}
	return BoxUpload{
		ID: id, SpaceID: spaceID, BoxName: boxName, Key: objKey, Sender: sender,
		TotalSize: totalSize, Offset: 0, ContentType: contentType, MetaJSON: metaJSON,
		ExpiresAt: expiresAt, CreatedAt: now,
	}, nil
}

// GetBoxUpload fetches upload progress for resuming after disconnect.
func (s *Store) GetBoxUpload(spaceID, boxName, id string) (BoxUpload, error) {
	if id == "" {
		return BoxUpload{}, ErrInvalidInput
	}
	var up BoxUpload
	err := s.Reader().QueryRow(
		`SELECT id,space_id,box_name,obj_key,sender,total_size,offset,meta_json,content_type,expires_at,created_at
		 FROM v2_box_uploads WHERE id=? AND space_id=? AND box_name=?`,
		id, spaceID, boxName,
	).Scan(&up.ID, &up.SpaceID, &up.BoxName, &up.Key, &up.Sender, &up.TotalSize, &up.Offset, &up.MetaJSON, &up.ContentType, &up.ExpiresAt, &up.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BoxUpload{}, ErrNotFound
	}
	if err != nil {
		return BoxUpload{}, err
	}
	if up.ExpiresAt <= time.Now().Unix() {
		return BoxUpload{}, ErrNotFound
	}
	return up, nil
}

// AppendBoxUploadChunk appends bytes starting at the exact current offset.
// A mismatched offset returns ErrConflict so the client can query GetBoxUpload
// and resume cleanly.
func (s *Store) AppendBoxUploadChunk(spaceID, boxName, id string, offset int64, body io.Reader) (BoxUpload, error) {
	if offset < 0 {
		return BoxUpload{}, ErrInvalidInput
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return BoxUpload{}, err
	}
	defer tx.Rollback()

	var up BoxUpload
	err = tx.QueryRow(
		`SELECT id,space_id,box_name,obj_key,sender,total_size,offset,meta_json,content_type,expires_at,created_at
		 FROM v2_box_uploads WHERE id=? AND space_id=? AND box_name=?`,
		id, spaceID, boxName,
	).Scan(&up.ID, &up.SpaceID, &up.BoxName, &up.Key, &up.Sender, &up.TotalSize, &up.Offset, &up.MetaJSON, &up.ContentType, &up.ExpiresAt, &up.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BoxUpload{}, ErrNotFound
	}
	if err != nil {
		return BoxUpload{}, err
	}
	if up.ExpiresAt <= time.Now().Unix() {
		return BoxUpload{}, ErrNotFound
	}
	if offset != up.Offset {
		return BoxUpload{}, ErrConflict
	}
	rem := up.TotalSize - up.Offset
	if rem <= 0 {
		return up, nil
	}

	f, err := os.OpenFile(s.uploadPartPath(id), os.O_WRONLY, 0o600)
	if err != nil {
		return BoxUpload{}, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return BoxUpload{}, err
	}
	// Read at most rem+1 to detect overflow past declared total_size.
	n, copyErr := io.Copy(f, io.LimitReader(body, rem+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Truncate(s.uploadPartPath(id), offset)
		return BoxUpload{}, copyErr
	}
	if n > rem {
		_ = os.Truncate(s.uploadPartPath(id), offset)
		return BoxUpload{}, ErrQuota
	}
	if syncErr != nil {
		return BoxUpload{}, syncErr
	}
	if closeErr != nil {
		return BoxUpload{}, closeErr
	}

	up.Offset += n
	if _, err := tx.Exec(`UPDATE v2_box_uploads SET offset=? WHERE id=?`, up.Offset, id); err != nil {
		return BoxUpload{}, err
	}
	if err := tx.Commit(); err != nil {
		return BoxUpload{}, err
	}
	return up, nil
}

// CompleteBoxUpload verifies the uploaded length, optional SHA-256 digest, and
// (for object Boxes) optional expectedETag CAS guard, then atomically promotes
// the staged file into a committed BoxItem or BoxObject (pruning stale versions
// according to box.KeepVersions).
func (s *Store) CompleteBoxUpload(spaceID, boxName, id, expectedSHA256, expectedETag string) (*BoxItem, *BoxObject, error) {
	box, err := s.GetBox(spaceID, boxName)
	if err != nil {
		return nil, nil, err
	}
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expectedSHA256 != "" {
		if raw, derr := hex.DecodeString(expectedSHA256); derr != nil || len(raw) != 32 {
			return nil, nil, ErrInvalidInput
		}
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	var up BoxUpload
	err = tx.QueryRow(
		`SELECT id,space_id,box_name,obj_key,sender,total_size,offset,meta_json,content_type,expires_at,created_at
		 FROM v2_box_uploads WHERE id=? AND space_id=? AND box_name=?`,
		id, spaceID, boxName,
	).Scan(&up.ID, &up.SpaceID, &up.BoxName, &up.Key, &up.Sender, &up.TotalSize, &up.Offset, &up.MetaJSON, &up.ContentType, &up.ExpiresAt, &up.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if up.ExpiresAt <= time.Now().Unix() {
		return nil, nil, ErrNotFound
	}
	if up.Offset != up.TotalSize {
		return nil, nil, ErrConflict
	}

	partPath := s.uploadPartPath(id)
	f, err := os.Open(partPath)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.New()
	written, herr := io.Copy(h, f)
	f.Close()
	if herr != nil {
		return nil, nil, herr
	}
	if written != up.TotalSize {
		return nil, nil, ErrConflict
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if expectedSHA256 != "" && digest != expectedSHA256 {
		return nil, nil, ErrInvalidInput
	}

	blobID := RandomHex(16)
	dstPath := s.blobPath(blobID)
	if err := os.Rename(partPath, dstPath); err != nil {
		return nil, nil, err
	}
	promoted := false
	defer func() {
		if !promoted {
			_ = os.Rename(dstPath, partPath)
		}
	}()

	now := time.Now().Unix()
	if _, err := tx.Exec(`DELETE FROM v2_box_uploads WHERE id=?`, id); err != nil {
		return nil, nil, err
	}

	if box.Mode == ModeQueue || box.Mode == ModeEphemeral {
		var expiresAt int64
		if box.TTLSec > 0 {
			expiresAt = now + box.TTLSec
		}
		if _, err := tx.Exec(`UPDATE v2_boxes SET next_seq = next_seq + 1 WHERE space_id=? AND name=?`, spaceID, boxName); err != nil {
			return nil, nil, err
		}
		var seq int64
		if err := tx.QueryRow(`SELECT next_seq FROM v2_boxes WHERE space_id=? AND name=?`, spaceID, boxName).Scan(&seq); err != nil {
			return nil, nil, err
		}
		_, err = tx.Exec(
			`INSERT INTO v2_box_items(id,space_id,box_name,seq,sender,size,sha256,content_type,meta_json,expires_at,created_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			blobID, spaceID, boxName, seq, up.Sender, up.TotalSize, digest, up.ContentType, up.MetaJSON, expiresAt, now,
		)
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, err
		}
		promoted = true
		item := BoxItem{
			ID: blobID, SpaceID: spaceID, BoxName: boxName, Seq: seq, Sender: up.Sender,
			Size: up.TotalSize, SHA256: digest, ContentType: up.ContentType, MetaJSON: up.MetaJSON,
			ExpiresAt: expiresAt, CreatedAt: now,
		}
		if s.OnBoxItem != nil {
			s.OnBoxItem(item)
		} else if s.OnBoxChange != nil {
			s.OnBoxChange(spaceID, boxName, "item", item.ID, item.Seq)
		}
		s.emitBoxChange(spaceID, boxName, "item", item.ID, item.Seq)
		return &item, nil, nil
	}

	// Object box promotion with optional CAS (expectedETag) and keep_versions pruning.
	var prevVer int64
	var curETag string
	verErr := tx.QueryRow(
		`SELECT version, etag FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? ORDER BY version DESC LIMIT 1`,
		spaceID, boxName, up.Key,
	).Scan(&prevVer, &curETag)
	if verErr != nil && !errors.Is(verErr, sql.ErrNoRows) {
		return nil, nil, verErr
	}
	expectedETag = strings.Trim(strings.TrimSpace(expectedETag), `"`)
	if expectedETag != "" {
		if expectedETag == "none" {
			if prevVer > 0 {
				return nil, nil, ErrConflict
			}
		} else if prevVer == 0 || curETag != expectedETag {
			return nil, nil, ErrConflict
		}
	}

	nextVer := prevVer + 1
	_, err = tx.Exec(
		`INSERT INTO v2_box_objects(space_id,box_name,obj_key,version,etag,size,content_type,meta_json,blob_id,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		spaceID, boxName, up.Key, nextVer, digest, up.TotalSize, up.ContentType, up.MetaJSON, blobID, now,
	)
	if err != nil {
		return nil, nil, err
	}

	var staleBlobs []string
	if box.KeepVersions > 0 {
		cutoff := nextVer - int64(box.KeepVersions)
		if cutoff > 0 {
			rows, qerr := tx.Query(
				`SELECT blob_id FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? AND version<=?`,
				spaceID, boxName, up.Key, cutoff,
			)
			if qerr != nil {
				return nil, nil, qerr
			}
			for rows.Next() {
				var bid string
				if rows.Scan(&bid) == nil {
					staleBlobs = append(staleBlobs, bid)
				}
			}
			rows.Close()
			if _, derr := tx.Exec(
				`DELETE FROM v2_box_objects WHERE space_id=? AND box_name=? AND obj_key=? AND version<=?`,
				spaceID, boxName, up.Key, cutoff,
			); derr != nil {
				return nil, nil, derr
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	promoted = true
	for _, bid := range staleBlobs {
		_ = os.Remove(s.blobPath(bid))
	}
	obj := BoxObject{
		SpaceID: spaceID, BoxName: boxName, Key: up.Key, Version: nextVer,
		ETag: digest, Size: up.TotalSize, ContentType: up.ContentType,
		MetaJSON: up.MetaJSON, BlobID: blobID, CreatedAt: now,
	}
	if s.OnBoxChange != nil {
		s.OnBoxChange(spaceID, boxName, "object", up.Key, nextVer)
	}
	s.emitBoxChange(spaceID, boxName, "object", up.Key, nextVer)
	return nil, &obj, nil
}

// AbortBoxUpload deletes an incomplete upload and releases its reserved quota.
func (s *Store) AbortBoxUpload(spaceID, boxName, id string) error {
	res, err := s.DB.Exec(`DELETE FROM v2_box_uploads WHERE id=? AND space_id=? AND box_name=?`, id, spaceID, boxName)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_ = os.Remove(s.uploadPartPath(id))
	return nil
}

// sweepExpiredUploads removes expired incomplete chunked uploads and their .part files.
func (s *Store) sweepExpiredUploads() {
	now := time.Now().Unix()
	rows, err := s.DB.Query(`SELECT id FROM v2_box_uploads WHERE expires_at <= ?`, now)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_, _ = s.DB.Exec(`DELETE FROM v2_box_uploads WHERE id=?`, id)
		_ = os.Remove(s.uploadPartPath(id))
	}
}

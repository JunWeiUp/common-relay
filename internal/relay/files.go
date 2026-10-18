package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type File struct {
	ID       string `json:"id"`
	To       string `json:"to"`
	From     string `json:"from"`
	Size     int64  `json:"size"`
	Offset   int64  `json:"offset"`
	Metadata string `json:"metadata"`
	Digest   string `json:"sha256"`
	State    string `json:"state"`
	Expires  int64  `json:"expires"`
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func (s *Server) path(id string) string { return filepath.Join(s.Store.Dir, "files", id) }
func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	d, err := s.auth(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/relay/v1/files")
	if suffix == "" || suffix == "/" {
		switch r.Method {
		case "POST":
			s.createFile(w, r, d)
		case "GET":
			rows, err := s.Store.DB.Query("SELECT id,sender,recipient,size,offset,metadata,digest,state,expires FROM files WHERE app=? AND grp=? AND recipient=? AND state='ready' AND expires>? LIMIT 100", d.App, d.Group, d.ID, time.Now().Unix())
			if err != nil {
				http.Error(w, "storage", 500)
				return
			}
			defer rows.Close()
			fs := []File{}
			for rows.Next() {
				var f File
				if rows.Scan(&f.ID, &f.From, &f.To, &f.Size, &f.Offset, &f.Metadata, &f.Digest, &f.State, &f.Expires) != nil {
					http.Error(w, "storage", 500)
					return
				}
				fs = append(fs, f)
			}
			reply(w, fs)
		default:
			http.Error(w, "method", 405)
		}
		return
	}
	parts := strings.Split(strings.TrimPrefix(suffix, "/"), "/")
	if len(parts) > 2 || !objectID.MatchString(parts[0]) {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	// Only operations on this object serialize; network reads never hold a global lock.
	unlock := s.lockFile(id)
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	var f File
	err = s.Store.DB.QueryRow("SELECT id,sender,recipient,size,offset,metadata,digest,state,expires FROM files WHERE id=? AND app=? AND grp=?", id, d.App, d.Group).Scan(&f.ID, &f.From, &f.To, &f.Size, &f.Offset, &f.Metadata, &f.Digest, &f.State, &f.Expires)
	if err != nil || f.Expires <= time.Now().Unix() || (f.From != d.ID && f.To != d.ID) {
		http.NotFound(w, r)
		return
	}
	if _, err = s.Store.Peer(d, f.From); err != nil {
		http.Error(w, "sender revoked", 403)
		return
	}
	if _, err = s.Store.Peer(d, f.To); err != nil {
		http.Error(w, "recipient revoked", 403)
		return
	}
	switch {
	case action == "" && r.Method == "GET":
		reply(w, f)
	case action == "" && r.Method == "DELETE":
		// Retain the row (and its quota) until ciphertext removal succeeds.
		// A retry can safely finish deleting a row whose file is already gone.
		if err = os.Remove(s.path(id)); err != nil && !os.IsNotExist(err) {
			http.Error(w, "storage", 500)
			return
		}
		if _, err = s.Store.DB.Exec("DELETE FROM files WHERE id=?", id); err != nil {
			http.Error(w, "storage", 500)
			return
		}
		w.WriteHeader(204)
	case action == "data" && r.Method == "PUT" && d.ID == f.From && f.State == "uploading":
		offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
		if err != nil || offset != f.Offset {
			http.Error(w, "offset conflict", 409)
			return
		}
		if r.ContentLength <= 0 || r.ContentLength > 1<<20 || r.ContentLength > f.Size-f.Offset {
			http.Error(w, "chunk size", 413)
			return
		}
		var stat syscall.Statfs_t
		if syscall.Statfs(s.Store.Dir, &stat) != nil || uint64(stat.Bavail)*uint64(stat.Bsize) < s.DiskReserve+uint64(r.ContentLength) {
			http.Error(w, "disk reserve", 507)
			return
		}
		rc := http.NewResponseController(w)
		rc.SetReadDeadline(time.Now().Add(30 * time.Second))
		data, err := io.ReadAll(io.LimitReader(r.Body, r.ContentLength+1))
		if err != nil || int64(len(data)) != r.ContentLength {
			http.Error(w, "incomplete chunk", 400)
			return
		}
		file, err := os.OpenFile(s.path(id), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			http.Error(w, "storage", 500)
			return
		}
		defer file.Close()
		if err = file.Truncate(f.Offset); err == nil {
			_, err = file.WriteAt(data, f.Offset)
		}
		if err == nil {
			err = file.Sync()
		}
		if err != nil {
			http.Error(w, "storage", 500)
			return
		}
		f.Offset += int64(len(data))
		if _, err = s.Store.DB.Exec("UPDATE files SET offset=? WHERE id=?", f.Offset, id); err != nil {
			http.Error(w, "storage", 500)
			return
		}
		reply(w, f)
	case action == "commit" && r.Method == "POST" && d.ID == f.From:
		if f.State == "ready" {
			reply(w, f)
			return
		}
		if f.Offset != f.Size {
			http.Error(w, "incomplete upload", 409)
			return
		}
		file, err := os.Open(s.path(id))
		if err != nil {
			http.Error(w, "storage", 500)
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, file)
		file.Close()
		digest := hex.EncodeToString(h.Sum(nil))
		if err != nil || n != f.Size || digest != f.Digest {
			http.Error(w, "digest mismatch", 409)
			return
		}
		if _, err = s.Store.DB.Exec("UPDATE files SET state='ready' WHERE id=?", id); err != nil {
			http.Error(w, "storage", 500)
			return
		}
		f.State = "ready"
		reply(w, f)
	case action == "data" && r.Method == "GET" && d.ID == f.To && f.State == "ready":
		file, err := os.Open(s.path(id))
		if err != nil {
			http.Error(w, "storage", 500)
			return
		}
		defer file.Close()
		unlock()
		locked = false
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, id, time.Time{}, file)
	default:
		http.Error(w, "method or state", 409)
	}
}
func (s *Server) createFile(w http.ResponseWriter, r *http.Request, d Device) {
	var f File
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&f) != nil || !objectID.MatchString(f.ID) || f.Size < 1 || f.Size > 1<<30 || len(f.Metadata) == 0 || len(f.Metadata) > 8192 || len(f.Digest) != 64 {
		http.Error(w, "invalid file", 400)
		return
	}
	if _, err := hex.DecodeString(f.Digest); err != nil {
		http.Error(w, "invalid digest", 400)
		return
	}
	if _, err := s.Store.Peer(d, f.To); err != nil || f.To == d.ID {
		http.Error(w, "unknown peer", 404)
		return
	}
	now := time.Now().Unix()
	if f.Expires == 0 {
		f.Expires = now + 86400
	}
	if f.Expires <= now || f.Expires > now+86400 {
		http.Error(w, "invalid expiry", 400)
		return
	}
	unlock := s.lockFile(f.ID)
	defer unlock()
	tx, err := s.Store.DB.Begin()
	if err != nil {
		http.Error(w, "storage", 500)
		return
	}
	defer tx.Rollback()
	if err = quota(tx, d.App, f.Size, s.Store.AppQuota, s.Store.GlobalQuota); err != nil {
		http.Error(w, "quota", 507)
		return
	}
	var stat syscall.Statfs_t
	var reserved int64
	if err = tx.QueryRow("SELECT COALESCE(SUM(size-offset),0) FROM files").Scan(&reserved); err != nil || syscall.Statfs(s.Store.Dir, &stat) != nil || uint64(stat.Bavail)*uint64(stat.Bsize) < s.DiskReserve+uint64(reserved+f.Size) {
		http.Error(w, "disk reserve", 507)
		return
	}
	_, err = tx.Exec("INSERT INTO files(id,app,grp,sender,recipient,size,metadata,digest,expires) VALUES(?,?,?,?,?,?,?,?,?)", f.ID, d.App, d.Group, d.ID, f.To, f.Size, f.Metadata, f.Digest, f.Expires)
	if err != nil {
		http.Error(w, "id conflict", 409)
		return
	}
	if tx.Commit() != nil {
		http.Error(w, "storage", 500)
		return
	}
	f.From = d.ID
	f.State = "uploading"
	f.Offset = 0
	w.WriteHeader(201)
	reply(w, f)
}

// Reference counts include waiters, so deleting a lock cannot split its users.
type fileLock struct {
	mu   sync.Mutex
	refs int
}

func (s *Server) lockFile(id string) func() {
	s.fileLocksMu.Lock()
	l := s.fileLocks[id]
	if l == nil {
		l = &fileLock{}
		s.fileLocks[id] = l
	}
	l.refs++
	s.fileLocksMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.fileLocksMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(s.fileLocks, id)
		}
		s.fileLocksMu.Unlock()
	}
}
func (s *Server) Collect() error {
	now := time.Now().Unix()
	if _, err := s.Store.DB.Exec("DELETE FROM group_invites WHERE expires<=?", now); err != nil {
		return err
	}
	if _, err := s.Store.DB.Exec("DELETE FROM group_bootstrap WHERE expires<=?", now); err != nil {
		return err
	}
	rows, err := s.Store.DB.Query(`SELECT f.id FROM files f WHERE expires<=? OR EXISTS(SELECT 1 FROM devices d WHERE d.app=f.app AND d.grp=f.grp AND d.id IN(f.sender,f.recipient) AND d.revoked=1)`, now)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var failures []error
	for _, id := range ids {
		unlock := s.lockFile(id)
		// Recheck under the same lock as upload/commit/create, including ID reuse.
		var eligible int
		err = s.Store.DB.QueryRow(`SELECT COUNT(*) FROM files f WHERE id=? AND (expires<=? OR EXISTS(SELECT 1 FROM devices d WHERE d.app=f.app AND d.grp=f.grp AND d.id IN(f.sender,f.recipient) AND d.revoked=1))`, id, now).Scan(&eligible)
		if err == nil && eligible > 0 {
			err = os.Remove(s.path(id))
			if err == nil || os.IsNotExist(err) {
				_, err = s.Store.DB.Exec("DELETE FROM files WHERE id=?", id)
			}
		}
		unlock()
		if err != nil {
			failures = append(failures, err)
		}
	}
	_, err = s.Store.DB.Exec(`DELETE FROM messages WHERE expires<=? OR EXISTS(SELECT 1 FROM devices d WHERE d.app=messages.app AND d.grp=messages.grp AND d.id IN(messages.sender,messages.recipient) AND d.revoked=1)`, now)
	if err != nil {
		failures = append(failures, err)
	}
	_, err = s.Store.DB.Exec("DELETE FROM receipts WHERE expires<=?", now)
	if err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

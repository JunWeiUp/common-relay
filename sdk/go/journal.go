package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	journalRetention = 7 * 86400
	journalMaxTTL    = 86400
	journalBatch     = 256
)

var journalRecordName = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

// ErrJournalLocked reports that another Journal (in this or another process) owns the directory.
var ErrJournalLocked = errors.New("journal directory is owned by another instance")

// Journal is durable offline-delivery state: one file per record, replaced atomically
// (temporary file, fsync, rename, directory fsync). One Journal owns a directory at a
// time, enforced with an OS file lock. Records are isolated by app/group/local device
// and peer/message ID; they hold ciphertext and digests only, never tokens, private
// keys or plaintext. Use an application-private directory, not a synced/shared folder.
type Journal struct {
	mu     sync.Mutex
	dir    string
	clock  func() int64
	lock   *os.File
	closed bool
}

type journalRecord struct {
	Recipient string `json:"recipient,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Body      string `json:"body,omitempty"`
	Expires   int64  `json:"expires,omitempty"`
	Purge     int64  `json:"purge"`
	Status    string `json:"status,omitempty"`
}

// OpenJournal takes ownership of dir (created 0700) and runs one cleanup round.
// clock returns Unix seconds; nil uses the system clock. Close releases ownership.
func OpenJournal(dir string, clock func() int64) (*Journal, error) {
	if dir == "" {
		return nil, errors.New("journal directory required")
	}
	if clock == nil {
		clock = func() int64 { return time.Now().Unix() }
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "owner.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = lockJournalFile(lock); err != nil {
		lock.Close()
		return nil, err
	}
	j := &Journal{dir: dir, clock: clock, lock: lock}
	// The owner lock guarantees leftover temporary files belong to a crashed writer.
	if matches, err := filepath.Glob(filepath.Join(dir, ".journal-*.tmp")); err == nil {
		for _, name := range matches {
			os.Remove(name)
		}
	}
	if err = j.Cleanup(); err != nil {
		j.Close()
		return nil, err
	}
	return j, nil
}

// Close releases directory ownership. Clients using the journal must be closed first.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	unlockJournalFile(j.lock)
	return j.lock.Close()
}

func (j *Journal) path(scope, kind, peer, id string) string {
	raw, _ := json.Marshal([]string{scope, kind, peer, id})
	sum := sha256.Sum256(raw)
	return filepath.Join(j.dir, hex.EncodeToString(sum[:])+".json")
}

func (j *Journal) read(path string) (*journalRecord, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r journalRecord
	if err = json.Unmarshal(raw, &r); err != nil || r.Purge <= 0 {
		return nil, fmt.Errorf("corrupt journal record %s", filepath.Base(path))
	}
	return &r, nil
}

func (j *Journal) write(path string, r *journalRecord) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var suffix [8]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return err
	}
	temporary := filepath.Join(j.dir, ".journal-"+hex.EncodeToString(suffix[:])+".tmp")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		os.Remove(temporary)
		return err
	}
	return syncDir(j.dir)
}

func (j *Journal) remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(j.dir)
}

func (j *Journal) usable() error {
	if j.closed {
		return errors.New("journal closed")
	}
	return nil
}

// prepare persists recipient, content digest, ciphertext and a fixed absolute expiry
// before first send; retries return the original ciphertext and expiry. A nil body
// with no error means the recipient already confirmed the message.
func (j *Journal) prepare(scope, id, to string, data []byte, ttl int64, seal func(expires int64) (string, error)) (string, int64, error) {
	if ttl < 1 || ttl > journalMaxTTL {
		return "", 0, errors.New("invalid TTL")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usable(); err != nil {
		return "", 0, err
	}
	path, now := j.path(scope, "out", "", id), j.clock()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	old, err := j.read(path)
	if err != nil {
		return "", 0, err
	}
	if old != nil {
		if old.Recipient != to || old.Digest != digest {
			return "", 0, errors.New("message ID reused with different content or recipient")
		}
		if old.Status == "received" {
			return "", old.Expires, nil
		}
		if old.Status != "pending" || old.Expires <= now || old.Body == "" {
			return "", 0, errors.New("message expired; send a new operation")
		}
		return old.Body, old.Expires, nil
	}
	expires := now + ttl
	body, err := seal(expires)
	if err != nil {
		return "", 0, err
	}
	record := &journalRecord{Recipient: to, Digest: digest, Body: body, Expires: expires, Purge: expires + journalRetention, Status: "pending"}
	if err = j.write(path, record); err != nil {
		return "", 0, err
	}
	return body, expires, nil
}

// complete drops the ciphertext and keeps a received tombstone for 7 days.
func (j *Journal) complete(scope, id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usable(); err != nil {
		return err
	}
	path := j.path(scope, "out", "", id)
	r, err := j.read(path)
	if err != nil || r == nil {
		return err
	}
	r.Body, r.Status, r.Purge = "", "received", j.clock()+journalRetention
	return j.write(path, r)
}

func (j *Journal) contains(scope, from, id string) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usable(); err != nil {
		return false, err
	}
	r, err := j.read(j.path(scope, "in", from, id))
	return r != nil && r.Purge > j.clock(), err
}

// acknowledge durably records a processed message; repeats never extend retention.
func (j *Journal) acknowledge(scope, from, id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usable(); err != nil {
		return err
	}
	path, now := j.path(scope, "in", from, id), j.clock()
	r, err := j.read(path)
	if err != nil {
		return err
	}
	if r != nil && r.Purge > now {
		return nil
	}
	return j.write(path, &journalRecord{Purge: now + journalRetention})
}

// Cleanup expires pending ciphertext and purges terminal/dedupe records, at most
// 256 changes per call. Call repeatedly to drain a large backlog.
func (j *Journal) Cleanup() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usable(); err != nil {
		return err
	}
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return err
	}
	now, changed := j.clock(), 0
	for _, entry := range entries {
		if changed >= journalBatch {
			break
		}
		if !entry.Type().IsRegular() || !journalRecordName.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(j.dir, entry.Name())
		r, err := j.read(path)
		if err != nil {
			return err
		}
		if r == nil {
			continue
		}
		if r.Purge <= now {
			if err = j.remove(path); err != nil {
				return err
			}
			changed++
		} else if r.Status == "pending" && r.Expires <= now {
			r.Body, r.Status = "", "expired"
			if err = j.write(path, r); err != nil {
				return err
			}
			changed++
		}
	}
	return nil
}

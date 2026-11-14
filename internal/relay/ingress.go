package relay

// Shared publishing path for trusted HTTP ingress (webhooks, WebDAV). The server
// acts as an explicit bridge sender: it encrypts a received body for one pinned
// recipient and durably queues it as an ordinary v1 file.
import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	sdk "github.com/JunWeiUp/common-relay/sdk/go"
)

// ingressTarget is the fixed delivery route of one ingress configuration entry.
type ingressTarget struct {
	identity                      *sdk.Identity
	app, group, sender, recipient string
	recipientKey                  string
}

// openPrivateConfig opens an opt-in ingress configuration. It must be a regular
// file readable only by its owner, or a systemd read-only credential (0440) placed
// directly in the private CREDENTIALS_DIRECTORY (0550).
func openPrivateConfig(path, kind string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	private := st.Mode().Perm()&0077 == 0
	if !private && st.Mode().Perm() == 0440 {
		credentials := os.Getenv("CREDENTIALS_DIRECTORY")
		absolute, e := filepath.Abs(path)
		directory, de := os.Stat(credentials)
		private = e == nil && de == nil && credentials != "" &&
			filepath.Dir(absolute) == filepath.Clean(credentials) && directory.IsDir() && directory.Mode().Perm()&0027 == 0
	}
	if !st.Mode().IsRegular() || !private || st.Size() > 1<<20 {
		f.Close()
		return nil, errors.New(kind + " config must be private (0600 or systemd read-only credential)")
	}
	return f, nil
}

// peersPinned reports whether both bridge devices are registered, not revoked and
// still use the public keys pinned in configuration.
func (s *Server) peersPinned(t *ingressTarget) bool {
	d := Device{App: t.app, Group: t.group}
	from, err := s.Store.Peer(d, t.sender)
	if err != nil || from.PublicKey != t.identity.PublicKey() {
		return false
	}
	to, err := s.Store.Peer(d, t.recipient)
	return err == nil && to.PublicKey == t.recipientKey
}

// diskAvailable keeps the configured reserve plus room for plaintext, ciphertext
// and one more staged body.
func (s *Server) diskAvailable(body int64) bool {
	var stat syscall.Statfs_t
	return syscall.Statfs(s.Store.Dir, &stat) == nil && uint64(stat.Bavail)*uint64(stat.Bsize) >= s.DiskReserve+3*uint64(body)
}

// ingressError carries the HTTP status for a failed publication.
type ingressError struct {
	status int
	msg    string
}

func (e *ingressError) Error() string               { return e.msg }
func (e *ingressError) write(w http.ResponseWriter) { http.Error(w, e.msg, e.status) }

// publishIngress encrypts the plaintext at source (inside the private temp dir
// created by the caller) and queues it. stage runs in the transaction that
// journals the staging row; ready runs in the transaction that publishes it.
// Either callback may return ErrQuota (507). No success is reported before the
// ciphertext and both transactions are durable; RecoverWebhooks finishes or
// removes interrupted publications on the next start.
func (s *Server) publishIngress(t *ingressTarget, temp, source string, meta map[string]any, stage, ready func(tx *sql.Tx, id string) error) (string, *ingressError) {
	prepared, err := sdk.PrepareFile(t.identity, t.recipient, source, filepath.Join(temp, "cipher"), meta)
	_ = os.Remove(source)
	if err != nil {
		return "", &ingressError{503, "encryption"}
	}
	info := prepared.Info
	unlock := s.lockFile(info.ID)
	defer unlock()
	fail := func(err error) (string, *ingressError) {
		if errors.Is(err, ErrQuota) {
			return "", &ingressError{507, "quota"}
		}
		return "", &ingressError{503, "storage"}
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	if err = quota(tx, t.app, info.Size, s.Store.AppQuota, s.Store.GlobalQuota); err != nil {
		return fail(err)
	}
	// Journal the descriptor before publishing ciphertext.
	_, err = tx.Exec(`INSERT INTO files(id,app,grp,sender,recipient,size,offset,metadata,digest,state,expires) VALUES(?,?,?,?,?,?,?,?,?,'webhook-staging',?)`, info.ID, t.app, t.group, t.sender, t.recipient, info.Size, info.Size, info.Metadata, info.SHA256, webhookExpiry)
	if err == nil && stage != nil {
		err = stage(tx, info.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return fail(err)
	}
	if err = os.Rename(prepared.Path, s.path(info.ID)); err == nil {
		err = syncDirectory(filepath.Join(s.Store.Dir, "files"))
	}
	if err != nil {
		return fail(err)
	}
	tx, err = s.Store.DB.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	_, err = tx.Exec("UPDATE files SET state='ready' WHERE id=?", info.ID)
	if err == nil && ready != nil {
		err = ready(tx, info.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return fail(err)
	}
	return info.ID, nil
}

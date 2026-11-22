package relay

// Optional trusted HTTP ingress. The bridge is an explicit endpoint of encryption;
// it never uses a device's private key or interprets application JSON.
import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/JunWeiUp/common-relay/sdk/go"
)

const webhookMaxBody = 32 << 20
const webhookExpiry = int64(253402300799) // Retain until explicit file acknowledgement.

type WebhookSignature struct {
	Secret          string `json:"secret"`
	TimestampHeader string `json:"timestamp_header"`
	SignatureHeader string `json:"signature_header"`
}

type WebhookRoute struct {
	Route        string            `json:"route"`
	App          string            `json:"app"`
	Group        string            `json:"group"`
	Sender       string            `json:"sender"`
	Recipient    string            `json:"recipient"`
	TokenHash    string            `json:"token_sha256"`
	SecretKey    string            `json:"secret_key"`
	RecipientKey string            `json:"recipient_public_key"`
	Signature    *WebhookSignature `json:"signature,omitempty"`
	identity     *sdk.Identity
	target       ingressTarget
	mu           sync.Mutex
}

// LoadWebhooks must run before serving. Config is private and opt-in. Sender must
// be a dedicated bridge identity, already registered and trusted by the receiver.
func (s *Server) LoadWebhooks(path string) error {
	f, err := openPrivateConfig(path, "webhook")
	if err != nil {
		return err
	}
	defer f.Close()
	var routes []*WebhookRoute
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&routes); err != nil {
		return errors.New("invalid webhook configuration")
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing webhook configuration")
	}
	next := make(map[string]*WebhookRoute)
	for _, h := range routes {
		if h == nil || !identifier.MatchString(h.Route) || !identifier.MatchString(h.Sender) || !identifier.MatchString(h.Recipient) || h.Sender == h.Recipient || next[h.Route] != nil {
			return errors.New("invalid webhook route")
		}
		hash, e := hex.DecodeString(h.TokenHash)
		if e != nil || len(hash) != 32 {
			return errors.New("invalid webhook token hash")
		}
		h.TokenHash = hex.EncodeToString(hash)
		h.identity, err = sdk.NewIdentity(h.App, h.Group, h.Sender, h.SecretKey, map[string]string{h.Recipient: h.RecipientKey})
		if err != nil {
			return errors.New("invalid webhook identity")
		}
		h.target = ingressTarget{identity: h.identity, app: h.App, group: h.Group, sender: h.Sender, recipient: h.Recipient, recipientKey: h.RecipientKey}
		if !s.peersPinned(&h.target) {
			return errors.New("webhook devices must be registered with matching pinned keys")
		}
		if h.Signature != nil {
			sig := h.Signature
			if len(sig.Secret) < 16 || !identifier.MatchString(sig.TimestampHeader) || !identifier.MatchString(sig.SignatureHeader) || strings.EqualFold(sig.TimestampHeader, sig.SignatureHeader) {
				return errors.New("invalid webhook signature configuration")
			}
		}
		next[h.Route] = h
	}
	s.webhooks = next
	return nil
}

func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	s.Usage.record("(webhook)", r)
	h := s.webhooks[strings.TrimPrefix(r.URL.Path, "/relay/v1/webhooks/")]
	if h == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method", 405)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest := hashToken(token)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || len(token) < 32 || subtle.ConstantTimeCompare([]byte(digest), []byte(h.TokenHash)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	// Bound aggregate staging and avoid concurrent duplicate requests per route.
	select {
	case s.webhookSlots <- struct{}{}:
		defer func() { <-s.webhookSlots }()
	default:
		http.Error(w, "busy; retry", 503)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.peersPinned(&h.target) {
		http.Error(w, "device unavailable", 403)
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "JSON required", 415)
		return
	}
	if r.ContentLength > webhookMaxBody {
		http.Error(w, "body too large", 413)
		return
	}
	if !s.diskAvailable(webhookMaxBody) {
		http.Error(w, "disk reserve", 507)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(30 * time.Second))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webhookMaxBody))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			http.Error(w, "body too large", 413)
		} else {
			http.Error(w, "incomplete body", 400)
		}
		return
	}
	if h.Signature != nil {
		sig := h.Signature
		stamp := r.Header.Get(sig.TimestampHeader)
		unix, e := strconv.ParseInt(stamp, 10, 64)
		now := time.Now().Unix()
		mac := hmac.New(sha256.New, []byte(sig.Secret))
		mac.Write([]byte(stamp + "."))
		mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if e != nil || unix < now-300 || unix > now+300 || subtle.ConstantTimeCompare([]byte(expected), []byte(r.Header.Get(sig.SignatureHeader))) != 1 {
			http.Error(w, "invalid signature", 401)
			return
		}
	}

	if !json.Valid(body) {
		http.Error(w, "invalid JSON", 400)
		return
	}
	idem := r.Header.Get("Idempotency-Key")
	if len(idem) > 128 {
		http.Error(w, "idempotency key too long", 400)
		return
	}
	bh := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(bh[:])
	scope := h.App + "/" + h.Group + "/" + h.Sender + "/" + h.Recipient + "/" + h.Route
	if idem != "" {
		var id, previous string
		var ready int
		err = s.Store.DB.QueryRow("SELECT file_id,body_hash,ready FROM webhook_receipts WHERE scope=? AND key_hash=? AND expires>?", scope, hashToken(idem), time.Now().Unix()).Scan(&id, &previous, &ready)
		if err == nil {
			if previous != bodyHash {
				http.Error(w, "idempotency conflict", 409)
				return
			}
			if ready != 1 {
				http.Error(w, "pending recovery; retry", 503)
				return
			}
			webhookAccepted(w, id)
			return
		}
		if !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "storage", 503)
			return
		}
	}
	temp, err := os.MkdirTemp(s.Store.Dir, "webhook-")
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	defer os.RemoveAll(temp)
	source := filepath.Join(temp, "body.json")
	if err = os.WriteFile(source, body, 0600); err != nil {
		http.Error(w, "storage", 503)
		return
	}
	meta := map[string]any{"type": "webhook", "version": 1, "route": h.Route, "content_type": "application/json", "received_at": time.Now().UnixMilli()}
	stage := func(tx *sql.Tx, id string) error {
		if idem == "" {
			return nil
		}
		var receiptCount int
		if err := tx.QueryRow("SELECT count(*) FROM webhook_receipts WHERE scope=? AND expires>?", scope, time.Now().Unix()).Scan(&receiptCount); err != nil {
			return err
		}
		if receiptCount >= 10000 {
			return ErrQuota
		}
		_, err := tx.Exec(`INSERT INTO webhook_receipts(scope,key_hash,body_hash,file_id,expires,ready) VALUES(?,?,?,?,?,0) ON CONFLICT(scope,key_hash) DO UPDATE SET body_hash=excluded.body_hash,file_id=excluded.file_id,expires=excluded.expires,ready=0`, scope, hashToken(idem), bodyHash, id, time.Now().Add(7*24*time.Hour).Unix())
		return err
	}
	ready := func(tx *sql.Tx, id string) error {
		_, err := tx.Exec("UPDATE webhook_receipts SET ready=1 WHERE file_id=?", id)
		return err
	}
	id, ierr := s.publishIngress(&h.target, temp, source, meta, stage, ready)
	if ierr != nil {
		ierr.write(w)
		return
	}
	webhookAccepted(w, id)
}
func webhookAccepted(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": "durably_queued"})
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// RecoverWebhooks runs once before the HTTP listener starts. Never run multiple
// server processes against a data directory. Incomplete staging is not accepted.
func (s *Server) RecoverWebhooks() error {
	rows, err := s.Store.DB.Query("SELECT id,size,digest FROM files WHERE state='webhook-staging'")
	if err != nil {
		return err
	}
	type staged struct {
		id     string
		size   int64
		digest string
	}
	pending := []staged{}
	for rows.Next() {
		var f staged
		if err = rows.Scan(&f.id, &f.size, &f.digest); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range pending {
		f, e := os.Open(s.path(p.id))
		valid := false
		if e == nil {
			h := sha256.New()
			n, readErr := io.Copy(h, f)
			f.Close()
			valid = readErr == nil && n == p.size && hex.EncodeToString(h.Sum(nil)) == p.digest
		} else if !os.IsNotExist(e) {
			return e
		}
		if valid {
			_, err = s.Store.DB.Exec("UPDATE files SET state='ready' WHERE id=?", p.id)
			if err == nil {
				_, err = s.Store.DB.Exec("UPDATE webhook_receipts SET ready=1 WHERE file_id=?", p.id)
			}
		} else {
			if e = os.Remove(s.path(p.id)); e != nil && !os.IsNotExist(e) {
				return e
			}
			_, err = s.Store.DB.Exec("DELETE FROM files WHERE id=?", p.id)
			if err == nil {
				_, err = s.Store.DB.Exec("DELETE FROM webhook_receipts WHERE file_id=?", p.id)
			}
		}
		if err != nil {
			return err
		}
	}
	if _, err = s.Store.DB.Exec("UPDATE webhook_receipts SET ready=1 WHERE file_id IN(SELECT id FROM files WHERE state='ready')"); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.Store.Dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "webhook-") {
			if err = os.RemoveAll(filepath.Join(s.Store.Dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

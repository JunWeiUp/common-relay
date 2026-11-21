package relay

// Optional WebDAV upload ingress. Third-party apps that can only "back up to
// WebDAV" upload files with HTTP Basic credentials; each stored file is encrypted
// for one pinned recipient device and queued as an ordinary v1 file. Like the
// webhook ingress, the server is the bridge sender and sees plaintext in transit.
// It never serves file contents back: GET of a file is refused (write-only).
import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/JunWeiUp/common-relay/sdk/go"
)

const (
	davPrefix         = "/relay/v1/dav/"
	davAccountsPrefix = "/relay/v1/dav/.accounts/"
	davDefaultMax     = 64 << 20
	davLimitMax       = 512 << 20
	davMaxEntries     = 10000
	davMaxAccounts    = 200
	davMaxDepth       = 16
	davMaxPath        = 1024
	davFailLimit      = 20
	davFailWindow     = 10 * time.Minute
	davAllowMethods   = "OPTIONS, PROPFIND, PROPPATCH, MKCOL, PUT, HEAD, GET, DELETE, MOVE"
)

// WebDAVRoute is one private upload endpoint at /relay/v1/dav/{route}/.
type WebDAVRoute struct {
	Route        string `json:"route"`
	App          string `json:"app"`
	Group        string `json:"group"`
	Sender       string `json:"sender"`
	Recipient    string `json:"recipient"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_sha256"`
	SecretKey    string `json:"secret_key"`
	RecipientKey string `json:"recipient_public_key"`
	MaxFileBytes int64  `json:"max_file_bytes,omitempty"`
	target       ingressTarget
	mu           sync.Mutex
	failMu       sync.Mutex
	fails        int
	failSince    time.Time
}

// LoadWebDAV must run before serving. The configuration is private and opt-in;
// sender must be a dedicated bridge identity trusted by the recipient.
func (s *Server) LoadWebDAV(file string) error {
	f, err := openPrivateConfig(file, "webdav")
	if err != nil {
		return err
	}
	defer f.Close()
	var routes []*WebDAVRoute
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&routes); err != nil {
		return errors.New("invalid webdav configuration")
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing webdav configuration")
	}
	next := make(map[string]*WebDAVRoute)
	for _, d := range routes {
		if d == nil || !identifier.MatchString(d.Route) || !identifier.MatchString(d.Sender) || !identifier.MatchString(d.Recipient) || d.Sender == d.Recipient || next[d.Route] != nil {
			return errors.New("invalid webdav route")
		}
		if !validDAVUser(d.Username) {
			return errors.New("invalid webdav username")
		}
		hash, e := hex.DecodeString(d.PasswordHash)
		if e != nil || len(hash) != 32 {
			return errors.New("invalid webdav password hash")
		}
		d.PasswordHash = hex.EncodeToString(hash)
		if d.MaxFileBytes == 0 {
			d.MaxFileBytes = davDefaultMax
		}
		if d.MaxFileBytes < 1 || d.MaxFileBytes > davLimitMax {
			return errors.New("invalid webdav max_file_bytes")
		}
		identity, e := sdk.NewIdentity(d.App, d.Group, d.Sender, d.SecretKey, map[string]string{d.Recipient: d.RecipientKey})
		if e != nil {
			return errors.New("invalid webdav identity")
		}
		d.target = ingressTarget{identity: identity, app: d.App, group: d.Group, sender: d.Sender, recipient: d.Recipient, recipientKey: d.RecipientKey}
		if !s.peersPinned(&d.target) {
			return errors.New("webdav devices must be registered with matching pinned keys")
		}
		next[d.Route] = d
	}
	s.davRoutes = next
	return nil
}

// validDAVUser accepts 1..64 printable ASCII characters except ':' (Basic auth separator).
func validDAVUser(u string) bool {
	if len(u) < 1 || len(u) > 64 {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] < 0x21 || u[i] > 0x7e || u[i] == ':' {
			return false
		}
	}
	return true
}

// davClean validates a decoded path below the route. "" is the route root.
func davClean(p string) (string, bool) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", true
	}
	if len(p) > davMaxPath {
		return "", false
	}
	parts := strings.Split(p, "/")
	if len(parts) > davMaxDepth {
		return "", false
	}
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." || len(seg) > 255 || strings.ContainsRune(seg, '\\') {
			return "", false
		}
		for _, c := range seg {
			if c < 0x20 || c == 0x7f {
				return "", false
			}
		}
	}
	return p, true
}

func davParent(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

type davEntry struct {
	path        string
	collection  bool
	size        int64
	digest      string
	contentType string
	modified    int64
}

func (s *Server) davGet(q interface {
	QueryRow(string, ...any) *sql.Row
}, route, p string) (*davEntry, error) {
	if p == "" {
		return &davEntry{collection: true, modified: time.Now().Unix()}, nil
	}
	e := &davEntry{path: p}
	var c int
	err := q.QueryRow("SELECT collection,size,digest,content_type,modified FROM webdav_entries WHERE route=? AND path=?", route, p).Scan(&c, &e.size, &e.digest, &e.contentType, &e.modified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	e.collection = c == 1
	return e, err
}

// davEnsureParents creates missing ancestor collections. Clients are not required
// to MKCOL first; an ancestor that is a file is a conflict.
func davEnsureParents(tx *sql.Tx, route, p string, now int64) error {
	var missing []string
	for dir := davParent(p); dir != ""; dir = davParent(dir) {
		var c int
		err := tx.QueryRow("SELECT collection FROM webdav_entries WHERE route=? AND path=?", route, dir).Scan(&c)
		if errors.Is(err, sql.ErrNoRows) {
			missing = append(missing, dir)
			continue
		}
		if err != nil {
			return err
		}
		if c != 1 {
			return errDAVConflict
		}
		break
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if _, err := tx.Exec("INSERT INTO webdav_entries(route,path,parent,collection,size,digest,content_type,modified,file_id) VALUES(?,?,?,1,0,'','',?,'')", route, missing[i], davParent(missing[i]), now); err != nil {
			return err
		}
	}
	return nil
}

var errDAVConflict = errors.New("conflict")

// davFileAncestor reports whether the nearest existing ancestor of p is a file.
func (s *Server) davFileAncestor(route, p string) (bool, error) {
	for dir := davParent(p); dir != ""; dir = davParent(dir) {
		var c int
		err := s.Store.DB.QueryRow("SELECT collection FROM webdav_entries WHERE route=? AND path=?", route, dir).Scan(&c)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		return err == nil && c != 1, err
	}
	return false, nil
}

// davAuth checks HTTP Basic credentials with a per-route failure throttle.
// Static route credentials grant access to the whole route (allowedFolder == "");
// dynamic per-folder accounts in webdav_accounts are scoped to allowedFolder.
func (s *Server) davAuth(w http.ResponseWriter, r *http.Request, d *WebDAVRoute) (string, bool) {
	d.failMu.Lock()
	if time.Since(d.failSince) > davFailWindow {
		d.fails, d.failSince = 0, time.Now()
	}
	blocked := d.fails >= davFailLimit
	d.failMu.Unlock()
	if blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(davFailWindow/time.Second)))
		http.Error(w, "too many failed logins", 429)
		return "", false
	}
	user, pass, ok := r.BasicAuth()
	digest := hashToken(pass)
	if ok && subtle.ConstantTimeCompare([]byte(user), []byte(d.Username)) == 1 && subtle.ConstantTimeCompare([]byte(digest), []byte(d.PasswordHash)) == 1 {
		return "", true
	}
	if ok && validDAVUser(user) {
		var folder, storedHash string
		err := s.Store.DB.QueryRow("SELECT folder, password_hash FROM webdav_accounts WHERE route=? AND username=?", d.Route, user).Scan(&folder, &storedHash)
		if err == nil && subtle.ConstantTimeCompare([]byte(digest), []byte(storedHash)) == 1 {
			return folder, true
		}
	}
	if ok {
		d.failMu.Lock()
		d.fails++
		d.failMu.Unlock()
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="common-relay", charset="UTF-8"`)
	http.Error(w, "unauthorized", 401)
	return "", false
}

// davPathAllowed checks whether a folder-scoped account may invoke method on p.
func davPathAllowed(allowedFolder, p, method string) bool {
	if allowedFolder == "" {
		return true
	}
	if p == allowedFolder || strings.HasPrefix(p, allowedFolder+"/") {
		if method == http.MethodDelete && p == allowedFolder {
			return false
		}
		return true
	}
	if p == "" || strings.HasPrefix(allowedFolder, p+"/") {
		switch method {
		case http.MethodOptions, "PROPFIND", http.MethodHead, http.MethodGet, "MKCOL":
			return true
		}
	}
	return false
}

func (s *Server) webdav(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, davPrefix)
	route, sub, _ := strings.Cut(rest, "/")
	d := s.davRoutes[route]
	if d == nil {
		http.NotFound(w, r)
		return
	}
	allowedFolder, ok := s.davAuth(w, r, d)
	if !ok {
		return
	}
	p, ok := davClean(sub)
	if !ok {
		http.Error(w, "invalid path", 400)
		return
	}
	if !davPathAllowed(allowedFolder, p, r.Method) {
		http.Error(w, "forbidden: path outside account folder", 403)
		return
	}
	base := davPrefix + url.PathEscape(route) + "/"
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", "1")
		w.Header().Set("MS-Author-Via", "DAV")
		w.Header().Set("Allow", davAllowMethods)
		w.WriteHeader(200)
	case "PROPFIND":
		s.davPropfind(w, r, d, base, p, allowedFolder)
	case "PROPPATCH":
		s.davProppatch(w, r, d, base, p)
	case "MKCOL":
		s.davMkcol(w, r, d, p)
	case http.MethodPut:
		s.davPut(w, r, d, p)
	case http.MethodGet, http.MethodHead:
		s.davRead(w, r, d, p)
	case http.MethodDelete:
		s.davDelete(w, d, p)
	case "MOVE":
		s.davMove(w, r, d, base, p, allowedFolder)
	default:
		w.Header().Set("Allow", davAllowMethods)
		http.Error(w, "method not supported", 405)
	}
}

func davHref(base, p string, collection bool) string {
	if p == "" {
		return base
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	h := base + strings.Join(parts, "/")
	if collection {
		h += "/"
	}
	return h
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func davResponse(b *strings.Builder, base string, e *davEntry, route string) {
	name := path.Base(e.path)
	if e.path == "" {
		name = route
	}
	b.WriteString("<D:response><D:href>" + xmlText(davHref(base, e.path, e.collection)) + "</D:href><D:propstat><D:prop>")
	b.WriteString("<D:displayname>" + xmlText(name) + "</D:displayname>")
	b.WriteString("<D:getlastmodified>" + time.Unix(e.modified, 0).UTC().Format(http.TimeFormat) + "</D:getlastmodified>")
	b.WriteString("<D:creationdate>" + time.Unix(e.modified, 0).UTC().Format(time.RFC3339) + "</D:creationdate>")
	if e.collection {
		b.WriteString("<D:resourcetype><D:collection/></D:resourcetype>")
	} else {
		b.WriteString("<D:resourcetype/><D:getcontentlength>" + strconv.FormatInt(e.size, 10) + "</D:getcontentlength>")
		b.WriteString("<D:getcontenttype>" + xmlText(e.contentType) + "</D:getcontenttype><D:getetag>" + xmlText(davETag(e)) + "</D:getetag>")
	}
	b.WriteString("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
}

func davETag(e *davEntry) string {
	if len(e.digest) >= 32 {
		return `"` + e.digest[:32] + `"`
	}
	return `"empty-` + strconv.FormatInt(e.modified, 10) + `"`
}

func writeMultistatus(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+`<D:multistatus xmlns:D="DAV:">`+body+`</D:multistatus>`)
}

// drainSmall discards a small request body (PROPFIND/PROPPATCH XML). Requested
// properties are ignored: the server always returns its fixed live properties.
func drainSmall(w http.ResponseWriter, r *http.Request) bool {
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 64<<10)); err != nil {
		http.Error(w, "request body too large", 413)
		return false
	}
	return true
}

func (s *Server) davPropfind(w http.ResponseWriter, r *http.Request, d *WebDAVRoute, base, p, allowedFolder string) {
	if !drainSmall(w, r) {
		return
	}
	e, err := s.davGet(s.Store.DB, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if e == nil {
		http.NotFound(w, r)
		return
	}
	var b strings.Builder
	davResponse(&b, base, e, d.Route)
	// Depth "infinity" (or absent) is answered as depth 1 to bound responses.
	if e.collection && r.Header.Get("Depth") != "0" {
		rows, err := s.Store.DB.Query("SELECT path,collection,size,digest,content_type,modified FROM webdav_entries WHERE route=? AND parent=? ORDER BY path", d.Route, p)
		if err != nil {
			http.Error(w, "storage", 503)
			return
		}
		defer rows.Close()
		filterAncestor := allowedFolder != "" && (p == "" || strings.HasPrefix(allowedFolder, p+"/"))
		for rows.Next() {
			c := &davEntry{}
			var col int
			if err = rows.Scan(&c.path, &col, &c.size, &c.digest, &c.contentType, &c.modified); err != nil {
				http.Error(w, "storage", 503)
				return
			}
			if filterAncestor && c.path != allowedFolder && !strings.HasPrefix(allowedFolder, c.path+"/") {
				continue
			}
			c.collection = col == 1
			davResponse(&b, base, c, d.Route)
		}
		if rows.Err() != nil {
			http.Error(w, "storage", 503)
			return
		}
	}
	writeMultistatus(w, b.String())
}

// davProppatch accepts and ignores dead properties (some clients set mtime after
// upload); live properties remain server-controlled.
func (s *Server) davProppatch(w http.ResponseWriter, r *http.Request, d *WebDAVRoute, base, p string) {
	if !drainSmall(w, r) {
		return
	}
	e, err := s.davGet(s.Store.DB, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if e == nil {
		http.NotFound(w, r)
		return
	}
	writeMultistatus(w, "<D:response><D:href>"+xmlText(davHref(base, p, e.collection))+"</D:href><D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
}

func (s *Server) davMkcol(w http.ResponseWriter, r *http.Request, d *WebDAVRoute, p string) {
	if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "MKCOL body not supported", 415)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := s.Store.DB.Begin()
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	defer tx.Rollback()
	e, err := s.davGet(tx, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if e != nil {
		w.Header().Set("Allow", davAllowMethods)
		http.Error(w, "already exists", 405)
		return
	}
	var n int
	if err = tx.QueryRow("SELECT count(*) FROM webdav_entries WHERE route=?", d.Route).Scan(&n); err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if n >= davMaxEntries {
		http.Error(w, "entry quota", 507)
		return
	}
	now := time.Now().Unix()
	if err = davEnsureParents(tx, d.Route, p, now); err == nil {
		_, err = tx.Exec("INSERT INTO webdav_entries(route,path,parent,collection,size,digest,content_type,modified,file_id) VALUES(?,?,?,1,0,'','',?,'')", d.Route, p, davParent(p), now)
	}
	if err == nil {
		err = tx.Commit()
	}
	if errors.Is(err, errDAVConflict) {
		http.Error(w, "parent is a file", 409)
		return
	}
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	w.WriteHeader(201)
}

func davContentType(r *http.Request, p string) string {
	if t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && t != "" {
		return t
	}
	if t := mime.TypeByExtension(strings.ToLower(path.Ext(p))); t != "" {
		if base, _, err := mime.ParseMediaType(t); err == nil {
			return base
		}
	}
	return "application/octet-stream"
}

func (s *Server) davPut(w http.ResponseWriter, r *http.Request, d *WebDAVRoute, p string) {
	if p == "" {
		w.Header().Set("Allow", davAllowMethods)
		http.Error(w, "cannot PUT the collection root", 405)
		return
	}
	if r.ContentLength > d.MaxFileBytes {
		http.Error(w, "file too large", 413)
		return
	}
	select {
	case s.davSlots <- struct{}{}:
		defer func() { <-s.davSlots }()
	default:
		http.Error(w, "busy; retry", 503)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !s.peersPinned(&d.target) {
		http.Error(w, "device unavailable", 403)
		return
	}
	if !s.diskAvailable(d.MaxFileBytes) {
		http.Error(w, "disk reserve", 507)
		return
	}
	existing, err := s.davGet(s.Store.DB, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if existing != nil && existing.collection {
		w.Header().Set("Allow", davAllowMethods)
		http.Error(w, "is a collection", 405)
		return
	}
	// Reject a file ancestor before anything is encrypted or staged; d.mu keeps the
	// listing stable until publication completes.
	if conflict, err := s.davFileAncestor(d.Route, p); err != nil || conflict {
		if err != nil {
			http.Error(w, "storage", 503)
		} else {
			http.Error(w, "parent is a file", 409)
		}
		return
	}
	// Temp directories share the webhook- prefix so startup recovery removes leftovers.
	temp, err := os.MkdirTemp(s.Store.Dir, "webhook-")
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	defer os.RemoveAll(temp)
	source := filepath.Join(temp, "body")
	out, err := os.OpenFile(source, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Minute))
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, hasher), http.MaxBytesReader(w, r.Body, d.MaxFileBytes))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			http.Error(w, "file too large", 413)
		} else {
			http.Error(w, "incomplete body", 400)
		}
		return
	}
	if r.ContentLength >= 0 && size != r.ContentLength {
		http.Error(w, "incomplete body", 400)
		return
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	contentType := davContentType(r, p)
	now := time.Now().Unix()
	status := 201
	if existing != nil {
		status = 204
	}
	upsert := func(tx *sql.Tx, id string) error {
		if err := davEnsureParents(tx, d.Route, p, now); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO webdav_entries(route,path,parent,collection,size,digest,content_type,modified,file_id) VALUES(?,?,?,0,?,?,?,?,?)
			ON CONFLICT(route,path) DO UPDATE SET size=excluded.size,digest=excluded.digest,content_type=excluded.content_type,modified=excluded.modified,file_id=excluded.file_id`, d.Route, p, davParent(p), size, digest, contentType, now, id)
		return err
	}
	countCheck := func(tx *sql.Tx, _ string) error {
		if existing != nil {
			return nil
		}
		var n int
		if err := tx.QueryRow("SELECT count(*) FROM webdav_entries WHERE route=?", d.Route).Scan(&n); err != nil {
			return err
		}
		if n >= davMaxEntries {
			return ErrQuota
		}
		return nil
	}
	finish := func(err error) {
		switch {
		case errors.Is(err, errDAVConflict):
			http.Error(w, "parent is a file", 409)
		case errors.Is(err, ErrQuota):
			http.Error(w, "entry quota", 507)
		case err != nil:
			http.Error(w, "storage", 503)
		default:
			w.Header().Set("ETag", davETag(&davEntry{digest: digest, modified: now}))
			w.WriteHeader(status)
		}
	}
	// Re-uploading identical bytes to the same path (periodic full backups that did
	// not change) or an empty probe file only updates the listing; nothing is queued.
	if size == 0 || (existing != nil && existing.digest == digest && existing.size == size) {
		tx, err := s.Store.DB.Begin()
		if err != nil {
			finish(err)
			return
		}
		defer tx.Rollback()
		if err = countCheck(tx, ""); err == nil {
			if err = upsert(tx, ""); err == nil {
				err = tx.Commit()
			}
		}
		finish(err)
		return
	}
	meta := map[string]any{"type": "webdav", "version": 1, "route": d.Route, "path": "/" + p, "name": path.Base(p), "content_type": contentType, "size": size, "sha256": digest, "received_at": time.Now().UnixMilli()}
	if _, ierr := s.publishIngress(&d.target, temp, source, meta, countCheck, upsert); ierr != nil {
		ierr.write(w) // 507 covers both the shared file quota and the per-route entry quota.
		return
	}
	finish(nil)
}

// davRead answers metadata only. Contents are encrypted for the recipient device
// and never returned, so GET on a file is refused.
func (s *Server) davRead(w http.ResponseWriter, r *http.Request, d *WebDAVRoute, p string) {
	e, err := s.davGet(s.Store.DB, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if e == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Last-Modified", time.Unix(e.modified, 0).UTC().Format(http.TimeFormat))
	if e.collection {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "Common Relay WebDAV upload endpoint (write-only).\n")
		}
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("ETag", davETag(e))
		w.Header().Set("Content-Type", e.contentType)
		w.Header().Set("Content-Length", strconv.FormatInt(e.size, 10))
		w.WriteHeader(200)
		return
	}
	http.Error(w, "write-only: file contents are delivered encrypted to the receiving device", 403)
}

// davSubtree returns p and every descendant path.
func davSubtree(tx *sql.Tx, route, p string) ([]string, error) {
	rows, err := tx.Query("SELECT path FROM webdav_entries WHERE route=?", route)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var x string
		if err = rows.Scan(&x); err != nil {
			return nil, err
		}
		if x == p || strings.HasPrefix(x, p+"/") {
			out = append(out, x)
		}
	}
	return out, rows.Err()
}

// davDelete removes listing entries only. Files already queued for the receiving
// device stay queued until that device acknowledges them.
func (s *Server) davDelete(w http.ResponseWriter, d *WebDAVRoute, p string) {
	if p == "" {
		http.Error(w, "cannot delete the collection root", 403)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := s.Store.DB.Begin()
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	defer tx.Rollback()
	paths, err := davSubtree(tx, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if len(paths) == 0 {
		http.Error(w, "not found", 404)
		return
	}
	for _, x := range paths {
		if _, err = tx.Exec("DELETE FROM webdav_entries WHERE route=? AND path=?", d.Route, x); err != nil {
			http.Error(w, "storage", 503)
			return
		}
	}
	if tx.Commit() != nil {
		http.Error(w, "storage", 503)
		return
	}
	w.WriteHeader(204)
}

// davMove renames listing entries (clients often upload "x.tmp" then MOVE). It does
// not queue another copy; receivers must not rely on the delivered file name.
func (s *Server) davMove(w http.ResponseWriter, r *http.Request, d *WebDAVRoute, base, p, allowedFolder string) {
	if p == "" {
		http.Error(w, "cannot move the collection root", 403)
		return
	}
	if allowedFolder != "" && p == allowedFolder {
		http.Error(w, "cannot move account root", 403)
		return
	}
	dest, err := url.Parse(r.Header.Get("Destination"))
	if err != nil || r.Header.Get("Destination") == "" || !strings.HasPrefix(dest.Path, base) {
		http.Error(w, "destination must be inside this route", 400)
		return
	}
	q, ok := davClean(strings.TrimPrefix(dest.Path, base))
	if !ok || q == "" {
		http.Error(w, "invalid destination", 400)
		return
	}
	if allowedFolder != "" && !strings.HasPrefix(q, allowedFolder+"/") {
		http.Error(w, "forbidden: destination outside account folder", 403)
		return
	}
	if q == p || strings.HasPrefix(q, p+"/") {
		http.Error(w, "destination inside source", 403)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := s.Store.DB.Begin()
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	defer tx.Rollback()
	src, err := davSubtree(tx, d.Route, p)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if len(src) == 0 {
		http.Error(w, "not found", 404)
		return
	}
	old, err := davSubtree(tx, d.Route, q)
	if err != nil {
		http.Error(w, "storage", 503)
		return
	}
	if len(old) > 0 && strings.EqualFold(r.Header.Get("Overwrite"), "F") {
		http.Error(w, "destination exists", 412)
		return
	}
	for _, x := range old {
		if _, err = tx.Exec("DELETE FROM webdav_entries WHERE route=? AND path=?", d.Route, x); err != nil {
			http.Error(w, "storage", 503)
			return
		}
	}
	now := time.Now().Unix()
	if err = davEnsureParents(tx, d.Route, q, now); err != nil {
		if errors.Is(err, errDAVConflict) {
			http.Error(w, "destination parent is a file", 409)
		} else {
			http.Error(w, "storage", 503)
		}
		return
	}
	for _, x := range src {
		y := q + strings.TrimPrefix(x, p)
		if _, err = tx.Exec("UPDATE webdav_entries SET path=?,parent=? WHERE route=? AND path=?", y, davParent(y), d.Route, x); err != nil {
			http.Error(w, "storage", 503)
			return
		}
	}
	if tx.Commit() != nil {
		http.Error(w, "storage", 503)
		return
	}
	if len(old) > 0 {
		w.WriteHeader(204)
	} else {
		w.WriteHeader(201)
	}
}

type davAccountView struct {
	Folder    string `json:"folder"`
	Username  string `json:"username"`
	UpdatedAt int64  `json:"updated_at"`
}

// webdavAccounts lets the pinned recipient device of a WebDAV route manage
// per-folder Basic Auth sub-accounts dynamically without server restarts or
// editing webdav.json.
func (s *Server) webdavAccounts(w http.ResponseWriter, r *http.Request) {
	dev, err := s.auth(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	route := strings.Trim(strings.TrimPrefix(r.URL.Path, davAccountsPrefix), "/")
	if route == "" || strings.Contains(route, "/") {
		http.NotFound(w, r)
		return
	}
	d := s.davRoutes[route]
	if d == nil {
		http.NotFound(w, r)
		return
	}
	if dev.App != d.App || dev.Group != d.Group || dev.ID != d.Recipient || !s.peersPinned(&d.target) {
		http.Error(w, "forbidden", 403)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.Store.DB.Query("SELECT folder, username, updated_at FROM webdav_accounts WHERE route=? ORDER BY folder", d.Route)
		if err != nil {
			http.Error(w, "storage", 503)
			return
		}
		defer rows.Close()
		list := []davAccountView{}
		for rows.Next() {
			var a davAccountView
			if rows.Scan(&a.Folder, &a.Username, &a.UpdatedAt) != nil {
				http.Error(w, "storage", 503)
				return
			}
			list = append(list, a)
		}
		if rows.Err() != nil {
			http.Error(w, "storage", 503)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		reply(w, map[string]any{"ok": true, "route": d.Route, "accounts": list})

	case http.MethodPut:
		var body struct {
			Folder       string `json:"folder"`
			Username     string `json:"username"`
			PasswordHash string `json:"password_sha256"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		folder, ok := davClean(body.Folder)
		if !ok || folder == "" {
			http.Error(w, "invalid folder", 400)
			return
		}
		if !validDAVUser(body.Username) {
			http.Error(w, "invalid username", 400)
			return
		}
		if body.Username == d.Username {
			http.Error(w, "username conflicts with route master account", 409)
			return
		}
		hash, err := hex.DecodeString(strings.TrimSpace(body.PasswordHash))
		if err != nil || len(hash) != 32 {
			http.Error(w, "invalid password_sha256", 400)
			return
		}
		normHash := hex.EncodeToString(hash)

		d.mu.Lock()
		defer d.mu.Unlock()
		tx, err := s.Store.DB.Begin()
		if err != nil {
			http.Error(w, "storage", 503)
			return
		}
		defer tx.Rollback()

		var conflictFolder string
		err = tx.QueryRow("SELECT folder FROM webdav_accounts WHERE route=? AND username=?", d.Route, body.Username).Scan(&conflictFolder)
		if err == nil && conflictFolder != folder {
			http.Error(w, "username already used by another folder", 409)
			return
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "storage", 503)
			return
		}

		var exists int
		if err := tx.QueryRow("SELECT count(*) FROM webdav_accounts WHERE route=? AND folder=?", d.Route, folder).Scan(&exists); err != nil {
			http.Error(w, "storage", 503)
			return
		}
		if exists == 0 {
			var total int
			if err := tx.QueryRow("SELECT count(*) FROM webdav_accounts WHERE route=?", d.Route).Scan(&total); err != nil {
				http.Error(w, "storage", 503)
				return
			}
			if total >= davMaxAccounts {
				http.Error(w, "account quota exceeded", 507)
				return
			}
		}

		now := time.Now().Unix()
		if _, err := tx.Exec(`INSERT INTO webdav_accounts(route,folder,username,password_hash,updated_at) VALUES(?,?,?,?,?)
			ON CONFLICT(route,folder) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash,updated_at=excluded.updated_at`,
			d.Route, folder, body.Username, normHash, now); err != nil {
			http.Error(w, "storage", 503)
			return
		}
		if existing, err := s.davGet(tx, d.Route, folder); err != nil {
			http.Error(w, "storage", 503)
			return
		} else if existing != nil && !existing.collection {
			http.Error(w, "folder path is a file", 409)
			return
		} else if existing == nil {
			if err := davEnsureParents(tx, d.Route, folder, now); err != nil {
				if errors.Is(err, errDAVConflict) {
					http.Error(w, "parent is a file", 409)
				} else {
					http.Error(w, "storage", 503)
				}
				return
			}
			if _, err := tx.Exec("INSERT INTO webdav_entries(route,path,parent,collection,size,digest,content_type,modified,file_id) VALUES(?,?,?,1,0,'','',?,'')", d.Route, folder, davParent(folder), now); err != nil {
				http.Error(w, "storage", 503)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, "storage", 503)
			return
		}
		d.failMu.Lock()
		d.fails = 0
		d.failMu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		reply(w, map[string]any{"ok": true, "route": d.Route, "folder": folder, "username": body.Username, "updated_at": now})

	case http.MethodDelete:
		folder, ok := davClean(r.URL.Query().Get("folder"))
		if !ok || folder == "" {
			http.Error(w, "invalid folder", 400)
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		res, err := s.Store.DB.Exec("DELETE FROM webdav_accounts WHERE route=? AND folder=?", d.Route, folder)
		if err != nil {
			http.Error(w, "storage", 503)
			return
		}
		n, _ := res.RowsAffected()
		w.Header().Set("Cache-Control", "no-store")
		reply(w, map[string]any{"ok": true, "deleted": n > 0})

	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", 405)
	}
}

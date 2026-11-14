package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	sdk "github.com/JunWeiUp/common-relay/sdk/go"
)

type davFixture struct {
	s             *Server
	http          *httptest.Server
	user, pass    string
	receiverToken string
	receiver      *sdk.Identity
	files         *sdk.Files
}

func newDAVFixture(t *testing.T, mutate func(*WebDAVRoute)) *davFixture {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store)
	s.DiskReserve = 0
	sk, pk, _ := sdk.GenerateKeyPair()
	rk, rp, _ := sdk.GenerateKeyPair()
	rt := RandomID() + RandomID()
	for _, v := range []struct {
		d     Device
		token string
	}{{Device{App: "test", Group: "group", ID: "dav-bridge", PublicKey: pk}, RandomID() + RandomID()}, {Device{App: "test", Group: "group", ID: "mac", PublicKey: rp}, rt}} {
		if err = store.AddDevice(v.d, v.token); err != nil {
			t.Fatal(err)
		}
	}
	pass := RandomID()
	d := &WebDAVRoute{Route: "backup", App: "test", Group: "group", Sender: "dav-bridge", Recipient: "mac", Username: "phone", PasswordHash: hashToken(pass), SecretKey: sk, RecipientKey: rp}
	if mutate != nil {
		mutate(d)
	}
	config := filepath.Join(t.TempDir(), "webdav.json")
	b, _ := json.Marshal([]*WebDAVRoute{d})
	if err = os.WriteFile(config, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.LoadWebDAV(config); err != nil {
		t.Fatal(err)
	}
	receiver, err := sdk.NewIdentity("test", "group", "mac", rk, map[string]string{"dav-bridge": pk})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.Handler())
	files, err := sdk.NewFiles(httpServer.URL+"/relay/v1/files", rt, sdk.Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.Close(); httpServer.Close(); s.Close(); store.DB.Close() })
	return &davFixture{s, httpServer, "phone", pass, rt, receiver, files}
}

func (f *davFixture) do(t *testing.T, method, p string, body []byte, headers ...string) (*http.Response, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequest(method, f.http.URL+"/relay/v1/dav/backup"+p, rd)
	if err != nil {
		t.Fatal(err)
	}
	r.SetBasicAuth(f.user, f.pass)
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "Authorization" && headers[i+1] == "" {
			r.Header.Del("Authorization")
			continue
		}
		r.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (f *davFixture) inbox(t *testing.T) []sdk.FileInfo {
	t.Helper()
	list, err := f.files.Inbox(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestWebDAVAuthAndThrottle(t *testing.T) {
	f := newDAVFixture(t, nil)
	resp, _ := f.do(t, "PROPFIND", "/", nil, "Authorization", "")
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	good := f.pass
	f.pass = "wrong-password"
	for i := 0; i < davFailLimit; i++ {
		if resp, _ = f.do(t, "PROPFIND", "/", nil); resp.StatusCode != 401 {
			t.Fatal(i, resp.StatusCode)
		}
	}
	f.pass = good
	if resp, _ = f.do(t, "PROPFIND", "/", nil); resp.StatusCode != 429 {
		t.Fatal("expected throttle", resp.StatusCode)
	}
	if resp, _ = f.do(t, "OPTIONS", "/", nil); resp.StatusCode != 429 {
		t.Fatal(resp.StatusCode)
	}
	// Unknown routes are indistinguishable from a disabled feature.
	r, _ := http.NewRequest("PROPFIND", f.http.URL+"/relay/v1/dav/other/", nil)
	r.SetBasicAuth(f.user, good)
	other, err := http.DefaultClient.Do(r)
	if err != nil || other.StatusCode != 404 {
		t.Fatal(err, other.StatusCode)
	}
	other.Body.Close()
}

func TestWebDAVUploadDeliversEncryptedFile(t *testing.T) {
	f := newDAVFixture(t, nil)
	resp, _ := f.do(t, "OPTIONS", "/", nil)
	if resp.StatusCode != 200 || resp.Header.Get("DAV") != "1" || !strings.Contains(resp.Header.Get("Allow"), "PROPFIND") {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	if resp, _ = f.do(t, "MKCOL", "/资料备份/", nil); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ = f.do(t, "MKCOL", "/资料备份/", nil); resp.StatusCode != 405 {
		t.Fatal("duplicate MKCOL", resp.StatusCode)
	}
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte("账单备份-"), 4000)...)
	resp, body := f.do(t, "PUT", "/%E8%B5%84%E6%96%99%E5%A4%87%E4%BB%BD/backup%20backup.zip", payload, "Content-Type", "application/zip")
	if resp.StatusCode != 201 || resp.Header.Get("ETag") == "" {
		t.Fatal(resp.StatusCode, body)
	}
	list := f.inbox(t)
	if len(list) != 1 || list[0].Expires != webhookExpiry {
		t.Fatalf("%+v", list)
	}
	cipher, _ := os.ReadFile(f.s.path(list[0].ID))
	if bytes.Contains(cipher, []byte("账单备份")) {
		t.Fatal("plaintext stored on relay")
	}
	dir := t.TempDir()
	if err := f.files.Download(context.Background(), list[0], filepath.Join(dir, "c")); err != nil {
		t.Fatal(err)
	}
	meta, err := sdk.DecryptFile(f.receiver, "dav-bridge", list[0], filepath.Join(dir, "c"), filepath.Join(dir, "p"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(meta, &m); err != nil || m["type"] != "webdav" || m["path"] != "/资料备份/backup backup.zip" || m["name"] != "backup backup.zip" || m["content_type"] != "application/zip" || m["route"] != "backup" {
		t.Fatalf("%s %v", meta, err)
	}
	plain, _ := os.ReadFile(filepath.Join(dir, "p"))
	if !bytes.Equal(plain, payload) {
		t.Fatal("plaintext mismatch")
	}

	resp, body = f.do(t, "PROPFIND", "/", nil, "Depth", "1")
	if resp.StatusCode != 207 || !strings.Contains(body, "<D:collection/>") || !strings.Contains(body, "/relay/v1/dav/backup/%E8%B5%84%E6%96%99%E5%A4%87%E4%BB%BD/") {
		t.Fatal(resp.StatusCode, body)
	}
	resp, body = f.do(t, "PROPFIND", "/资料备份", nil, "Depth", "1")
	if resp.StatusCode != 207 || !strings.Contains(body, "backup%20backup.zip") || !strings.Contains(body, "<D:getcontentlength>") {
		t.Fatal(resp.StatusCode, body)
	}
	resp, body = f.do(t, "PROPFIND", "/资料备份/backup backup.zip", nil, "Depth", "0")
	if resp.StatusCode != 207 || strings.Count(body, "<D:response>") != 1 {
		t.Fatal(body)
	}
	if resp, _ = f.do(t, "GET", "/资料备份/backup backup.zip", nil); resp.StatusCode != 403 {
		t.Fatal("GET must be refused", resp.StatusCode)
	}
	if resp, _ = f.do(t, "HEAD", "/资料备份/backup backup.zip", nil); resp.StatusCode != 200 || resp.ContentLength != int64(len(payload)) {
		t.Fatal(resp.StatusCode, resp.ContentLength)
	}
	if resp, _ = f.do(t, "PROPPATCH", "/资料备份/backup backup.zip", []byte(`<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"/>`)); resp.StatusCode != 207 {
		t.Fatal(resp.StatusCode)
	}

	// Unchanged full backups do not queue again; changed ones do.
	if resp, _ = f.do(t, "PUT", "/资料备份/backup backup.zip", payload); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if n := len(f.inbox(t)); n != 1 {
		t.Fatal("identical upload queued", n)
	}
	if resp, _ = f.do(t, "PUT", "/资料备份/backup backup.zip", append(payload, 'x')); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if n := len(f.inbox(t)); n != 2 {
		t.Fatal("changed upload not queued", n)
	}
	// Empty probe files are listed but never queued.
	if resp, _ = f.do(t, "PUT", "/probe.txt", []byte{}); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if n := len(f.inbox(t)); n != 2 {
		t.Fatal("empty file queued", n)
	}
	// Uploading without MKCOL creates parents.
	if resp, _ = f.do(t, "PUT", "/a/b/c.zip", []byte("z")); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if _, body = f.do(t, "PROPFIND", "/a", nil, "Depth", "1"); !strings.Contains(body, "/relay/v1/dav/backup/a/b/") {
		t.Fatal(body)
	}
	if resp, _ = f.do(t, "PUT", "/a/b/c.zip/inner", []byte("z")); resp.StatusCode != 409 {
		t.Fatal("file as parent", resp.StatusCode)
	}
	if n := len(f.inbox(t)); n != 3 {
		t.Fatal("rejected upload must not queue", n)
	}
	if resp, _ = f.do(t, "PUT", "/", []byte("z")); resp.StatusCode != 405 {
		t.Fatal(resp.StatusCode)
	}
}

func TestWebDAVMoveDelete(t *testing.T) {
	f := newDAVFixture(t, nil)
	base := f.http.URL + "/relay/v1/dav/backup"
	if resp, _ := f.do(t, "PUT", "/up/backup.zip.tmp", []byte("one")); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "PUT", "/up/existing.zip", []byte("two")); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "MOVE", "/up/backup.zip.tmp", nil, "Destination", base+"/up/existing.zip", "Overwrite", "F"); resp.StatusCode != 412 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "MOVE", "/up/backup.zip.tmp", nil, "Destination", base+"/done/backup.zip"); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "PROPFIND", "/up/backup.zip.tmp", nil, "Depth", "0"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "PROPFIND", "/done/backup.zip", nil, "Depth", "0"); resp.StatusCode != 207 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "MOVE", "/up", nil, "Destination", "https://elsewhere.example/relay/v1/dav/other/x"); resp.StatusCode != 400 {
		t.Fatal("cross-route move", resp.StatusCode)
	}
	if resp, _ := f.do(t, "MOVE", "/up", nil, "Destination", base+"/up/inside"); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
	if n := len(f.inbox(t)); n != 2 {
		t.Fatal("MOVE must not queue again", n)
	}
	if resp, _ := f.do(t, "DELETE", "/up", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "PROPFIND", "/up/existing.zip", nil, "Depth", "0"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "DELETE", "/", nil); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
	// Listing deletion never withdraws files already queued for the receiver.
	if n := len(f.inbox(t)); n != 2 {
		t.Fatal(n)
	}
}

func TestWebDAVLimits(t *testing.T) {
	f := newDAVFixture(t, func(d *WebDAVRoute) { d.MaxFileBytes = 1024 })
	if resp, _ := f.do(t, "PUT", "/big.zip", bytes.Repeat([]byte("x"), 2048)); resp.StatusCode != 413 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "LOCK", "/x", nil); resp.StatusCode != 405 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := f.do(t, "MKCOL", "/body", []byte("<x/>")); resp.StatusCode != 415 {
		t.Fatal(resp.StatusCode)
	}
	for _, bad := range []string{"a/../b", "a/./b", "a//b", "a\\b", "x\x00y", strings.Repeat("a/", 20) + "z"} {
		if _, ok := davClean(bad); ok {
			t.Fatal("accepted", bad)
		}
	}
	if p, ok := davClean("/资料备份/x.zip/"); !ok || p != "资料备份/x.zip" {
		t.Fatal(p, ok)
	}
	if n := len(f.inbox(t)); n != 0 {
		t.Fatal(n)
	}
}

func TestWebDAVConfigValidation(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	s := New(store)
	sk, pk, _ := sdk.GenerateKeyPair()
	_, rp, _ := sdk.GenerateKeyPair()
	_ = store.AddDevice(Device{App: "test", Group: "group", ID: "dav-bridge", PublicKey: pk}, RandomID()+RandomID())
	_ = store.AddDevice(Device{App: "test", Group: "group", ID: "mac", PublicKey: rp}, RandomID()+RandomID())
	write := func(mode os.FileMode, d *WebDAVRoute) string {
		p := filepath.Join(t.TempDir(), "webdav.json")
		b, _ := json.Marshal([]*WebDAVRoute{d})
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
		return p
	}
	ok := func() *WebDAVRoute {
		return &WebDAVRoute{Route: "backup", App: "test", Group: "group", Sender: "dav-bridge", Recipient: "mac", Username: "phone", PasswordHash: hashToken("secret"), SecretKey: sk, RecipientKey: rp}
	}
	if err = s.LoadWebDAV(write(0600, ok())); err != nil {
		t.Fatal(err)
	}
	if s.LoadWebDAV(write(0644, ok())) == nil {
		t.Fatal("world-readable config accepted")
	}
	for name, mutate := range map[string]func(*WebDAVRoute){
		"user colon":   func(d *WebDAVRoute) { d.Username = "a:b" },
		"empty user":   func(d *WebDAVRoute) { d.Username = "" },
		"bad hash":     func(d *WebDAVRoute) { d.PasswordHash = "abc" },
		"huge limit":   func(d *WebDAVRoute) { d.MaxFileBytes = davLimitMax + 1 },
		"wrong key":    func(d *WebDAVRoute) { _, d.RecipientKey, _ = sdk.GenerateKeyPair() },
		"self":         func(d *WebDAVRoute) { d.Recipient = d.Sender },
		"bad route id": func(d *WebDAVRoute) { d.Route = "a/b" },
	} {
		d := ok()
		mutate(d)
		if s.LoadWebDAV(write(0600, d)) == nil {
			t.Fatal("accepted", name)
		}
	}
}

// TestWebDAVRcloneInterop exercises a real third-party WebDAV client. Opt-in:
// COMMON_RELAY_RCLONE=1 go test ./internal/relay -run Rclone
func TestWebDAVRcloneInterop(t *testing.T) {
	rclone, err := exec.LookPath("rclone")
	if os.Getenv("COMMON_RELAY_RCLONE") != "1" || err != nil {
		t.Skip("set COMMON_RELAY_RCLONE=1 with rclone on PATH")
	}
	f := newDAVFixture(t, nil)
	obscured, err := exec.Command(rclone, "obscure", f.pass).Output()
	if err != nil {
		t.Fatal(err)
	}
	remote := ":webdav,url='" + f.http.URL + "/relay/v1/dav/backup/',vendor=other,user=" + f.user + ",pass=" + strings.TrimSpace(string(obscured)) + ":"
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(rclone, append([]string{"--config", "", "--low-level-retries", "1", "--retries", "1"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("rclone %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	local := filepath.Join(t.TempDir(), "backup.zip")
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte("rclone-账单"), 5000)...)
	if err = os.WriteFile(local, payload, 0600); err != nil {
		t.Fatal(err)
	}
	run("mkdir", remote+"资料备份")
	run("copyto", local, remote+"资料备份/backup.zip")
	if out := run("lsjson", remote+"资料备份"); !strings.Contains(out, `"Name":"backup.zip"`) || !strings.Contains(out, `"Size":`+strconv.Itoa(len(payload))) {
		t.Fatal(out)
	}
	run("copyto", local, remote+"资料备份/backup.zip") // unchanged: no second delivery
	run("moveto", remote+"资料备份/backup.zip", remote+"归档/backup-1.zip")
	if out := run("lsjson", "-R", remote); !strings.Contains(out, "backup-1.zip") || strings.Contains(out, `"Path":"资料备份/backup.zip"`) {
		t.Fatal(out)
	}
	run("purge", remote+"归档")
	if n := len(f.inbox(t)); n != 1 {
		t.Fatal("expected exactly one delivered file", n)
	}
}

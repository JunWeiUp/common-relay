package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedStreamAndOfflineVectors(t *testing.T) {
	raw, err := os.ReadFile("../../protocol/crypto-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ID               string           `json:"id"`
		StreamDescriptor streamDescriptor `json:"stream_descriptor"`
		StreamAAD        string           `json:"stream_aad"`
		StreamCiphertext string           `json:"stream_ciphertext"`
		OfflineExpires   int64            `json:"offline_expires"`
		OfflineMessage   string           `json:"offline_message"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b := bob(t)
	aad := b.streamAAD("alice", "bob", "stream", v.ID, 0)
	if string(aad) != v.StreamAAD {
		t.Fatalf("AAD %s", aad)
	}
	pull, err := newSecretStreamPull(v.StreamDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := pull.pull(unhexT(t, v.StreamCiphertext), aad)
	if err != nil || string(plain) != "hello" || !pull.finished {
		t.Fatalf("stream vector: %v", err)
	}
	data, expires, err := b.openMessage("alice", v.ID, v.OfflineMessage)
	if err != nil || expires != v.OfflineExpires || len(data) == 0 {
		t.Fatalf("offline vector: %v %d", err, expires)
	}
	if _, err = b.OpenMessage("alice", v.ID, v.OfflineMessage); err == nil {
		t.Fatal("expired vector accepted by OpenMessage")
	}
	// Kinds are bound into the authenticated context.
	a, _ := NewIdentity("example", "test", "alice", vectors(t)["alice_secret"], map[string]string{"bob": b.PublicKey()})
	body, err := a.sealEnvelope("bob", "stream.open", v.ID, streamDescriptor{Key: "k", Header: "h"})
	if err != nil {
		t.Fatal(err)
	}
	var d streamDescriptor
	if err = b.openEnvelope("alice", "stream.accept", v.ID, body, &d); err == nil {
		t.Fatal("kind substitution accepted")
	}
	if err = b.openEnvelope("alice", "stream.open", v.ID, body, &d); err != nil || d.Key != "k" {
		t.Fatalf("envelope: %v", err)
	}
	sealed, err := a.sealMessage("bob", v.ID, []byte("x"), 4102444800)
	if err != nil {
		t.Fatal(err)
	}
	if got, exp, err := b.openMessage("alice", v.ID, sealed); err != nil || string(got) != "x" || exp != 4102444800 {
		t.Fatal("authenticated expiry round trip failed")
	}
}

func filePair(t *testing.T) (*Identity, *Identity) {
	t.Helper()
	v := vectors(t)
	a, err := NewIdentity(v["app"], v["group"], "alice", v["alice_secret"], map[string]string{"bob": v["bob_public"]})
	if err != nil {
		t.Fatal(err)
	}
	return a, bob(t)
}

func TestFileEncryptionRoundTripAndRejections(t *testing.T) {
	alice, bob := filePair(t)
	dir := t.TempDir()
	for _, size := range []int{0, 1, streamRecordPlain, streamRecordPlain + 1, 3*streamRecordPlain + 7} {
		source := filepath.Join(dir, fmt.Sprintf("in-%d", size))
		data := make([]byte, size)
		rand.Read(data)
		os.WriteFile(source, data, 0o600)
		prepared, err := PrepareFile(alice, "bob", source, source+".enc", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = PrepareFile(alice, "bob", source, source+".enc", nil); err == nil {
			t.Fatal("existing staging file overwritten")
		}
		info, _ := os.Stat(prepared.Path)
		if info.Mode().Perm() != 0o600 || info.Size() != prepared.Info.Size {
			t.Fatal("staging file mode or size")
		}
		out := source + ".out"
		metadata, err := DecryptFile(bob, "alice", prepared.Info, prepared.Path, out)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		got, _ := os.ReadFile(out)
		if !bytes.Equal(got, data) || string(metadata) != fmt.Sprintf(`{"name":"in-%d"}`, size) {
			t.Fatalf("size %d mismatch", size)
		}
		if _, err = DecryptFile(bob, "alice", prepared.Info, prepared.Path, out); err == nil {
			t.Fatal("destination overwritten")
		}
	}
	source := filepath.Join(dir, "in-65520")
	prepared, err := PrepareFile(alice, "bob", source, filepath.Join(dir, "custom.enc"), map[string]any{"name": "../../etc/passwd", "type": "x"})
	if err != nil {
		t.Fatal(err)
	}
	staged, _ := os.ReadFile(prepared.Path)
	try := func(name string, mutate func([]byte) []byte, info FileInfo) {
		t.Helper()
		path := filepath.Join(dir, name+".enc")
		changed := mutate(append([]byte(nil), staged...))
		os.WriteFile(path, changed, 0o600)
		sum := sha256.Sum256(changed)
		info.SHA256, info.Size = hex.EncodeToString(sum[:]), int64(len(changed))
		out := filepath.Join(dir, name+".out")
		if _, err := DecryptFile(bob, "alice", info, path, out); err == nil {
			t.Fatalf("%s accepted", name)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%s published plaintext", name)
		}
		if leftovers, _ := filepath.Glob(out + ".*.partial"); len(leftovers) != 0 {
			t.Fatalf("%s left partial file", name)
		}
	}
	lastRecord := len(staged) - (4 + secretStreamABytes)
	try("missing-final", func(b []byte) []byte { return b[:lastRecord] }, prepared.Info)
	try("truncated", func(b []byte) []byte { return b[:len(b)-1] }, prepared.Info)
	try("tampered", func(b []byte) []byte { b[10] ^= 1; return b }, prepared.Info)
	try("after-final", func(b []byte) []byte { return append(b, b[lastRecord:]...) }, prepared.Info)
	try("reordered", func(b []byte) []byte {
		first := 4 + streamRecordPlain + secretStreamABytes
		second := first + 4 + 1 + secretStreamABytes
		return append(append(append([]byte(nil), b[first:second]...), b[:first]...), b[second:]...)
	}, prepared.Info)
	wrongID := prepared.Info
	wrongID.ID = strings.Repeat("0", 32)
	try("wrong-id", func(b []byte) []byte { return b }, wrongID)
	digestOnly := filepath.Join(dir, "digest.out")
	bad := prepared.Info
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err = DecryptFile(bob, "alice", bad, prepared.Path, digestOnly); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	metadata, err := DecryptFile(bob, "alice", prepared.Info, prepared.Path, filepath.Join(dir, "ok.out"))
	if err != nil || !strings.Contains(string(metadata), `"../../etc/passwd"`) {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"../../etc/passwd": "_.._etc_passwd", "..": "file", "a\x00b": "a_b", "CON.txt": "_CON.txt", "  .hidden ": "hidden", "报告.pdf": "报告.pdf", "a‮b": "a_b"} {
		if got := SafeFileName(in); got != want {
			t.Errorf("SafeFileName(%q) = %q, want %q", in, got, want)
		}
	}
	if len(SafeFileName(strings.Repeat("界", 100))) > 200 {
		t.Fatal("long name not truncated")
	}
}

// fakeFiles implements the /relay/v1/files contract closely enough for client tests.
type fakeFiles struct {
	mu      sync.Mutex
	objects map[string]*FileInfo
	data    map[string][]byte
	puts    atomic.Int32
	failPut int32 // Fail this PUT (1-based) after storing it, to simulate a lost response.
}

func (f *fakeFiles) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 64) {
			w.WriteHeader(401)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		reply := func(status int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(v)
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/relay/v1/files"), "/")
		switch {
		case len(parts) == 1 && r.Method == "POST":
			var info FileInfo
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&info) != nil || info.Offset != 0 || info.State != "" || info.From != "" {
				w.WriteHeader(400)
				return
			}
			if f.objects[info.ID] != nil {
				w.WriteHeader(409)
				return
			}
			info.From, info.State = "alice", "uploading"
			f.objects[info.ID] = &info
			reply(201, info)
		case len(parts) == 1 && r.Method == "GET":
			list := []FileInfo{}
			for _, o := range f.objects {
				if o.State == "ready" {
					list = append(list, *o)
				}
			}
			reply(200, list)
		default:
			o := f.objects[parts[1]]
			if o == nil {
				w.WriteHeader(404)
				return
			}
			action := ""
			if len(parts) == 3 {
				action = parts[2]
			}
			switch {
			case action == "" && r.Method == "GET":
				reply(200, o)
			case action == "" && r.Method == "DELETE":
				delete(f.objects, o.ID)
				w.WriteHeader(204)
			case action == "data" && r.Method == "PUT":
				offset, _ := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
				body, _ := io.ReadAll(r.Body)
				if offset != o.Offset || len(body) == 0 || len(body) > 1<<20 || o.Offset+int64(len(body)) > o.Size {
					w.WriteHeader(409)
					return
				}
				f.data[o.ID] = append(f.data[o.ID], body...)
				o.Offset += int64(len(body))
				if f.puts.Add(1) == f.failPut {
					w.WriteHeader(500)
					return
				}
				reply(200, o)
			case action == "commit" && r.Method == "POST":
				sum := sha256.Sum256(f.data[o.ID])
				if o.Offset != o.Size || hex.EncodeToString(sum[:]) != o.SHA256 {
					w.WriteHeader(409)
					return
				}
				o.State = "ready"
				reply(200, o)
			case action == "data" && r.Method == "GET" && o.State == "ready":
				http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.data[o.ID]))
			default:
				w.WriteHeader(409)
			}
		}
	})
}

func TestFilesUploadResumeDownloadAndDelete(t *testing.T) {
	alice, bob := filePair(t)
	server := &fakeFiles{objects: map[string]*FileInfo{}, data: map[string][]byte{}, failPut: 2}
	s := httptest.NewServer(server.handler(t))
	defer s.Close()
	token := strings.Repeat("x", 64)
	if _, err := NewFiles(s.URL+"/relay/v1/files", token, Options{}); err == nil {
		t.Fatal("plain HTTP accepted without local test option")
	}
	for _, bad := range []string{s.URL + "/relay/v1/other", s.URL + "/relay/v1/files?x=1", "http://user@127.0.0.1/relay/v1/files", "http://localhost/relay/v1/files"} {
		if _, err := NewFiles(bad, token, Options{AllowLocalTest: true}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	files, err := NewFiles(s.URL+"/relay/v1/files", token, Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	dir := t.TempDir()
	source := filepath.Join(dir, "source.bin")
	data := make([]byte, 2<<20+12345)
	rand.Read(data)
	os.WriteFile(source, data, 0o600)
	prepared, err := PrepareFile(alice, "bob", source, filepath.Join(dir, "up.enc"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = files.Upload(ctx, prepared); err == nil {
		t.Fatal("lost PUT response not reported")
	}
	ready, err := files.Upload(ctx, prepared) // Resumes after 409 from the server offset.
	if err != nil || ready.State != "ready" {
		t.Fatalf("resume: %v", err)
	}
	if again, err := files.Upload(ctx, prepared); err != nil || again.State != "ready" {
		t.Fatalf("idempotent upload: %v", err)
	}
	conflict := prepared
	conflict.Info.Metadata = prepared.Info.Metadata[:len(prepared.Info.Metadata)-4] + "AAAA"
	if _, err = files.Upload(ctx, conflict); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("descriptor substitution accepted: %v", err)
	}
	inbox, err := files.Inbox(ctx)
	if err != nil || len(inbox) != 1 || inbox[0].ID != prepared.Info.ID {
		t.Fatalf("inbox: %v", err)
	}
	staged := filepath.Join(dir, "down.enc")
	partial, _ := os.ReadFile(prepared.Path)
	os.WriteFile(staged, partial[:12345], 0o600) // Resume a partial download.
	if err = files.Download(ctx, inbox[0], staged); err != nil {
		t.Fatal(err)
	}
	if _, err = DecryptFile(bob, "alice", inbox[0], staged, filepath.Join(dir, "result.bin")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "result.bin")); !bytes.Equal(got, data) {
		t.Fatal("download mismatch")
	}
	if status, err := files.Status(ctx, prepared.Info.ID); err != nil || status.State != "ready" {
		t.Fatal(err)
	}
	if err = files.Delete(ctx, prepared.Info.ID); err != nil {
		t.Fatal(err)
	}
	var status fileStatusError
	if _, err = files.Status(ctx, prepared.Info.ID); !errors.As(err, &status) || status.status != 404 {
		t.Fatalf("deleted file still visible: %v", err)
	}
}

func TestFilesNeverFollowRedirects(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(r.Header.Get("Authorization") != "")
		w.WriteHeader(200)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	files, err := NewFiles(source.URL+"/relay/v1/files", strings.Repeat("x", 64), Options{AllowLocalTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = files.Inbox(context.Background()); err == nil || reached.Load() {
		t.Fatal("redirect followed")
	}
}

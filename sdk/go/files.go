package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const fileChunk = 1 << 20

// FileInfo is the relay's file descriptor/status. Size and SHA256 cover the whole
// ciphertext file; Metadata is a kind=file envelope with the secretstream key/header
// and the application's encrypted metadata.
type FileInfo struct {
	ID       string `json:"id"`
	To       string `json:"to"`
	From     string `json:"from,omitempty"`
	Size     int64  `json:"size"`
	Offset   int64  `json:"offset,omitempty"`
	Metadata string `json:"metadata"`
	SHA256   string `json:"sha256"`
	State    string `json:"state,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
}

func (f FileInfo) sameDescriptor(other FileInfo) bool {
	return f.ID == other.ID && f.To == other.To && f.Size == other.Size && f.Metadata == other.Metadata && f.SHA256 == other.SHA256
}

// PreparedFile is an encrypted staging file ready to upload. Keep Info and the
// staging file (ciphertext only) to resume an interrupted upload with Upload.
type PreparedFile struct {
	Info FileInfo
	Path string
}

type fileDescriptor struct {
	Key      string          `json:"key"`
	Header   string          `json:"header"`
	Metadata json.RawMessage `json:"metadata"`
}

// PrepareFile encrypts source into a new staging file (mode 0600, must not exist) as
// records length[4 BE]|secretstream record, ending with an empty FINAL record.
// metadata is encrypted with the descriptor; nil uses {"name": base name of source}.
func PrepareFile(identity *Identity, to, source, staged string, metadata any) (PreparedFile, error) {
	if identity == nil {
		return PreparedFile{}, errors.New("identity required")
	}
	if metadata == nil {
		metadata = map[string]string{"name": filepath.Base(source)}
	}
	rawMetadata, err := json.Marshal(metadata)
	if err != nil || bytes.Equal(rawMetadata, []byte("null")) {
		return PreparedFile{}, errors.New("invalid file metadata")
	}
	id, err := newID()
	if err != nil {
		return PreparedFile{}, err
	}
	push, err := newSecretStreamPush()
	if err != nil {
		return PreparedFile{}, err
	}
	d := push.descriptor()
	sealed, err := identity.sealEnvelope(to, "file", id, fileDescriptor{Key: d.Key, Header: d.Header, Metadata: rawMetadata})
	if err != nil {
		return PreparedFile{}, err
	}
	if len(sealed) > 8192 {
		return PreparedFile{}, errors.New("file metadata too large")
	}
	input, err := os.Open(source)
	if err != nil {
		return PreparedFile{}, err
	}
	defer input.Close()
	output, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return PreparedFile{}, err
	}
	ok := false
	defer func() {
		if !ok {
			output.Close()
			os.Remove(staged)
		}
	}()
	digest := sha256.New()
	writer := io.MultiWriter(output, digest)
	buffer := make([]byte, streamRecordPlain)
	var size int64
	for sequence := uint64(0); ; sequence++ {
		n, err := io.ReadFull(input, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return PreparedFile{}, err
		}
		tag := byte(secretStreamTagMessage)
		if n == 0 {
			tag = secretStreamTagFinal
		}
		cipher, err := push.push(buffer[:n], identity.streamAAD(identity.device, to, "file", id, sequence), tag)
		if err != nil {
			return PreparedFile{}, err
		}
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(cipher)))
		if _, err = writer.Write(prefix[:]); err == nil {
			_, err = writer.Write(cipher)
		}
		if err != nil {
			return PreparedFile{}, err
		}
		size += int64(4 + len(cipher))
		if n == 0 {
			break
		}
	}
	if err = output.Sync(); err != nil {
		return PreparedFile{}, err
	}
	if err = output.Close(); err != nil {
		return PreparedFile{}, err
	}
	ok = true
	return PreparedFile{Info: FileInfo{ID: id, To: to, Size: size, Metadata: sealed, SHA256: hex.EncodeToString(digest.Sum(nil))}, Path: staged}, nil
}

// DecryptFile verifies the staged ciphertext's SHA-256, every record and the FINAL
// record before publishing plaintext to destination, which must not exist and is never
// overwritten. Choose destination yourself (see SafeFileName); the returned metadata
// comes from the authenticated sender but is still untrusted input.
func DecryptFile(identity *Identity, from string, info FileInfo, staged, destination string) (json.RawMessage, error) {
	if identity == nil {
		return nil, errors.New("identity required")
	}
	var d fileDescriptor
	if err := identity.openEnvelope(from, "file", info.ID, info.Metadata, &d); err != nil {
		return nil, err
	}
	if len(d.Metadata) == 0 {
		return nil, errors.New("missing file metadata")
	}
	pull, err := newSecretStreamPull(streamDescriptor{Key: d.Key, Header: d.Header})
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(destination); err == nil {
		return nil, errors.New("destination exists")
	}
	input, err := os.Open(staged)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	digest := sha256.New()
	if n, err := io.Copy(digest, input); err != nil || n != info.Size || hex.EncodeToString(digest.Sum(nil)) != info.SHA256 {
		return nil, errors.New("ciphertext size or digest mismatch")
	}
	if _, err = input.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var suffix [16]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	temporary := destination + "." + hex.EncodeToString(suffix[:]) + ".partial"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(temporary)
	defer output.Close()
	cipher := make([]byte, streamRecordPlain+secretStreamABytes)
	for sequence := uint64(0); ; sequence++ {
		var prefix [4]byte
		n, err := io.ReadFull(input, prefix[:])
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil {
			return nil, errors.New("truncated record")
		}
		size := binary.BigEndian.Uint32(prefix[:])
		if size < secretStreamABytes || size > streamRecordPlain+secretStreamABytes {
			return nil, errors.New("invalid record size")
		}
		if _, err = io.ReadFull(input, cipher[:size]); err != nil {
			return nil, errors.New("truncated ciphertext")
		}
		plain, err := pull.pull(cipher[:size], identity.streamAAD(from, identity.device, "file", info.ID, sequence))
		if err != nil {
			return nil, err
		}
		if _, err = output.Write(plain); err != nil {
			return nil, err
		}
	}
	if !pull.finished {
		return nil, errors.New("missing authenticated final record")
	}
	if err = output.Sync(); err != nil {
		return nil, err
	}
	if err = output.Close(); err != nil {
		return nil, err
	}
	// A hard link publishes atomically and fails instead of replacing a file.
	if err = os.Link(temporary, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("destination appeared during decryption")
		}
		if _, statErr := os.Lstat(destination); statErr == nil {
			return nil, errors.New("destination appeared during decryption")
		}
		if err = os.Rename(temporary, destination); err != nil { // Filesystems without hard links.
			return nil, err
		}
	}
	return d.Metadata, nil
}

// SafeFileName reduces an untrusted remote name to a single path component: no
// separators, control characters, leading dots or Windows reserved names, at most
// 200 bytes. Callers must still pick a unique destination in their own directory.
func SafeFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r), strings.ContainsRune(`/\:*?"<>|`, r), unicode.Is(unicode.Cf, r):
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	clean := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(b.String()), "."))
	clean = strings.TrimRight(clean, ". ")
	for len(clean) > 200 {
		_, size := utf8.DecodeLastRuneInString(clean)
		clean = clean[:len(clean)-size]
	}
	stem := strings.ToUpper(strings.SplitN(clean, ".", 2)[0])
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		clean = "_" + clean
	}
	if clean == "" {
		return "file"
	}
	return clean
}

// Files is the /relay/v1/files client. Redirects and environment proxies are not
// followed so the bearer credential only reaches the configured relay.
type Files struct {
	base  string
	token string
	http  *http.Client
}

// NewFiles takes the files base URL, e.g. https://relay.example.com/relay/v1/files.
func NewFiles(base, token string, options Options) (*Files, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("invalid files endpoint")
	}
	local := options.AllowLocalTest && u.Scheme == "http" && u.Hostname() == "127.0.0.1"
	if (u.Scheme != "https" && !local) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "/relay/v1/files" && u.Path != "/relay/v1/files/") {
		return nil, errors.New("an HTTPS /relay/v1/files endpoint is required")
	}
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("invalid device credential")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Files{
		base:  u.Scheme + "://" + u.Host + "/relay/v1/files",
		token: token,
		http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("relay redirects forbidden")
		}},
	}, nil
}

// Close releases idle connections.
func (f *Files) Close() { f.http.CloseIdleConnections() }

type fileStatusError struct{ status int }

func (e fileStatusError) Error() string { return fmt.Sprintf("file request failed (%d)", e.status) }

func (f *Files) do(ctx context.Context, method, path string, body []byte, header http.Header) (*http.Response, error) {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(bounded, method, f.base+path, reader)
	if err != nil {
		cancel()
		return nil, err
	}
	for k, v := range header {
		request.Header[k] = v
	}
	request.Header.Set("Authorization", "Bearer "+f.token)
	response, err := f.http.Do(request)
	if err != nil {
		cancel()
		return nil, err
	}
	response.Body = cancelOnClose{response.Body, cancel}
	return response, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error { err := c.ReadCloser.Close(); c.cancel(); return err }

func (f *Files) json(ctx context.Context, method, path string, body any, accept []int, out any) (int, error) {
	var raw []byte
	header := http.Header{}
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, err
		}
		header.Set("Content-Type", "application/json")
	}
	response, err := f.do(ctx, method, path, raw, header)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	ok := false
	for _, status := range accept {
		ok = ok || response.StatusCode == status
	}
	if !ok {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode, fileStatusError{response.StatusCode}
	}
	if out == nil {
		return response.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	if err != nil {
		return response.StatusCode, err
	}
	if len(data) > 4<<20 || json.Unmarshal(data, out) != nil {
		return response.StatusCode, errors.New("invalid file response")
	}
	return response.StatusCode, nil
}

func fileObjectPath(id string) (string, error) {
	if !objectID.MatchString(id) {
		return "", errors.New("invalid file ID")
	}
	return "/" + id, nil
}

// Upload creates the relay object, or after 409 resumes it only if the stored
// descriptor matches exactly, sends the remaining ciphertext in ≤1 MiB chunks at
// the server offset and commits. Call again with the same PreparedFile to resume.
func (f *Files) Upload(ctx context.Context, prepared PreparedFile) (FileInfo, error) {
	info := prepared.Info
	path, err := fileObjectPath(info.ID)
	if err != nil {
		return FileInfo{}, err
	}
	descriptor := FileInfo{ID: info.ID, To: info.To, Size: info.Size, Metadata: info.Metadata, SHA256: info.SHA256, Expires: info.Expires}
	var status FileInfo
	code, err := f.json(ctx, "POST", "", descriptor, []int{201}, &status)
	if code == 409 {
		_, err = f.json(ctx, "GET", path, nil, []int{200}, &status)
	}
	if err != nil {
		return FileInfo{}, err
	}
	if !status.sameDescriptor(info) {
		return FileInfo{}, errors.New("upload ID conflict")
	}
	if status.State == "ready" {
		return status, nil
	}
	offset := status.Offset
	if status.State != "uploading" || offset < 0 || offset > info.Size {
		return FileInfo{}, errors.New("invalid upload offset")
	}
	input, err := os.Open(prepared.Path)
	if err != nil {
		return FileInfo{}, err
	}
	defer input.Close()
	if stat, err := input.Stat(); err != nil || stat.Size() != info.Size {
		return FileInfo{}, errors.New("staging file size mismatch")
	}
	buffer := make([]byte, fileChunk)
	for offset < info.Size {
		n, err := input.ReadAt(buffer[:min(int64(fileChunk), info.Size-offset)], offset)
		if err != nil && !(err == io.EOF && int64(n) == info.Size-offset) {
			return FileInfo{}, err
		}
		header := http.Header{"Upload-Offset": {strconv.FormatInt(offset, 10)}, "Content-Type": {"application/octet-stream"}}
		response, err := f.do(ctx, "PUT", path+"/data", buffer[:n], header)
		if err != nil {
			return FileInfo{}, err
		}
		var progress FileInfo
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		if response.StatusCode != 200 {
			return FileInfo{}, fileStatusError{response.StatusCode}
		}
		if readErr != nil || json.Unmarshal(data, &progress) != nil || progress.Offset != offset+int64(n) || progress.Offset > info.Size {
			return FileInfo{}, errors.New("invalid upload progress")
		}
		offset = progress.Offset
	}
	var result FileInfo
	if _, err = f.json(ctx, "POST", path+"/commit", nil, []int{200}, &result); err != nil {
		return FileInfo{}, err
	}
	if !result.sameDescriptor(info) || result.State != "ready" {
		return FileInfo{}, errors.New("invalid commit response")
	}
	return result, nil
}

// Inbox lists ready, unexpired files addressed to this device.
func (f *Files) Inbox(ctx context.Context) ([]FileInfo, error) {
	var list []FileInfo
	_, err := f.json(ctx, "GET", "", nil, []int{200}, &list)
	return list, err
}

// Status returns the state of a file this device sent or receives.
func (f *Files) Status(ctx context.Context, id string) (FileInfo, error) {
	path, err := fileObjectPath(id)
	if err != nil {
		return FileInfo{}, err
	}
	var info FileInfo
	if _, err = f.json(ctx, "GET", path, nil, []int{200}, &info); err != nil {
		return FileInfo{}, err
	}
	if info.ID != id {
		return FileInfo{}, errors.New("invalid file status")
	}
	return info, nil
}

// Download appends the remaining ciphertext to staged (created 0600) with ranged
// requests, resuming from its current size. Then call DecryptFile.
func (f *Files) Download(ctx context.Context, info FileInfo, staged string) error {
	path, err := fileObjectPath(info.ID)
	if err != nil {
		return err
	}
	if info.Size < 1 {
		return errors.New("invalid file size")
	}
	output, err := os.OpenFile(staged, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer output.Close()
	stat, err := output.Stat()
	if err != nil {
		return err
	}
	offset := stat.Size()
	if offset > info.Size {
		return errors.New("staged file exceeds declared size")
	}
	for offset < info.Size {
		end := min(offset+fileChunk, info.Size) - 1
		response, err := f.do(ctx, "GET", path+"/data", nil, http.Header{"Range": {fmt.Sprintf("bytes=%d-%d", offset, end)}})
		if err != nil {
			return err
		}
		want := end - offset + 1
		data, readErr := io.ReadAll(io.LimitReader(response.Body, want+1))
		response.Body.Close()
		if response.StatusCode != 206 {
			return fileStatusError{response.StatusCode}
		}
		if readErr != nil || int64(len(data)) != want || response.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", offset, end, info.Size) {
			return errors.New("invalid range download")
		}
		if _, err = output.Write(data); err != nil {
			return err
		}
		offset += want
	}
	if err = output.Sync(); err != nil {
		return err
	}
	return output.Close()
}

// Delete cancels an upload (sender) or acknowledges a received file (recipient).
func (f *Files) Delete(ctx context.Context, id string) error {
	path, err := fileObjectPath(id)
	if err != nil {
		return err
	}
	_, err = f.json(ctx, "DELETE", path, nil, []int{204}, nil)
	return err
}

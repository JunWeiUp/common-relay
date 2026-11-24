package server_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	v2server "github.com/JunWeiUp/common-relay/internal/v2/server"
)

func TestBoxResumableChunkedUploads(t *testing.T) {
	store, err := core.OpenStore(filepath.Join(t.TempDir(), "relay_v2.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	accessPw := "access-pass-123456"
	adminSecret := "root-admin-secret-12345678901234567890"
	srv := v2server.New(store, v2server.Config{
		AccessHash:    core.HashSecret(accessPw),
		RootAdminHash: core.HashSecret(adminSecret),
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if _, err := store.CreateSpace("sp-up", "Upload Space", core.TrustStrictE2E); err != nil {
		t.Fatalf("CreateSpace: %v", err)
	}
	if _, err := store.CreateBox(core.Box{SpaceID: "sp-up", Name: "inbox", Mode: core.ModeQueue}); err != nil {
		t.Fatalf("CreateBox queue: %v", err)
	}
	if _, err := store.CreateBox(core.Box{SpaceID: "sp-up", Name: "vault", Mode: core.ModeObject}); err != nil {
		t.Fatalf("CreateBox object: %v", err)
	}
	dev, tok, err := store.CreateDevice("dev-up", "Uploader", strings.Repeat("a", 64), false)
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if _, err := store.SetSpaceMember("sp-up", dev.ID, core.RoleMember); err != nil {
		t.Fatalf("SetSpaceMember: %v", err)
	}

	devDo := func(method, path string, body io.Reader, contentType string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, body)
		req.Header.Set("Relay-Access", accessPw)
		req.Header.Set("Authorization", "Bearer "+tok)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	// 1. Queue box chunked upload with resume & mismatch offset recovery.
	payload := []byte("hello-chunk-1|hello-chunk-2|hello-chunk-3!")
	sum := sha256.Sum256(payload)
	wantHash := hex.EncodeToString(sum[:])

	initBody, _ := json.Marshal(map[string]any{
		"total_size":   len(payload),
		"content_type": "application/octet-stream",
		"meta":         `{"filename":"big.bin"}`,
	})
	resp := devDo(http.MethodPost, "/v2/spaces/sp-up/boxes/inbox/uploads", bytes.NewReader(initBody), "application/json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create upload: %d", resp.StatusCode)
	}
	var initRes struct {
		Upload core.BoxUpload `json:"upload"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&initRes)
	resp.Body.Close()
	uid := initRes.Upload.ID

	// Upload chunk 1 (first 14 bytes).
	resp = devDo(http.MethodPatch, "/v2/spaces/sp-up/boxes/inbox/uploads/"+uid+"?offset=0", bytes.NewReader(payload[:14]), "application/octet-stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chunk 1: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong offset must fail with 409 Conflict.
	resp = devDo(http.MethodPatch, "/v2/spaces/sp-up/boxes/inbox/uploads/"+uid+"?offset=0", bytes.NewReader(payload[:4]), "application/octet-stream")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 on mismatched offset, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Query progress to resume.
	resp = devDo(http.MethodGet, "/v2/spaces/sp-up/boxes/inbox/uploads/"+uid, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get upload: %d", resp.StatusCode)
	}
	var progRes struct {
		Upload core.BoxUpload `json:"upload"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&progRes)
	resp.Body.Close()
	if progRes.Upload.Offset != 14 {
		t.Fatalf("expected offset=14, got %d", progRes.Upload.Offset)
	}

	// Upload remaining bytes.
	resp = devDo(http.MethodPatch, "/v2/spaces/sp-up/boxes/inbox/uploads/"+uid+"?offset=14", bytes.NewReader(payload[14:]), "application/octet-stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chunk 2: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Complete with wrong sha256 fails 400.
	badComp, _ := json.Marshal(map[string]any{"sha256": strings.Repeat("0", 64)})
	resp = devDo(http.MethodPost, "/v2/spaces/sp-up/boxes/inbox/uploads/"+uid+"/complete", bytes.NewReader(badComp), "application/json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad sha256, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Complete with valid sha256 promotes into a BoxItem.
	goodComp, _ := json.Marshal(map[string]any{"sha256": wantHash})
	resp = devDo(http.MethodPost, "/v2/spaces/sp-up/boxes/inbox/uploads/"+uid+"/complete", bytes.NewReader(goodComp), "application/json")
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("complete upload: %d %s", resp.StatusCode, string(b))
	}
	var compRes struct {
		Item core.BoxItem `json:"item"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&compRes)
	resp.Body.Close()
	if compRes.Item.SHA256 != wantHash || compRes.Item.Size != int64(len(payload)) {
		t.Fatalf("unexpected promoted item: %+v", compRes.Item)
	}

	// Download promoted item and verify exact bytes.
	resp = devDo(http.MethodGet, "/v2/spaces/sp-up/boxes/inbox/items/"+compRes.Item.ID, nil, "")
	gotBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(gotBytes, payload) {
		t.Fatalf("downloaded bytes mismatch: got %q", string(gotBytes))
	}

	// 2. Object box chunked upload & abort test.
	objInit, _ := json.Marshal(map[string]any{"total_size": 10, "key": "docs/test.enc"})
	resp = devDo(http.MethodPost, "/v2/spaces/sp-up/boxes/vault/uploads", bytes.NewReader(objInit), "application/json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create object upload: %d", resp.StatusCode)
	}
	var objInitRes struct {
		Upload core.BoxUpload `json:"upload"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&objInitRes)
	resp.Body.Close()

	resp = devDo(http.MethodPatch, "/v2/spaces/sp-up/boxes/vault/uploads/"+objInitRes.Upload.ID+"?offset=0", bytes.NewReader([]byte("0123456789")), "application/octet-stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("object chunk: %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = devDo(http.MethodPost, "/v2/spaces/sp-up/boxes/vault/uploads/"+objInitRes.Upload.ID+"/complete", nil, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("complete object upload: %d", resp.StatusCode)
	}
	var objCompRes struct {
		Object core.BoxObject `json:"object"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&objCompRes)
	resp.Body.Close()
	if objCompRes.Object.Key != "docs/test.enc" || objCompRes.Object.Version != 1 {
		t.Fatalf("unexpected promoted object: %+v", objCompRes.Object)
	}

	// 3. Abort frees upload cleanly.
	abortInit, _ := json.Marshal(map[string]any{"total_size": 100})
	resp = devDo(http.MethodPost, "/v2/spaces/sp-up/boxes/inbox/uploads", bytes.NewReader(abortInit), "application/json")
	var abRes struct {
		Upload core.BoxUpload `json:"upload"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&abRes)
	resp.Body.Close()
	resp = devDo(http.MethodDelete, "/v2/spaces/sp-up/boxes/inbox/uploads/"+abRes.Upload.ID, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("abort upload: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

package v2client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// BoxUpload describes an in-progress resumable chunked upload into a Box.
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

// SetSpaceQuota updates a single Space's byte quota (0 resets to server default).
func (c *Client) SetSpaceQuota(ctx context.Context, spaceID string, quotaBytes int64) (Space, error) {
	var res struct {
		Space Space `json:"space"`
	}
	err := c.doJSON(ctx, http.MethodPut, "/v2/admin/spaces/"+url.PathEscape(spaceID)+"/quota", map[string]any{
		"quota_bytes": quotaBytes,
	}, &res)
	return res.Space, err
}

func boxUploadsPath(spaceID, boxName string) string {
	return "/v2/spaces/" + url.PathEscape(spaceID) + "/boxes/" + escapeBoxPath(boxName) + "/uploads"
}

func escapeBoxPath(boxName string) string {
	parts := strings.Split(boxName, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// CreateBoxUpload opens a resumable chunked upload session for a Box.
// Pass key="" for queue/ephemeral Boxes, or a valid object key for object Boxes.
func (c *Client) CreateBoxUpload(ctx context.Context, spaceID, boxName, key, contentType, metaJSON string, totalSize, ttlSec int64) (BoxUpload, error) {
	var res struct {
		Upload BoxUpload `json:"upload"`
	}
	err := c.doJSON(ctx, http.MethodPost, boxUploadsPath(spaceID, boxName), map[string]any{
		"total_size":   totalSize,
		"key":          key,
		"content_type": contentType,
		"meta":         metaJSON,
		"ttl":          ttlSec,
	}, &res)
	return res.Upload, err
}

// GetBoxUpload queries the server-side offset of an in-progress Box upload.
func (c *Client) GetBoxUpload(ctx context.Context, spaceID, boxName, uploadID string) (BoxUpload, error) {
	var res struct {
		Upload BoxUpload `json:"upload"`
	}
	err := c.doJSON(ctx, http.MethodGet, boxUploadsPath(spaceID, boxName)+"/"+url.PathEscape(uploadID), nil, &res)
	return res.Upload, err
}

// AppendBoxUploadChunk uploads one chunk starting at offset.
func (c *Client) AppendBoxUploadChunk(ctx context.Context, spaceID, boxName, uploadID string, offset int64, chunk []byte) (BoxUpload, error) {
	u := c.base + boxUploadsPath(spaceID, boxName) + "/" + url.PathEscape(uploadID) + "?offset=" + strconv.FormatInt(offset, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(chunk))
	if err != nil {
		return BoxUpload{}, err
	}
	req.Header = c.authHeaders()
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return BoxUpload{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return BoxUpload{}, &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(msg))}
	}
	var res struct {
		Upload BoxUpload `json:"upload"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return BoxUpload{}, err
	}
	return res.Upload, nil
}

// CompleteBoxUpload finalizes a chunked upload, verifying expectedSHA256 if non-empty.
func (c *Client) CompleteBoxUpload(ctx context.Context, spaceID, boxName, uploadID, expectedSHA256 string) (*BoxItem, *BoxObject, error) {
	var res struct {
		Item   *BoxItem   `json:"item"`
		Object *BoxObject `json:"object"`
	}
	var body any
	if expectedSHA256 != "" {
		body = map[string]string{"sha256": expectedSHA256}
	}
	err := c.doJSON(ctx, http.MethodPost, boxUploadsPath(spaceID, boxName)+"/"+url.PathEscape(uploadID)+"/complete", body, &res)
	return res.Item, res.Object, err
}

// AbortBoxUpload deletes an incomplete upload and releases reserved quota.
func (c *Client) AbortBoxUpload(ctx context.Context, spaceID, boxName, uploadID string) error {
	return c.doJSON(ctx, http.MethodDelete, boxUploadsPath(spaceID, boxName)+"/"+url.PathEscape(uploadID), nil, nil)
}

// UploadBoxResumable uploads data in chunks of chunkSize (default 256 KiB) with SHA-256 verification.
func (c *Client) UploadBoxResumable(ctx context.Context, spaceID, boxName, key, contentType, metaJSON string, data []byte, chunkSize int, ttlSec int64) (*BoxItem, *BoxObject, error) {
	if chunkSize <= 0 {
		chunkSize = 256 << 10
	}
	sum := sha256.Sum256(data)
	wantHash := hex.EncodeToString(sum[:])

	up, err := c.CreateBoxUpload(ctx, spaceID, boxName, key, contentType, metaJSON, int64(len(data)), ttlSec)
	if err != nil {
		return nil, nil, err
	}
	for offset := int64(0); offset < int64(len(data)); {
		end := offset + int64(chunkSize)
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		up, err = c.AppendBoxUploadChunk(ctx, spaceID, boxName, up.ID, offset, data[offset:end])
		if err != nil {
			return nil, nil, err
		}
		offset = up.Offset
	}
	return c.CompleteBoxUpload(ctx, spaceID, boxName, up.ID, wantHash)
}

/* ───────── Optional Direct-Upgrade Convention (relay.direct.v1) ───────── */

// DirectUpgradeTopic is the Pipe msg topic reserved for optional LAN/direct
// candidate exchange (§4.9). The relay forwards it as opaque encrypted traffic.
const DirectUpgradeTopic = "relay.direct.v1"

// DirectUpgradeMessage is the plaintext JSON carried inside a §6 encrypted
// envelope on DirectUpgradeTopic.
type DirectUpgradeMessage struct {
	Op         string   `json:"op"` // "offer" | "answer" | "fallback"
	Session    string   `json:"session"`
	Candidates []string `json:"candidates,omitempty"`
	Nonce      string   `json:"nonce,omitempty"`
}

func (m DirectUpgradeMessage) Validate() error {
	switch m.Op {
	case "offer", "answer", "fallback":
	default:
		return fmt.Errorf("invalid direct upgrade op %q", m.Op)
	}
	if strings.TrimSpace(m.Session) == "" {
		return errors.New("direct upgrade session is required")
	}
	return nil
}

func EncodeDirectUpgrade(m DirectUpgradeMessage) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func DecodeDirectUpgrade(raw []byte) (DirectUpgradeMessage, error) {
	var m DirectUpgradeMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return DirectUpgradeMessage{}, err
	}
	return m, m.Validate()
}

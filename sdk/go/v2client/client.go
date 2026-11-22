package v2client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BaseURL        string // e.g. "https://relay.example" (no trailing slash)
	AccessPassword string // Sent in Relay-Access header
	Token          string // Device Bearer token or Root Admin token
	AllowLocal     bool   // Allow plain http:// on loopback for isolated testing
	HTTPClient     *http.Client
}

type Client struct {
	base   string
	access string
	token  string
	http   *http.Client
}

func New(cfg Config) (*Client, error) {
	raw := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("invalid v2 BaseURL")
	}
	if u.Scheme == "http" {
		h := strings.ToLower(u.Hostname())
		if !cfg.AllowLocal || (h != "127.0.0.1" && h != "localhost" && h != "::1") {
			return nil, errors.New("v2 client requires https (except loopback with AllowLocal)")
		}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		base:   raw,
		access: cfg.AccessPassword,
		token:  cfg.Token,
		http:   hc,
	}, nil
}

func (c *Client) WSURL() string {
	if strings.HasPrefix(c.base, "https://") {
		return "wss://" + strings.TrimPrefix(c.base, "https://") + "/v2/ws"
	}
	return "ws://" + strings.TrimPrefix(c.base, "http://") + "/v2/ws"
}

func (c *Client) authHeaders() http.Header {
	h := http.Header{}
	if c.access != "" {
		h.Set("Relay-Access", c.access)
	}
	if c.token != "" {
		h.Set("Authorization", "Bearer "+c.token)
	}
	return h
}

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header = c.authHeaders()
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(msg))}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	}
	return nil
}

/* ───────── Admin Control Plane (/v2/admin/*) ───────── */

func (c *Client) Status(ctx context.Context) (StatusSnapshot, error) {
	var res struct {
		Status StatusSnapshot `json:"status"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/status", nil, &res)
	return res.Status, err
}

func (c *Client) GetAccessPasswordInfo(ctx context.Context) (AccessPasswordInfo, error) {
	var res AccessPasswordInfo
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/access-password", nil, &res)
	return res, err
}

func (c *Client) SetAccessPasswordHash(ctx context.Context, accessHash string) (AccessPasswordInfo, error) {
	var res AccessPasswordInfo
	err := c.doJSON(ctx, http.MethodPut, "/v2/admin/access-password", map[string]any{
		"access_hash": accessHash,
	}, &res)
	return res, err
}

func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	var res struct {
		Devices []Device `json:"devices"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/devices", nil, &res)
	return res.Devices, err
}

func (c *Client) CreateDevice(ctx context.Context, id, name, pubKey string, isAdmin bool) (Device, string, error) {
	var res struct {
		Device Device `json:"device"`
		Token  string `json:"token"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v2/admin/devices", map[string]any{
		"id": id, "name": name, "public_key": pubKey, "is_admin": isAdmin,
	}, &res)
	return res.Device, res.Token, err
}

func (c *Client) RevokeDevice(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v2/admin/devices/"+url.PathEscape(id), nil, nil)
}

// Me returns the device the client's token belongs to. RootAdmin is true (and
// Device zero) for the Root Admin secret. Older servers answer IsUnsupported.
func (c *Client) Me(ctx context.Context) (Device, bool, error) {
	var res struct {
		Device    Device `json:"device"`
		RootAdmin bool   `json:"root_admin"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/me", nil, &res)
	return res.Device, res.RootAdmin, err
}

// Metrics returns the relay's operational counters. Older servers answer IsUnsupported.
func (c *Client) Metrics(ctx context.Context) (Metrics, error) {
	var res struct {
		Metrics Metrics `json:"metrics"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/metrics", nil, &res)
	return res.Metrics, err
}

func (c *Client) ListSpaces(ctx context.Context) ([]Space, error) {
	var res struct {
		Spaces []Space `json:"spaces"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/spaces", nil, &res)
	return res.Spaces, err
}

func (c *Client) CreateSpace(ctx context.Context, id, name, trustLevel string) (Space, error) {
	var res struct {
		Space Space `json:"space"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v2/admin/spaces", map[string]any{
		"id": id, "name": name, "trust_level": trustLevel,
	}, &res)
	return res.Space, err
}

func (c *Client) SetSpaceMember(ctx context.Context, spaceID, deviceID, role string) (SpaceMember, error) {
	var res struct {
		Member SpaceMember `json:"member"`
	}
	err := c.doJSON(ctx, http.MethodPut, "/v2/admin/spaces/"+url.PathEscape(spaceID)+"/members", map[string]any{
		"device_id": deviceID, "role": role,
	}, &res)
	return res.Member, err
}

func (c *Client) CreateBox(ctx context.Context, spaceID string, b Box) (Box, error) {
	var res struct {
		Box Box `json:"box"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v2/admin/spaces/"+url.PathEscape(spaceID)+"/boxes", b, &res)
	return res.Box, err
}

func (c *Client) ListBoxes(ctx context.Context, spaceID string) ([]Box, error) {
	var res struct {
		Boxes []Box `json:"boxes"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/spaces/"+url.PathEscape(spaceID)+"/boxes", nil, &res)
	return res.Boxes, err
}

func (c *Client) ListPlugins(ctx context.Context, pluginID string) ([]string, []PluginBinding, error) {
	var res struct {
		Registered []string        `json:"registered"`
		Bindings   []PluginBinding `json:"bindings"`
	}
	p := "/v2/admin/plugins"
	if pluginID != "" {
		p += "?plugin_id=" + url.QueryEscape(pluginID)
	}
	err := c.doJSON(ctx, http.MethodGet, p, nil, &res)
	return res.Registered, res.Bindings, err
}

func (c *Client) UpsertPlugin(ctx context.Context, pluginID, mount, spaceID, boxName string, config any, enabled bool) (PluginBinding, error) {
	var cfgRaw json.RawMessage
	if config != nil {
		b, err := json.Marshal(config)
		if err != nil {
			return PluginBinding{}, err
		}
		cfgRaw = b
	}
	var res struct {
		Binding PluginBinding `json:"binding"`
	}
	err := c.doJSON(ctx, http.MethodPut, "/v2/admin/plugins", map[string]any{
		"plugin_id": pluginID, "mount": mount, "space_id": spaceID,
		"box_name": boxName, "config": cfgRaw, "enabled": enabled,
	}, &res)
	return res.Binding, err
}

// PluginOverview is the full GET /v2/admin/plugins answer.
type PluginOverview struct {
	Registered []string        `json:"registered"`
	Plugins    []PluginInfo    `json:"plugins"` // empty on servers that predate schemas
	Bindings   []PluginBinding `json:"bindings"`
}

// PluginOverview returns bindings, registered IDs and plugin schemas in one call.
func (c *Client) PluginOverview(ctx context.Context) (PluginOverview, error) {
	var res PluginOverview
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/plugins", nil, &res)
	return res, err
}

// PluginCatalog returns the registered plugins with their config schemas
// (nil on servers that predate schemas).
func (c *Client) PluginCatalog(ctx context.Context) ([]PluginInfo, error) {
	var res struct {
		Plugins []PluginInfo `json:"plugins"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/plugins", nil, &res)
	return res.Plugins, err
}

// GetPlugin returns one binding (public view) regardless of its enabled state.
func (c *Client) GetPlugin(ctx context.Context, pluginID, mount string) (PluginBinding, error) {
	var res struct {
		Binding PluginBinding `json:"binding"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v2/admin/plugins/"+url.PathEscape(pluginID)+"/"+url.PathEscape(mount), nil, &res)
	return res.Binding, err
}

// PatchPlugin merges a partial update into an existing binding. Servers older
// than the PATCH API answer 404/405 (see IsUnsupported).
func (c *Client) PatchPlugin(ctx context.Context, pluginID, mount string, patch PluginPatch) (PluginBinding, error) {
	var res struct {
		Binding PluginBinding `json:"binding"`
	}
	err := c.doJSON(ctx, http.MethodPatch, "/v2/admin/plugins/"+url.PathEscape(pluginID)+"/"+url.PathEscape(mount), patch, &res)
	return res.Binding, err
}

// UpsertPluginAccountPassword stores an account whose password the server hashes
// with salted scrypt (preferred over UpsertPluginAccount's bare SHA-256).
func (c *Client) UpsertPluginAccountPassword(ctx context.Context, pluginID, mount, scopeKey, username, password, mode string) (PluginAccount, error) {
	var res struct {
		Account PluginAccount `json:"account"`
	}
	p := fmt.Sprintf("/v2/admin/plugins/%s/%s/accounts", url.PathEscape(pluginID), url.PathEscape(mount))
	err := c.doJSON(ctx, http.MethodPut, p, map[string]any{
		"scope_key": scopeKey, "username": username, "password": password, "mode": mode,
	}, &res)
	return res.Account, err
}

func (c *Client) DeletePlugin(ctx context.Context, pluginID, mount string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v2/admin/plugins/"+url.PathEscape(pluginID)+"/"+url.PathEscape(mount), nil, nil)
}

func (c *Client) ListPluginAccounts(ctx context.Context, pluginID, mount string) ([]PluginAccount, error) {
	var res struct {
		Accounts []PluginAccount `json:"accounts"`
	}
	p := fmt.Sprintf("/v2/admin/plugins/%s/%s/accounts", url.PathEscape(pluginID), url.PathEscape(mount))
	err := c.doJSON(ctx, http.MethodGet, p, nil, &res)
	return res.Accounts, err
}

func (c *Client) UpsertPluginAccount(ctx context.Context, pluginID, mount, scopeKey, username, secretSHA256, mode string) (PluginAccount, error) {
	var res struct {
		Account PluginAccount `json:"account"`
	}
	p := fmt.Sprintf("/v2/admin/plugins/%s/%s/accounts", url.PathEscape(pluginID), url.PathEscape(mount))
	err := c.doJSON(ctx, http.MethodPut, p, map[string]any{
		"scope_key": scopeKey, "username": username, "secret_sha256": secretSHA256, "mode": mode,
	}, &res)
	return res.Account, err
}

func (c *Client) DeletePluginAccount(ctx context.Context, pluginID, mount, scopeKey string) error {
	p := fmt.Sprintf("/v2/admin/plugins/%s/%s/accounts?scope_key=%s", url.PathEscape(pluginID), url.PathEscape(mount), url.QueryEscape(scopeKey))
	return c.doJSON(ctx, http.MethodDelete, p, nil, nil)
}

/* ───────── Device Kernel Plane (/v2/spaces/*) ───────── */

func (c *Client) ListBoxItems(ctx context.Context, spaceID, boxName string, afterSeq int64, limit int) ([]BoxItem, error) {
	var res struct {
		Items []BoxItem `json:"items"`
	}
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/items?after=%d&limit=%d", url.PathEscape(spaceID), boxName, afterSeq, limit)
	err := c.doJSON(ctx, http.MethodGet, p, nil, &res)
	return res.Items, err
}

func (c *Client) PutBoxItem(ctx context.Context, spaceID, boxName, contentType, metaJSON string, ttlSec int64, body io.Reader) (BoxItem, error) {
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/items", url.PathEscape(spaceID), boxName)
	if ttlSec > 0 {
		p += "?ttl=" + strconv.FormatInt(ttlSec, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+p, body)
	if err != nil {
		return BoxItem{}, err
	}
	req.Header = c.authHeaders()
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if metaJSON != "" {
		req.Header.Set("X-Box-Meta", metaJSON)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return BoxItem{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return BoxItem{}, &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(msg))}
	}
	var res struct {
		Item BoxItem `json:"item"`
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	return res.Item, err
}

func (c *Client) DownloadBoxItem(ctx context.Context, spaceID, boxName, itemID string) ([]byte, error) {
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/items/%s", url.PathEscape(spaceID), boxName, url.PathEscape(itemID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header = c.authHeaders()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(msg))}
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) AckBoxItem(ctx context.Context, spaceID, boxName, itemID string) error {
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/items/%s", url.PathEscape(spaceID), boxName, url.PathEscape(itemID))
	return c.doJSON(ctx, http.MethodDelete, p, nil, nil)
}

func (c *Client) PutBoxObject(ctx context.Context, spaceID, boxName, key, contentType, ifMatch string, body io.Reader) (BoxObject, error) {
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/objects/%s", url.PathEscape(spaceID), boxName, strings.TrimLeft(key, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+p, body)
	if err != nil {
		return BoxObject{}, err
	}
	req.Header = c.authHeaders()
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return BoxObject{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return BoxObject{}, &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(msg))}
	}
	var res struct {
		Object BoxObject `json:"object"`
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	return res.Object, err
}

func (c *Client) GetBoxObject(ctx context.Context, spaceID, boxName, key string) ([]byte, string, int64, error) {
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/objects/%s", url.PathEscape(spaceID), boxName, strings.TrimLeft(key, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+p, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header = c.authHeaders()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", 0, &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(msg))}
	}
	data, err := io.ReadAll(resp.Body)
	ver, _ := strconv.ParseInt(resp.Header.Get("X-Object-Version"), 10, 64)
	return data, strings.Trim(resp.Header.Get("ETag"), `"`), ver, err
}

func (c *Client) ListBoxObjects(ctx context.Context, spaceID, boxName, prefix string) ([]BoxObject, error) {
	var res struct {
		Objects []BoxObject `json:"objects"`
	}
	p := fmt.Sprintf("/v2/spaces/%s/boxes/%s/objects", url.PathEscape(spaceID), boxName)
	if prefix != "" {
		p += "?prefix=" + url.QueryEscape(prefix)
	}
	err := c.doJSON(ctx, http.MethodGet, p, nil, &res)
	return res.Objects, err
}

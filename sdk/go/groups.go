package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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

type Groups struct {
	Config *GroupConfig
	base   string
	local  bool
	client *http.Client
}

func NewGroups(c *GroupConfig, allowLocalTest bool) (*Groups, error) {
	if c == nil {
		return nil, errors.New("missing config")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/relay/v1/ws" || u.RawPath != "" || (u.Scheme != "wss" && !(allowLocalTest && u.Scheme == "ws" && u.Hostname() == "127.0.0.1")) {
		return nil, errors.New("WSS URL required")
	}
	scheme := "https"
	if u.Scheme == "ws" {
		scheme = "http"
	}
	return &Groups{Config: c, base: scheme + "://" + u.Host + "/relay/v1", local: allowLocalTest, client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}}, nil
}
func (g *Groups) call(method, path string, body any, auth string, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.base+path, r)
	if err != nil {
		return err
	}
	if auth == "" {
		auth = "Bearer " + g.Config.Token
	}
	req.Header.Set("Authorization", auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("group request failed (%d)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024+1))
	if err != nil {
		return err
	}
	if len(b) > 3*1024*1024 {
		return errors.New("response too large")
	}
	return json.Unmarshal(b, out)
}
func (g *Groups) own(name string) (GroupMember, error) {
	c := g.Config
	i, err := NewIdentity(c.App, c.Group, c.Device, c.SecretKey, nil)
	if err != nil {
		return GroupMember{}, err
	}
	key, err := decodeKey(c.SecretKey)
	if err != nil {
		return GroupMember{}, err
	}
	return GroupMember{Device: c.Device, Name: name, PublicKey: i.PublicKey(), SigningKey: hex.EncodeToString(groupSigningKey(key).Public().(ed25519.PublicKey))}, nil
}
func (g *Groups) token() error {
	if g.Config.Token == "" {
		token, err := groupRandom(32)
		if err != nil {
			return err
		}
		g.Config.Token = token
	}
	return nil
}
func (g *Groups) accept(e GroupEntry) error {
	s, err := groupState(e)
	if err != nil {
		return err
	}
	own, err := g.own(g.Config.Device)
	if err != nil {
		return err
	}
	g.Config.GroupEntry = &e
	g.Config.PublicKey = own.PublicKey
	g.Config.TrustedPeers = map[string]string{}
	for _, m := range s.Members {
		if m.Device != g.Config.Device {
			g.Config.TrustedPeers[m.Device] = m.PublicKey
		}
	}
	return nil
}

type GroupRefresh struct {
	State  GroupState `json:"state"`
	Online []string   `json:"online"`
}

func (g *Groups) Refresh() (GroupRefresh, error) {
	var ret GroupRefresh
	if g.Config.GroupEntry == nil {
		return ret, errors.New("group not enrolled")
	}
	current := *g.Config.GroupEntry
	for {
		s, err := groupState(current)
		if err != nil {
			return ret, err
		}
		var result struct {
			Entries  []GroupEntry `json:"entries"`
			Revision int          `json:"revision"`
			Online   []string     `json:"online"`
		}
		if err = g.call("GET", "/group?after="+strconv.Itoa(s.Revision), nil, "", &result); err != nil {
			return ret, err
		}
		for _, e := range result.Entries {
			if err = VerifyGroupAdvance(current, e); err != nil {
				return ret, err
			}
			current = e
		}
		if err = g.accept(current); err != nil {
			return ret, err
		}
		s, err = groupState(current)
		if err != nil {
			return ret, err
		}
		if len(result.Entries) == 0 || s.Revision >= result.Revision {
			return GroupRefresh{s, result.Online}, nil
		}
	}
}
func (g *Groups) PrepareCreate(groupName, deviceName string) error {
	c := g.Config
	if c.GroupEntry != nil || c.PendingJoin != nil {
		return errors.New("already enrolled")
	}
	if c.PendingCreate != nil {
		return nil
	}
	groupName = strings.TrimSpace(groupName)
	deviceName = strings.TrimSpace(deviceName)
	if len(groupName) == 0 || len(groupName) > 128 || len(deviceName) == 0 || len(deviceName) > 128 || c.Group != "" {
		return errors.New("invalid name or group")
	}
	id, err := groupRandom(16)
	if err != nil {
		return err
	}
	c.Group = "g-" + id
	if err = g.token(); err != nil {
		return err
	}
	own, err := g.own(deviceName)
	if err != nil {
		return err
	}
	own.Manager = true
	s := GroupState{Version: 1, App: c.App, Group: c.Group, Name: groupName, Revision: 1, Members: []GroupMember{own}}
	e, err := groupSign(s, c.SecretKey, c.Device)
	if err == nil {
		c.PendingCreate = &e
	}
	return err
}
func (g *Groups) Create() error {
	c := g.Config
	if c.PendingCreate == nil {
		return errors.New("creation not prepared")
	}
	var response any
	if err := g.call("POST", "/group/create", map[string]any{"entry": c.PendingCreate, "token_hash": groupDigest([]byte(c.Token))}, "", &response); err != nil {
		return err
	}
	if err := g.accept(*c.PendingCreate); err != nil {
		return err
	}
	c.PendingCreate = nil
	return nil
}

type GroupBootstrapCode struct {
	App       string `json:"app"`
	Group     string `json:"group"`
	Bootstrap string `json:"bootstrap"`
}

func (g *Groups) Bootstrap(code GroupBootstrapCode, name string) error {
	c := g.Config
	if code.App != c.App || code.Group != c.Group {
		return errors.New("bootstrap scope")
	}
	if err := g.token(); err != nil {
		return err
	}
	own, err := g.own(name)
	if err != nil {
		return err
	}
	own.Manager = true
	members := []GroupMember{own}
	for id, key := range c.TrustedPeers {
		if id != c.Device {
			members = append(members, GroupMember{Device: id, Name: id, PublicKey: key})
		}
	}
	e, err := groupSign(GroupState{Version: 1, App: c.App, Group: c.Group, Revision: 1, Members: members}, c.SecretKey, c.Device)
	if err != nil {
		return err
	}
	var out any
	if err = g.call("POST", "/group/bootstrap", map[string]any{"entry": e, "token_hash": groupDigest([]byte(c.Token))}, "Bootstrap "+code.Bootstrap, &out); err != nil {
		return err
	}
	return g.accept(e)
}
func (g *Groups) Invite(mode string, compact bool) (GroupInvitation, error) {
	var inv GroupInvitation
	if mode == "" {
		mode = "manual"
	}
	if mode != "manual" && mode != "auto" {
		return inv, errors.New("invalid invitation mode")
	}
	r, err := g.Refresh()
	if err != nil {
		return inv, err
	}
	own, ok := groupMember(r.State, g.Config.Device)
	if !ok || !own.Manager {
		return inv, errors.New("manager permission required")
	}
	secret, err := groupRandom(32)
	if err != nil {
		return inv, err
	}
	data := map[string]any{"secret_hash": groupDigest([]byte(secret))}
	var grant *GroupEntry
	delegate := ""
	if mode == "auto" {
		delegate, err = groupRandom(32)
		if err != nil {
			return inv, err
		}
		id, e := groupRandom(16)
		if e != nil {
			return inv, e
		}
		key, _ := decodeKey(delegate)
		raw, _ := groupBytes(*g.Config.GroupEntry)
		gr := GroupGrant{Version: 1, Purpose: "common-relay/admission/v1", Mode: "auto", App: r.State.App, Group: r.State.Group, Invitation: id, Expires: time.Now().Unix() + 600, SecretHash: data["secret_hash"].(string), DelegateKey: hex.EncodeToString(groupSigningKey(key).Public().(ed25519.PublicKey)), AnchorRevision: r.State.Revision, AnchorHash: groupDigest(raw)}
		signed, e := groupSign(gr, g.Config.SecretKey, g.Config.Device)
		if e != nil {
			return inv, e
		}
		grant = &signed
		data["mode"] = mode
		data["grant"] = grant
	}
	var result struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
		Mode    string `json:"mode"`
	}
	if err = g.call("POST", "/group/invitations", data, "", &result); err != nil {
		return inv, err
	}
	if grant != nil {
		var gr GroupGrant
		_ = groupDecode(*grant, payloadGrantSchema, &gr)
		if result.Mode != mode || result.ID != gr.Invitation || result.Expires != gr.Expires {
			return inv, errors.New("automatic admission unsupported")
		}
	}
	inv = GroupInvitation{Version: 1, Mode: mode, URL: g.Config.URL, App: g.Config.App, Group: g.Config.Group, ID: result.ID, Expires: result.Expires, Secret: secret, Manager: own, Grant: grant, DelegateSecret: delegate}
	if compact {
		var key [32]byte
		var nonce [24]byte
		if _, err = rand.Read(key[:]); err != nil {
			return inv, err
		}
		if _, err = rand.Read(nonce[:]); err != nil {
			return inv, err
		}
		packet, e := invitationSeal(inv, key, nonce)
		if e != nil {
			return inv, e
		}
		var response any
		if err = g.call("POST", "/group/invitations/"+inv.ID+"/link", map[string]any{"read_hash": groupDigest([]byte(invitationToken(key))), "packet": packet}, "", &response); err != nil {
			return inv, err
		}
		inv.ShortLink, err = invitationMakeLink(inv, key)
	}
	return inv, err
}
func (g *Groups) ResolveInvitation(text string) (GroupInvitation, error) {
	var inv GroupInvitation
	u, id, key, err := invitationParseLink(strings.TrimSpace(text), g.local)
	if err != nil {
		return inv, err
	}
	endpoint, err := NewGroups(&GroupConfig{URL: u}, g.local)
	if err != nil {
		return inv, err
	}
	var result struct {
		Version int    `json:"version"`
		Packet  string `json:"packet"`
	}
	if err = endpoint.call("GET", "/enroll/"+id+"/link", nil, "InvitationLink "+invitationToken(key), &result); err != nil {
		return inv, err
	}
	if result.Version != 1 {
		return inv, errors.New("invalid packet version")
	}
	inv, err = invitationOpen(result.Packet, key)
	if err != nil {
		return inv, err
	}
	if inv.Version != 1 || inv.URL != u || inv.ID != id || inv.App != g.Config.App || inv.Expires <= time.Now().Unix() {
		return inv, errors.New("invitation scope mismatch")
	}
	return inv, nil
}

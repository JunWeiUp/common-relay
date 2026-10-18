package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func groupSigned(t *testing.T, v any, id string, sk ed25519.PrivateKey) SignedEntry {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return SignedEntry{Payload: base64.StdEncoding.EncodeToString(b), Signer: id, Signature: hex.EncodeToString(ed25519.Sign(sk, b))}
}
func groupRequest(t *testing.T, f *fixture, method, path, auth string, value any) (int, []byte) {
	t.Helper()
	var body []byte
	if value != nil {
		body, _ = json.Marshal(value)
	}
	req, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", auth)
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Error(e)
		return 0, nil
	}
	defer res.Body.Close()
	data, e := io.ReadAll(res.Body)
	if e != nil {
		t.Error(e)
	}
	return res.StatusCode, data
}
func TestGroupPermissionsConcurrentApprovalAndRevocation(t *testing.T) {
	f := setup(t)
	pk, sk, _ := ed25519.GenerateKey(nil)
	token := RandomID() + RandomID()
	secret := RandomID() + RandomID()
	m := Member{Device: "manager", Name: "Manager", PublicKey: strings.Repeat("01", 32), SigningKey: hex.EncodeToString(pk), Manager: true}
	g := GroupState{Version: 1, App: "example", Group: "test", Revision: 1, Members: []Member{m}}
	initial := groupSigned(t, g, m.Device, sk)
	if e := f.s.Store.GroupBootstrap(g.App, g.Group, secret); e != nil {
		t.Fatal(e)
	}
	input := map[string]any{"entry": initial, "token_hash": hashToken(token)}
	status, _ := groupRequest(t, f, "POST", "/relay/v1/group/bootstrap", "Bootstrap "+secret, input)
	if status != 200 {
		t.Fatalf("bootstrap: %d", status)
	}
	status, _ = groupRequest(t, f, "POST", "/relay/v1/group/bootstrap", "Bootstrap "+secret, input)
	if status != 200 {
		t.Fatalf("idempotent bootstrap: %d", status)
	}
	if f.s.Store.AddDevice(Device{App: g.App, Group: g.Group, ID: "bypass", PublicKey: m.PublicKey}, RandomID()+RandomID()) == nil {
		t.Fatal("CLI bypassed signed group")
	}
	f.tokens[m.Device] = token
	type candidate struct {
		state         GroupState
		entry         SignedEntry
		device, token string
	}
	candidates := []candidate{}
	for _, id := range []string{"phone-a", "phone-b"} {
		invitationSecret := RandomID() + RandomID()
		status, data := groupRequest(t, f, "POST", "/relay/v1/group/invitations", "Bearer "+token, map[string]string{"secret_hash": hashToken(invitationSecret)})
		if status != 200 {
			t.Fatal(status)
		}
		var invitation struct {
			ID string `json:"id"`
		}
		json.Unmarshal(data, &invitation)
		p, k, _ := ed25519.GenerateKey(nil)
		newToken := RandomID() + RandomID()
		j := JoinRequest{Version: 1, App: g.App, Group: g.Group, Invitation: invitation.ID, TokenHash: hashToken(newToken), Member: Member{Device: id, Name: id, PublicKey: strings.Repeat("02", 32), SigningKey: hex.EncodeToString(p)}}
		request := groupSigned(t, j, id, k)
		status, _ = groupRequest(t, f, "POST", "/relay/v1/enroll/"+invitation.ID, "Invitation "+invitationSecret, request)
		if status != 200 {
			t.Fatal(status)
		}
		raw, _ := request.bytes()
		prior, _ := initial.bytes()
		next := g
		next.Revision = 2
		next.Previous = digest(prior)
		next.Members = append([]Member{m}, j.Member)
		next.Invitation = invitation.ID
		next.RequestHash = digest(raw)
		candidates = append(candidates, candidate{next, groupSigned(t, next, m.Device, sk), id, newToken})
	}
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := range candidates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i], _ = groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+token, candidates[i].entry)
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, s := range statuses {
		if s == 200 {
			if winner >= 0 {
				t.Fatal("both stale revisions committed")
			}
			winner = i
		} else if s != 409 {
			t.Fatalf("unexpected status %d", s)
		}
	}
	if winner < 0 {
		t.Fatal(statuses)
	}
	c := candidates[winner]
	f.tokens[c.device] = c.token
	ws := f.dial(c.device)
	status, _ = groupRequest(t, f, "POST", "/relay/v1/group/invitations", "Bearer "+c.token, map[string]string{"secret_hash": strings.Repeat("ab", 32)})
	if status != 403 {
		t.Fatalf("member invited: %d", status)
	}
	wrong := c.state
	wrong.App = "other"
	status, _ = groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+token, groupSigned(t, wrong, m.Device, sk))
	if status != 403 {
		t.Fatalf("cross-app: %d", status)
	}
	remove := g
	remove.Revision = 3
	b, _ := c.entry.bytes()
	remove.Previous = digest(b)
	status, _ = groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+token, groupSigned(t, remove, m.Device, sk))
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = groupRequest(t, f, "GET", "/relay/v1/group", "Bearer "+c.token, nil)
	if status != 401 {
		t.Fatalf("revoked token: %d", status)
	}
	// The revoked socket must be cancelled without waiting for the 1 s heartbeat.
	f.s.mu.Lock()
	peer := f.s.peers[key(Device{App: g.App, Group: g.Group, ID: c.device})]
	f.s.mu.Unlock()
	if peer != nil {
		select {
		case <-peer.ctx.Done():
		default:
			t.Fatal("revoked socket not cancelled")
		}
	}
	ws.CloseNow()
	status, _ = groupRequest(t, f, "PUT", "/relay/v1/group", "Bearer "+token, c.entry)
	if status != 409 {
		t.Fatalf("rollback: %d", status)
	}
}

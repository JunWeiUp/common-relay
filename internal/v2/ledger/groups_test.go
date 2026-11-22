package ledger

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
	status, _ := groupRequest(t, f, "POST", "/v2/group/bootstrap", "Bootstrap "+secret, input)
	if status != 200 {
		t.Fatalf("bootstrap: %d", status)
	}
	status, _ = groupRequest(t, f, "POST", "/v2/group/bootstrap", "Bootstrap "+secret, input)
	if status != 200 {
		t.Fatalf("idempotent bootstrap: %d", status)
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
		status, data := groupRequest(t, f, "POST", "/v2/group/invitations", "Bearer "+token, map[string]string{"secret_hash": hashToken(invitationSecret)})
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
		status, _ = groupRequest(t, f, "POST", "/v2/enroll/"+invitation.ID, "Invitation "+invitationSecret, request)
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
			statuses[i], _ = groupRequest(t, f, "PUT", "/v2/group", "Bearer "+token, candidates[i].entry)
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
	status, _ = groupRequest(t, f, "POST", "/v2/group/invitations", "Bearer "+c.token, map[string]string{"secret_hash": strings.Repeat("ab", 32)})
	if status != 403 {
		t.Fatalf("member invited: %d", status)
	}
	wrong := c.state
	wrong.App = "other"
	status, _ = groupRequest(t, f, "PUT", "/v2/group", "Bearer "+token, groupSigned(t, wrong, m.Device, sk))
	if status != 403 {
		t.Fatalf("cross-app: %d", status)
	}
	remove := g
	remove.Revision = 3
	b, _ := c.entry.bytes()
	remove.Previous = digest(b)
	status, _ = groupRequest(t, f, "PUT", "/v2/group", "Bearer "+token, groupSigned(t, remove, m.Device, sk))
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = groupRequest(t, f, "GET", "/v2/group", "Bearer "+c.token, nil)
	if status != 401 {
		t.Fatalf("revoked token: %d", status)
	}
	// The removal reached the v2 space in the same commit and the live session was dropped.
	var members, revoked int
	f.s.Store.DB.QueryRow("SELECT count(*) FROM v2_space_members WHERE space_id='test'").Scan(&members)
	f.s.Store.DB.QueryRow("SELECT revoked FROM v2_devices WHERE id=?", c.device).Scan(&revoked)
	f.hub.mu.Lock()
	notified, disconnected := strings.Join(f.hub.notified, ","), strings.Join(f.hub.disconnected, ",")
	f.hub.mu.Unlock()
	if members != 1 || revoked != 1 || disconnected != c.device || !strings.HasSuffix(notified, "test@3") {
		t.Fatalf("v2 space after removal: members=%d revoked=%d disconnected=%q notified=%q", members, revoked, disconnected, notified)
	}
	status, _ = groupRequest(t, f, "PUT", "/v2/group", "Bearer "+token, c.entry)
	if status != 409 {
		t.Fatalf("rollback: %d", status)
	}
}

// Invitation links and automatic admission are reachable on the /v2 paths only.
func TestInvitationLinkAndAutoRoutesOverV2(t *testing.T) {
	f := setup(t)
	pk, sk, _ := ed25519.GenerateKey(nil)
	token, secret := RandomID()+RandomID(), RandomID()+RandomID()
	m := Member{Device: "manager", Name: "Manager", PublicKey: strings.Repeat("01", 32), SigningKey: hex.EncodeToString(pk), Manager: true}
	g := GroupState{Version: 1, App: "example", Group: "links", Revision: 1, Members: []Member{m}}
	if err := f.s.Store.GroupBootstrap(g.App, g.Group, secret); err != nil {
		t.Fatal(err)
	}
	if status, _ := groupRequest(t, f, "POST", "/v2/group/bootstrap", "Bootstrap "+secret, map[string]any{"entry": groupSigned(t, g, m.Device, sk), "token_hash": hashToken(token)}); status != 200 {
		t.Fatalf("bootstrap: %d", status)
	}
	status, data := groupRequest(t, f, "POST", "/v2/group/invitations", "Bearer "+token, map[string]string{"secret_hash": hashToken(RandomID())})
	if status != 200 {
		t.Fatalf("invite: %d", status)
	}
	var inv struct {
		ID string `json:"id"`
	}
	json.Unmarshal(data, &inv)
	read := RandomID() + RandomID()
	packet := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 48))
	if status, body := groupRequest(t, f, "POST", "/v2/group/invitations/"+inv.ID+"/link", "Bearer "+token, map[string]string{"read_hash": hashToken(read), "packet": packet}); status != 200 {
		t.Fatalf("publish link: %d %s", status, body)
	}
	status, data = groupRequest(t, f, "GET", "/v2/enroll/"+inv.ID+"/link", "InvitationLink "+read, nil)
	var got struct {
		Packet string `json:"packet"`
	}
	if json.Unmarshal(data, &got); status != 200 || got.Packet != packet {
		t.Fatalf("read link: %d %s", status, data)
	}
	// A manual invitation has no admission grant: the auto handler answers, not the mux.
	status, data = groupRequest(t, f, "GET", "/v2/enroll/"+inv.ID+"/auto", "Claim "+RandomID(), nil)
	if status != 404 || !strings.Contains(string(data), "not found or expired") {
		t.Fatalf("auto route: %d %s", status, data)
	}
	if status, _ := groupRequest(t, f, "GET", "/relay/v1/enroll/"+inv.ID+"/link", "InvitationLink "+read, nil); status != 404 {
		t.Fatalf("v1 path still served: %d", status)
	}
	if status, _ := groupRequest(t, f, "GET", "/v2/group", "Bearer "+token, nil); status != 200 {
		t.Fatalf("group list: %d", status)
	}
}

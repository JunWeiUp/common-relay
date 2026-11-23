package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	v2server "github.com/JunWeiUp/common-relay/internal/v2/server"
	"github.com/coder/websocket"
)

// legacySchema is the relay.db DDL of the last release with two stores
// (internal/relay/store.go and groups.go initGroups), plus one table of the
// removed v1 transport that existing databases still carry.
const legacySchema = `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS devices(app TEXT NOT NULL, grp TEXT NOT NULL, id TEXT NOT NULL, token TEXT UNIQUE NOT NULL, public_key TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(app,grp,id));
 CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,size INTEGER NOT NULL,offset INTEGER NOT NULL DEFAULT 0,metadata TEXT NOT NULL,digest TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'uploading',expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS group_creations(app TEXT NOT NULL,grp TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(app,grp));
 CREATE TABLE IF NOT EXISTS group_entries(app TEXT NOT NULL,grp TEXT NOT NULL,revision INTEGER NOT NULL,entry TEXT NOT NULL,PRIMARY KEY(app,grp,revision));
 CREATE TABLE IF NOT EXISTS group_bootstrap(token_hash TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS group_invites(id TEXT PRIMARY KEY,app TEXT NOT NULL,grp TEXT NOT NULL,owner TEXT NOT NULL,secret_hash TEXT NOT NULL,expires INTEGER NOT NULL,request TEXT NOT NULL DEFAULT '',token_hash TEXT NOT NULL DEFAULT '',approved TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS group_invite_grants(id TEXT PRIMARY KEY REFERENCES group_invites(id) ON DELETE CASCADE,grant_entry TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS group_invite_links(id TEXT PRIMARY KEY REFERENCES group_invites(id) ON DELETE CASCADE,read_hash TEXT NOT NULL,packet TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, body TEXT);`

type legacyDevice struct {
	app, group, id, token, pub string
	revoked                    bool
}

type legacyFixture struct {
	dir      string
	devices  []legacyDevice
	heads    map[string]string // app/group → latest entry JSON
	adminTok string
	fileID   string
	payload  []byte // full plaintext-sized ciphertext of the pending file
	dbSum    [32]byte
}

func legacyKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pk), sk
}

// buildLegacy writes a relay.db (old schema) and files/ payload, and the
// relay_v2.db rows the old binary's projection had created, into a data dir.
func buildLegacy(t *testing.T) *legacyFixture {
	t.Helper()
	fx := &legacyFixture{dir: t.TempDir(), heads: map[string]string{}}
	db, err := sql.Open("sqlite", filepath.Join(fx.dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	put := func(app, group string, revision int, e SignedEntry) {
		raw, _ := json.Marshal(e)
		if _, err := db.Exec("INSERT INTO group_entries VALUES(?,?,?,?)", app, group, revision, string(raw)); err != nil {
			t.Fatal(err)
		}
		fx.heads[app+"/"+group] = string(raw)
	}
	dev := func(d legacyDevice) {
		rev := 0
		if d.revoked {
			rev = 1
		}
		if _, err := db.Exec("INSERT INTO devices(app,grp,id,token,public_key,revoked) VALUES(?,?,?,?,?,?)", d.app, d.group, d.id, hashToken(d.token), d.pub, rev); err != nil {
			t.Fatal(err)
		}
		fx.devices = append(fx.devices, d)
	}
	pub := func(b string) string { return strings.Repeat(b, 32) }

	// app-a/g-…: manager desktop + phone joined (rev 2), tablet joined then removed (rev 3, revoked).
	appAGroup := "g-0123456789abcdef0123456789abcdef"
	deskSign, deskKey := legacyKey(t)
	desk := Member{Device: "desktop", Name: "Desktop", PublicKey: pub("01"), SigningKey: deskSign, Manager: true}
	phone := Member{Device: "phone", Name: "Phone", PublicKey: pub("02")}
	tablet := Member{Device: "tablet", Name: "Tablet", PublicKey: pub("03")}
	g := GroupState{Name: "My Devices", Version: 1, App: "app-a", Group: appAGroup, Revision: 1, Members: []Member{desk}}
	e1 := groupSigned(t, g, "desktop", deskKey)
	put("app-a", appAGroup, 1, e1)
	b1, _ := e1.bytes()
	g2 := g
	g2.Revision, g2.Previous, g2.Members = 2, digest(b1), []Member{desk, phone, tablet}
	e2 := groupSigned(t, g2, "desktop", deskKey)
	put("app-a", appAGroup, 2, e2)
	b2, _ := e2.bytes()
	g3 := g2
	g3.Revision, g3.Previous, g3.Members = 3, digest(b2), []Member{desk, phone}
	put("app-a", appAGroup, 3, groupSigned(t, g3, "desktop", deskKey))
	if _, err := db.Exec("INSERT INTO group_creations VALUES('app-a',?,?)", appAGroup, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	dev(legacyDevice{"app-a", appAGroup, "desktop", RandomID() + RandomID(), desk.PublicKey, false})
	dev(legacyDevice{"app-a", appAGroup, "phone", RandomID() + RandomID(), phone.PublicKey, false})
	dev(legacyDevice{"app-a", appAGroup, "tablet", RandomID() + RandomID(), tablet.PublicKey, true})

	// app-b/production: same device ID "desktop" as in app-a (per-group credential),
	// plus a member whose ID collides with the admin device.
	bSign, bKey := legacyKey(t)
	bDesk := Member{Device: "desktop", Name: "AppB Desktop", PublicKey: pub("04"), SigningKey: bSign, Manager: true}
	bHub := Member{Device: "hub-host", Name: "Hub", PublicKey: pub("05")}
	cg := GroupState{Version: 1, App: "app-b", Group: "production", Revision: 1, Members: []Member{bDesk, bHub}}
	put("app-b", "production", 1, groupSigned(t, cg, "desktop", bKey))
	dev(legacyDevice{"app-b", "production", "desktop", RandomID() + RandomID(), bDesk.PublicKey, false})
	dev(legacyDevice{"app-b", "production", "hub-host", RandomID() + RandomID(), bHub.PublicKey, false})

	// app-c/closed: disbanded group, every credential revoked.
	cSign, cKey := legacyKey(t)
	cm := Member{Device: "pc", Name: "PC", PublicKey: pub("06"), SigningKey: cSign, Manager: true}
	wg := GroupState{Version: 1, App: "app-c", Group: "closed", Revision: 1, Members: []Member{cm}}
	w1 := groupSigned(t, wg, "pc", cKey)
	put("app-c", "closed", 1, w1)
	wb, _ := w1.bytes()
	wg2 := wg
	wg2.Revision, wg2.Previous, wg2.Members, wg2.Closed = 2, digest(wb), []Member{}, true
	put("app-c", "closed", 2, groupSigned(t, wg2, "pc", cKey))
	dev(legacyDevice{"app-c", "closed", "pc", RandomID() + RandomID(), cm.PublicKey, true})

	// legacy-svc/old: a pre-ledger group (credentials only, no signed entries).
	dev(legacyDevice{"legacy-svc", "old", "box", RandomID() + RandomID(), pub("07"), false})
	dev(legacyDevice{"legacy-svc", "old", "laptop", RandomID() + RandomID(), pub("08"), false})

	// A pending invitation with a grant and link, and an unused bootstrap.
	if _, err := db.Exec(`INSERT INTO group_invites(id,app,grp,owner,secret_hash,expires) VALUES(?,?,?,?,?,?);
		INSERT INTO group_invite_grants VALUES(?,'{}'); INSERT INTO group_invite_links VALUES(?,?,'cipher');
		INSERT INTO group_bootstrap VALUES(?,?,?,?); INSERT INTO messages VALUES('m1','old v1 message')`,
		strings.Repeat("a", 32), "app-a", appAGroup, "desktop", hashToken("secret"), time.Now().Add(time.Hour).Unix(),
		strings.Repeat("a", 32), strings.Repeat("a", 32), hashToken("read"),
		hashToken("bootstrap"), "demo-app", "home", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	// A pending file: desktop → phone, 5 of 10 bytes uploaded.
	fx.payload = []byte("0123456789")
	sum := sha256.Sum256(fx.payload)
	fx.fileID = RandomID()
	if _, err := db.Exec("INSERT INTO files(id,app,grp,sender,recipient,size,offset,metadata,digest,expires) VALUES(?,?,?,?,?,?,?,?,?,?)",
		fx.fileID, "app-a", appAGroup, "desktop", "phone", len(fx.payload), 5, "cipher-meta", hex.EncodeToString(sum[:]), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fx.dir, "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.dir, "files", fx.fileID), fx.payload[:5], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// relay_v2.db as the previous binary left it: admin device + admin space, and
	// the projected spaces/devices of the open signed groups.
	v2, err := core.OpenStore(fx.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, fx.adminTok, err = v2.CreateDevice("hub-host", "Hub (admin)", pub("aa"), true); err != nil {
		t.Fatal(err)
	}
	if _, err = v2.CreateSpace("personal", "Personal", core.TrustBridgeAllowed); err != nil {
		t.Fatal(err)
	}
	tok := func(app, group, id string) string {
		for _, d := range fx.devices {
			if d.app == app && d.group == group && d.id == id {
				return hashToken(d.token)
			}
		}
		t.Fatalf("no device %s/%s/%s", app, group, id)
		return ""
	}
	if err := v2.SyncManagedGroupWithApp(appAGroup, "app-a", "My Devices", []core.ManagedMember{
		{ID: "desktop", Name: "Desktop", PublicKey: desk.PublicKey, TokenHash: tok("app-a", appAGroup, "desktop"), Manager: true},
		{ID: "phone", Name: "Phone", PublicKey: phone.PublicKey, TokenHash: tok("app-a", appAGroup, "phone")},
	}, []string{"tablet"}, false); err != nil {
		t.Fatal(err)
	}
	// "desktop" of app-b collides with app-a's projected "desktop", "hub-host" with
	// the admin device: the old projection skipped both, and so must the import.
	if err := v2.SyncManagedGroupWithApp("production", "app-b", "", []core.ManagedMember{
		{ID: "desktop", Name: "AppB Desktop", PublicKey: bDesk.PublicKey, TokenHash: tok("app-b", "production", "desktop"), Manager: true},
		{ID: "hub-host", Name: "Hub", PublicKey: bHub.PublicKey, TokenHash: tok("app-b", "production", "hub-host")},
	}, nil, false); err != nil {
		t.Fatal(err)
	}
	v2.Close()
	raw, err := os.ReadFile(filepath.Join(fx.dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	fx.dbSum = sha256.Sum256(raw)
	return fx
}

func (fx *legacyFixture) token(app, group, id string) string {
	for _, d := range fx.devices {
		if d.app == app && d.group == group && d.id == id {
			return d.token
		}
	}
	return ""
}

func countRows(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestLegacyImportPreservesLedgerDevicesAndFiles(t *testing.T) {
	fx := buildLegacy(t)
	v2, err := core.OpenStore(fx.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	st, err := Open(v2)
	if err != nil {
		t.Fatal(err)
	}
	v2DevicesBefore := countRows(t, v2.DB, "SELECT count(*) FROM v2_devices")
	res, err := st.ImportLegacy()
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped || res.Groups != 3 || res.Entries != 6 || res.Devices != len(fx.devices) || res.Invites != 1 || res.Files != 1 || res.Payloads != 1 {
		t.Fatalf("import result = %+v", res)
	}

	// Identical ledger heads.
	for key, want := range fx.heads {
		app, group, _ := strings.Cut(key, "/")
		var got string
		if err := v2.DB.QueryRow("SELECT entry FROM v2_ledger_entries WHERE app=? AND grp=? ORDER BY revision DESC LIMIT 1", app, group).Scan(&got); err != nil || got != want {
			t.Fatalf("head %s: %v\n got %s\nwant %s", key, err, got, want)
		}
	}
	rep, err := st.Check()
	if err != nil || len(rep.Problems) != 0 || rep.Groups != 3 || rep.Entries != 6 || !rep.Imported || rep.Files != 1 {
		t.Fatalf("check = %+v %v", rep, err)
	}

	// No duplicate v2 devices; admin device untouched.
	if n := countRows(t, v2.DB, "SELECT count(*) FROM v2_devices"); n != v2DevicesBefore {
		t.Fatalf("v2_devices %d → %d", v2DevicesBefore, n)
	}
	var adminName, adminHash string
	var isAdmin, revoked int
	if err := v2.DB.QueryRow("SELECT name, token_hash, is_admin, revoked FROM v2_devices WHERE id='hub-host'").Scan(&adminName, &adminHash, &isAdmin, &revoked); err != nil {
		t.Fatal(err)
	}
	if adminName != "Hub (admin)" || adminHash != core.HashSecret(fx.adminTok) || isAdmin != 1 || revoked != 0 {
		t.Fatalf("admin device changed: %s %d %d", adminName, isAdmin, revoked)
	}
	if n := countRows(t, v2.DB, "SELECT count(*) FROM v2_space_members WHERE space_id='personal'"); n != 0 {
		t.Fatalf("admin space touched: %d members", n)
	}
	// relay.db is a backup now: byte-for-byte unchanged, legacy payload kept.
	raw, _ := os.ReadFile(filepath.Join(fx.dir, "relay.db"))
	if sha256.Sum256(raw) != fx.dbSum {
		t.Fatal("relay.db modified by the import")
	}
	if _, err := os.Stat(filepath.Join(fx.dir, "files", fx.fileID)); err != nil {
		t.Fatal("legacy payload moved:", err)
	}

	// Serve the merged store the way main does.
	srv := New(st)
	srv.DiskReserve = 0
	v2srv := v2server.New(v2, v2server.Config{})
	srv.Hub = v2srv.Pipe
	mux := http.NewServeMux()
	for _, p := range []string{"/v2/group", "/v2/group/", "/v2/enroll/", "/v2/files", "/v2/files/"} {
		mux.Handle(p, srv.Handler())
	}
	mux.Handle("/", v2srv.Handler())
	ts := httptest.NewServer(mux)
	defer ts.Close()
	do := func(method, path, token string, body []byte, hdr map[string]string) (int, []byte) {
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b
	}
	ws := func(token string) int {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/v2/ws", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
		if err != nil {
			if resp != nil {
				return resp.StatusCode
			}
			t.Fatal(err)
		}
		c.CloseNow()
		return 101
	}
	appAGroup := "g-0123456789abcdef0123456789abcdef"
	for _, id := range []string{"desktop", "phone"} {
		tok := fx.token("app-a", appAGroup, id)
		if code := ws(tok); code != 101 {
			t.Fatalf("%s on /v2/ws: %d", id, code)
		}
		code, body := do("GET", "/v2/group", tok, nil, nil)
		var list struct {
			Revision int `json:"revision"`
		}
		if json.Unmarshal(body, &list); code != 200 || list.Revision != 3 {
			t.Fatalf("%s /v2/group: %d %s", id, code, body)
		}
	}
	// Revoked credentials stay revoked on both planes.
	for _, d := range [][3]string{{"app-a", appAGroup, "tablet"}, {"app-c", "closed", "pc"}} {
		tok := fx.token(d[0], d[1], d[2])
		if code, _ := do("GET", "/v2/group", tok, nil, nil); code != 401 {
			t.Fatalf("revoked %v on /v2/group: %d", d, code)
		}
		if code := ws(tok); code != 401 {
			t.Fatalf("revoked %v on /v2/ws: %d", d, code)
		}
	}
	// A credential whose ID collided in v2_devices still works on the ledger planes.
	if code, _ := do("GET", "/v2/group", fx.token("app-b", "production", "hub-host"), nil, nil); code != 200 {
		t.Fatalf("collided member on /v2/group: %d", code)
	}
	if code := ws(fx.adminTok); code != 101 {
		t.Fatalf("admin device on /v2/ws: %d", code)
	}
	// Pre-ledger credentials keep their file plane.
	if code, _ := do("GET", "/v2/files", fx.token("legacy-svc", "old", "box"), nil, nil); code != 200 {
		t.Fatalf("pre-ledger device on /v2/files: %d", code)
	}

	// The pending upload resumes at its offset, commits and downloads.
	deskTok, phone := fx.token("app-a", appAGroup, "desktop"), fx.token("app-a", appAGroup, "phone")
	if code, body := do("PUT", "/v2/files/"+fx.fileID+"/data", deskTok, fx.payload[5:], map[string]string{"Upload-Offset": "5"}); code != 200 {
		t.Fatalf("resume: %d %s", code, body)
	}
	if code, body := do("POST", "/v2/files/"+fx.fileID+"/commit", deskTok, nil, nil); code != 200 {
		t.Fatalf("commit: %d %s", code, body)
	}
	if code, body := do("GET", "/v2/files/"+fx.fileID+"/data", phone, nil, nil); code != 200 || !bytes.Equal(body, fx.payload) {
		t.Fatalf("download: %d %q", code, body)
	}
	if used, _ := st.UsedBytes(); used != int64(len(fx.payload)) {
		t.Fatalf("ledger bytes = %d", used)
	}
	if n := countRows(t, v2.DB, "SELECT COALESCE(SUM(bytes),0) FROM v2_usage WHERE space_id=?", appAGroup); n != len(fx.payload) {
		t.Fatalf("v2_usage for %s = %d", appAGroup, n)
	}

	// Re-import is a no-op, also after a restart.
	again, err := st.ImportLegacy()
	if err != nil || !again.Skipped {
		t.Fatalf("re-import: %+v %v", again, err)
	}
	if n := countRows(t, v2.DB, "SELECT count(*) FROM v2_ledger_devices"); n != len(fx.devices) {
		t.Fatalf("devices after re-import: %d", n)
	}
	if code, _ := do("DELETE", "/v2/files/"+fx.fileID, phone, nil, nil); code != 204 {
		t.Fatal("delete", code)
	}
	if n := countRows(t, v2.DB, "SELECT COALESCE(SUM(bytes),0) FROM v2_usage WHERE space_id=?", appAGroup); n != 0 {
		t.Fatalf("v2_usage after delete = %d", n)
	}
}

func TestLegacyImportRollsBackOnFailure(t *testing.T) {
	fx := buildLegacy(t)
	v2, err := core.OpenStore(fx.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	st, err := Open(v2)
	if err != nil {
		t.Fatal(err)
	}
	// A conflicting row makes the copy fail after devices were already inserted.
	if _, err := v2.DB.Exec("INSERT INTO v2_ledger_entries VALUES('app-c','closed',2,'{}')"); err != nil {
		t.Fatal(err)
	}
	var spacesBefore, devicesBefore string
	v2.DB.QueryRow("SELECT group_concat(id||':'||name, ',') FROM (SELECT id, name FROM v2_spaces ORDER BY id)").Scan(&spacesBefore)
	v2.DB.QueryRow("SELECT group_concat(id||':'||token_hash||':'||revoked, ',') FROM (SELECT * FROM v2_devices ORDER BY id)").Scan(&devicesBefore)
	if _, err := st.ImportLegacy(); err == nil {
		t.Fatal("conflicting import succeeded")
	}
	for q, want := range map[string]int{
		"SELECT count(*) FROM v2_ledger_devices":                                   0,
		"SELECT count(*) FROM v2_ledger_entries":                                   1,
		"SELECT count(*) FROM v2_ledger_files":                                     0,
		"SELECT count(*) FROM v2_ledger_invites":                                   0,
		"SELECT COALESCE(SUM(bytes),0) FROM v2_usage":                              0,
		"SELECT count(*) FROM v2_settings WHERE key='" + LegacyImportSetting + "'": 0,
	} {
		if n := countRows(t, v2.DB, q); n != want {
			t.Fatalf("%s = %d, want %d", q, n, want)
		}
	}
	var spacesAfter, devicesAfter string
	v2.DB.QueryRow("SELECT group_concat(id||':'||name, ',') FROM (SELECT id, name FROM v2_spaces ORDER BY id)").Scan(&spacesAfter)
	v2.DB.QueryRow("SELECT group_concat(id||':'||token_hash||':'||revoked, ',') FROM (SELECT * FROM v2_devices ORDER BY id)").Scan(&devicesAfter)
	if spacesAfter != spacesBefore || devicesAfter != devicesBefore {
		t.Fatal("v2 rows changed by a failed import")
	}
	if entries, _ := os.ReadDir(FilesDir(fx.dir)); len(entries) != 0 {
		t.Fatalf("payload copies left behind: %d", len(entries))
	}
	// After the operator fixes the conflict the import succeeds.
	if _, err := v2.DB.Exec("DELETE FROM v2_ledger_entries"); err != nil {
		t.Fatal(err)
	}
	if res, err := st.ImportLegacy(); err != nil || res.Skipped {
		t.Fatalf("retry: %+v %v", res, err)
	}
}

func TestImportWithoutLegacyDatabaseIsNoop(t *testing.T) {
	v2, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	st, err := Open(v2)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := st.ImportLegacy(); err != nil || !res.Skipped || st.imported() {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestCheckReportsBrokenChain(t *testing.T) {
	f := setup(t)
	pkHex, sk := legacyKey(t)
	m := Member{Device: "m", Name: "M", PublicKey: strings.Repeat("01", 32), SigningKey: pkHex, Manager: true}
	g := GroupState{Version: 1, App: "example", Group: "chain", Revision: 1, Members: []Member{m}}
	e1 := groupSigned(t, g, "m", sk)
	g3 := g
	g3.Revision, g3.Previous = 3, strings.Repeat("00", 32)
	e3 := groupSigned(t, g3, "m", sk)
	for rev, e := range map[int]SignedEntry{1: e1, 3: e3} {
		raw, _ := json.Marshal(e)
		if _, err := f.s.Store.DB.Exec("INSERT INTO v2_ledger_entries VALUES('example','chain',?,?)", rev, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := f.s.Store.Check()
	if err != nil || len(rep.Problems) != 2 {
		t.Fatalf("problems = %+v %v", rep.Problems, err)
	}
	for _, p := range rep.Problems {
		if p.Where != "example/chain@3" {
			t.Fatalf("unexpected problem %+v", p)
		}
	}
}

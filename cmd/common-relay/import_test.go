package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
)

func TestImportV1RoutesIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	st, err := v2core.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSpace("personal", "P", v2core.TrustBridgeAllowed); err != nil {
		t.Fatal(err)
	}
	st.Close()

	hook := filepath.Join(dir, "hooks.json")
	dav := filepath.Join(dir, "dav.json")
	tokHash := v2core.HashSecret(strings.Repeat("t", 40))
	os.WriteFile(hook, []byte(`[{"route":"demo-hook","app":"a","group":"g","sender":"s","recipient":"r","token_sha256":"`+tokHash+`",
		"secret_key":"x","recipient_public_key":"y","signature":{"secret":"0123456789abcdef0123","timestamp_header":"X-Ts","signature_header":"X-Sig"}}]`), 0o600)
	os.WriteFile(dav, []byte(`[{"route":"bills","app":"a","group":"g","sender":"s","recipient":"r","username":"bills-phone",
		"password_sha256":"`+v2core.HashSecret("pw")+`","secret_key":"x","recipient_public_key":"y"}]`), 0o600)

	for i := 0; i < 2; i++ {
		if err := importV1(dir, hook, dav, "personal", "", false); err != nil {
			t.Fatalf("import #%d: %v", i, err)
		}
	}
	st, err = v2core.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.DB.Query(`SELECT plugin_id, mount FROM v2_plugin_bindings ORDER BY plugin_id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var p, m string
		rows.Scan(&p, &m)
		got = append(got, p+"/"+m)
	}
	rows.Close()
	if strings.Join(got, ",") != "webdav/bills,webhook/demo-hook" {
		t.Fatalf("bindings = %v", got)
	}
	var n int
	st.DB.QueryRow(`SELECT count(*) FROM v2_plugin_accounts`).Scan(&n)
	if n != 1 {
		t.Fatalf("accounts = %d", n)
	}

	// World-readable configs are refused.
	os.Chmod(hook, 0o644)
	if err := importV1(dir, hook, "", "personal", "", true); err == nil {
		t.Fatal("expected permission error")
	}
}

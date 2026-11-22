package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/JunWeiUp/common-relay/internal/relay"
	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
	v2drop "github.com/JunWeiUp/common-relay/internal/v2/plugins/drop"
	v2mcp "github.com/JunWeiUp/common-relay/internal/v2/plugins/mcpedge"
	v2webdav "github.com/JunWeiUp/common-relay/internal/v2/plugins/webdav"
	v2webhook "github.com/JunWeiUp/common-relay/internal/v2/plugins/webhook"
	v2server "github.com/JunWeiUp/common-relay/internal/v2/server"
)

// importV1 converts v1 --webhook-config / --webdav-config routes into v2 plugin
// bindings on one space. It is idempotent (existing bindings are merged, not
// replaced) and never deletes v1 configuration: run both side by side, move
// clients to /edge/... URLs, then drop the v1 flags.
//
// v1 bridges encrypted each payload for one pinned recipient device; v2 bridges
// store plaintext in a bridge_allowed space unless --seal-public-key is given,
// in which case payloads are sealed (crs1) for that consumer key.
func importV1(dir, webhookFile, webdavFile, space, sealKey string, dry bool) error {
	if webhookFile == "" && webdavFile == "" {
		return errors.New("import-v1: pass --webhook-config and/or --webdav-config")
	}
	if !v2core.ValidIdent(space) {
		return errors.New("import-v1: --space is required")
	}
	st, err := v2core.OpenStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.GetSpace(space); err != nil {
		return fmt.Errorf("import-v1: space %q: %w (create it first via /v2/admin/spaces)", space, err)
	}
	srv := v2server.New(st, v2server.Config{})
	for _, p := range []plugin.Plugin{v2drop.New(), v2webhook.New(), v2webdav.New(), v2mcp.New()} {
		if err := srv.RegisterPlugin(p); err != nil {
			return err
		}
	}
	defer srv.Plugins.Close()

	var updates []plugin.BindingUpdate
	type account struct{ mount, user, hash string }
	var accounts []account
	str := func(v string) *string { return &v }

	if webhookFile != "" {
		var routes []*relay.WebhookRoute
		if err := readPrivateJSON(webhookFile, &routes); err != nil {
			return err
		}
		for _, r := range routes {
			if r == nil {
				continue
			}
			cfg := map[string]any{"token_sha256": strings.ToLower(r.TokenHash), "tag": r.Route}
			if r.Signature != nil {
				cfg["hmac_secret"] = r.Signature.Secret
				cfg["timestamp_header"] = r.Signature.TimestampHeader
				cfg["signature_header"] = r.Signature.SignatureHeader
			}
			if sealKey != "" {
				cfg[plugin.SealPublicKeyField] = sealKey
			}
			updates = append(updates, plugin.BindingUpdate{
				PluginID: "webhook", Mount: r.Route, SpaceID: str(space), BoxName: str("webhook/" + r.Route), Config: cfg,
			})
		}
	}
	if webdavFile != "" {
		var routes []*relay.WebDAVRoute
		if err := readPrivateJSON(webdavFile, &routes); err != nil {
			return err
		}
		for _, r := range routes {
			if r == nil {
				continue
			}
			cfg := map[string]any{}
			if sealKey != "" {
				cfg[plugin.SealPublicKeyField] = sealKey
			}
			updates = append(updates, plugin.BindingUpdate{
				PluginID: "webdav", Mount: r.Route, SpaceID: str(space), BoxName: str("webdav/" + r.Route), Config: cfg,
			})
			accounts = append(accounts, account{r.Route, r.Username, strings.ToLower(r.PasswordHash)})
		}
	}

	for _, u := range updates {
		fmt.Printf("%s /edge/%s/%s -> space %s box %s\n", map[bool]string{true: "would bind", false: "binding"}[dry], u.PluginID, u.Mount, space, *u.BoxName)
		if dry {
			continue
		}
		if _, err := srv.Plugins.SaveBinding(u); err != nil {
			return fmt.Errorf("import-v1: %s/%s: %w", u.PluginID, u.Mount, err)
		}
	}
	for _, a := range accounts {
		fmt.Printf("%s webdav account %s on /edge/webdav/%s (queue mode)\n", map[bool]string{true: "would add", false: "adding"}[dry], a.user, a.mount)
		if dry {
			continue
		}
		b, err := srv.Plugins.GetBinding("webdav", a.mount)
		if err != nil {
			return err
		}
		if _, err := srv.Plugins.UpsertAccount(b.ID, a.mount, a.user, a.hash, "queue", "{}"); err != nil {
			return fmt.Errorf("import-v1: webdav account %s: %w", a.user, err)
		}
	}
	if !dry {
		fmt.Println("done. v1 routes keep working; point clients at /edge/... then remove the v1 config flags.")
	}
	return nil
}

func readPrivateJSON(path string, dst any) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be group/world accessible (chmod 600)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

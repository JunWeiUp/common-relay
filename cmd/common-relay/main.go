package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/JunWeiUp/common-relay/internal/relay"
	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
	v2drop "github.com/JunWeiUp/common-relay/internal/v2/plugins/drop"
	v2mcp "github.com/JunWeiUp/common-relay/internal/v2/plugins/mcpedge"
	v2webdav "github.com/JunWeiUp/common-relay/internal/v2/plugins/webdav"
	v2webhook "github.com/JunWeiUp/common-relay/internal/v2/plugins/webhook"
	v2server "github.com/JunWeiUp/common-relay/internal/v2/server"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
func run() error {
	f := flag.NewFlagSet("common-relay", flag.ContinueOnError)
	dir := f.String("data", "./data", "private state directory")
	listen := f.String("listen", "127.0.0.1:47805", "HTTP listener behind TLS")
	app := f.String("app", "", "application namespace")
	group := f.String("group", "", "device group")
	device := f.String("device", "", "device identifier")
	pub := f.String("public-key", "", "device Curve25519 public key (hex)")
	out := f.String("credential-out", "", "new private credential file (must not exist)")
	appQuota := f.Int64("app-quota", 2<<30, "per application bytes")
	globalQuota := f.Int64("global-quota", 5<<30, "global bytes")
	selfService := f.String("self-service-apps", "", "comma-separated app namespaces allowed to create new groups")
	accessFile := f.String("access-password-file", "", "file with lowercase hex SHA-256 of the required Relay-Access password")
	webhooks := f.String("webhook-config", "", "optional private webhook route configuration")
	webdav := f.String("webdav-config", "", "optional private WebDAV upload route configuration")
	v2AdminFile := f.String("v2-admin-hash-file", "", "optional file with lowercase hex SHA-256 of the v2 Root Admin secret; enables /v2/* and /edge/*")
	reserve := f.Uint64("disk-reserve", 2<<30, "minimum free disk bytes")
	wsOrigins := f.String("v2-ws-origins", "", "comma-separated browser Origin patterns allowed on /v2/ws (native clients send none)")
	importSpace := f.String("space", "", "import-v1: target v2 space (bridge_allowed or client_encrypted)")
	importSeal := f.String("seal-public-key", "", "import-v1: optional X25519 public key (hex) to seal imported routes' payloads")
	importDry := f.Bool("dry-run", false, "import-v1: print the bindings without writing")
	backupOut := f.String("out", "", "backup: directory for snapshots (not inside --data)")
	backupKeep := f.Int("keep", 7, "backup: number of snapshots to keep (0 = keep all)")
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: common-relay serve|device-add|device-revoke|group-bootstrap|check|backup|schema|hash-password|import-v1 [flags]")
	}
	command := os.Args[1]
	switch command {
	case "serve", "device-add", "device-revoke", "group-bootstrap", "check", "import-v1", "backup", "schema":
	case "hash-password":
		return hashPassword()
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", f.Args())
	}
	// backup and schema read the data directory without opening (and migrating) it.
	switch command {
	case "backup":
		path, err := runBackup(*dir, *backupOut, *backupKeep, time.Now())
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	case "schema":
		rep, err := schemaReport(*dir)
		if err != nil {
			return err
		}
		return printJSON(rep)
	}
	var accessHash []byte
	if command == "serve" {
		if *accessFile == "" {
			return fmt.Errorf("--access-password-file required")
		}
		var err error
		if accessHash, err = relay.LoadAccessHash(*accessFile); err != nil {
			return err
		}
	}
	if command == "import-v1" {
		return importV1(*dir, *webhooks, *webdav, *importSpace, *importSeal, *importDry)
	}
	s, err := relay.OpenStore(*dir)
	if err != nil {
		return err
	}
	defer s.DB.Close()
	s.AppQuota = *appQuota
	s.GlobalQuota = *globalQuota
	d := relay.Device{App: *app, Group: *group, ID: *device, PublicKey: *pub}
	switch command {
	case "group-bootstrap":
		if *out == "" {
			return fmt.Errorf("--credential-out required")
		}
		secret := relay.RandomID() + relay.RandomID()
		file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		if err = s.GroupBootstrap(*app, *group, secret); err != nil {
			os.Remove(*out)
			return err
		}
		if err = json.NewEncoder(file).Encode(map[string]any{"version": 1, "app": *app, "group": *group, "bootstrap": secret}); err != nil {
			return err
		}
		return file.Sync()
	case "device-add":
		if *out == "" {
			return fmt.Errorf("--credential-out required; credentials are never printed")
		}
		file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		b := make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return err
		}
		token := hex.EncodeToString(b)
		if err = s.AddDevice(d, token); err != nil {
			os.Remove(*out)
			return err
		}
		if err = json.NewEncoder(file).Encode(map[string]any{"identity": d, "token": token}); err != nil {
			s.Revoke(d)
			return err
		}
		return file.Sync()
	case "device-revoke":
		return s.Revoke(d)
	case "check":
		if err = s.DB.Ping(); err != nil {
			return err
		}
		bad, err := s.CheckGroups()
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			return fmt.Errorf("group entries violate strict payload rules: %s", strings.Join(bad, ", "))
		}
		return nil
	case "serve":
		server := relay.New(s)
		server.DiskReserve = *reserve
		server.AccessHash = accessHash
		if err := server.RecoverWebhooks(); err != nil {
			return err
		}
		if *webhooks != "" {
			if err := server.LoadWebhooks(*webhooks); err != nil {
				return err
			}
		}
		if *webdav != "" {
			if err := server.LoadWebDAV(*webdav); err != nil {
				return err
			}
		}
		server.SelfServiceApps = map[string]bool{}
		var selfServiceList []string
		for _, name := range strings.Split(*selfService, ",") {
			if name = strings.TrimSpace(name); name != "" {
				server.SelfServiceApps[name] = true
				selfServiceList = append(selfServiceList, name)
			}
		}
		var handler http.Handler = server.Handler()
		var v2Store *v2core.Store
		usageRefresh := func() {}
		if *v2AdminFile != "" {
			adminHashBytes, err := relay.LoadAccessHash(*v2AdminFile)
			if err != nil {
				return fmt.Errorf("load v2 admin hash: %w", err)
			}
			v2Store, err = v2core.OpenStore(*dir)
			if err != nil {
				return fmt.Errorf("open v2 store: %w", err)
			}
			defer v2Store.Close()
			v2Store.SpaceQuota = *appQuota
			v2Store.GlobalQuota = *globalQuota
			v2Store.DiskReserve = *reserve
			// One global quota spans both stores. Each side reads the other's usage
			// from a cached counter (refreshed every minute and after startup) so no
			// transaction ever waits on the other database's single connection.
			var v1Used, v2Used atomic.Int64
			refreshUsage := func() {
				if n, err := s.UsedBytes(); err == nil {
					v1Used.Store(n)
				}
				if n, err := v2Store.UsedBytes(); err == nil {
					v2Used.Store(n)
				}
			}
			refreshUsage()
			v2Store.ExternalUsage = v1Used.Load
			s.ExternalUsage = v2Used.Load
			usageRefresh = refreshUsage

			activeAccessHex, activeAccessSource, activeAccessUpdated, err := resolveAccessHash(v2Store, hex.EncodeToString(accessHash))
			if err != nil {
				return err
			}
			if raw, decErr := hex.DecodeString(activeAccessHex); decErr == nil && len(raw) == 32 {
				server.SetAccessHash(raw)
			}

			v2Srv := v2server.New(v2Store, v2server.Config{
				AccessHash:      activeAccessHex,
				AccessSource:    activeAccessSource,
				AccessUpdatedAt: activeAccessUpdated,
				RootAdminHash:   hex.EncodeToString(adminHashBytes),
				SelfServiceAll:  server.SelfServiceApps["*"],
				SelfServiceApps: selfServiceList,
			})
			v2Srv.V1Usage = func() any { return server.Usage.Snapshot() }
			v2Srv.OnAccessHashChanged = func(hexHash string) {
				if raw, decErr := hex.DecodeString(hexHash); decErr == nil && len(raw) == 32 {
					server.SetAccessHash(raw)
				}
			}
			for _, regErr := range []error{
				v2Srv.RegisterPlugin(v2drop.New()),
				v2Srv.RegisterPlugin(v2webhook.New()),
				v2Srv.RegisterPlugin(v2webdav.New()),
				v2Srv.RegisterPlugin(v2mcp.New()),
			} {
				if regErr != nil {
					return regErr
				}
			}
			for _, o := range strings.Split(*wsOrigins, ",") {
				if o = strings.TrimSpace(o); o != "" {
					v2Srv.Pipe.OriginPatterns = append(v2Srv.Pipe.OriginPatterns, o)
				}
			}
			v1Handler := handler
			v2Handler := v2Srv.Handler()
			server.ExtraOnlinePeers = func(_, group string) []string {
				return v2Srv.Pipe.OnlineDevices(group)
			}
			server.OnGroupSynced = func(app, group, groupName string, members []relay.SyncedGroupMember, removed []string, closed bool, revision int) {
				projected := make([]v2core.ManagedMember, 0, len(members))
				for _, m := range members {
					projected = append(projected, v2core.ManagedMember{
						ID:        m.ID,
						Name:      m.Name,
						PublicKey: m.PublicKey,
						TokenHash: m.TokenHash,
						Manager:   m.Manager,
					})
				}
				if err := v2Store.SyncManagedGroupWithApp(group, app, groupName, projected, removed, closed); err != nil {
					log.Printf("v2 group sync error for %s: %v", group, err)
					return
				}
				for _, id := range removed {
					v2Srv.Pipe.DisconnectDevice(id)
				}
				if closed {
					for _, id := range v2Srv.Pipe.OnlineDevices(group) {
						v2Srv.Pipe.DisconnectDevice(id)
					}
				} else {
					v2Srv.Pipe.NotifyGroupChanged(group, revision)
				}
			}
			server.SyncExistingGroups()
			v2GroupHandler := server.V2GroupHandler()
			v2FilesHandler := server.V2FilesHandler()
			mux := http.NewServeMux()
			mux.Handle("/v2/group", v2GroupHandler)
			mux.Handle("/v2/group/", v2GroupHandler)
			mux.Handle("/v2/enroll/", v2GroupHandler)
			mux.Handle("/v2/files", v2FilesHandler)
			mux.Handle("/v2/files/", v2FilesHandler)
			mux.Handle("/v2/", v2Handler)
			mux.Handle("/edge/", v2Handler)
			mux.Handle("/", v1Handler)
			handler = mux
		}
		httpServer := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := server.Collect(); err != nil {
						log.Printf("collection failed")
					}
					if v2Store != nil {
						v2Store.SweepExpired()
					}
					usageRefresh()
				}
			}
		}()
		go func() {
			<-ctx.Done()
			server.Close()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			httpServer.Shutdown(shutdown)
		}()
		if v2Store != nil {
			log.Printf("common-relay listening on %s (protocol v1 + v2, edge plugins enabled)", *listen)
		} else {
			log.Printf("common-relay listening on %s (protocol v1 only; pass --v2-admin-hash-file to enable v2)", *listen)
		}
		err = httpServer.ListenAndServe()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

// hashPassword reads one password line from stdin and prints its SHA-256 for --access-password-file.
func hashPassword() error {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("read password from stdin: %w", err)
	}
	p := strings.TrimRight(line, "\r\n")
	if !relay.ValidAccessPassword(p) {
		return fmt.Errorf("password must be 8-128 printable ASCII characters without spaces")
	}
	fmt.Println(relay.AccessPasswordHash(p))
	return nil
}

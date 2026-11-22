package main

import (
	"bufio"
	"context"
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
	out := f.String("credential-out", "", "group-bootstrap: new private credential file (must not exist)")
	appQuota := f.Int64("app-quota", 2<<30, "per application bytes")
	globalQuota := f.Int64("global-quota", 5<<30, "global bytes")
	selfService := f.String("self-service-apps", "", "comma-separated app namespaces allowed to create new groups")
	accessFile := f.String("access-password-file", "", "file with lowercase hex SHA-256 of the required Relay-Access password")
	v2AdminFile := f.String("v2-admin-hash-file", "", "serve: file with lowercase hex SHA-256 of the v2 Root Admin secret (required)")
	reserve := f.Uint64("disk-reserve", 2<<30, "minimum free disk bytes")
	wsOrigins := f.String("v2-ws-origins", "", "comma-separated browser Origin patterns allowed on /v2/ws (native clients send none)")
	backupOut := f.String("out", "", "backup: directory for snapshots (not inside --data)")
	backupKeep := f.Int("keep", 7, "backup: number of snapshots to keep (0 = keep all)")
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: common-relay serve|group-bootstrap|check|backup|schema|hash-password [flags]")
	}
	command := os.Args[1]
	switch command {
	case "serve", "group-bootstrap", "check", "backup", "schema":
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
		if *v2AdminFile == "" {
			return fmt.Errorf("--v2-admin-hash-file required (protocol v2 is the only protocol)")
		}
	}
	s, err := relay.OpenStore(*dir)
	if err != nil {
		return err
	}
	defer s.DB.Close()
	s.AppQuota = *appQuota
	s.GlobalQuota = *globalQuota
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
		server.SelfServiceApps = map[string]bool{}
		var selfServiceList []string
		for _, name := range strings.Split(*selfService, ",") {
			if name = strings.TrimSpace(name); name != "" {
				server.SelfServiceApps[name] = true
				selfServiceList = append(selfServiceList, name)
			}
		}
		adminHashBytes, err := relay.LoadAccessHash(*v2AdminFile)
		if err != nil {
			return fmt.Errorf("load v2 admin hash: %w", err)
		}
		v2Store, err := v2core.OpenStore(*dir)
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
		var ledgerUsed, v2Used atomic.Int64
		refreshUsage := func() {
			if n, err := s.UsedBytes(); err == nil {
				ledgerUsed.Store(n)
			}
			if n, err := v2Store.UsedBytes(); err == nil {
				v2Used.Store(n)
			}
		}
		refreshUsage()
		v2Store.ExternalUsage = ledgerUsed.Load
		s.ExternalUsage = v2Used.Load

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
		v2Handler := v2Srv.Handler()
		server.OnlinePeers = func(_, group string) []string {
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
		ledger := server.Handler()
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", server.Healthz)
		mux.Handle("/v2/group", ledger)
		mux.Handle("/v2/group/", ledger)
		mux.Handle("/v2/enroll/", ledger)
		mux.Handle("/v2/files", ledger)
		mux.Handle("/v2/files/", ledger)
		mux.Handle("/v2/", v2Handler)
		mux.Handle("/edge/", v2Handler)
		var handler http.Handler = mux
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
					v2Store.SweepExpired()
					refreshUsage()
				}
			}
		}()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			httpServer.Shutdown(shutdown)
		}()
		log.Printf("common-relay listening on %s (protocol v2, edge plugins enabled)", *listen)
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

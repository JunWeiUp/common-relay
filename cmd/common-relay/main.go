package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	v2core "github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/ledger"
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
		if accessHash, err = ledger.LoadAccessHash(*accessFile); err != nil {
			return err
		}
		if *v2AdminFile == "" {
			return fmt.Errorf("--v2-admin-hash-file required (protocol v2 is the only protocol)")
		}
	}
	// One store: relay_v2.db (+ blobs/) holds the v2 spaces, the signed device
	// group ledger and the file plane. A legacy relay.db is imported once.
	v2Store, err := v2core.OpenStore(*dir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer v2Store.Close()
	v2Store.SpaceQuota = *appQuota
	v2Store.GlobalQuota = *globalQuota
	v2Store.DiskReserve = *reserve
	s, err := ledger.Open(v2Store)
	if err != nil {
		return err
	}
	s.AppQuota = *appQuota
	s.GlobalQuota = *globalQuota
	imp, err := s.ImportLegacy()
	if err != nil {
		return err
	}
	if !imp.Skipped {
		log.Printf("imported %s into relay_v2.db: %d groups, %d entries, %d devices, %d invites, %d files (%d payloads); %s and files/ are left untouched as a backup",
			ledger.LegacyDB, imp.Groups, imp.Entries, imp.Devices, imp.Invites, imp.Files, imp.Payloads, ledger.LegacyDB)
	}
	switch command {
	case "group-bootstrap":
		if *out == "" {
			return fmt.Errorf("--credential-out required")
		}
		secret := ledger.RandomID() + ledger.RandomID()
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
		if err = v2Store.DB.Ping(); err != nil {
			return err
		}
		rep, err := s.Check()
		if err != nil {
			return err
		}
		if err := printJSON(rep); err != nil {
			return err
		}
		if len(rep.Problems) > 0 {
			bad := make([]string, 0, len(rep.Problems))
			for _, p := range rep.Problems {
				bad = append(bad, p.Where+" ("+p.Reason+")")
			}
			return fmt.Errorf("group ledger check failed: %s", strings.Join(bad, ", "))
		}
		return nil
	case "serve":
		if err := s.MirrorAll(); err != nil {
			return fmt.Errorf("mirror groups into v2 spaces: %w", err)
		}
		server := ledger.New(s)
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
		adminHashBytes, err := ledger.LoadAccessHash(*v2AdminFile)
		if err != nil {
			return fmt.Errorf("load v2 admin hash: %w", err)
		}

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
		v2Srv.LedgerUsage = func() any { return server.Usage.Snapshot() }
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
		server.Hub = v2Srv.Pipe
		v2Handler := v2Srv.Handler()
		ledgerHandler := server.Handler()
		mux := http.NewServeMux()
		mux.Handle("/healthz", v2Handler)
		mux.Handle("/v2/group", ledgerHandler)
		mux.Handle("/v2/group/", ledgerHandler)
		mux.Handle("/v2/enroll/", ledgerHandler)
		mux.Handle("/v2/files", ledgerHandler)
		mux.Handle("/v2/files/", ledgerHandler)
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
	if !ledger.ValidAccessPassword(p) {
		return fmt.Errorf("password must be 8-128 printable ASCII characters without spaces")
	}
	fmt.Println(ledger.AccessPasswordHash(p))
	return nil
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/JunWeiUp/common-relay/internal/relay"
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
	device := f.String("device", "", "device identifier")
	pub := f.String("public-key", "", "device Curve25519 public key (hex)")
	out := f.String("credential-out", "", "new private credential file (must not exist)")
	appQuota := f.Int64("app-quota", 2<<30, "per application bytes")
	globalQuota := f.Int64("global-quota", 5<<30, "global bytes")
	selfService := f.String("self-service-apps", "", "comma-separated app namespaces allowed to create new groups")
	reserve := f.Uint64("disk-reserve", 2<<30, "minimum free disk bytes")
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: common-relay serve|device-add|device-revoke|group-bootstrap|check [flags]")
	}
	command := os.Args[1]
	switch command {
	case "serve", "device-add", "device-revoke", "group-bootstrap", "check":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", f.Args())
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
		server.SelfServiceApps = map[string]bool{}
		for _, name := range strings.Split(*selfService, ",") {
			if name = strings.TrimSpace(name); name != "" {
				server.SelfServiceApps[name] = true
			}
		}
		httpServer := &http.Server{Addr: *listen, Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
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
		log.Printf("common-relay v1 listening on %s", *listen)
		err = httpServer.ListenAndServe()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

// Echo is an isolated local interop probe (online, offline and stream echo);
// never point it at production identities.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	relay "github.com/JunWeiUp/common-relay/sdk/go"
)

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: echo test-config.json")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var config struct {
		App     string            `json:"app"`
		Group   string            `json:"group"`
		Device  string            `json:"device"`
		Secret  string            `json:"secret_key"`
		Trusted map[string]string `json:"trusted_peers"`
		URL     string            `json:"url"`
		Token   string            `json:"token"`
		Local   bool              `json:"allow_local_test"`
		State   string            `json:"state_path"`
	}
	if err = json.Unmarshal(raw, &config); err != nil {
		return err
	}
	if !config.Local {
		return fmt.Errorf("local tests only")
	}
	identity, err := relay.NewIdentity(config.App, config.Group, config.Device, config.Secret, config.Trusted)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// With state_path the probe also echoes offline messages (journal) and streams.
	var journal *relay.Journal
	if config.State != "" {
		if journal, err = relay.OpenJournal(config.State, nil); err != nil {
			return err
		}
		defer journal.Close()
	}
	client, err := relay.DialJournal(ctx, config.URL, config.Token, identity, journal, relay.Options{AllowLocalTest: true})
	if err != nil {
		return err
	}
	defer client.Close()
	peers, err := client.Peers(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, p := range peers {
		found = found || p.Device == "python"
	}
	// The online-only harness starts Python first; the durable harness connects it later.
	if !found && journal == nil {
		return fmt.Errorf("Python peer missing")
	}
	fmt.Println("READY")
	failures := make(chan error, 1)
	for {
		event, err := client.NextEvent(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case err = <-failures:
			return err
		default:
		}
		switch {
		case event.Type == "stream.open":
			go func() {
				if err := echoStream(ctx, client, event); err != nil {
					select {
					case failures <- err:
					default:
					}
					client.Close()
				}
			}()
		case event.Type == "message" && event.Offline:
			id, err := relay.NewMessageID()
			if err == nil {
				_, err = client.MessageOffline(ctx, event.From, id, event.Data)
			}
			if err == nil {
				err = client.Acknowledge(ctx, event)
			}
			if err != nil {
				return err
			}
		case event.Type == "message":
			if _, err = client.Message(ctx, event.From, event.Data); err != nil {
				return err
			}
		}
	}
}

// echoStream returns every record and ends with FINAL after the peer's FINAL.
func echoStream(ctx context.Context, client *relay.Client, event relay.Event) error {
	stream, err := client.AcceptStream(ctx, event)
	if err != nil {
		return err
	}
	for !stream.ReceivedFinal() {
		data, err := stream.Receive(ctx)
		if err != nil {
			return err
		}
		if err = stream.Send(ctx, data, stream.ReceivedFinal()); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	sdk "github.com/JunWeiUp/common-relay/sdk/go"
)

func TestGoSDKV2StreamFlowControlAndEncryption(t *testing.T) {
	e := newEnv(t)

	secA, pubA, err := sdk.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	secB, pubB, err := sdk.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const spaceID = "g-b71a6f76db6824d176cc07b89106f666"
	tokA := core.RandomHex(24)
	tokB := core.RandomHex(24)
	if err := e.srv.Store.SyncManagedGroup(spaceID, "ADB WiFi", []core.ManagedMember{
		{ID: "pc-mac", Name: "Mac", PublicKey: pubA, TokenHash: core.HashSecret(tokA)},
		{ID: "device-b", Name: "DeviceB", PublicKey: pubB, TokenHash: core.HashSecret(tokB)},
	}, nil, false); err != nil {
		t.Fatalf("SyncManagedGroup: %v", err)
	}

	idA, err := sdk.NewIdentity("tunnelapp", spaceID, "pc-mac", secA, map[string]string{"device-b": pubB})
	if err != nil {
		t.Fatal(err)
	}
	idB, err := sdk.NewIdentity("tunnelapp", spaceID, "device-b", secB, map[string]string{"pc-mac": pubA})
	if err != nil {
		t.Fatal(err)
	}

	wsURL := "ws" + strings.TrimPrefix(e.ts.URL, "http") + "/v2/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientA, err := sdk.Dial(ctx, wsURL, tokA, idA, sdk.Options{Password: e.access, AllowLocalTest: true})
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	defer clientA.Close()
	clientB, err := sdk.Dial(ctx, wsURL, tokB, idB, sdk.Options{Password: e.access, AllowLocalTest: true})
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	defer clientB.Close()

	// 2.2 MiB payload (>35 chunks, exercises streamWindowV2=16 credit flow control).
	payload := make([]byte, 2200*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	replyPayload := []byte("adb-ok-response-payload")

	errCh := make(chan error, 1)
	go func() {
		ev, err := clientB.NextEvent(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if ev.Type != "stream.open" || ev.From != "pc-mac" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		stB, err := clientB.AcceptStream(ctx, ev)
		if err != nil {
			errCh <- err
			return
		}
		defer stB.Close()
		var got bytes.Buffer
		for !stB.ReceivedFinal() {
			chunk, err := stB.Receive(ctx)
			if err != nil {
				errCh <- err
				return
			}
			got.Write(chunk)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			errCh <- io.ErrShortBuffer
			return
		}
		errCh <- stB.Send(ctx, replyPayload, true)
	}()

	stA, err := clientA.OpenStream(ctx, "device-b")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stA.Close()
	if err := stA.Send(ctx, payload, true); err != nil {
		t.Fatalf("Send 2.2 MiB: %v", err)
	}
	gotReply, err := stA.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive reply: %v", err)
	}
	if !bytes.Equal(gotReply, replyPayload) || !stA.ReceivedFinal() {
		t.Fatalf("unexpected reply: %q final=%v", gotReply, stA.ReceivedFinal())
	}
	if err := <-errCh; err != nil {
		t.Fatalf("peer B error: %v", err)
	}
}

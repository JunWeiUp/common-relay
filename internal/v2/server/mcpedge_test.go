package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/plugins/mcpedge"
	"github.com/JunWeiUp/common-relay/sdk/go/v2client"
)

func TestMCPEdgePluginOverPipeRPCAndPhotoLease(t *testing.T) {
	e := newEnv(t)
	if err := e.srv.RegisterPlugin(mcpedge.New()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	admin, err := v2client.New(v2client.Config{
		BaseURL: e.ts.URL, AccessPassword: e.access, Token: e.rootAdmin, AllowLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, deskTok, err := admin.CreateDevice(ctx, "hub-mcp", "Mac Hub", fakePubKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CreateSpace(ctx, "ops", "Ops", "bridge_allowed"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SetSpaceMember(ctx, "ops", "hub-mcp", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.UpsertPlugin(ctx, "mcpedge", "main", "ops", "", map[string]any{
		"target_device": "hub-mcp",
		"public_base":   e.ts.URL,
	}, true); err != nil {
		t.Fatal(err)
	}
	clientSecret := "claude-mcp-client-key-1234567890"
	if _, err := admin.UpsertPluginAccount(ctx, "mcpedge", "main", "claude-desktop", "claude", v2client.HashSecret(clientSecret), "read"); err != nil {
		t.Fatal(err)
	}

	// Start Hub Hub answering "mcp" RPC calls.
	deskClient, err := v2client.New(v2client.Config{
		BaseURL: e.ts.URL, AccessPassword: e.access, Token: deskTok, AllowLocal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := v2client.NewHub(deskClient)
	fakePNG := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1, 2, 3, 4}
	hub.HandleRPC("ops", "mcp", func(ctx context.Context, payload string) (string, error) {
		var req struct {
			Method string `json:"method"`
			Grant  string `json:"grant"`
		}
		_ = json.Unmarshal([]byte(payload), &req)
		if req.Method == "tools/list" {
			return `{"tools":[{"name":"console_daily_photo"}]}`, nil
		}
		b, _ := json.Marshal(map[string]any{
			"content": []map[string]any{
				{"type": "image", "mimeType": "image/png", "data": base64.StdEncoding.EncodeToString(fakePNG)},
			},
			"grant": req.Grant,
		})
		return string(b), nil
	})
	hub.Start(ctx)
	defer hub.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := hub.Status(); ok {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	// 1. Reject Origin header (anti-CSRF 403).
	rOrigin := e.do("POST", "/edge/mcpedge/main/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), map[string]string{
		"Origin":        "https://evil.example",
		"Authorization": "Bearer " + clientSecret,
		"Content-Type":  "application/json",
	})
	rOrigin.Body.Close()
	if rOrigin.StatusCode != 403 {
		t.Fatalf("Origin header = %d, want 403", rOrigin.StatusCode)
	}

	// 2. initialize succeeds with valid Bearer token.
	rInit := e.do("POST", "/edge/mcpedge/main/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`), map[string]string{
		"Authorization": "Bearer " + clientSecret,
		"Content-Type":  "application/json",
	})
	initBody, _ := io.ReadAll(rInit.Body)
	rInit.Body.Close()
	if rInit.StatusCode != 200 || !strings.Contains(string(initBody), `"工作台"`) {
		t.Fatalf("initialize = %d %s", rInit.StatusCode, string(initBody))
	}

	// 3. tools/call over Pipe RPC returns image + short-lived photo URL, and fetching that URL returns exact PNG!
	rCall := e.do("POST", "/edge/mcpedge/main/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"console_daily_photo"}}`), map[string]string{
		"Authorization": "Bearer " + clientSecret,
		"Content-Type":  "application/json",
	})
	var callResp struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	_ = json.NewDecoder(rCall.Body).Decode(&callResp)
	rCall.Body.Close()
	if rCall.StatusCode != 200 || len(callResp.Result.Content) < 2 {
		t.Fatalf("tools/call failed: status=%d resp=%+v", rCall.StatusCode, callResp)
	}
	var linkMeta struct {
		ImageURL string `json:"imageUrl"`
	}
	_ = json.Unmarshal([]byte(callResp.Result.Content[1].Text), &linkMeta)
	if !strings.Contains(linkMeta.ImageURL, "/edge/mcpedge/main/photo/") {
		t.Fatalf("unexpected photo link: %+v", linkMeta)
	}
	rPhoto, err := http.Get(linkMeta.ImageURL)
	if err != nil {
		t.Fatal(err)
	}
	gotPNG, _ := io.ReadAll(rPhoto.Body)
	rPhoto.Body.Close()
	if rPhoto.StatusCode != 200 || string(gotPNG) != string(fakePNG) {
		t.Fatalf("photo fetch = %d len=%d", rPhoto.StatusCode, len(gotPNG))
	}
}

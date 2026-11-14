// mcp-probe checks client compatibility without accessing application data.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type probe struct{ tokenHash [32]byte }
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (p probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != "/mcp" && r.URL.Path != "/public-probe" {
		http.NotFound(w, r)
		return
	}
	log.Printf("transport method=%s path=%s protocol=%q", r.Method, r.URL.Path, r.Header.Get("MCP-Protocol-Version"))
	// No browser origin is needed for this server-to-server probe.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "origin not allowed", 403)
		return
	}
	auth := r.Header.Get("Authorization")
	credential := r.Header.Get("X-Console-Key")
	if strings.HasPrefix(auth, "Bearer ") {
		credential = strings.TrimPrefix(auth, "Bearer ")
	}
	got := sha256.Sum256([]byte(credential))
	if r.URL.Path != "/public-probe" && (credential == "" || subtle.ConstantTimeCompare(got[:], p.tokenHash[:]) != 1) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-probe"`)
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !supported(v) {
		http.Error(w, "unsupported protocol", 400)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "JSON required", 415)
		return
	}
	var q request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&q); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if q.JSONRPC != "2.0" || q.Method == "" {
		http.Error(w, "invalid request", 400)
		return
	}
	log.Printf("mcp method=%s", q.Method)
	if len(q.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	var rpcError any
	switch q.Method {
	case "initialize":
		var v struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(q.Params, &v)
		if !supported(v.ProtocolVersion) {
			v.ProtocolVersion = "2025-06-18"
		}
		result = map[string]any{"protocolVersion": v.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "console-mcp-probe", "version": "0.1.0"}, "instructions": "Only a connectivity test. No private data is available."}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": []any{map[string]any{"name": "console_connection_test", "description": "测试 MCP 连接。只返回固定测试文字，不读取私人数据。", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}}}}
	case "tools/call":
		var a struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(q.Params, &a)
		if a.Name != "console_connection_test" {
			rpcError = map[string]any{"code": -32602, "message": "Unknown tool"}
		} else {
			result = map[string]any{"content": []any{map[string]string{"type": "text", "text": "MCP 连接测试成功。这是固定测试文字，尚未接入真实数据或 Common Relay 通道。"}}, "isError": false}
		}
	default:
		rpcError = map[string]any{"code": -32601, "message": "Method not found"}
	}
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{"jsonrpc": "2.0", "id": q.ID}
	if rpcError != nil {
		out["error"] = rpcError
	} else {
		out["result"] = result
	}
	_ = json.NewEncoder(w).Encode(out)
}
func supported(v string) bool { return v == "2025-03-26" || v == "2025-06-18" || v == "2025-11-25" }
func main() {
	listen := flag.String("listen", "127.0.0.1:47807", "loopback listen address")
	hashFile := flag.String("token-hash-file", "", "file containing SHA-256 hex of bearer token")
	flag.Parse()
	b, e := os.ReadFile(*hashFile)
	if e != nil {
		log.Fatal("read token hash: ", e)
	}
	h, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(h) != 32 {
		log.Fatal("invalid token hash")
	}
	var p probe
	copy(p.tokenHash[:], h)
	server := http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	fmt.Println("MCP probe listening on", *listen)
	log.Fatal(server.ListenAndServe())
}

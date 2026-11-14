# MCP connectivity probe

Standalone, authenticated Streamable HTTP test endpoint. This is not part of the
relay server. It exposes one fixed-text tool, `console_connection_test`, and does
not read application data or use the relay protocol yet.

Build with `go build -o build/mcp-probe ./examples/mcp-probe`. Generate a random
Bearer token locally, store its SHA-256 hex digest in a private file, and run:

```sh
build/mcp-probe --listen 127.0.0.1:47807 --token-hash-file /private/path/token.sha256
```

Publish only `/mcp` through an HTTPS reverse proxy. Configure the client with that
URL and the original token, without a `Bearer ` prefix in a dedicated token field.
The server stores only the hash and logs method names, never tokens or payloads.
The same credential may alternatively be sent in `X-Console-Key` to diagnose
clients that handle custom API-key headers differently from Bearer profiles.
This diagnostic credential has no automatic expiry; stop the probe or rotate the
hash to revoke it. It grants access only to the fixed test tool.

For separating credential failures from transport failures, `/public-probe`
exposes the same fixed-text tool without authentication. It contains no private
data and must never be extended to query application data. Publish this path only
when explicitly running the connectivity diagnostic.

The endpoint is stateless, returns JSON for POST requests and 202 for notifications,
and returns 405 for GET (no server-initiated SSE stream). Requests with an Origin
header are rejected: this probe is intended for server-to-server clients.

下一阶段：先确认 MCP 客户端能加载并调用测试工具，再单独设计 MCP 网关与本机服务之间的
Common Relay 请求/响应通道。不得把私人数据查询加入中继核心，也不得把本示例误报为
已经接入真实数据的产品接口。

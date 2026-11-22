# Common Relay Protocol v2 (Wire & Cross-Language Contract)

- **Device Kernel Plane (`/v2/*`)**: `Relay-Access` + `Authorization: Bearer <device_token>`.
- **Admin Control Plane (`/v2/admin/*`)**: `Relay-Access` + `Authorization: Bearer <root_admin_or_admin_device_token>`.
- **Edge Plugin Plane (`/edge/<plugin>/*`)**: Standard per-plugin auth (`Basic` / `Bearer` / `HMAC`), no `Relay-Access`.

## Binary Stream Frame (`/v2/ws` Binary WebSocket Message)
```text
[ 16-byte ASCII/hex stream_id ][ raw encrypted chunk bytes ]
```

## Optional: inline `box.changed` and batch ACK
- A `/v2/ws` client may opt in with `?features=box-inline` (or header `X-Relay-Features: box-inline`). For opted-in connections only, `box.changed` (`event:"item"`) for an item of at most 64 KiB may carry `"item": {BoxItem fields…, "data_b64": "<standard base64>"}` when the frame fits 256 KiB and the connection's send queue has headroom. It is a prefetch only: the item stays queued until ACKed. Clients that do not opt in see no change.
- `POST /v2/spaces/{space}/boxes/{box}/items/ack` with `{"ids":[…]}` (1–200) ACKs several items in one transaction and returns `{"ok":true,"acked":[…],"missing":[…]}`; IDs not in that Box are `missing` (idempotent). Same authorization as `DELETE …/items/{id}`; older servers answer 405.
- See [docs/V2-ARCHITECTURE.md §2.3.1](../../docs/V2-ARCHITECTURE.md). Implemented by the Go SDK `v2client.Hub`; other SDKs keep the list/download/DELETE path.

## Shared Test Vectors
See [vectors.json](vectors.json) for canonical SHA-256 secret hashing, TrustLevel matrix, binary stream framing, and `PipeEvent` JSON envelopes validated across Go, Rust, Swift, Dart, and Java SDKs.

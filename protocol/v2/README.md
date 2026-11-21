# Common Relay Protocol v2 (Wire & Cross-Language Contract)

- **Device Kernel Plane (`/v2/*`)**: `Relay-Access` + `Authorization: Bearer <device_token>`.
- **Admin Control Plane (`/v2/admin/*`)**: `Relay-Access` + `Authorization: Bearer <root_admin_or_admin_device_token>`.
- **Edge Plugin Plane (`/edge/<plugin>/*`)**: Standard per-plugin auth (`Basic` / `Bearer` / `HMAC`), no `Relay-Access`.

## Binary Stream Frame (`/v2/ws` Binary WebSocket Message)
```text
[ 16-byte ASCII/hex stream_id ][ raw encrypted chunk bytes ]
```

## Shared Test Vectors
See [vectors.json](vectors.json) for canonical SHA-256 secret hashing, TrustLevel matrix, binary stream framing, and `PipeEvent` JSON envelopes validated across Go, Rust, Swift, Dart, and Java SDKs.

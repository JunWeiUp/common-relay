# Common Relay protocol

- **[v2/README.md](v2/README.md)** — the authoritative wire specification
  (Pipe, Boxes, signed group ledger, invitations, files, `crs1`, admin, edge
  plugins, limits).
- **[v2/](v2/)** — shared cross-SDK test vectors, regenerated with
  `go run ./scripts/protocol-vectors` (see spec §14).

## History

Protocol v1 (`/relay/v1/*`: `common-relay.v1` WebSocket control frames,
credit-based streams, Webhook/WebDAV routes) has been retired: the server and
all SDKs speak only v2. Its specification and vectors live in git history
(this file before the v2-only cleanup, and `protocol/*-vectors.json`). The
signed group ledger, invitation, compact-link, file and content-envelope
formats carried over to v2 unchanged apart from the `/v2` path prefix.

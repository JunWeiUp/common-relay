# Common Relay Protocol v2

This is the authoritative wire specification of Common Relay. It is written
from the server implementation; when this document and the code disagree, the
code is the bug report:

| Area | Source |
|---|---|
| Planes, auth middleware, `/v2/me`, Box HTTP, admin | `internal/v2/server/server.go` |
| Pipe (`/v2/ws`) | `internal/v2/core/pipe.go` |
| Spaces, devices, Boxes, quotas | `internal/v2/core/{types,store,box}.go` |
| Signed group ledger, invitations, files | `internal/v2/ledger/` |
| Plugin host, edge plugins, sealed writes | `internal/v2/plugin/`, `internal/v2/plugins/*` |
| `crs1` sealed payloads | `sdk/go/v2client/sealed.go` (used by the server) |

v2 is the only protocol. v1 (`/relay/v1/*`) was removed from the server and
every SDK; see [../README.md](../README.md#history). Shared test vectors are
listed in [§14](#14-shared-test-vectors).

Conventions: "hex" means lowercase hexadecimal; "base64" is standard base64
with padding unless "base64url" (unpadded, URL alphabet) is stated; all times
are Unix seconds; JSON bodies are UTF-8.

## 1. Planes and routing

One HTTP listener (TLS terminated by a reverse proxy) serves:

| Path | Plane | Guard |
|---|---|---|
| `GET /healthz` | health (`ok`, or 503 when the store is unavailable) | none |
| `/v2/ws` | Pipe (WebSocket) | `Relay-Access` + device Bearer |
| `/v2/me` | identity probe | `Relay-Access` + device or Root Admin Bearer |
| `/v2/spaces/{space}/boxes/...` | Box data plane | `Relay-Access` + device Bearer + Space membership |
| `/v2/admin/*` | admin control plane | `Relay-Access` + Root Admin or admin-device Bearer |
| `/v2/group*`, `/v2/enroll/*` | signed group ledger | `Relay-Access` + per-route scheme (§7) |
| `/v2/files*` | end-to-end encrypted files | `Relay-Access` + ledger-device Bearer |
| `/edge/{plugin}/{mount}/...` | edge plugins | per-plugin auth only, **no** `Relay-Access` |

Anything else is 404. Dynamic JSON responses carry `Cache-Control: no-store`.

## 2. Authentication

### 2.1 `Relay-Access`

Every `/v2/*` request (including the WebSocket upgrade) carries
`Relay-Access: <server access password>`. The server stores only
`hex(SHA-256(password))` and compares in constant time; a missing or wrong
value is **401** before any other processing. The password is 8–128 printable
ASCII characters (0x21–0x7E, no space). `serve` refuses to start without
`--access-password-file`; an admin may later replace the hash at runtime
(`PUT /v2/admin/access-password`). The password is independent of every other
credential, is never part of end-to-end encryption, and must not appear in
logs, URLs or invitation packets (a compact link may carry it in its fragment,
§7.8). `/healthz` and `/edge/*` do not use it.

### 2.2 `Authorization` schemes

| Scheme | Used on | Credential |
|---|---|---|
| `Bearer <device token>` | `/v2/ws`, `/v2/me`, `/v2/spaces/*` | v2 device token (admin-created or ledger-mirrored) |
| `Bearer <root admin secret>` | `/v2/admin/*`, `/v2/me` | Root Admin secret (`--v2-admin-hash-file` holds its SHA-256) |
| `Bearer <ledger device token>` | `/v2/group*`, `/v2/files*` | per-group ledger credential |
| `Bootstrap <secret>` | `POST /v2/group/bootstrap` | one-time operator secret (`common-relay group-bootstrap`) |
| `Invitation <secret>` | `POST /v2/enroll/{id}` | invitation secret from the trusted QR/link |
| `Claim <token>` | `GET /v2/enroll/{id}`, `/v2/enroll/{id}/auto` | the joining device's own new token |
| `InvitationLink <read_token>` | `GET /v2/enroll/{id}/link` | 64-hex read capability (§7.8) |

All secrets are stored server-side only as `hex(SHA-256(UTF-8 secret))`
(`HashSecret`, vectors: `vectors.json` → `hash_secret`). Tokens shorter than 32
characters are rejected outright.

Credential classes:

- **v2 device** — row in `v2_devices`. Admin-created devices get a random
  64-hex token once from `POST /v2/admin/devices`. A device with
  `is_admin:true` may also use `/v2/admin/*`.
- **Ledger device** — row in `v2_ledger_devices`, keyed by (app, group,
  device). The client generates its token and registers only `token_hash`.
  Every committed group state is mirrored, in the same transaction, into a
  v2 Space whose ID is the group ID (trust `strict_e2e`, `managed_by =
  "v1:<app>"`), a v2 device with the same ID and token hash, and a membership
  (`admin` for managers, `member` otherwise). The same token therefore works
  on `/v2/ws` and `/v2/spaces/*`. The mirror never overwrites an admin space,
  an admin device, or a device ID owned by another group (that member then
  only lacks the v2 mirror; the ledger still commits).
- **Root Admin** — not a device: `/v2/me` answers `{ok,root_admin:true}`; it
  cannot open `/v2/ws`.

Responses: missing/invalid credential **401**; valid device without the
required role **403** (`admin role required`, `forbidden`, `read-only role`).

## 3. Identifiers and roles

| Item | Rule |
|---|---|
| Space ID, device ID (v2) | `^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$` |
| Box name | `^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$`, no `..`, `//`, trailing `/`, and no segment equal to `items` or `objects` |
| Object key | 1–512 bytes after trimming `/`, no `..` |
| Ledger app / group / device | `^[A-Za-z0-9_-]{1,80}$` |
| Invitation / file ID | 32 hex (16 random bytes) |
| Device public key | 64 hex (X25519) |

Trust levels (fixed at Space creation): `strict_e2e` < `client_encrypted` <
`bridge_allowed`. A plugin requiring trust *P* may bind to a Space of level
*S* iff rank(P) ≤ rank(S) (`vectors.json` → `trust_matrix`).

Roles: `admin` and `member` may write; `archive_observer` may only read Box
data and receive `box.changed`.

## 4. Pipe: `/v2/ws`

### 4.1 Handshake

`GET /v2/ws` WebSocket upgrade with `Relay-Access` and `Authorization:
Bearer <device token>`; no subprotocol, no credentials in the query.
Optional feature opt-in: query `?features=box-inline` or header
`X-Relay-Features: box-inline` (comma-separated, case-insensitive). Browser
`Origin`s are rejected unless allowlisted (`--v2-ws-origins`); native clients
send none.

The session snapshots the device's Space memberships at connect time. A new
connection of the same device replaces the old one (closed with status 1001
`replaced`). Revocation, role changes (`PUT …/members`), group removal and
disband disconnect the device so it reconnects with fresh state.

On connect the server sends, in order: `hello`, a `presence` broadcast for
each of the device's Spaces, then up to 256 pending offline `msg` events per
Space.

### 4.2 Frames

- **Text frame**: one JSON `PipeEvent`. Unknown fields are ignored; empty
  fields are omitted.
- **Binary frame**: `stream_id[16] || chunk`, forwarded verbatim to the other
  end of a ready stream (vectors: `vectors.json` → `binary_stream_frame`).
  Frames for unknown or not-yet-accepted streams are dropped silently.
- Maximum incoming frame: 256 KiB (larger closes the connection). Clients that
  opt in to `box-inline` must accept text frames up to 256 KiB.

`PipeEvent` fields: `type`, `space`, `id`, `from`, `to`, `topic`, `box`,
`event`, `ref`, `seq` (int), `body` (string), `ttl` (int), `offline` (bool),
`peers` ([]string), `code`, `item` (inline Box item).

### 4.3 Client → server

| `type` | Fields | Effect / reply |
|---|---|---|
| `ping` | `id` | `{type:"pong",id}` |
| `presence` | `space,id` | `{type:"presence",space,id,peers}`; not a member → `error forbidden` |
| `msg` | `space,to,id?,topic?,body,offline?,ttl?` | see 4.5 |
| `ack` | `space,from,id` | deletes a stored offline message addressed to this device; the sender, if online, gets `{type:"received",space,id,from:<acker>}`. No reply. |
| `stream.open` | `space,to,id(16 chars),topic?,body?` | target gets `stream.open` with `from`; errors `invalid_stream`, `offline`, `forbidden` |
| `stream.accept` | `id,body?` | only the target; origin gets `stream.accept` with `from`; else `error unknown_stream` |
| `stream.credit` | `id,seq` (`seq ≥ 0`) | grants `seq` frames of flow-control credit (or `0` to request pause) to the other end of a ready stream; errors `invalid_stream`, `unknown_stream` |
| `stream.close` | `id` | other end gets `stream.close` with `from` (ordered behind already-queued binary stream chunks) |
| `rpc.res` | `id,body?,code?` | answers a server `rpc.req`; accepted only from the device the request went to; a non-empty `code` is an error |

### 4.4 Server → client

| `type` | Fields | Meaning |
|---|---|---|
| `hello` | `from` (own device ID), `seq` (monotonic session seq) | session ready |
| `presence` | `space,peers[,id]` | online device IDs of the Space (broadcast on every connect/disconnect, or a reply) |
| `pong` | `id` | reply to `ping` |
| `msg` | `space,id,from,to,topic,body[,offline]` | message; `offline:true` when it came from (or was also stored in) the offline queue |
| `ack` | `space,id,event` | `event:"forwarded"` (handed to the online recipient's queue) or `"stored"` (persisted offline) |
| `received` | `space,id,from` | the recipient ACKed an offline message |
| `box.changed` | `space,box,event,ref,seq[,item]` | Box wake-up, see 4.6 |
| `group.changed` | `space` (group ID), `seq` (revision) | signed membership advanced; fetch and verify `GET /v2/group` (the event is not proof) |
| `stream.open` / `stream.accept` / `stream.credit` / `stream.close` | `space,id,from[,topic,body,seq]` | stream lifecycle & back-pressure; `stream.credit` without `from` and `seq:0` is a server back-pressure hint (only when opted into `stream-credit`); `stream.close` without `from` means the peer disconnected |
| `rpc.req` | `space,id,topic,body` | plugin RPC (e.g. `mcpedge`) to this device; answer with `rpc.res` within 15 s |
| `error` | `code[,id]` | see 4.7 |

### 4.5 Messages

The sender must have a writing role in `space`; `to` must be a member of the
Space (`unknown_recipient`). `id` defaults to a random 24-hex value.

- `offline:false`: forwarded only if `to` is online (`ack forwarded`), else
  `error offline`. Nothing is stored.
- `offline:true`: stored (deduplicated by space/sender/recipient/id; `ttl`
  seconds, default 86400) and delivered now if online, then re-delivered on
  every connect until ACKed or expired (`ack stored`). Delivery is
  at-least-once: process idempotently by `id`, then send `ack`. Bodies count
  toward the Space quota.

`body` is opaque to the server; SDKs carry the content envelope of §6.

Client rules (all SDK message clients):

- A `msg` whose envelope cannot be opened (sender not in the receiver's pinned
  keys, or authentication failure) must not fail the connection: the relay
  would re-deliver the stored copy on every connect. Surface it to the app
  (`undecryptable`, with whether the sender was trusted). The app reconnects
  with fresh pinned keys when the sender is in its current signed roster or is
  seen for the first time (it may have just joined), and sends `ack` to drop
  it when it returns from a sender that is still not a member, or when a
  trusted sender's envelope is corrupt.
- Reconnect with back-off: 1 s doubling to 30 s, reset only after a connection
  stayed up for 120 s. HTTP 401/403 at the upgrade or on `/v2/group*` means the
  credentials or access password were rejected: stop and ask the user.

### 4.6 `box.changed`

Sent to every online member (including `archive_observer`) of the Space:

| `event` | `ref` | `seq` |
|---|---|---|
| `item` | item ID | item seq |
| `object` | object key | new version |
| `object_deleted` | object key | 0 |

With `box-inline`, an `item` event for an item of at most 64 KiB may carry
`item: {BoxItem fields…, data_b64}` (standard base64 of the stored bytes)
when the frame fits 256 KiB and the peer's send queue is at most half full.
It is a prefetch only: the item stays queued until ACKed (§5.3). Otherwise
the compact event is sent.

### 4.7 Error codes

`bad_json`, `forbidden`, `unknown_recipient`, `offline`, `storage`,
`invalid_stream`, `unknown_stream`. Errors carry the request `id` when known.

### 4.8 Keepalive, priority queues, and back-pressure

- The server sends a WebSocket ping every 30 s and closes a peer that does not
  pong within 10 s (`keepalive_timeout`). Clients must answer control pings
  (all WebSocket libraries do) and should send their own `ping` event or
  WebSocket ping if their proxies time out faster.
- Each peer has a **high-priority control queue** (64 frames: `hello`, `ping`/`pong`,
  `presence`, `msg`, `ack`, `received`, `rpc.*`, `box.changed`, `group.changed`,
  `stream.open`/`accept`/`credit`, `error`) and a **lower-priority binary stream
  queue** (64 frames: binary stream chunks plus `stream.close` to preserve stream
  end ordering). All peers share 32 MiB of queued bytes. A single frame write
  times out after 10 s.
- Control queue overflow disconnects the peer; binary stream queue overflow drops
  the excess binary chunk instead of killing the WebSocket session, increments
  `metrics.stream_drops`, and (when the sender opted into `features=stream-credit`)
  sends `{type:"stream.credit",space,id,seq:0}` as a back-pressure hint.
- Streams live only while both ends are connected; a disconnect closes them. Use
  a Box (`ephemeral` or resumable `uploads`) when the peer may be offline.

### 4.9 Optional direct-upgrade convention (`relay.direct.v1`)

The relay remains strictly transport-only and always acts as the fallback path.
Apps/SDKs that wish to opportunistically upgrade high-bandwidth traffic to a LAN
or direct TCP/QUIC link may exchange encrypted candidate endpoints over normal
online Pipe `msg` frames with `topic: "relay.direct.v1"`:

- Payload (inside the normal §6 encrypted envelope):
  `{"op":"offer"|"answer"|"fallback","session":"<hex>","candidates":["<host:port>",…],"nonce":"<hex>"}`.
- Peers must authenticate the direct connection with the same pinned X25519/Ed25519
  keys used for the Space and fall back seamlessly to `/v2/ws` on probe timeout
  (recommended ≤ 1.5 s) or network change.

## 5. Boxes

### 5.1 Modes

| Mode | Semantics | Defaults |
|---|---|---|
| `queue` | inbox; monotonic `seq`; deleted on ACK | `max_bytes` 64 MiB per item |
| `object` | versioned opaque objects, ETag/CAS, keeps `keep_versions` | 64 MiB, `keep_versions` 10 |
| `ephemeral` | like `queue` with a TTL, for large one-off transfers | 512 MiB, `ttl_sec` 86400 |

`max_bytes` (per item/object, ≤ 512 MiB) and `ttl_sec` are set at creation by
an admin (`POST /v2/admin/spaces/{id}/boxes`); plugins create their Boxes on
demand. A body over `max_bytes` or any quota is **507**.

### 5.2 Routes

Base: `/v2/spaces/{space}/boxes/{box}` (box names may contain `/`). Any member
may read; writing requires `admin`/`member` (else 403). Non-members get 403.

| Method & path | Body / query | Response |
|---|---|---|
| `GET …/items` | `after=<seq>` (default 0), `limit` (default 100, max 500) | `{ok,items:[BoxItem]}` ordered by seq, unexpired only |
| `POST …/items` | raw bytes; `Content-Type`; `X-Box-Meta: <json>`; `ttl=<s>` overrides the Box TTL | 201 `{ok,item}` |
| `GET …/items/{id}` | | bytes; `Content-Type`, `X-Box-Seq`, `X-Box-SHA256` |
| `DELETE …/items/{id}` | | ACK: `{ok}`; 404 if absent |
| `POST …/items/ack` | `{"ids":[…]}` (1–200 IDs, each ≤ 128 chars) | `{ok,acked:[…],missing:[…]}` |
| `GET …/objects` | `prefix=` | `{ok,objects:[BoxObject]}` (latest versions) |
| `PUT …/objects/{key}` | raw bytes; `If-Match: "<etag>"` or `If-Match: none` | `{ok,object}`, `ETag` header; 409 on CAS failure |
| `GET`/`HEAD …/objects/{key}` | `version=<n>`; `If-None-Match` | bytes; `ETag`, `X-Object-Version`; 304 when the ETag matches |
| `GET …/objects/{key}?versions=1` | | `{ok,versions:[BoxObject]}` |
| `DELETE …/objects/{key}` | | `{ok}` |
| `POST …/uploads` | `{"total_size":N,"key"?:…,"content_type"?:…,"meta"?:…,"ttl"?:…}` | 201 `{ok,upload}` (reserves quota; `key` required for `object` Boxes, forbidden for `queue`/`ephemeral`) |
| `GET …/uploads/{id}` | | `{ok,upload}` (current `offset` for resume) |
| `PATCH …/uploads/{id}?offset=<n>` | raw chunk bytes | `{ok,upload}` (409 on offset mismatch; 507 if exceeding `total_size`) |
| `POST …/uploads/{id}/complete` | optional `{"sha256":"<64 hex>"}` | 201 `{ok,item}` (`queue`/`ephemeral`) or `{ok,object}` (`object`) |
| `DELETE …/uploads/{id}` | | `{ok}` (aborts upload and frees reserved quota) |

`BoxItem`: `id, space_id, box_name, seq, sender, size, sha256, content_type,
meta_json, expires_at, created_at`. `BoxObject`: `space_id, box_name, key,
version, etag, size, content_type, meta_json, created_at`. ETag = hex SHA-256
of the content. Items go to `queue`/`ephemeral` Boxes and objects to `object`
Boxes; the wrong mode is 400.

### 5.3 ACK

`DELETE …/items/{id}` and the batch `POST …/items/ack` delete items in that
Box only. The batch runs in one transaction; duplicate IDs are ignored; IDs
not in this Box (already ACKed, expired, other Box/Space) are reported in
`missing`, so retries are idempotent and reveal nothing about other Boxes.
Servers without batch ACK answer 405; clients fall back to per-item DELETE.

## 6. Content envelope and secretstream

End-to-end payloads between ledger devices (file metadata, SDK message bodies)
use static X25519 identities whose public keys are pinned from verified group
state. `body` = base64 of `nonce[24] || crypto_box_easy(plaintext)`, where the
plaintext is JSON:

```json
{"context":[1,"<app>","<group>","<sender>","<recipient>","<kind>","<object-id>"],"value":{}}
```

The receiver requires `context` to equal the expected routing exactly. Kinds
in use: `file` (value `{key,header,…}` — secretstream key/header plus
encrypted application metadata) and SDK-defined message kinds (`message`
value `{data:<base64>[,expires]}`, `stream` value `{key,header}`).

Bulk data uses libsodium `crypto_secretstream_xchacha20poly1305`: records with
tag MESSAGE (0), the last with FINAL (3); AAD is the whitespace-free UTF-8
JSON array `[1,app,group,sender,recipient,kind,id,sequence]`. Duplicate,
reordered, modified or post-final records are rejected. Static identities
give no forward secrecy. Vectors: `crypto-vectors.json`.

## 7. Signed group ledger

Group membership is an append-only chain of entries signed by clients. The
relay authorizes and orders transitions but cannot forge a trusted key.

### 7.1 Entries and payloads

```json
{"payload":"<base64>","signature":"<hex Ed25519>","signer":"<device>","authorization":{…optional nested entry…}}
```

`signature = Ed25519(signing_key(signer), payload bytes)`. A device's signing
key is `Ed25519.NewKeyFromSeed(SHA-256("common-relay/group-signing/v1\0" ||
x25519_secret[32]))`. The payload hash `hex(SHA-256(payload bytes))` links
entries (`previous`) and binds requests (`request_hash`) and grants
(`anchor_hash`). Payloads are at most 32 KiB decoded.

Group state (all fields required except `closed`, `name`):

```json
{"closed":false,"name":"我的设备","version":1,"app":"…","group":"…","revision":3,"previous":"<sha256 of rev 2 payload>","members":[{"device":"mac","name":"Mac","public_key":"<x25519 hex>","signing_key":"<ed25519 hex>","manager":true}],"invitation":"","request_hash":""}
```

Join request: `{version:1,app,group,invitation,member,token_hash}`
(`member.manager` must be false). Admission grant (§7.5):
`{version:1,purpose:"common-relay/admission/v1",mode:"auto",app,group,invitation,expires,secret_hash,delegate_key,anchor_revision,anchor_hash}`.

State rules: `version` 1; `revision` ≥ 1; 1–32 unique members, at least one
manager, unless `closed:true` with an empty member list; names non-blank, ≤
128 bytes; managers need a signing key; `name` is an immutable display field
(absent means the group ID is the display name).

### 7.2 Strict payload

The server and every SDK accept exactly one encoding, so no parser reads a
signed record differently:

- canonical standard base64 (padding, no CR/LF, zero pad bits) of valid UTF-8
  holding one JSON object, only JSON whitespace around it;
- exactly the schema's keys: no unknown, duplicate, case-variant or escaped
  keys; required keys present;
- strings are strings; `manager`/`closed` are `true`/`false`; integers are `0`
  or unsigned decimal without leading zeros, ≤ 2^53−1; no `null`;
- no unescaped control characters and no `\uD800`–`\uDFFF` escapes.

Vectors: `group-vectors.json` → `strict_payload` (signed correctly, encoded
ambiguously). `common-relay check` scans stored entries.

### 7.3 Transitions (`PUT /v2/group`, Bearer)

The new entry must have `revision = old + 1`, `previous = sha256(old
payload)`, the same `name`, be signed by the requesting device (whose signing
key comes from the previous state), and be exactly one of:

| Transition | Who | Constraints |
|---|---|---|
| add / upgrade one member | manager that owns the manual invitation | `invitation` = invitation ID, `request_hash` = hash of the claimed request, member equals the request's member (manager flag chosen by the approver); upgrade = legacy member gaining a signing key with the same public key |
| remove one member | manager, or the member itself | `invitation`/`request_hash` empty; the removed token is revoked |
| rename one member | manager, or the member itself | only that `name` changes |
| disband | manager | `closed:true`, no members; all tokens and invitations revoked |

409 `stale revision` on a wrong revision/previous; 507 once revision ≥ 4096
unless the change shrinks the group. Nothing follows a closed state.

### 7.4 Bootstrap and self-service creation

- **Bootstrap** — the operator runs `common-relay group-bootstrap --app A
  --group G --credential-out F` (10-minute secret). The first manager posts
  `POST /v2/group/bootstrap` with `Authorization: Bootstrap <secret>` and
  `{entry,token_hash}`: revision 1, empty previous/invitation, signer a
  manager; pre-existing devices of that namespace must appear unchanged as
  non-manager members. Identical retries are idempotent.
- **Self-service** — only for apps in `--self-service-apps` (`*` = all):
  `POST /v2/group/create` without device credential, `{entry,token_hash}`;
  one member (the signing manager), revision 1, group ID `g-` + 32 hex,
  non-empty `name`. Identical retries (same root entry and active token) are
  idempotent even after later revisions. Global limits: 20 creations/hour,
  1000 total (429 with `Retry-After: 3600`).

### 7.5 Invitations and joining

Managers create invitations with `POST /v2/group/invitations`
`{secret_hash, mode?, grant?}` → `{id, expires, mode}`; at most 16 unused per
group (429), 10-minute lifetime. A spent invitation (its join committed) stays
until expiry so the joiner can replay its exact commit after a lost reply, but
it no longer counts toward the 16. The trusted channel (QR/link) carries the
complete invitation:
`{version:1,mode,url:"wss://host/v2/ws",app,group,id,expires,secret,manager:{…},grant?,delegate_secret?}`.

**Manual** (`mode` omitted or `manual`, no grant):

1. Joiner: `POST /v2/enroll/{id}` with `Authorization: Invitation <secret>`
   and its signed join request (its own new token's hash inside). One request
   per invitation; an identical retry returns `{pending}`, another is 409.
2. Manager: `GET /v2/group/invitations/{id}` → `{request, approved}`, then
   approves with the add transition (`PUT /v2/group`).
3. Joiner: `GET /v2/enroll/{id}` with `Authorization: Claim <token>` →
   `{entry}` (null until approved) and verifies it against the pinned
   manager key before trusting any roster.

`DELETE /v2/group/invitations/{id}` cancels.

**Auto** (`mode:"auto"`): the manager derives a delegate key from a fresh
32-byte `delegate_secret` (same derivation as §7.1), signs a grant anchored to
the current tip (`anchor_revision`, `anchor_hash`, `expires` ≤ 600 s ahead,
`secret_hash` = the invitation secret's hash) and posts it with the
invitation. The QR/link adds `grant` and `delegate_secret`; the relay never
sees the delegate private key. After the normal `POST /v2/enroll/{id}`:

- `GET /v2/enroll/{id}/auto?after=N` (Claim) → `{entries, revision, entry}`:
  up to 64 entries from the anchor (default `after` = anchor − 1).
- `POST /v2/enroll/{id}/auto` (Claim) with a state that appends exactly the
  requested non-manager member, signed by the delegate key, `signer` = the
  inviting manager, `authorization` = the exact grant entry.

The server checks the stored grant, issuer still a manager, request hash and
member, unused device ID and capacity in one transaction. Repeating the same
committed POST is idempotent; a stale proposal is 409 (refetch, re-sign,
retry). Readers verify delegated entries by the same rules regardless of the
current time. Cancellation, expiry, issuer removal or disband stop admission.

### 7.6 Reading and notifications

`GET /v2/group?after=N` (Bearer) → `{entries:[…≤64], online:[device IDs],
revision:<count>}`; 404 before initialization. After each commit online
members receive `group.changed`; removed devices and (on disband) everyone
are disconnected. Clients must verify every entry from their pinned state; the
HTTP roster and `online` are never trust input.

### 7.7 Leaving and disbanding

`POST /v2/group/exit` (Bearer) with a signed state that no longer contains
the signer (self-removal, or `closed` disband by a manager; a sole manager of
an otherwise empty group disbands). The last manager cannot leave while other
members remain (the state would have no manager); it must disband instead.
SDKs offer an offline `check_exit` so an app can validate the exit before
clearing local state and notifying the relay best-effort. The device's token is revoked by the
commit; a revoked token may still re-post the exact committed exit entry and
gets it back, so a lost response is recoverable. Clients persist the pending
exit before sending.

### 7.8 Compact invitation links

`common-relay://<relay-authority>/v2/i/<id>#<key>[.<access>]`

- `id`: invitation ID as base64url (22 chars); `key`: fresh random 32-byte
  SecretBox key as base64url (43 chars); optional `.access` = base64url of the
  server access password (must decode to a valid password; empty suffix,
  padding or a second `.` is rejected).
- The relay URL is `wss://<authority>/v2/ws` (`ws://` only for explicit
  loopback tests). Userinfo, query strings, non-canonical base64url, wrong
  lengths, other paths (including the retired `/i/` form) are rejected.
- Packet: base64 of `nonce[24] || secretbox(JSON
  {"version":1,"purpose":"common-relay/invitation-link/v1","invitation":{…}},
  nonce, key)`, 40–16384 decoded bytes. The password is never inside.
- `read_token = hex(SHA-256("common-relay/invitation-link/read/v1\0" ||
  key))`; the server stores `read_hash = hex(SHA-256(read_token))`.

| Endpoint | Contract |
|---|---|
| `POST /v2/group/invitations/{id}/link` | inviting manager Bearer; `{read_hash, packet}`; only for unclaimed active invitations; immutable (exact retry OK, else 409) → `{published:true}` |
| `GET /v2/enroll/{id}/link` | `Authorization: InvitationLink <read_token>` → `{version:1,packet}` while active, unapproved and the issuer is still a manager |

After decrypting, the resolver requires version/purpose, the same relay URL
and ID as the link, its own app, and an unexpired invitation; it sends the
link's password (or its own, only to its own relay) as `Relay-Access`.

## 8. Files (`/v2/files`)

Resumable transfer of ciphertext between two active ledger devices of the
same group (Bearer = ledger token).

| Method & path | Who | Contract |
|---|---|---|
| `POST /v2/files` | sender | `{id,to,size,metadata,sha256,expires?}`; 201 with `File`, `offset:0`, `state:"uploading"`; existing ID 409 (query and compare, then resume) |
| `GET /v2/files` | recipient | JSON array of its unexpired `ready` files (≤100) |
| `GET /v2/files/{id}` | sender or recipient | `File` |
| `PUT /v2/files/{id}/data` | sender, while uploading | `Upload-Offset` must equal the current offset (else 409); 1 B–1 MiB per request; returns `File` |
| `POST /v2/files/{id}/commit` | sender | requires offset = size and matching SHA-256 (else 409) → `state:"ready"`; idempotent |
| `GET /v2/files/{id}/data` | recipient, ready | ciphertext, HTTP Range supported |
| `DELETE /v2/files/{id}` | sender or recipient | 204 |

`File`: `id, to, from, size, offset, metadata, sha256, state, expires`.
`size` 1 B–1 GiB and `sha256` cover the whole ciphertext file; `metadata`
(1–8192 bytes) is a `file` content envelope (§6); `expires` ≤ 24 h (default
24 h). Ciphertext layout: records `length[4, big-endian] ||
secretstream-ciphertext[length]`, 17–65536 bytes each, last record FINAL.
Clients must not publish data before the FINAL record verifies and must not
derive local paths from remote names. Unknown peer 404; revoked sender or
recipient 403; quota or disk reserve 507. Expired and partial transfers, and
transfers of revoked devices, are purged.

## 9. `crs1` sealed bridge payloads

Bridge plugins encrypt plaintext received over TLS to the binding's
`seal_public_key` (X25519) before it touches disk. Item `content_type` is
`application/vnd.common-relay.sealed`; the item meta carries
`"sealed":"crs1"` and the original `content_type`.

```text
"CRS1" (4)
box.SealAnonymous(content_key[32], recipient_pk) (80)
nonce_prefix (16)
frames: uint32 BE length || secretbox(chunk, prefix || uint64 BE counter, content_key)
```

Chunks are at most 64 KiB plaintext (frame length 16…65552); counters start
at 0 and the final frame sets bit 63, so truncation, reordering and trailing
data fail. Empty plaintext is one empty final frame. Vectors:
`sealed-vectors.json`.

## 10. `/v2/me`

`GET /v2/me` → `{ok:true, device:{id,name,public_key,is_admin,revoked,created_at}}`
for a device, `{ok:true, root_admin:true}` for the Root Admin, 401 otherwise.
Servers that predate it answer 404 (SDKs report "unsupported").

## 11. Admin control plane (`/v2/admin/*`)

Bodies are JSON (≤ 64 KiB, unknown fields rejected → 400). Errors are
`{ok:false,error}` with the status mapping of §13.

| Route | Purpose |
|---|---|
| `GET status` | counts, used bytes, global quota, online peers, `sync_conflicts`, plugins |
| `GET metrics` | `{metrics:{started_at,uptime_seconds,edge:{…},spaces:{"<space>":{messages_online,messages_offline,stream_frames,stream_bytes,stream_drops,last_at}},devices:{…},keepalive_timeouts,replaced,box_inline,box_inline_skipped,stream_frames,stream_bytes,stream_drops,recent:[…≤30]}, sync_conflicts, ledger:{rows:[{app,kind,requests,last_at}]}}` |
| `GET`/`PUT access-password` | read hash prefix/source; set `{access_hash:"<64 hex>"}` (takes effect immediately) |
| `GET`/`POST devices` | list; create `{id,name,public_key,is_admin}` → `{device, token}` (token shown once) |
| `DELETE devices/{id}` | revoke and disconnect |
| `GET`/`POST spaces` | list (with `governance`, `quota_bytes`, members, online flags, boxes, usage); create `{id,name,trust_level,quota_bytes?}` |
| `PUT spaces/{id}/quota` | `{quota_bytes}` (`0` resets to default Space quota) |
| `PUT spaces/{id}/members` | `{device_id, role}`; disconnects the device to apply the role |
| `GET`/`POST spaces/{id}/boxes` | list; create `{name,mode,max_bytes?,keep_versions?,ttl_sec?}` |
| `GET plugins[?plugin_id=]` | `{registered, plugins (schemas), bindings}` |
| `PUT plugins` | create/replace `{plugin_id,mount,space_id,box_name,config,enabled?,if_version?}`; omitted secret keys are kept |
| `GET`/`PATCH`/`DELETE plugins/{plugin}/{mount}` | read; merge-update `{space_id?,box_name?,enabled?,config?,if_version?}` (a `null` config value deletes the key; never creates); delete |
| `GET`/`PUT`/`DELETE plugins/{plugin}/{mount}/accounts` | per-binding accounts; PUT `{scope_key,username,password|secret_sha256,mode,meta_json}`; DELETE `?scope_key=` |

Bindings: secret config fields are write-only (stored encrypted, reported
only in `secret_keys` and `summary.has_token`/`has_hmac`). Each update
increments `config_version`; passing `if_version` > 0 that does not match is
409. Binding requires the Space trust to allow the plugin (403 otherwise).

## 12. Edge plugins (`/edge/{plugin}/{mount}/...`)

No `Relay-Access`; each binding authenticates its own clients, failed
attempts are limited per source (20 per 10 min, `mcpedge` 30) → 429. Request
bodies are capped at 513 MiB overall and by each plugin's `max_bytes`.

| Plugin | Min trust | Auth | Behavior |
|---|---|---|---|
| `drop` | `bridge_allowed` | `Bearer` (config `token_sha256`) | POST body → queue item (sealed if `seal_public_key`); default 32 MiB |
| `webhook` | `bridge_allowed` | `Bearer`; optional HMAC-SHA256 over `timestamp "." body` in `X-Webhook-Signature` (`sha256=` hex) with `X-Webhook-Timestamp` (±5 min, single use); `Idempotency-Key` dedup | body (validated if JSON) → queue item, sealed if configured; default 32 MiB, max 64 MiB |
| `webdav` | `client_encrypted` | Basic, per-folder accounts | `object` mode: GET/HEAD/PUT/DELETE/PROPFIND on an object Box; `queue` mode (needs `bridge_allowed`): write-only inbox |
| `mcpedge` | `bridge_allowed` | `Bearer` / `X-Console-Key` accounts (SHA-256 stored) | read-only MCP gateway forwarded as `rpc.req` to `target_device` over `/v2/ws`; rejects any `Origin` |
| `egress` | `bridge_allowed` | outbound-only (`HMAC-SHA256` over `timestamp "." body` in `X-Relay-Signature`) | subscribes to committed Box events (`item`/`object`/`object_deleted`) and asynchronously POSTs metadata-only JSON (never payload bytes) to `target_url` (rejects private/loopback URLs unless `allow_private_url:true`) |

## 13. Limits and status codes

| Limit | Value |
|---|---|
| Pipe frame | 256 KiB; inline item ≤ 64 KiB |
| Peer send queue / global queued bytes | 64 frames / 32 MiB (overflow disconnects) |
| Keepalive | ping every 30 s, 10 s timeout |
| Offline messages | default TTL 24 h; ≤ 256 flushed per Space per connect |
| Box item/object | default 64 MiB (ephemeral 512 MiB), hard 512 MiB |
| Batch ACK | 1–200 IDs, body ≤ 64 KiB |
| Quotas (defaults) | per Space / per app 2 GiB (`--app-quota`), global 5 GiB (`--global-quota`), free-disk reserve 2 GiB (`--disk-reserve`) |
| Group | ≤ 32 members, ≤ 4096 revisions, 64 entries per page, payload ≤ 32 KiB, group JSON body ≤ 64 KiB |
| Invitations | 10 min, ≤ 16 unused per group; auto grant expiry ≤ 600 s |
| Self-service creation | 20/hour, 1000 total |
| Files | 1 GiB each, chunks ≤ 1 MiB, expiry ≤ 24 h, metadata ≤ 8 KiB |

| Status | Meaning |
|---|---|
| 400 | malformed JSON/body, invalid input, wrong Box mode |
| 401 | `Relay-Access` or credential missing/wrong |
| 403 | role/trust boundary/authorization (incl. ledger `not authorized`, revoked file peer) |
| 404 | unknown route, object, item, invitation (or expired) |
| 405 | method not allowed (also: batch ACK on older servers) |
| 409 | CAS/ETag conflict, stale revision, claimed invitation, offset/state conflict, duplicate ID, `if_version` mismatch, replayed webhook |
| 413 | edge payload over the plugin limit |
| 429 | invitation capacity, self-service creation capacity, edge auth/query limits |
| 503 | storage unavailable (v2 plane) |
| 507 | quota, Box `max_bytes`, disk reserve, membership history capacity |

## 14. Shared test vectors

Generated reproducibly by `go run ./scripts/protocol-vectors` (`-check`
verifies; `scripts/protocol-vectors` test fails when stale). Public test
material only.

| File | Content | Consumed by |
|---|---|---|
| [vectors.json](vectors.json) | `hash_secret` cases, `binary_stream_frame`, `trust_matrix` | server core; Go, Dart, Java, Rust, Swift (hash; frame where implemented); Python (hash via `groups.digest`) |
| [sealed-vectors.json](sealed-vectors.json) | `crs1` valid blobs (single, empty, two-frame) and mutation cases | Go, Dart, Java, Rust, Swift |
| [group-vectors.json](group-vectors.json) | signed fixtures, transitions, auto admission, `strict_payload`, `entry_hashes` (payload hashes, signature validity, chain links) | server ledger; Go, Dart, Java, Rust, Swift, Python |
| [invitation-link-vectors.json](invitation-link-vectors.json) | packet, read token/hash, links with/without password, invalid suffixes and links | Go, Dart, Java, Rust, Swift, Python |
| [crypto-vectors.json](crypto-vectors.json) | content envelope and secretstream record (§6) | Go, Dart, Java, Rust, Swift, Python |

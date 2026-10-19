# Common Relay v1

唯一支持的协议版本。不提供其他协议的兼容适配。

## 身份与接入

`GET /relay/v1/ws` 使用 `Authorization: Bearer <device-token>` 和 `Sec-WebSocket-Protocol: common-relay.v1`。TLS 在反向代理终止；不使用查询参数传凭据，不协商压缩。未授权返回401，重复在线设备或连接额度耗尽返回409。

服务器发送 `welcome`，含 `version:1`、`identity:{app,group,device,public_key}` 和 `capabilities`。SDK 必须核对自己本地身份。应用、设备组来自服务器登记记录，不信任客户端提交的命名空间。同一设备只允许一个连接。

`peers` 请求返回当前同组在线设备列表。发现返回的公钥只是信息，不能自动写入可信公钥表。

## 控制消息

JSON 控制帧通用字段：`type`、`id`（32位小写hex随机对象ID）、`to`、`from`、`body`。服务器覆盖发送方，不接受客户端冒充其他设备。未知类型返回 `error`，含关联ID和固定错误码。

| 请求 | 字段 | 结果 |
|---|---|---|
| `peers` | `id` | `peers` 与 `devices` |
| `message` | `id,to,body,offline?,ttl?,expires?` | `forwarded`、`stored` 或 `received` |
| `ack` | `id,from` | `acked`；仅收件人可确认自己的消息 |
| `stream.open` | `id,to,body` | 对端收到请求；仅在线，不允许offline |
| `stream.accept` | `id,body` | 发起方收到accept，接收方收到ready |
| `stream.credit` | `id,sequence` | 累计已消费记录数，转发给发送方 |
| `stream.close` | `id` | 两端关闭当前流，不恢复或重放 |

`body` 是 SDK 生成的不透明加密信封。消息 body 最多256KiB（含Base64），不是256KiB明文。默认TTL24小时。离线消息成功持久化后返回stored；收到ACK后保留有效期内的去重收据。重试必须使用相同ID与原密文，不允许覆盖同ID内容。新 SDK 离线消息同时发送固定绝对 `expires`（Unix 秒），服务端以此作为保存期限；值必须晚于当前时间且不超过24小时，优先于 ttl。重试不延长首次期限。旧客户端不含 expires 时保留 ttl 行为；旧服务不能保证此新增期限约束，应先更新服务端。

`forwarded` 只代表进入在线转发队列，不表示设备收到或业务完成。离线消息至少一次投递；应用持久化并按ID幂等处理后才ACK。远控、ADB和临时授权不得使用offline。

## 双向流

open/accept各带独立方向的加密secretstream描述。仅两端完成accept后可发送二进制记录。每个设备最多8条流，全局最多256条；未接受请求40秒到期。

二进制帧格式：`0x01 | stream-id[16] | sequence[8,big-endian] | ciphertext[17..65536]`。每方向从序号0开始。每条最多65519字节明文；各方向最多8条未消费记录。

接收者完成解密及消费后发送 `stream.credit(sequence=下一条待接收序号)`。服务器验证确认值单调且不超过已发送数量。SDK 在额度耗尽时暂停发送；不无限缓存。主动close、断线、撤销和非法序号终止流。取消不是可靠的半关闭；需要完整结束的应用应接收并验证secretstream final记录。

## 内容加密

设备 Curve25519 私钥在客户端生成，公钥通过受信通道固定。`body` 为 Base64：`nonce[24] | crypto_box_easy ciphertext`。解密得到 JSON：

```json
{"context":[1,"app","group","sender","recipient","kind","object-id"],"value":{}}
```

context必须与外层路由和预期kind逐项相等。kind为message、stream.open、stream.accept或file。message的在线value为`{"data":"<base64 plaintext>"}`；新SDK离线value增加经加密认证的`expires`，与外层绝对期限相同，接收端不得投递已过期内容。旧信封仍可解密，但没有新的认证期限保证。stream的value为`{"key":"<hex32bytes>","header":"<hex24bytes>"}`。

流与文件的secretstream AAD是无空白UTF-8 JSON数组：`[1,app,group,sender,recipient,kind,id,sequence]`。流kind为stream，文件为file。普通记录使用tag MESSAGE（0），末条使用FINAL（3）；重复、乱序、修改以及final后的记录必须拒绝。

固定公开测试材料在 `crypto-vectors.json`。它们不是部署凭据。静态身份加密不提供前向保密。

## 文件

`POST /relay/v1/files`：提交 `id,to,size,metadata,sha256,expires?`。size与SHA-256针对完整密文文件；metadata是kind=file的信封，其value包含secretstream key/header和加密业务metadata。服务器先预留配额，返回201和offset=0；同ID返回409，客户端查询状态并严格核对原描述才能续传。

密文文件为连续记录：`length[4,big-endian] | secretstream-ciphertext[length]`，长度17..65536。客户端不得将未验证完整性和final标记的文件发布到最终目的路径。文件名不来自公开HTTP头，解密后也不能直接用远端文件名拼接任意路径。

- `PUT /files/{id}/data`：`Upload-Offset`必须等于服务器当前偏移；每次1字节至1MiB，完整写入并同步后推进offset。
- `POST /files/{id}/commit`：上传完整并匹配SHA-256后变为ready。
- `GET /files`：仅返回当前设备未过期的ready收件列表。
- `GET /files/{id}`：发送方、收件方可查询同组对象状态。
- `GET /files/{id}/data`：仅收件方读取ready密文，支持HTTP Range。
- `DELETE /files/{id}`：发送方取消或收件方确认后删除。

所有文件路径均以 `/relay/v1` 为前缀；SDK禁止跨源重定向，以免泄露令牌。

默认单文件1GiB、应用2GiB、全局5GiB，保留2GiB可用磁盘。超配额返回507，偏移冲突或状态错误返回409。部分上传与过期内容定期清理，不提供永久网盘存储。

## SDK 持久化与清理

离线能力需要持久化日志；原密文重试、7天去重记录、Python旧表迁移、清理周期及接入接口见 [可靠性说明](../docs/RELIABILITY.md)。共享 `crypto-vectors.json` 增加含认证有效期的离线消息向量；原密码算法、上下文与流格式不变。

## 设备组管理扩展

详见 [设备组与信任链](../docs/DEVICE-GROUPS.md)。现有 v1 消息、流和文件格式不变；管理状态独立持久化，普通接入令牌不能直接获取管理权限。

| HTTP 接口（均在 `/relay/v1` 下） | 用途与授权 |
|---|---|
| `POST /group/bootstrap` | `Bootstrap <一次性秘密>`，提交 `{entry,token_hash}`，初始化签名管理名单 |
| `GET /group?after=N` | 成员 Bearer，最多 64 条后续签名记录及在线设备 ID |
| `PUT /group` | 管理员 Bearer + 签名记录，原子增加/升级/移除一个成员 |
| `POST /group/invitations` | 管理员 Bearer，提交 `secret_hash`，返回邀请 ID 与 expires |
| `GET /group/invitations/{id}` | 原邀请管理员读取待批准的已签名申请 |
| `DELETE /group/invitations/{id}` | 原邀请管理员取消邀请 |
| `POST /enroll/{id}` | `Invitation <短时秘密>`，新设备提交签名申请，只能被一个请求认领 |
| `GET /enroll/{id}` | `Claim <本机接入令牌>`，按申请中 token_hash 验证，读取批准记录 |

签名记录为 `{payload,signature,signer}`。payload 解码后名单字段为 `{version:1,app,group,revision,previous,members,invitation,request_hash}`。成员字段为 `{device,name,public_key,signing_key,manager}`。新申请的 payload 为 `{version:1,app,group,invitation,member,token_hash}`，member.manager 必须 false，批准时由邀请管理员明确授予权限。

#### 严格载荷

各语言 JSON 解析器对重复键、键名大小写、未知字段、null、数字形式及孤立代理项的处理不一致；同一签名记录若在不同实现中读出不同含义或部分实现无法读取，整条链会分叉或卡死。因此服务端与四 SDK 对名单、申请及自动邀请授权 payload 执行同一字节级校验，任一不满足即拒绝：

- payload 为标准 base64（含填充、不含换行），解码后为合法 UTF-8，且是一个 JSON 对象，前后只允许 JSON 空白。
- 字段集合与上文完全一致：必填字段齐全，不得有未知字段、重复键、大小写变体或转义写法的键。名单仅 `closed`、`name` 可省略；成员对象五个字段均必填。
- 类型严格：字符串字段只能是字符串，`manager`/`closed` 只能是 `true`/`false`，整数只能是 `0` 或无前导零的十进制且不超过 2^53−1（不得带符号、小数或指数）；不得出现 null。
- 字符串内不得含未转义控制字符或 `\uD800`–`\uDFFF` 转义；其余标准转义允许。

共享向量 `group-vectors.json` 的 `strict_payload` 包含签名正确但编码有歧义的反例，由 `scripts/group-strict-vectors.py` 生成。升级服务端前用 `common-relay check` 扫描已有记录。

初始化 revision=1、previous 为空。后续 previous 必须为前一 payload 的 SHA-256；新增或旧成员升级时 invitation/request_hash 绑定原申请；删除时两字段为空。对端新加入时以可信邀请中的签名公钥验证批准快照，此后只接受连续、合法的签名更新。不得用未验证的 HTTP 成员列表填充 trusted_peers。

成功管理请求返回 200，失败使用 400/401/403/404/409/429/507，正文不包含令牌或私钥。初始化重复提交只允许在初始化秘密有效期内且记录、令牌哈希完全一致的幂等请求。服务端成功变更后向组内在线连接发送 `{type:"group.changed",revision:N}`；客户端需验证更新，通知本身不是信任证明。已管理组的连接在 welcome 后同样收到当前版本提示，防止错过连接前的变化；仅版本更新时才需要刷新。

### Self-service group creation

`POST /relay/v1/group/create` accepts `{entry, token_hash}` without a device credential, only for explicitly enabled application namespaces (`--self-service-apps`). The signed initial state has exactly one member (the signer, a manager), revision 1, empty previous/invitation/request_hash, a random `g-` + 32 lowercase hex group ID, and a nonempty `name` (up to 128 UTF-8 bytes). `name` is an optional immutable display field on all group states; absent means the group ID is the display name. Member changes preserve it. Existing device namespaces and pending bootstrap reservations cannot be claimed.

Persist the prepared creation request before sending. An identical initial entry and still-active token hash is idempotent, including after later membership revisions. Different credentials or root entries are rejected. Durable global quotas allow 20 creations/hour and 1000 total (429 with Retry-After); other apps remain disabled. The server stores only token hashes; no private key is sent. `group-vectors.json.self_service` supplies a shared Unicode-name signed root.

### Rename, leave and disband

A member may sign a transition changing only its own `name` or removing itself. A manager may rename any one member, remove another member, leave while another manager remains, or disband the group. A rename preserves all identity/key/role fields, changes exactly one name, and has empty invitation/request_hash. Names are nonblank, at most 128 UTF-8 bytes.

Disband is a terminal signed state with `closed: true` and an empty members array; it requires a manager in the previous state. Active states still require at least one manager. No transition can follow a closed state. A sole manager leaving an otherwise empty group signs this terminal state. All group tokens and invitations are revoked on disband.

`POST /relay/v1/group/exit` accepts the signed exit/disband entry with Bearer authorization. The signer must be absent from the resulting membership. A revoked token can only acknowledge the exact previously committed signed exit from that same device/group/revision, allowing response-loss recovery without restoring access. Persist `pending_exit` before sending. Normal `remove` SDK methods remain for other devices; use the explicit exit flow for self-removal.

### Invitation approval modes

`POST /group/invitations` accepts `{secret_hash, mode?, grant?}`. Omitted `mode` means `manual`; unknown modes are rejected. The response is `{id, expires, mode}`. Manual invitations retain the existing request → administrator approval → finish flow. A manual request must not carry a grant.

For `auto`, the inviter generates a separate random 32-byte `delegate_secret`, derives its Ed25519 signing key using the same domain-separated derivation as device signing, and signs this grant with its own administrator key:

```json
{"version":1,"purpose":"common-relay/admission/v1","mode":"auto","app":"…","group":"…","invitation":"<random 16-byte lowercase hex>","expires":2000000000,"secret_hash":"<SHA-256 of invitation secret>","delegate_key":"<Ed25519 public key>","anchor_revision":1,"anchor_hash":"<SHA-256 of the currently verified group payload>"}
```

The timestamp above is illustrative. Actual expiry must be in the future and at most 600 seconds ahead of the server. `grant` is a normal `{payload,signature,signer}` envelope, with no nested authorization. The server verifies the issuer is a current administrator and the anchor exactly matches the current group tip. The QR/link contains the existing invitation fields plus `mode: auto`, `grant`, and `delegate_secret`. The delegation secret never goes to the relay; it is sensitive bearer authority for this invitation, not a device identity key. Do not log or retain it after the pending join completes.

After the normal `POST /enroll/{id}` claims one signed join request, the joining SDK completes automatic admission without any inviter activity:

| Endpoint | Authorization / behavior |
|---|---|
| `GET /enroll/{id}/auto?after=N` | `Claim <joining-device token>`; returns `{entries, revision, entry}`. Starts at the grant anchor, pages at most 64 entries, ends at the current tip or already approved entry. `after` defaults to anchor revision minus one and cannot precede it. |
| `POST /enroll/{id}/auto` | Same Claim token; submits a membership entry signed by the delegation key, with `signer` set to the inviting administrator and `authorization` containing the exact signed grant. Returns the committed entry. |

The joining SDK verifies the grant against the invitation's pinned manager, checks secret/delegate-key/expiry/ID binding, verifies the first fetched payload against the signed anchor hash, then verifies every later chain transition. It appends exactly its requested ordinary member, advances revision/previous, binds invitation/request_hash, and signs the full state with the delegation key. No server-authored roster is trusted without this verification.

Every SDK's chain verifier recognizes `authorization`, verifies the administrator's grant and delegated entry signature, and permits only one new non-manager member with all existing members, group name and scope unchanged. No legacy identity upgrade, rename, removal, disband or manager grant can use this authority. If the previous revision equals the anchor, its hash must match. Historical verification does not compare grant expiry with the reader's current clock: the server enforces expiry at admission, while an already committed chain remains valid later.

The server also requires the exact stored grant, claimed request hash and member, current issuer permission, active invitation, unused device ID and normal capacity limits. Registration, chain insertion and invitation consumption are one transaction. Repeating the same committed POST is idempotent; another proposal is 409. On concurrent changes, keep the pending request and retry `finishJoin` / `finish_join`: it fetches and verifies the current chain before producing a new proposal. If a POST response was lost, the next finish reads and verifies the already committed chain instead of adding twice.

Cancellation, expiry, issuer removal and group disband prevent further admission. The server enforces single use and cancellation; as with the existing protocol, this is not an external transparency log or protection against colluding authorized clients and a forking server. The relay alone cannot forge a delegated entry because it never receives the delegation private key.

Compatibility: old invitations and callers default to manual. Pre-extension SDKs cannot verify delegated entries and must fail closed; update every member's SDK before enabling automatic invitations for that group. Old servers reject auto requests rather than silently downgrade them. Wire message/stream/file formats remain v1 and unchanged. Both modes still use `join` followed by `finishJoin` / `finish_join`; apps should automatically drive the latter, persist pending state on success and failure, and label auto progress as “正在加入” rather than asking for manual approval.

### Compact invitation links

New SDKs can call `invite(..., compact=True)` (Python), `invite(mode: ..., compact: true)` (Swift), `invite(mode: ..., compact: true)` (Dart), or `invite(mode, true)` (Java). Existing callers remain compatible; the returned invitation adds `short_link`. `resolve_invitation(link)` / `resolveInvitation(link)` authenticates and resolves the packet before the existing `join` flow. Old full JSON/Base64 invitations remain valid.

Wire form: `common-relay://<relay-authority>/i/<id>#<key>`. `id` is the invitation's random 16-byte ID encoded as unpadded base64url (22 characters); `key` is a fresh random 32-byte SecretBox key encoded as unpadded base64url (43 characters). The relay endpoint is derived as `wss://<relay-authority>/relay/v1/ws`; only explicit loopback tests may use ws. Reject userinfo, query strings, noncanonical base64url or wrong lengths. The complete link length depends on the relay authority. A shorter human guessable code is deliberately not used.

The inviter encrypts UTF-8 JSON `{version:1,purpose:"common-relay/invitation-link/v1",invitation:<complete existing invitation>}` with libsodium SecretBox (XSalsa20-Poly1305), a fresh random 24-byte nonce and the link key. The packet is standard Base64 of `nonce || MAC || ciphertext`, at most 16384 decoded bytes. It contains the original expiry, scope, pinned manager, invitation secret and automatic grant/delegation secret when applicable. The relay receives only ciphertext; authenticated decryption protects all of these fields.

Read capability: `read_token = lowercase_hex(SHA256(UTF8("common-relay/invitation-link/read/v1\0") || key))`. The key itself stays in the URI fragment and is never used in an HTTP URL, query, body or authorization header.

| Endpoint | Contract |
|---|---|
| `POST /group/invitations/{id}/link` | Inviting administrator Bearer. Body `{read_hash: SHA256(UTF8(read_token)), packet}`. Only unclaimed active invitations can be published. The packet is immutable; exact retries succeed, replacements return 409. |
| `GET /enroll/{id}/link` | `Authorization: InvitationLink <read_token>`. Returns `{version:1,packet}` only while the invitation is active and not approved. Requires a currently authorized issuer. |

After decryption, the SDK requires version/purpose match, the original relay URL and ID equal those in the compact URI, the app equal the receiving app, and expiry remain valid. Existing grant signatures and membership-chain checks still run during joining. Tampered ciphertext, a wrong key, cross-app/scope substitution and redirects are rejected; there is no fallback to trusting server-supplied plaintext. The fragment key is independent of both the invitation secret and delegate key, so the relay cannot derive signing authority from the read credential.

`group_invite_links` is an additive table with an invitation foreign key and delete cascade. Cancellation, expiry cleanup, issuer removal and disband remove or disable packets; successful approval makes them unreadable. A resolver needs an online relay, just as actual group enrollment does. Four SDKs share `invitation-link-vectors.json`, including authenticated ciphertext, key derivation and URL encoding. No business message/stream format changes.

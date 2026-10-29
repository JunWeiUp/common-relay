# Go client

原生 Go SDK：加密在线消息、在线设备查询、presence 通知、持久化离线消息、双向加密流和加密文件。独立 module 为 `github.com/JunWeiUp/common-relay/sdk/go`，Go 1.25+；仅依赖 `coder/websocket` 与 `golang.org/x/crypto`、`golang.org/x/sys`（Windows 文件锁），无需 CGO、libsodium、Rust 或预编译库。secretstream（xchacha20poly1305）基于 x/crypto 的 HChaCha20/ChaCha20/Poly1305 实现，与 libsodium 输出逐字节一致（`testdata/secretstream-libsodium.json` 由 PyNaCl 生成）。

当前通过源码接入，尚无稳定公共模块版本。在接入项目中：

```sh
go mod edit -require=github.com/JunWeiUp/common-relay/sdk/go@v0.0.0
go mod edit -replace=github.com/JunWeiUp/common-relay/sdk/go=/absolute/path/common-relay/sdk/go
go mod tidy
```

```go
import relay "github.com/JunWeiUp/common-relay/sdk/go"

// secretKey、trustedPeers、deviceToken 均由应用从私有存储提供。
identity, err := relay.NewIdentity("example", "my-group", "my-device", secretKey, trustedPeers)
if err != nil { return err }
client, err := relay.Dial(ctx, "wss://relay.example.com/relay/v1/ws", deviceToken, identity, relay.Options{})
if err != nil { return err }
defer client.Close()
peers, err := client.Peers(ctx) // 发现信息不能自动成为可信公钥。
if err != nil { return err }
_ = peers
receipt, err := client.Message(ctx, "peer-device", []byte("hello"))
if err != nil { return err }
_ = receipt // forwarded 只表示进入中继转发队列。
event, err := client.NextEvent(ctx)
if err != nil { return err }
if event.Type == "message" { handleMessage(event.From, event.Data) }
```

`GenerateKeyPair()` 本地生成 Curve25519 私钥和公钥；私钥必须持久化到应用私有存储，公钥通过可信配对固定。设备接入令牌独立使用，不能代替加密密钥。

### 离线消息

```go
journal, err := relay.OpenJournal(privateDir, nil) // 每个目录同一时间只允许一个实例（OS 文件锁）。
if err != nil { return err }
defer journal.Close()
client, err := relay.DialJournal(ctx, endpoint, deviceToken, identity, journal, relay.Options{})
id, _ := relay.NewMessageID() // 应用先持久化 ID，重试同一逻辑发送时复用。
receipt, err := client.MessageOffline(ctx, "peer-device", id, data) // stored 或 received
// 接收：业务事务提交后再确认。
if event.Type == "message" { process(event); err = client.Acknowledge(ctx, event) }
```

文件日志逐记录原子替换（临时文件、fsync、rename、目录 fsync），按应用/组/本机设备与对端/消息 ID 隔离，只存密文与摘要，不存令牌、私钥或明文。发送前持久化接收方、内容摘要、原密文和固定绝对 `expires`（默认 24 小时，`MessageOfflineTTL` 可设 1 秒–24 小时，并在信封内认证）；重试复用同一 ID、密文和期限，同 ID 不同内容/接收方被拒绝，过期后明确失败。`stored` 表示中继已保存，`received` 表示对端已确认（删除密文、终态保留 7 天）。`Acknowledge` 先写去重记录再发 ACK；ACK 丢失后的重投自动重新 ACK、不再交给业务，去重保留 7 天；已过期的离线消息自动 ACK 并丢弃。打开日志及连接期间每小时清理一次，每轮最多 256 次变更，可调用 `client.Cleanup()` / `journal.Cleanup()`。未配置日志时离线发送报错，离线接收仍明确断开、不自动 ACK。

### 双向流

`NextEvent` 返回 `stream.open` 请求，由应用 `AcceptStream` 或 `RejectStream`；`OpenStream(ctx, peer)` 发起。`Send(ctx, data, final)` 按 ≤65519 字节分记录，未消费记录达 8 条时暂停等待 credit；`Receive` 按序解密并回送 credit，FINAL 之后返回 `io.EOF`。乱序、重复、篡改及 final 之后的记录会终止流。`Close`/断线终止流，不重放；取消不是可靠的半关闭，需要完整结束时以 FINAL 判断（`ReceivedFinal`）。

### 文件

`PrepareFile` 将源文件加密为 `length[4 BE]|secretstream` 记录的暂存密文（0600，不覆盖已存在文件），`Files.Upload` 创建对象，409 后严格核对原描述再按服务器偏移续传（每块 ≤1 MiB）并提交；`Inbox`/`Status`/`Download`（Range 续传）/`Delete`。`DecryptFile` 先校验密文 SHA-256，再逐条认证并要求 final，同步后以硬链接发布到不存在的目标路径，不覆盖已有文件。远端文件名只是不可信元数据，可用 `SafeFileName` 处理后在应用自己的目录内选择唯一路径。`NewFiles` 只接受 `https://…/relay/v1/files`，拒绝重定向且不使用环境代理。

### 设备组

`NewGroups(&config, allowLocalTest)` 使用 `GroupConfig`，与 Python/Dart 的 JSON 配置字段一致（`app`、`group`、`device`、`secret_key`、`trusted_peers`、`url`、`token`、`group_entry` 及 `pending_*`），调用会就地更新它；应用在每次调用后将其持久化到私有存储。

- 创建/初始化：`PrepareCreate(groupName, deviceName)` 生成已签名草稿，应用保存后再 `Create()`；运维初始化用 `Bootstrap(code, name)`。
- 邀请：`Invite("manual"|"auto", compact)`（compact 时返回 `ShortLink`）、`ResolveInvitation(link)`、`Pending`、`Approve(invitation, request, manager)`、`Cancel`。
- 加入：`Join(invitation, name)` 后由应用驱动 `FinishJoin()`；auto 模式由扫码方验证授权链后自行签署入组，邀请端可离线。
- 成员变更：`Refresh`、`Remove`、`Rename`、`PrepareExit(disband)` + `Exit()`（退出本机或由管理员解散）。

签名载荷执行与服务端相同的字节级严格校验，签名链逐条验证（含委托 `authorization`，`VerifyGroupAdvance`），不信任未验证的 HTTP 成员列表。组 HTTP 请求拒绝重定向。`examples/groupprobe` 供 `scripts/group-interop.py` 驱动。

连接由 `Close` 结束，`Dial` 的 context 只控制握手。请求自身 context 可取消等待，但无法撤销已发送消息；请求上限 64、最长 45 秒，事件队列上限 64，满时关闭连接。断线后显式创建新连接，不重放。仅支持 WSS；拒绝重定向；测试选项只允许 `127.0.0.1` 的明文回环连接。

```sh
cd sdk/go
go test -race ./...
```

测试覆盖共享密码向量（含流与离线向量）、libsodium secretstream 逐字节一致与计数回绕换钥、上下文与公钥固定、篡改/过期拒绝、在线消息、查询、超时取消、关闭、重定向、无日志离线拒绝、日志重启重试/冲突/过期/终态/7 天清理/批量上限/目录独占、ACK 丢失重投去重、流 credit 窗口与 FINAL、文件加解密拒绝及上传续传/下载续传。仓库根目录的 `go test ./...` **不会**运行此独立 module，需单独执行。`scripts/lightweight-interop.py` 使用临时回环服务和身份验证 Python ↔ Go 在线互通；`examples/echo` 在配置含 `state_path` 时还回显离线消息（并 ACK）与流，可供 `scripts/local-interop.py` 驱动（双向离线 + 8 MiB 双向流）。

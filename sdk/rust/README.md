# Rust client

原生 Rust SDK，能力与 Swift/Java/Dart/Python 一致：加密在线/离线消息（持久化日志、ACK、去重、清理）、双向加密流、加密文件、在线设备查询与 presence、签名设备组（自助创建、manual/auto 邀请、加密短邀请链接、改名、退出、解散）。独立 crate `common-relay`（Rust 1.89+，tokio 异步），纯 Rust 实现：`crypto_box`（NaCl box）、基于 RustCrypto `chacha20`/`poly1305` 的 secretstream（与 libsodium 逐字节一致）、`ed25519-dalek`、`tokio-tungstenite` 与 `reqwest`，TLS 统一使用 rustls + ring（webpki 根证书）。无需 libsodium、C 编译器或预编译库；它不是共享核心，其他语言 SDK 不依赖它。

当前通过源码接入，尚无 crates.io 发布。在接入项目的 `Cargo.toml` 中：

```toml
[dependencies]
common-relay = { path = "/absolute/path/common-relay/sdk/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use std::sync::Arc;
use common_relay::{Client, Identity, Options, RelayJournal, new_message_id};

// secret_key、trusted_peers、device_token 均由应用从私有存储提供。
let identity = Arc::new(Identity::new("example", "my-group", "my-device", &secret_key, trusted_peers)?);
let journal = Arc::new(RelayJournal::open(private_state_dir)?); // 每个目录只能有一个实例
let client = Client::connect_with_journal(endpoint, &device_token, identity, Options::default(), journal).await?;
let peers = client.peers().await?;                     // 发现信息不能自动成为可信公钥
client.message("peer-device", b"hello").await?;        // 在线：forwarded 只表示进入转发队列
let id = new_message_id()?;                            // 应用先持久化此 ID，重试复用
client.message_offline("peer-device", &id, b"durable").await?; // stored 或 received
let event = client.next_event().await?;
match event.kind.as_str() {
    "message" if event.offline => { commit(&event.data)?; client.acknowledge(&event).await?; }
    "message" => handle(&event.from, &event.data),
    "stream.open" => { let stream = client.accept_stream(&event).await?; /* send/receive/close */ }
    _ => {}
}
```

## 离线消息

`connect_with_journal` 才能离线收发；`connect` 保持原有仅在线行为，此时离线发送/ACK 报错，收到离线消息明确断开且不自动 ACK。`RelayJournal` 每条记录一个文件（临时文件、fsync、rename、目录 fsync，权限 0600/0700），`journal.lock` 文件锁保证单一所有者，按应用/组/本机设备/对端/消息 ID 隔离，只存密文与摘要，不存令牌、私钥或明文。

发送前持久化接收方、内容摘要、原密文和固定绝对 `expires`（默认 24 小时，并在信封内认证）；重试复用同一 ID、密文和期限，同 ID 不同内容/接收方被拒绝。`stored` 表示中继已保存，`received` 表示对端已确认，终态保留 7 天。`acknowledge` 先写去重记录再发 ACK；ACK 丢失后的重投自动重新 ACK、不再交给业务，去重保留 7 天。打开日志时与连接期间每小时清理，每轮最多 256 次变更，也可调用 `cleanup()`。应用仍须按消息 ID 幂等。

## 双向流

`open_stream` / `accept_stream` / `reject_stream` 得到 `RelayStream`：`send(data, final)`、`receive()`、`received_final()`、`close()`。每个方向独立 secretstream 描述，每条记录最多 65519 字节明文，最多 8 条未消费记录（额度耗尽时暂停发送）；乱序、重复、篡改和 FINAL 之后的记录终止该流。收到的 `stream.open` 交给应用处理，不处理则服务器 40 秒后超时关闭。关闭/断线是取消而非可靠半关闭，需要完整结束时发送并检查 FINAL。

## 文件

`prepare_file` 把源文件加密为 `length[4 BE] | secretstream 记录` 的暂存密文；`RelayFiles::for_relay_endpoint(endpoint, token, options)` 提供 `upload`（409 时严格核对原描述后续传，每块 ≤1 MiB）、`inbox`、`status`、`download`（Range 续传）、`delete`。`decrypt_file` 先校验长度与 SHA-256，再逐条认证并要求 FINAL，最后以硬链接发布到不存在的目标路径，不覆盖已有文件；远端文件名仅经 `safe_file_name` 清洗后使用。`prepare_file` / `decrypt_file` 是阻塞 IO，大文件请放入 `spawn_blocking`。

## 设备组

`Groups::new(config, allow_local_test)` 使用与 Python/Dart 相同的 JSON 配置（`app`、`group`、`device`、`secret_key`、`trusted_peers`、`url`、`token` 及 `pending_*` 状态）。每次调用后，应用必须把 `groups.config` 持久化到私有存储。

- 创建/初始化：`prepare_create(group_name, device_name)` 先生成并保存已签名草稿，再 `create()`；运维初始化用 `bootstrap(code, name)`。
- 邀请：`invite(mode, compact)`（`"manual"` / `"auto"`，`compact` 时返回 `short_link`）、`resolve_invitation(link)`、`pending`、`approve(invitation, request, manager)`、`cancel`。
- 加入：`join(invitation, name)` 后由应用驱动 `finish_join()`；auto 模式由扫码方验证授权链后自行签署入组，邀请端可离线。
- 成员变更：`refresh`、`remove`、`rename`、`prepare_exit(disband)` + `exit()`（`leave()` / `disband()` 为便捷封装）。

所有签名载荷执行与服务端相同的字节级严格校验，签名链逐条验证（含委托 `authorization`），不信任未验证的 HTTP 成员列表；组变更通知只提示刷新，不是信任证明。

## 连接与安全

`Client` 可放入 `Arc` 跨任务共享；`close()` 或 drop 结束连接，`connect` 的 45 秒上限只覆盖握手。用 `tokio::time::timeout` 或丢弃 future 可取消等待，但无法撤销已发送消息；请求上限 64、最长 45 秒，事件队列上限 64，满时关闭连接。断线后显式创建新连接，在线消息与流不重放。仅支持 WSS/HTTPS，拒绝重定向；测试选项只允许 `127.0.0.1` 的明文回环连接。若宿主进程同时启用 rustls 的 aws-lc-rs 与 ring，需在连接前自行调用 `CryptoProvider::install_default`。

```sh
cd sdk/rust
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

测试覆盖共享密码/设备组/短邀请向量（含严格载荷与委托授权）、secretstream 与 libsodium 已知答案、日志重启/冲突/清理/单一所有者、流额度与 FINAL、文件续传与篡改拒绝、WSS/HTTPS TLS 初始化与重定向拒绝，并在 `build/common-relay` 临时回环服务上验证离线、流、文件与设备组流程。`examples/echo.rs` 与 `examples/group_probe.rs` 是 `scripts/local-interop.py`、`scripts/group-interop.py`、`scripts/lightweight-interop.py` 使用的互通探针。均不是公网或长期运行验收。

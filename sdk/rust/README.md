# Rust SDK

原生 Rust SDK（Common Relay v2）：签名设备组（`/v2/group`、`/v2/enroll`：自助创建、manual/auto 邀请、加密短邀请链接、改名、退出、解散）、端到端加密的可续传文件（`/v2/files`）以及 `common_relay::v2`（`V2Client`：`/v2/me` 与插件绑定的 HTTP 接口；Box/Pipe 帧与结构、插件绑定类型、`crs1` 封存载荷的生成与打开）。独立 crate `common-relay`（Rust 1.89+），纯 Rust 实现：`crypto_box`（NaCl box）、基于 RustCrypto `chacha20`/`poly1305` 的 secretstream（与 libsodium 逐字节一致）、`ed25519-dalek` 与 `reqwest`，TLS 使用 rustls + ring（webpki 根证书）。无需 libsodium、C 编译器或预编译库；它不是共享核心，其他语言 SDK 不依赖它。

2026-11-22 起服务器只提供 v2：旧的 v1 WebSocket 客户端（`Client`、`RelayStream`、`RelayJournal`，`/relay/v1/ws`）已删除。设备间的实时消息走 `/v2/ws` 管道：`Pipe`（见下文“消息”）。所有端点都由设备的 `wss://host/v2/ws` 地址推导，`/relay/v1/*` 地址与旧 `/i/` 短链接一律拒绝。

当前通过源码接入，尚无 crates.io 发布。在接入项目的 `Cargo.toml` 中：

```toml
[dependencies]
common-relay = { path = "/absolute/path/common-relay/sdk/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## 服务器访问密码

`Options.password` 与组配置 `"password"`（8–128 个可打印 ASCII，不含空格），设置后在组/入组及文件的每个请求上发送 `Relay-Access` 头；生产中继强制要求。密码不写入加密邀请包，`Debug` 中脱敏。`invite(.., compact=true)` 会把邀请方密码以 `#<key>.<base64url密码>` 附在短链接片段（不进入 HTTP）；`invitation_links::make_link`/`parse_link` 相应多一个可选密码。`resolve_invitation` 优先使用链接中的密码并写入返回值 `"password"`，否则仅当链接地址与本机 `url` 相同才携带自身密码；`join` 遇到 `"password"` 会校验并存入 `config["password"]`。

## 文件

`prepare_file` 把源文件加密为 `length[4 BE] | secretstream 记录` 的暂存密文；`RelayFiles::for_relay_endpoint("wss://host/v2/ws", token, options)`（或 `RelayFiles::new("https://host/v2/files", ..)`）提供 `upload`（409 时严格核对原描述后续传，每块 ≤1 MiB）、`inbox`、`status`、`download`（Range 续传）、`delete`。令牌是设备入组时登记的组设备令牌（`groups.config["token"]`）。`decrypt_file` 先校验长度与 SHA-256，再逐条认证并要求 FINAL，最后以硬链接发布到不存在的目标路径，不覆盖已有文件；远端文件名仅经 `safe_file_name` 清洗后使用。`prepare_file` / `decrypt_file` 是阻塞 IO，大文件请放入 `spawn_blocking`。

## 消息（`/v2/ws`）

`Pipe::connect(url, token, &options, identity, Some(Journal::open(dir)?))` 建立一条连接并等待服务器 `hello`；`next_event(timeout)` 取应用事件，`message(to, data, offline, id)` 发送并等待 `stored`/`forwarded`/`received`，`acknowledge(from, id, offline)` 在应用持久处理后确认，`peers()` 查询在线设备，`close()` 断开。离线消息先写入投递日志（`Journal`），用同一 `id` 重试会重发同一密文；收到的消息记入日志以丢弃重放。

事件：`message`（已解密，`data` 为 base64）、`peer.up`/`peer.down`、`group.changed`，以及 `undecryptable`（`{from,id,offline,trusted}`）——本连接无法打开的信封不会断开连接。若发送方在当前签名名单内或首次出现（可能刚入组），应用应刷新名单并用新的信任公钥重连（服务器会重投）；刷新后仍非成员、或可信发送方的信封损坏时，调用 `acknowledge` 永久丢弃。

`policy` 提供通用默认：`authentication_failure(&err)`（401/403 → 停止并提示用户）、`retry(rejected, previous, connected)`（1 秒起翻倍至 30 秒，连接稳定 120 秒后才重置）、`fresh_identity()`（退出组后换新设备 ID 与传输密钥）。重连由应用驱动。

## 设备组

`Groups::new(config, allow_local_test)` 使用与 Go/Python/Dart 相同的 JSON 配置（`app`、`group`、`device`、`secret_key`、`trusted_peers`、`url`（`wss://host/v2/ws`）、`password`、`token` 及 `pending_*` 状态）。每次调用后，应用必须把 `groups.config` 持久化到私有存储。

- 创建/初始化：`prepare_create(group_name, device_name)` 先生成并保存已签名草稿，再 `create()`（服务器须以 `--self-service-apps` 为该应用开启）；运维初始化用 `bootstrap(code, name)`（`common-relay group-bootstrap`）。
- 邀请：`invite(mode, compact)`（`"manual"` / `"auto"`，`compact` 时返回 `common-relay://host/v2/i/...` 短链接）、`resolve_invitation(link)`、`pending`、`approve(invitation, request, manager)`、`cancel`。
- 取消：丢弃组操作的 future（或 `tokio::time::timeout`）即中止进行中的 HTTP 请求。
- 加入：`join(invitation, name)` 后由应用驱动 `finish_join()`；auto 模式由扫码方验证授权链后自行签署入组，邀请端可离线。
- 成员变更：`refresh`、`remove`、`rename`、`prepare_exit(disband)` + `exit()`（`leave()` / `disband()` 为便捷封装）。`check_exit(disband)` 离线校验退出是否合法（最后一位管理员不能撇下其他成员，只有管理员能解散），便于先清本地再尽力通知服务器。
- HTTP 失败统一为 `Error::Http(status)`。

所有签名载荷执行与服务端相同的字节级严格校验，签名链逐条验证（含委托 `authorization`），不信任未验证的 HTTP 成员列表。仅支持 HTTPS（测试选项只允许 `127.0.0.1` 的明文回环），拒绝重定向。若宿主进程同时启用 rustls 的 aws-lc-rs 与 ring，需先自行调用 `CryptoProvider::install_default`。

```sh
cd sdk/rust
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features
```

测试覆盖共享密码/设备组/短邀请/v2 封存向量（含严格载荷与委托授权）、secretstream 与 libsodium 已知答案、文件加密与篡改拒绝、HTTPS TLS 初始化与重定向拒绝、v1 地址拒绝，并在 `build/common-relay`（先 `go build -o build/common-relay ./cmd/common-relay`）临时回环服务上验证 v2 设备组全流程（自助创建、auto/manual 短链接邀请、批准、改名、退出、解散）与组成员之间的 `/v2/files` 上传/收件箱/下载/解密/删除；`tests/pipe_live.rs` 验证 `/v2/ws` 消息客户端（在线名单、离线投递与日志重发、无法解密消息上报且不断连并在信任后重投、错误密码分类）与 `check_exit`。`examples/group_probe.rs` 是 `scripts/group-interop.py` 使用的互通探针。均不是公网或长期运行验收。

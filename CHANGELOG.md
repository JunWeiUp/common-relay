# Changelog

## Unreleased

### 文档与测试：v2 协议规范与共享测试向量

- `protocol/v2/README.md` 成为唯一权威线协议规范（按服务端代码编写）：鉴权头与凭据类别、`/v2/ws` 帧与全部事件/错误码、保活与背压、Box 路由（queue/object/ephemeral、单条/批量 ACK、CAS/ETag）、签名组账本（记录格式、签名与哈希链、严格载荷、手动/自动邀请、短邀请、初始化、自助创建、退出/解散）、端到端文件、`crs1` 封存格式、`/v2/me`、管理面与插件 `if_version`、边缘插件鉴权、限额与状态码。v1 协议文档删除，`protocol/README.md` 只留索引与历史说明。
- 共享向量移至 `protocol/v2/`，只含 v2 地址（`/v2/ws`、`common-relay://host/v2/i/…`），由 `go run ./scripts/protocol-vectors` 确定性生成（`-check` 与测试校验未过期）：新增 `sealed-vectors.json`（`crs1` 正例与篡改反例）、`group-vectors.json` 的 `entry_hashes`（载荷哈希、签名有效性、链接）、`invitation-link-vectors.json` 的 `packet_plaintext`/`read_hash`/`invalid_links`，`vectors.json` 的 `hash_secret` 改为多用例列表。删除无人使用的 `journal-vectors.json`、`webhook-vectors.json` 与 `scripts/group-strict-vectors.py`（严格载荷反例改由生成器产出，内容不变）。
- 服务端与 Go、Dart、Java、Rust、Swift、Python SDK 测试直接读取同一批向量，去掉测试内把 v1 向量改写成 v2 的逻辑（含 Java `AccessTest.v2Link`）。
- Go SDK：`NewGroups`、`NewFiles` 与短邀请只接受 `/v2` 地址（不再接受 `/relay/v1/*` 与旧 `/i/` 链接）。
- 清理 SDK 删除后遗留的文档（TypeScript/Kotlin SDK、已删除的 v1 互通脚本、`RelayClient`、`/relay/v1` 路径与把 `relay.db` 当作在用存储的描述）。

### 性能：v2 存储读写分离

- `relay_v2.db` 新增只读连接池（`mode=ro` + `query_only`，WAL，最多 4 连接，`Store.RDB` / `Store.Reader()`）：鉴权、成员角色、Space/Box/条目/对象列表与下载、状态与用量、插件绑定查询、账本组记录与文件列表改走读池，不再排在写事务之后。所有写入与事务仍走唯一写连接（账本共用）；事务内禁止使用读池。`backup`、旧库导入不受影响。

### 新增：小条目内联唤醒与批量 ACK（向后兼容）

- `/v2/ws` 可声明 `?features=box-inline`（或请求头 `X-Relay-Features: box-inline`）。仅对声明的连接，≤64 KiB 的队列/临时条目在 `box.changed` 中附带 `item`（条目元数据 + `data_b64`）；超过帧上限或发送队列压力过大时退回普通事件。内联只是预取，条目仍需 ACK。未声明的客户端行为与报文完全不变。
- 新增 `POST /v2/spaces/{space}/boxes/{box}/items/ack`（`{"ids":[...]}`，≤200）：同一事务批量确认，返回 `acked` / `missing`，幂等，鉴权与单条 `DELETE` 相同。
- Go `v2client`：新增 `Client.AckBoxItems`；`Hub` 自动启用内联，小条目直接交给处理函数，确认按 200 ms / 50 条批量发送（旧服务端回退逐条 `DELETE`）；处理失败不确认、下次拉取重投。实测 3 个小条目由 12 次 HTTP 降为 1 次。
- `/v2/admin/metrics` 新增 `box_inline`、`box_inline_skipped`。

### Breaking：服务端只保留一个数据库

- 签名设备组账本与端到端文件从 `relay.db` + `files/` 迁入 `relay_v2.db`（schema 5，`v2_ledger_*` 表）+ `blobs/files/`（`internal/relay` → `internal/v2/ledger`）。首次启动在一个事务内导入已有 `relay.db`，`relay.db`/`files/` 原样保留作备份；失败整体回滚并拒绝启动。
- 组成员变化与签名记录在同一事务内写入 v2 Space / 成员 / 设备，删除原「投影」钩子（`OnGroupSynced`）与两库互读配额（`ExternalUsage`）；组内传输中的文件计入该组 Space 的用量。`managed_by` 仍为 `v1:<app>[:<group>]`。
- `/v2/group*`、`/v2/enroll/*`、`/v2/files*` 报文不变，客户端无需更新。
- `/v2/admin/metrics` 的 `v1` 段改为 `ledger`（`rows: [{app, kind, requests, last_at}]`）；Go `v2client.Metrics.V1` → `Metrics.Ledger`。
- `common-relay check` 额外校验每组修订号连续与哈希链并输出 JSON 摘要；`schema` 报告 `ledger_imported`；`backup` 包含 `blobs/files/`（复制，不硬链接）。

### Breaking：SDK 仅支持 v2

- 删除全部只连 `/relay/v1/*` 的 SDK 接口，设备组、短邀请与文件客户端只接受 `/v2/ws`、`/v2/files`（报文格式不变）。
- TypeScript SDK（整体 v1、无应用使用）删除，Release 不再附带 tgz；Kotlin SDK 删除，JitPack 与 Release 只发布 `common-relay:java`。
- Rust：删除 `Client`/`Event`/`Peer`/`RelayStream`/`RelayJournal` 与 echo 示例；`Groups`、`RelayFiles`、短邀请改走 `/v2`；`Options`/`ACCESS_HEADER` 移至 `access` 模块；去掉 tokio-tungstenite、futures-util 与直接 rustls 依赖。
- Python：`Client` 只接受 `/v2/ws`，删除 v1 字节流（`Stream`、`open_stream`/`accept_stream`）；设备组与邀请链接改走 `/v2/group`、`/v2/enroll`；`Files` 要求 `/v2/files`。
- Dart/Java/Swift：删除 `RelayClient`/`RelayStream`（Java、Swift 另删 `RelayJournal`，Swift 删 `RelayDevice`），设备消息改用各自 v2 客户端（`RelayV2Client`/`RelayV2Pipe`、`V2Client`）；`RelayGroups` 只接受 `/v2/ws`；Swift `RelayFiles` 要求 `/v2/files`。
- 短邀请只生成和解析 `common-relay://host/v2/i/…`，旧 `/i/` 链接被拒绝。
- 测试：Python、Rust、Dart 设备组/文件测试直接对真实服务端运行（用签名设备组注册设备）；`group-interop.py` 覆盖 Swift/Dart/Java/Go/Rust。
- 应用影响：SyncApp（Flutter/macOS）升级 SDK 时需删除 v1 分支，仅保留 `RelayV2Pipe` 路径。

### Breaking：移除 Common Relay v1

服务端只提供协议 v2，`serve` 现在必须带 `--v2-admin-hash-file`（缺少时启动即报错）。

- 删除 v1 WebSocket 传输：`/relay/v1/ws`（`common-relay.v1` 子协议）、在线/离线消息与回执、双向流、在线状态事件。
- 删除全部公开 `/relay/v1/*` 路由：`ws`、`files`、`group`、`enroll`、`dav`（含 `.accounts`）、`webhooks`，现在一律 404。
- 删除 v1 Webhook / WebDAV 入口及 `--webhook-config`、`--webdav-config` 参数（改用 v2 `webhook`/`webdav` 插件）。
- 删除 `import-v1` 命令及 `--space`、`--seal-public-key`、`--dry-run` 参数；删除 `device-add`、`device-revoke` 及 `--device`、`--public-key` 参数（静态设备无法登录 v2）。保留 `serve`、`group-bootstrap`、`check`、`backup`、`schema`、`hash-password`。
- `/healthz` 由主进程直接提供；`deploy/nginx.conf` 只导出 `/v2/ws`、`/v2/files*`、`/v2/group*`、`/v2/enroll/*`、`/v2/admin/`、`/v2/`、`/edge/`；systemd 单元通过 `LoadCredential=v2admin:/etc/common-relay/v2-admin.sha256` 传入 Root Admin 哈希。
- **不变**：`/v2/group`、`/v2/group/*`、`/v2/enroll/*`（含 `/auto`、`/link`）、`/v2/files`、`/v2/files/*` 的报文、签名账本、`Relay-Access` 校验与行为完全不变；组变更继续投影到 v2 Space（`OnGroupSynced`）。
- 数据：旧库的 `messages`、`receipts`、`webdav_*`、`webhook_receipts` 表不再读写，原样保留（无破坏性迁移）；配额只计文件。
- `/v2/admin/metrics` 的 `v1` 段只统计账本/文件调用，`family` 恒为 `v2`，移除 `live_ws`。
- **SDK**：见下方「SDK 仅支持 v2」。

### v2（实验性，需 `--v2-admin-hash-file`）

- **安全**：v1 签名组投影到 v2 时记录来源（`managed_by`），不再合并到同 ID 的管理员空间、其他应用的组或管理员创建的设备；冲突拒绝并计数，投影只吊销自己创建的设备。
- **安全**：吊销设备或修改空间角色会立即断开其 `/v2/ws` 会话；RPC 响应只接受目标设备回复，默认 15 秒超时（MCP 10 秒），等待槽位先于鉴权 RPC 占用。
- **安全**：插件失败限流改为按「绑定 + 客户端 IP」计数（仅信任回环/指定代理的转发头），攻击者不能把合法客户端锁在外面。
- **安全**：插件密钥（令牌哈希、HMAC 密钥）只写不读，与公开配置分列存储并用 `plugin-secrets.key` 加密；账户密码改为加盐 scrypt（旧 SHA-256 记录仍可验证）。
- 可选封存：桥接插件配置 `seal_public_key` 后，Webhook/Drop/WebDAV 收到的明文在落盘前按 `crs1` 格式封存给消费端公钥；Go SDK 提供 `OpenSealed`。
- **迁移**：`/v2/admin/metrics` 增加 `v1` 段：按 应用 × 类型（ws / files / group / enroll / dav / webhook）× 入口（`/relay/v1` 地址，或经 v1 代码处理的 `/v2` 地址）统计调用次数与最近时间，以及当前在线的 v1 WebSocket 数，用于判断何时可以退役 v1；Go SDK `Metrics.V1`。
- **运维**：新增 `common-relay backup`（运行中一致性快照：`VACUUM INTO` + 密钥 + 硬链接不可变载荷，保留 N 份）与 `common-relay schema`；`scripts/deploy-remote.sh` + `deploy/upgrade.sh` 一键升级（快照演练、按 schema 变化生成回滚脚本、失败自动回滚）；`deploy/common-relay-backup.{service,timer}` 每日快照。
- **运维**：新增 `GET /v2/admin/metrics`（边缘插件请求结果计数、设备连接/断线次数与原因、近 24 小时断线、最近连接事件；内存有界、重启清零），Go SDK `Client.Metrics()`。
- **可靠性**：`/v2/ws` 服务端每 30 秒主动 ping（`PipeHub.Keepalive`），Go SDK `Hub` 也每 30 秒 ping 并在无响应时立即重连（`Hub.Keepalive`）；修复空闲连接被反向代理（nginx `proxy_read_timeout`）每约 2 分钟断开一次的问题。
- 新增 `GET /v2/me`：设备令牌返回自身设备信息（Root Admin 返回 `root_admin:true`），管理端创建 Space 后可把自己加为成员；Go / Dart / Java / Rust / Swift SDK 均提供 `Me()`（`me()`）。
- 新增 `PATCH /v2/admin/plugins/{id}/{mount}`（合并更新、`null` 删除、`if_version` 乐观锁）与 `GET` 单个绑定；`PUT` 省略的密钥保持不变，停用/启用无需轮换令牌；`GET /v2/admin/plugins` 返回插件配置 Schema，未知配置键直接 400。
- Webhook：签名重放 409、`Idempotency-Key` 7 天回执去重、请求体上限可配（最大 64 MiB）；Drop/MCP 补齐配置校验。
- 配额：v1/v2 共用全局配额并检查磁盘余量（`--disk-reserve`），v2 用量改由触发器维护的计数表 O(1) 读取；启动和定期清理孤立 blob。
- 访问密码单一来源：管理接口轮换后以数据库为准；运维修改 `--access-password-file` 后下次启动以文件为准并记录日志。
- 路由按完整路径段解析，Box 名保留 `items`/`objects` 段；边缘插件请求体总上限与崩溃兜底；schema 版本由 `PRAGMA user_version` 管理并拒绝更新版本的数据库。
- 新增 `common-relay import-v1`：把 v1 `--webhook-config`/`--webdav-config` 路由幂等导入为 v2 插件绑定（可加 `--seal-public-key`、`--dry-run`），v1 路由继续可用。
- Go SDK `v2client`：`PatchPlugin`、`GetPlugin`、`PluginCatalog`、`UpsertPluginAccountPassword`、`IsUnsupported`（识别不支持 PATCH 的旧服务端以回退 PUT）。

### 其他

- SDK 改为按 Git 标签依赖分发：根目录 `Package.swift`（Swift）、JitPack（Java/Kotlin）、Git 子目录依赖（Dart/Python/Go/Rust）及 Release tgz（TypeScript）；新增 `release.yml` 发布工作流，各 SDK 版本统一为 0.1.0，源码快照降为可选。
- 保持各语言独立 SDK，不依赖共享 Rust 核心或自有多平台原生库。
- 新增 Kotlin Android 协程接口，复用 Java 的完整协议实现。
- 新增 TypeScript（Node.js）及 Go 轻量客户端：加密在线消息、在线设备查询、共享向量与回环互通验证。
- 新增 Rust 轻量客户端（独立 crate，纯 Rust NaCl box 与 rustls）：能力与 TypeScript/Go 一致，并加入回环互通脚本。
- TypeScript、Go、Rust 补齐完整能力：持久化离线消息（日志、ACK、去重、清理）、secretstream 双向流、加密文件、签名设备组（严格载荷、委托授权、自助创建、改名、退出、解散）及加密短邀请；七类 SDK 共用向量，`local-interop.py`、`group-interop.py` 增加三者的互通探针。
- 源码快照工具支持 Kotlin、TypeScript、Go、Rust；保留文件续传偏移检查与 Python 流关闭唤醒修复。

## 0.1.7

- 新增可选 WebDAV 上传入口 `/relay/v1/dav/{route}/`（`--webdav-config`）：HTTP Basic 账号 + 授权密码（只存 SHA-256，失败限流），支持 OPTIONS/PROPFIND/MKCOL/PUT/HEAD/DELETE/MOVE/PROPPATCH；每次 PUT 加密为标准 v1 文件投递给固定接收设备，只收不读。同路径相同内容与 0 字节文件不重复投递。
- Webhook 与 WebDAV 共用 `ingress.go` 的私密配置加载、设备公钥校验、加密暂存与持久发布；Webhook 行为不变。
- nginx 模板新增 `/relay/v1/dav/` location；rclone 真实客户端互通测试（可选）。
- 新增可选通用 Webhook 入口 `POST /relay/v1/webhooks/{route}`（`--webhook-config`），复用标准加密文件和各 SDK 接收接口。
- 增加路由令牌哈希、固定目标、持久队列、7 天幂等回执与重启恢复。
- 新入口明确采用服务器桥接信任模型，默认关闭；现有服务与普通文件 TTL 保持原行为。
- 补充可配置的时间戳/HMAC-SHA256 请求签名，保留现有 Webhook 的签名校验；兼容 systemd 私有只读凭据目录。
- 设备组请求支持调用方取消并在各 SDK 对齐：Go `WithContext`/`Close`，TypeScript `withSignal(AbortSignal)`，Dart `withAbort(Future)`，Java 中断调用线程即取消进行中的请求（抛 `InterruptedException`），Kotlin 新增 `groupCall {}` 协程取消；Swift/Python/Rust 沿用原生 Task/asyncio/future 取消，Swift 已取消任务不再发起请求。短邀请解析沿用调用方取消；协议不变。
- 新增独立 MCP 客户端连通性探针示例 `examples/mcp-probe`（固定测试文字，不属于中继服务）。
- SDK 清单、依赖示例和源码快照版本统一更新至 0.1.7。

## 0.1.6

- Swift：WebSocket 传输由 `URLSessionWebSocketTask` 改为 Network.framework（`NWConnection` + `NWProtocolWebSocket`）。macOS 26 上 CFNetwork 会在 cancel + invalidate 后仍保留每个 WebSocket 任务及其会话，长驻客户端每次重连泄漏一整套会话；新传输取消即释放。握手失败时补一次普通 HTTP 状态探测，401/403 仍以 `NSURLErrorUserAuthenticationRequired` 上报；协议与其他 SDK 不变，新增回环 `SocketTests`。
- SDK 清单、依赖示例和源码快照版本统一更新至 0.1.6。

## 0.1.5

- **不兼容**：新增服务器访问密码。`serve` 必须提供 `--access-password-file`（仅存 SHA-256，`hash-password` 生成），所有 `/relay/v1/*` 请求须带 `Relay-Access`，否则 401；七类 SDK 新增 `password` 配置，互通脚本、systemd（LoadCredential）与安装脚本同步更新。
- 加密短邀请可携带服务器访问密码；七类 SDK 同步支持解析与传递，密码以 Base64URL 编码置于 URI 片段，解析时通过 Relay-Access 请求头使用；持有完整链接即可获知密码。
- SDK 清单、依赖示例和源码快照版本统一更新至 0.1.5。

## 0.1.4

- 发布 Linux amd64 / arm64 服务端部署包，包含二进制、安装脚本、systemd/Nginx 配置、部署文档、SOURCE.json 及 SHA-256 校验。
- 安装脚本按目标 Linux 架构选择二进制；Release 新增服务端打包和 amd64 启动健康检查，与客户端 SDK 一起分发。
- SDK 版本统一更新至 0.1.4，协议与客户端功能不变。

## 0.1.3

- 修正 Kotlin Maven 发布校验：项目依赖可省略 type，由目标 Java POM 的 AAR packaging 确定类型。
- 保留 0.1.2 的 Android 原生依赖元数据修复与明确的 TypeScript 产物命名。

## 0.1.2

- Android Maven 发布保留 JNA/LazySodium 的 AAR 类型，避免 Gradle 模块元数据将原生运行库解析为桌面 JAR，导致重复类或缺失原生库。
- TypeScript Release 附件明确命名为 `common-relay-typescript-<version>.tgz`，包含 JavaScript 与类型声明。

## 0.1.1

- Java/Swift/Dart/Python 转发 `group.changed` 通知，由调用方继续核验签名成员链；Kotlin 复用 Java，TypeScript/Go/Rust 已有对应行为。
- 签名组载荷跨 SDK 统一拒绝缺失 Base64 padding、非零尾部 padding bits 和换行；共享向量及生成器增加同密文反例。
- Java 修复 Android journal 路径对斜杠的 JSON 编码差异、流关闭后重复读取阻塞和关闭期间的原生状态释放竞态；JNA size_t 使用平台 NativeLong，可信公钥集合兼容 API 26。


## 早期条目（0.1.0 之前，未标注版本）

- 增加可独立运行的 Python 消息、双向流与设备组示例。
- 整理公开文档、测试命名空间及共享向量，部署脚本改用项目专属插入标记。
- CLI 在打开数据目录前校验子命令及多余位置参数，帮助正常退出。
- 新增签名设备组管理、自助创建、改名、退出与解散，四 SDK 共用签名向量。
- 新增 `manual` / `auto` 邀请、一次性委托授权、自动入组链验证与幂等恢复。默认手动，启用自动模式前须整组升级 SDK。
- 新增加密短邀请、用途隔离的读取凭据、过期/撤销/单次消费；四 SDK 提供可选 compact API，兼容完整邀请。
- Java 请求超时使用可取消定时器，兼容 Android API 26。
- 修复：服务端与四 SDK 对签名组 payload 统一执行严格字节级校验（未知字段、重复/大小写/转义键、null、小数/指数、孤立代理项、base64 换行一律拒绝），防止成员提交歧义记录使全组签名链永久卡死；新增共享反例向量，`check` 会扫描已存储记录。

## 0.1.0-dev

- 统一 v1 协议、Go 服务与 CLI、SQLite 离线投递、密文文件分块上传与续传、四 SDK 与互通探针。
- 持久化离线重试、认证绝对有效期、去重与分批清理；服务端文件锁、流额度及定时回收。
- Swift 日志存储支持严格并发检查。

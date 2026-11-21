# Common Relay v2 架构规格书（通用个人加密聚合总线）

> 本文档定义 `common-relay` v2 的目标架构：以 **「4 个正交内核原语 + 可插拔边缘协议插件 + 唯一动态控制面」** 统一服务 **PasswordVault**、**Clipy**、**工作台（local-ops）**、**日日 / 涛声 / 一木记账** 及未来任意扩展能力。
>
> v2 代码独立落地于 `internal/v2/`，与存量 `internal/relay/`（v1）完全解耦并存，待各客户端平滑迁移后统一退役 v1。

---

## 1. 三平面路由与鉴权边界

所有公网流量经 Nginx TLS 反代进入单二进制服务，按前缀做硬隔离：

| 路径前缀 | 平面 | 鉴权方式 | 服务对象 |
|---|---|---|---|
| `/v2/*` | **设备内核面** | `Relay-Access`（公网准入门禁） + `Authorization: Bearer <device_token>` | Clipy、PasswordVault、日日、工作台 `RelayHub` |
| `/v2/admin/*` | **管理员控制面** | `Relay-Access` + **Root Admin Token / 签名管理员身份**（普通设备 Token 一律 `403`） | 工作台 `#settings/sync` 图形化总控台 |
| `/edge/{plugin}/*` | **边缘插件面** | **各插件独立标准协议鉴权**（HTTP Basic / Bearer / HMAC / API Key，不要求 `Relay-Access`） | 一木记账、一木笔记、Obsidian、涛声、快捷指令、外部 AI MCP |

---

## 2. 四个正交内核原语（`internal/v2/core`）

内核不包含任何业务语义（不认识剪贴板、密码库、账单或日程），只提供四个最小原语：

### 2.1 `Identity & Space`（设备与空间隔离）
- **Device**：物理设备（或独立应用实例）持独立密钥对与访问令牌（服务端仅存 `SHA-256(token)`，支持随时吊销）。
  - 独立产品（`Clipy`、`PasswordVault`）各自独立连接，不强依赖工作台进程；
  - **工作台（local-ops）内部**将多归档模块收敛为单一 `RelayHub`（1 个设备身份 + 1 条长连接，按 `(space, slot)` 路由分发）。
- **Space**：安全与成员信任边界，创建时锁定不可变 **`TrustLevel`**：
  - `strict_e2e`（最高密级，如 `pv`、`clipy`）：**内核级禁止**绑定任何 `bridge_allowed` 明文插件；数据仅由客户端加密。
  - `client_encrypted`（客户端预加密，如 `pv-backup`、`obsidian`）：允许挂载客户端密文透传插件（如双向 WebDAV），服务端只存盲密文。
  - `bridge_allowed`（受托桥接，如 `personal`）：允许挂载 WebDAV / Webhook / Drop 等明文入口插件，由插件托管桥接密钥加密入箱。
- **成员角色（`MemberRole`）**：
  - `admin`：管理本 Space 成员与 Box；
  - `member`：读写本 Space 的 `Pipe` 与 `Box`；
  - `archive_observer`：**只读密文观察者**（用于工作台冷备 PasswordVault：只能订阅与拉取 `Box(object)` 密文历史版本 + SHA-256 校验，无写入权限、无解密密钥）。

### 2.2 `Pipe`（实时消息、在线状态与双向字节流）
- 单条 WebSocket `/v2/ws` 承载四类轻量事件：
  1. **`presence`**：空间内在线设备列表，支持 **3 秒快速心跳探活** 与切网即时清理旧会话（保障 Clipy 低内存零泄漏）。
  2. **`msg`**：端到端加密短消息，带 `msg_id` 幂等去重与短 `TTL`（对方离线时暂存，重连按游标一次补齐，过期自动回收）。
  3. **`stream`**：有界背压加密双向字节流（零落盘直通，服务端内存恒定），服务 Clipy 在线 512 MiB 文件/文件夹直传、WiFiADB 隧道、对外只读 MCP。
  4. **`box.changed`**：Box 产生新条目或新版本时的即时推送唤醒（**WS 仅作加速，真源永远是 Box 的 `seq` / `version`**）。

### 2.3 `Box`（统一分块密文存储盒）
所有离线数据统一走两级寻址 `Space / BoxName`，提供 **3 种生命周期策略**：

| `BoxMode` | 核心语义 | 典型场景 | 清理策略 |
|---|---|---|---|
| `queue` | 递增 `seq` 收件箱；支持 `?after=seq` 断线补齐 | 日日快照、涛声、一木记账/笔记、快捷指令 Drop、WebDAV 只收通道 | 接收端落盘后 `ACK` 立即物理删除 |
| `object` | 单调递增 `version` + `ETag`（SHA-256）+ **`If-Match` CAS 乐观锁**；保留近 `N` 版 | **PasswordVault 多端强一致同步**、双向加密 WebDAV（Obsidian / PV 灾难恢复） | 按 `keep_versions` 滚动淘汰旧版；可通知 `archive_observer` 冷归档 |
| `ephemeral` | 分块大文件（默认上限 512 MiB）+ 短 TTL | **Clipy 对方离线时的 512 MiB 文件/文件夹中转** | 取完 `ACK` 或超过 TTL 自动物理回收 |

### 2.4 `Plugin & Admin`（边缘插件框架与统一控制面）
- 所有外部协议都是实现 `plugin.Plugin` 接口的薄插件，位于 `internal/v2/plugins/<name>/`：
  ```go
  type Plugin interface {
      ID() string
      RequiredTrust() core.TrustLevel
      EdgeHandler(host Host) http.Handler   // 挂载到 /edge/<id>/*
      AdminHandler(host Host) http.Handler  // 挂载到 /v2/admin/plugins/<id>/*
  }
  ```
- **内核强拦截**：通过 Admin API 将任何插件实例绑定到目标 `Space` 时，由内核统一校验 `space.TrustLevel.Allows(plugin.RequiredTrust())`——从代码结构上杜绝误将明文插件绑到 `strict_e2e` 密码库空间。
- **零静态配置文件**：所有 Space、Box、插件绑定、WebDAV 子账号、Webhook/Drop 令牌全部动态持久化在 `relay.db`（SQLite WAL），通过 `/v2/admin/*` 热生效，无需 SSH 登录服务器改 JSON 或重启进程。

---

## 3. 核心 SQLite 表结构（`relay.db` + `blobs/`）

数据目录仅包含 `relay.db`（权限 `0600`）与 `blobs/<sha_or_id>` 密文块目录（权限 `0700`）：

- `v2_devices(id PK, name, public_key, token_hash UNIQUE, is_admin, revoked, created_at)`
- `v2_spaces(id PK, name, trust_level, created_at)`
- `v2_space_members(space_id, device_id, role, added_at, PK(space_id, device_id))`
- `v2_boxes(space_id, name, mode, max_bytes, keep_versions, ttl_sec, next_seq, PK(space_id, name))`
- `v2_box_items(id PK, space_id, box_name, seq, sender, size, sha256, content_type, meta_json, expires_at, created_at)`（承载 `queue` 与 `ephemeral`）
- `v2_box_objects(space_id, box_name, obj_key, version, etag, size, content_type, meta_json, blob_id, created_at, PK(space_id, box_name, obj_key, version))`（承载 `object`）
- `v2_messages(space_id, sender, recipient, id, topic, body, expires_at, created_at, PK(space_id, sender, id))`
- `v2_plugin_bindings(id PK, plugin_id, mount, space_id, box_name, config_json, enabled, updated_at, UNIQUE(plugin_id, mount))`
- `v2_plugin_accounts(binding_id, scope_key, username, secret_hash, mode, meta_json, updated_at, PK(binding_id, scope_key))`

---

## 4. 四大生态接入蓝图

1. **Clipy（Swift / Dart）**：
   - 独立 `Space: clipy`（`strict_e2e`）。
   - 三档传输降级链（统一 `transfer_id` 幂等去重）：
     1. 局域网可达 → LAN 直连；
     2. 跨网 + 目标在线 → 剪贴板走 `Pipe(msg)`，512 MiB 文件/文件夹走 `Pipe(stream)` 零落盘直通；
     3. 跨网 + 目标离线 → 剪贴板走 `Pipe(offline_msg, ttl=24h)`，大文件走 `Box(ephemeral, ttl=24h)`。
   - SDK 裁剪：仅需实现 `Space + Pipe + Box(ephemeral)`，单共享连接，守住低常驻内存。
2. **PasswordVault（Rust / Swift / Kotlin）**：
   - 独立 `Space: pv`（`strict_e2e`）。
   - 日常多端同步：`Box(object)` 存客户端主密码加密的盲密文 + `If-Match` CAS 防覆盖 + `Pipe` 变更唤醒。
   - 冷备归档：工作台以 `archive_observer` 只读加入 `pv`（无解密能力），监听 `box.changed` 自动把每个密文版本落盘并校验 SHA-256；若需外部 WebDAV 灾难恢复，可在 `client_encrypted` 空间挂载 `plugin/webdav(object)`。
3. **工作台（local-ops，Go）**：
   - 新增 `internal/relayhub`：1 个设备身份 + 1 条长连接，业务模块按 `(space, box/topic)` 注册回调；
   - `#settings/sync` 对接 `/v2/admin/*`：可视化查看磁盘余量、配额、在线设备，热管理所有 Space 与插件账号。
4. **第三方与外部 AI（边缘插件）**：
   - `plugin/webdav`：支持单目录策略 `queue`（只收不读：一木记账/笔记）或 `object`（客户端密文双向：Obsidian / PV 恢复）；
   - `plugin/webhook`：JSON + HMAC 幂等投递到 `Box(queue)`（涛声等）；
   - `plugin/drop`：单 Bearer Token 极简 `POST` 投递文本/文件到 `Box(queue)`（iOS 快捷指令、脚本、Clipy 一键转存工作台）；
   - `plugin/mcp-edge`（后续收编 `cmd/mcp-gateway`）：公网 MCP 入口经 `Pipe(stream)` 路由到工作台只读查询，保留 5 分钟照片短链哈希与脱敏日志红线。

---

## 5. AI Agent 新增一个协议插件的 4 步配方

1. 新建 `internal/v2/plugins/<name>/<name>.go`，实现 `plugin.Plugin` 接口并声明 `RequiredTrust()`。
2. 在插件内部通过 `host.BoxPutQueue` / `host.BoxPutObject` / `host.BoxGetObject` / `host.Accounts` 访问内核与存储，**禁止直接操作 `core` 私有表或绕过信任校验**。
3. 在服务启动装配处调用 `srv.RegisterPlugin(<name>.New())`。
4. 编写 `internal/v2/plugins/<name>/<name>_test.go`（覆盖正常流量、鉴权失败、越权绑定 `strict_e2e` 被拒），执行 `go test -race ./internal/v2/...`。

---

## 6. 渐进迁移路线

1. **阶段 1（本次先行落地）**：实现 `internal/v2/{core,plugin,server}` 与首批 3 个插件（`drop`、`webhook`、`webdav`），全套 `-race` 集成测试通过，不破坏现有 v1 服务。
2. **阶段 2**：在 `cmd/common-relay` 接入可选 `--v2-admin-key` 挂载 `/v2/*` 与 `/edge/*`，并编写 Go 客户端库 `internal/v2/client`（供工作台 `RelayHub` 复用）。
3. **阶段 3**：升级工作台 `local-ops`（`internal/relayhub` + `#settings/sync` 动态控制面板），率先收编 WebDAV / 记账 / 涛声 / 日日 / 快捷指令 Drop。
4. **阶段 4**：依次将 `Clipy`（Swift/Dart）、`PasswordVault`（Rust）、`日日`（Kotlin）与 `mcp-edge` 迁至 v2，并退役 `internal/relay/` 旧代码。

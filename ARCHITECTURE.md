# Common Relay v2 架构与迭代标准

本文档定义 Common Relay 的核心架构边界、协议演进标准与 SDK 维护纪律，用于防止协议蔓延、保持服务端零业务耦合，并让后续迭代与新应用集成有章可循。

---

## 1. 核心架构：2 + 1 + 1 正交模型

所有新应用与新能力都收敛在这 4 个正交概念内，**禁止再造平行抽象**：

| 层级 | 唯一抽象 | 路由与入口 | 职责边界 |
|---|---|---|---|
| **通信原语 ①** | **Pipe**（实时通道） | `/v2/ws` | 在线小消息（可选 `offline:true` 兜底 + `msg.pull` 续拉）、零落盘双向加密流（`stream.*` + `stream.credit` 背压）、同步 `rpc.req/res`、`box.changed`/`group.changed` 实时唤醒 |
| **通信原语 ②** | **Box**（持久存储） | `/v2/spaces/{space}/boxes/{box}` | `queue` 收件箱、`object` 版本化对象（ETag CAS + `keep_versions`）、`ephemeral` 临时存储、`uploads` 分块断点续传 |
| **隔离与治理** | **Space**（信任与配额边界） | `/v2/group*` · `/v2/enroll/*` · `/v2/admin/spaces` | 设备成员、角色（`admin`/`member`/`archive_observer`）、单空间硬配额（`quota_bytes`）、固定信任等级（`strict_e2e` < `client_encrypted` < `bridge_allowed`）、两种治理模式（`signed_ledger` / `admin_managed`） |
| **边缘扩展** | **Edge Plugins**（薄协议适配） | `/edge/{plugin}/{mount}` | 外部非原生协议适配（`webdav`、`webhook`、`drop`、`mcpedge`、`egress`），统一经 `plugin.Host` 受 `TrustLevel` 矩阵、限流与 `crs1` 封存约束 |

> **一条红线**：中继服务端永远只做**认证、隔离、路由、密文暂存与薄边缘桥接**，绝不实现剪贴板、ADB、密码库、远控等业务逻辑。

---

## 2. 推荐路径 vs 维护态路径（防协议混乱）

为了避免同一件事出现多套入口让接入方困惑，明确各路径定位：

| 场景 | 推荐标准路径（新应用必选） | 维护态路径（仅向后兼容） |
|---|---|---|
| 实时信令 / 小消息 / 在线流 | Pipe `/v2/ws`（开启 `features=box-inline,stream-credit`） | 无 |
| 离线大文件 / 断点续传 | **Box `uploads`**（`/v2/spaces/{space}/boxes/{box}/uploads`） | `/v2/files*`（仅维持现有签名组应用兼容，**不再新增特性**） |
| 端到端用户设备组 | `signed_ledger`（`/v2/group*` + `/v2/enroll/*`，同事务投影为 `strict_e2e` Space） | 无 |
| 服务端 / 自动化 / 第三方桥接 | `admin_managed` Space + `/edge/{plugin}/{mount}` | 无 |
| 局域网 / P2P 加速 | SDK 可选约定 `relay.direct.v1`（通过 Pipe `msg` 交换加密候选地址，失败回落 `/v2/ws`） | 服务端永不内置打洞或业务直连状态 |

---

## 3. 协议演进标准（Protocol Evolution Rules）

任何涉及线协议的改动必须遵守以下 5 条硬标准：

1. **权威单一来源**：先更新 [protocol/v2/README.md](protocol/v2/README.md)，再改实现；文档与代码不一致时以文档为基准修 bug。
2. **严格向后兼容**：
   - 只允许新增可选 JSON 字段、opt-in `features`（`?features=...` / `X-Relay-Features`）或独立插件；
   - 禁止静默更改已有字段类型/语义，禁止恢复已移除的 `/relay/v1/*`。
3. **单库迁移纪律**：
   - 所有服务端持久化状态必须保存在单一 `relay_v2.db`（文件载荷在 `blobs/`）；
   - 结构变更只能向 `internal/v2/core/migrate.go` **追加**迁移并递增 `SchemaVersion`，严禁原地修改旧迁移或新增第二个 SQLite 库。
4. **安全边界不可绕过**：
   - 所有 `/v2/*` 必须走 `Relay-Access` 常量时间 SHA-256 校验 + 独立凭据哈希；
   - 新增边缘插件必须放在 `internal/v2/plugins/<name>/`，实现 `plugin.Plugin` 与 `plugin.Configurable`（`ConfigSchema` 标记 `Secret`、`ValidateConfig` 拒绝未知键），声明 `RequiredTrust()`，严禁绕过 `Space.TrustLevel`；
   - 出站类插件（如 `egress`）必须具备运行时 DNS/IP SSRF 防护与禁止重定向，且严禁发送密文或明文载荷。
5. **共享测试向量与 CI 门禁**：
   - 密码学、签名链、短邀请、封存格式变更必须通过 `go run ./scripts/protocol-vectors` 刷新 `protocol/v2/*.json`，各 SDK 直接读取共享向量校验；
   - 所有 PR/分支必须通过 `.github/workflows/ci.yml`（Go `-race` + 各 SDK 单测 + 跨语言互通）。

---

## 4. SDK 分层维护标准（策略 A）

保持**纯源码独立 SDK（Git Tag 分发，无跨平台 FFI 二进制产物负担）**，按实际消费频率分层：

- **Tier-1 主力消费 SDK**：`Swift`、`Dart`、`Android Java`、`Rust`、`Python`
  - 完整覆盖：签名设备组、短邀请、回调式草稿先行状态机（`GroupStateMachine`）、`/v2/ws` Pipe（含 §4.5 `undecryptable` 非致命处理、离线 ACK、`stream.credit`）、Box 分块续传、`relay.direct.v1` 辅助。
- **核心配套 SDK**：`Go`（`sdk/go` + `sdk/go/v2client`）
  - 完整覆盖服务端配套、CLI/自动化工具与 `v2client`（Pipe/Box/Admin/Uploads/Sealed）。

---

## 5. 新应用 3 步标准接入清单

1. **确定治理与信任等级**：
   - 个人多端 E2E 应用 → `signed_ledger`（`strict_e2e`）；
   - 需接 Webhook / WebDAV / MCP / Egress → `admin_managed`（按需选 `client_encrypted` 或 `bridge_allowed`）并设置单 Space `quota_bytes`。
2. **接入状态机与密钥存储**：
   - 使用对应 SDK 的 `GroupStateMachine`，提供 `saveDraft` / `loadDraft` / `commit` / `clearDraft` 回调对接本地安全存储（Keychain / Keystore / SQLite），确保“发请求前先落盘草稿”。
3. **按数据形态选原语**：
   - 小消息/实时通知 → Pipe `msg`（离线必配 Journal + §4.5 `undecryptable` 处理）；
   - 持续实时字节流 → Pipe `stream`（自动 `stream.credit` 背压，局域网可选 `relay.direct.v1`）；
   - 大文件/离线附件/同步状态 → Box `uploads` / `queue` / `object`（CAS）。

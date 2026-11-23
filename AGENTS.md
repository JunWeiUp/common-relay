# Common Relay development

- 使用中文解释；工作分支使用 feat/、fix/、docs/ 等加小写 kebab-case。
- 服务端只提供协议 v2（v1 传输与 `/relay/v1/*` 已移除，不得恢复）。签名组账本与文件平面在 `internal/v2/ledger/`，挂在 `/v2/group*`、`/v2/enroll/*`、`/v2/files*`，与 v2 共用单一存储 `relay_v2.db`（表 `v2_ledger_*`，文件载荷在 `blobs/files/`）；组成员变更在同一事务内写入 `v2_spaces`/`v2_space_members`/`v2_devices`。旧 `relay.db` 只在启动时一次性导入（之后原样保留作备份），不得再新增第二个数据库。不加入旧项目协议适配器。
- 中继不得实现剪贴板、ADB、远控等业务；各应用、组和设备必须隔离。
- 令牌只保存哈希；客户端本地生成私钥并固定可信公钥。不得将接入令牌当作端到端密钥。
- 测试使用临时目录与测试身份。不得在普通测试中操作真实桌面、运行 ADB 命令或修改生产客户端配置。
- 协议变化必须同步服务端、所有实现该能力的 SDK（Go、Dart、Java、Rust、Swift、Python）、协议规范 `protocol/v2/README.md` 与共享向量（`go run ./scripts/protocol-vectors` 生成，各 SDK 测试直接读取 `protocol/v2/*.json`，不得在测试里改写向量）。禁止宣称未执行的真机或持续运行验收已通过。
- 执行 go test -race ./...，各 SDK 测试及跨语言互通；生产切换前验证真实 `/v2/ws`、备份和回滚。
- 私有文件放 .local/；数据目录、构建目录和签名材料不提交。SOURCE.json 为 SDK 来源与文件校验记录。

## v2 通用聚合架构（`internal/v2/`）

- 线协议与接口规格见 [protocol/v2/README.md](protocol/v2/README.md)。
- 目录边界：`internal/v2/core/`（`Identity & Space`、`Pipe`、`Box` 四原语内核）、`internal/v2/ledger/`（签名组账本、邀请/入组、文件平面、旧库导入与 `check`）、`internal/v2/plugin/`（插件接口与信任等级校验）、`internal/v2/plugins/{drop,webhook,webdav,mcpedge}/`（薄边缘协议插件）、`internal/v2/server/`（`/v2/*` 设备面、`/v2/admin/*` 管理员面、`/edge/*` 插件面）。
- 新增外部协议一律在 `internal/v2/plugins/<name>/` 实现 `plugin.Plugin` 接口并声明 `RequiredTrust()`，禁止修改内核硬编码业务协议，禁止绕过 `Space.TrustLevel` 校验。
- 插件实现 `plugin.Configurable`（`ConfigSchema` 标记 `Secret` 字段、`ValidateConfig` 拒绝未知键）；桥接写入一律走 `host.PutBridgedItem`（支持 `seal_public_key` 封存），限流键用 `host.SourceKey`，RPC 用 `host.CallRPCTimeout`。
- `relay_v2.db` 结构变更只能追加 `internal/v2/core/migrate.go` 的迁移步骤并提升 `SchemaVersion`。
- `common-relay serve` 必须带 `--access-password-file` 与 `--v2-admin-hash-file <sha256文件>`；`/healthz` 由主进程直接提供。

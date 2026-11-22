# Common Relay development

- 使用中文解释；工作分支使用 feat/、fix/、docs/ 等加小写 kebab-case。
- v1 是稳定协议；v2（`internal/v2/`）为实验性聚合层，与 v1 并存。不加入旧项目协议适配器。
- 中继不得实现剪贴板、ADB、远控等业务；各应用、组和设备必须隔离。
- 令牌只保存哈希；客户端本地生成私钥并固定可信公钥。不得将接入令牌当作端到端密钥。
- 测试使用临时目录与测试身份。不得在普通测试中操作真实桌面、运行 ADB 命令或修改生产客户端配置。
- 协议变化必须同步所有实现该能力的 SDK、共享测试向量和协议文档；Kotlin 复用 Java；Swift、Java/Kotlin、Dart、Python、TypeScript、Go、Rust 均为完整能力。禁止宣称未执行的真机或持续运行验收已通过。
- 执行 go test -race ./...，各 SDK 测试及跨语言互通；生产切换前验证真实 WSS、备份和回滚。
- 私有文件放 .local/；数据目录、构建目录和签名材料不提交。SOURCE.json 为 SDK 来源与文件校验记录。

## v2 通用聚合架构（`internal/v2/`，与 v1 解耦并存）

- 架构规格与插件扩展配方见 [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md)。
- 目录边界：`internal/v2/core/`（`Identity & Space`、`Pipe`、`Box` 四原语内核）、`internal/v2/plugin/`（插件接口与信任等级校验）、`internal/v2/plugins/{drop,webhook,webdav,mcpedge}/`（薄边缘协议插件）、`internal/v2/server/`（`/v2/*` 设备面、`/v2/admin/*` 管理员面、`/edge/*` 插件面）。
- 新增外部协议一律在 `internal/v2/plugins/<name>/` 实现 `plugin.Plugin` 接口并声明 `RequiredTrust()`，禁止修改内核硬编码业务协议，禁止绕过 `Space.TrustLevel` 校验。
- 插件实现 `plugin.Configurable`（`ConfigSchema` 标记 `Secret` 字段、`ValidateConfig` 拒绝未知键）；桥接写入一律走 `host.PutBridgedItem`（支持 `seal_public_key` 封存），限流键用 `host.SourceKey`，RPC 用 `host.CallRPCTimeout`。
- `relay_v2.db` 结构变更只能追加 `internal/v2/core/migrate.go` 的迁移步骤并提升 `SchemaVersion`。
- 启动开启 v2：在 `common-relay serve` 追加 `--v2-admin-hash-file <sha256文件>` 即可同进程挂载 `/v2/*` 与 `/edge/*`，不影响存量 v1 服务。

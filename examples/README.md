# 可运行示例

独立 MCP 客户端兼容性检查见 [mcp-probe](mcp-probe/README.md)：仅返回固定测试文字，
不读取应用数据，也尚未使用中继通道。它独立于下面的设备通信示例。

在仓库根目录执行，需要 Go 1.27.1+、Python 3.11+：

```sh
go build -o build/common-relay ./cmd/common-relay
python3 -m venv .venv
.venv/bin/pip install -e sdk/python
.venv/bin/python examples/python/device_groups.py
```

> 注意：服务端已移除 v1 传输，Python SDK 仍使用 `/relay/v1/*`，该示例需随 Python SDK 迁到 `/v2` 后才能对新服务端运行（原 `messages.py` 依赖已删除的 v1 消息与 `device-add`，已移除）。

- `device_groups.py`：创建签名设备组，演示手动审批和自动加入，以及加密短邀请解析和配置保存。
- `local_server.py`：共用的临时服务生命周期辅助模块，不是独立示例。

示例使用随机身份、临时私有目录和动态回环端口，最多运行 60 秒，退出时停止服务并清理数据，不连接公网或真实设备。预期输出为成功提示；任何断言或请求失败均以非零状态退出。

示例显式开启 `allow_local_test`，仅用于回环地址。实际部署使用 WSS；公钥和邀请应经可信渠道交付。实际应用应在发出接入请求前持久化身份和待重试申请，成功后保存 SDK 更新后的配置；本示例不实现崩溃恢复界面。令牌、密钥及完整邀请不应写入日志。

Swift、Dart 和 Java 的完整传输/设备组调用还可参考 `sdk/swift/Examples/RelayProbe`、`sdk/dart/bin/probe.dart` 与 `sdk/java/src/test/java/io/github/junweiup/commonrelay/`。运行这些探针的隔离测试入口见[开发指南](../docs/DEVELOPMENT.md)。

## 其他语言

- [Kotlin](../sdk/kotlin/README.md)：Java 完整能力的协程接口。
- [TypeScript / Node.js](../sdk/typescript/README.md)、[Go 客户端](../sdk/go/README.md)、[Rust 客户端](../sdk/rust/README.md)：完整能力。先按各 SDK 文档准备工具链，TypeScript 需 `npm ci && npm run build`。

这些测试探针只允许回环测试配置；正式应用从私有存储载入身份并使用 WSS。离线、流与设备组互通见 [开发指南](../docs/DEVELOPMENT.md#新增语言-sdk)。

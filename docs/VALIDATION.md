# 验证指南

所有本地测试使用临时目录和测试身份，不连接真实设备，不读生产配置。测试向量中的密钥是公开测试数据，不能用于实际部署。

| 层级 | 入口 | 验证内容 |
| --- | --- | --- |
| 服务端 | `go test -race ./...` | 认证、隔离、并发、存储、配额与设备组权限 |
| Python | `python -m unittest discover -s sdk/python -v` | 加密、消息、流、文件、日志、设备组与短邀请 |
| Swift | `swift test --package-path sdk/swift` | 共享向量、日志与设备组验证 |
| Dart | `dart analyze`、`dart test`（sdk/dart） | 静态检查、共享向量、日志与设备组验证 |
| Java | `gradle testDebugUnitTest lintDebug`（sdk/java） | Android SDK 单测与 Lint |
| 跨语言传输 | `scripts/local-interop.py` | 四语言双向离线消息及每方向 8 MiB 加密流 |
| 跨语言管理 | `scripts/group-interop.py` | 手动/自动加入、短邀请与成员管理 |
| 入门示例 | `examples/python/*.py` | 独立服务、随机身份与实际 SDK 调用 |

工具链及完整命令见[开发指南](DEVELOPMENT.md)。运行结果应记录使用的提交、工具链、命令和失败信息；本页不代表任何环境的验收证明。

公网部署还需单独验证真实 WSS、反向代理、断线恢复、长时负载、完整数据备份与回滚。健康检查通过不能替代业务链路验证；本地回环测试不能替代公网或真实设备验收。

## 轻量 SDK 与 Kotlin

新增 SDK 的验证命令见 [开发指南](DEVELOPMENT.md#新增语言-sdk)。Kotlin 共用 Java 实现的向量和组链测试，并通过协程接口执行回环离线消息/流互通。TypeScript/Go/Rust 验证全部共享向量（密码、流、离线、设备组含严格载荷与委托授权、短邀请）、secretstream 与 libsodium 一致、日志重启/冲突/清理/单一所有者、流额度与 FINAL、文件续传与篡改拒绝、WSS/HTTPS 校验及拒绝重定向；回环脚本覆盖与 Python 的双向离线消息、8 MiB 双向流、在线消息与设备组全流程。这些均为本地回环验证，不代表公网、真机或长期运行验收。

# Common Relay

**可自行部署的端到端加密设备通信服务。**

[English](README.md) · 简体中文

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol: v1](https://img.shields.io/badge/Protocol-v1-2563eb.svg)](protocol/README.md)
[![Status: Development](https://img.shields.io/badge/Status-Development-orange.svg)](CHANGELOG.md)

Common Relay 包含一个 Go 中继服务，以及 Swift、Android Java/Kotlin、Dart 和 Python 客户端 SDK。通过加密消息、双向字节流和离线文件投递连接不同网络中的设备，并隔离各应用与设备组。

**开发状态：** 服务端和 SDK 已提供源码实现，尚未发布稳定 SDK 版本或公共包。目前仅支持 v1 协议。

[快速开始](#快速开始) · [客户端 SDK](#客户端-sdk) · [文档](#文档) · [参与贡献](CONTRIBUTING.md#简体中文)

## 功能特性

- **端到端加密内容**：客户端生成密钥并固定可信对端公钥，中继转发密文。
- **在线与离线消息**：显式离线投递、接收确认、持久化重试与去重。
- **双向字节流**：支持有界队列与流量控制的加密流。
- **离线文件**：密文暂存、分块上传、断点续传与完整性校验。
- **签名设备组**：成员验证、设备撤销、手动审批与一次性自动入组。
- **加密短邀请**：加密邀请包，解密密钥保留在链接片段中。
- **自行部署**：单个 Go 服务、SQLite 存储与 TLS 反向代理。

应用负责业务逻辑和权限，Common Relay 提供通信能力。

## 工作方式

```text
设备 A                              自行部署的基础设施                              设备 B
客户端 SDK ── WSS / HTTPS ──> TLS 代理 → Go 中继 → SQLite <── WSS / HTTPS ── 客户端 SDK
   └────────────────────────── 应用内容端到端加密 ──────────────────────────┘
```

每台设备使用独立接入令牌认证。服务端保存令牌哈希，并在应用和设备组内路由数据。SDK 使用 libsodium 加密内容，依据本地可信公钥验证对端身份。

中继仍能观察路由、时间及密文大小。静态身份密钥**不提供前向保密**，接入前请阅读[安全模型](SECURITY.md)。

## 快速开始

以下命令适用于 macOS 或 Linux，需要 **Go 1.27.1+** 和 **Python 3.11+**。Python 示例不需要安装其他 SDK 的工具链。

```sh
git clone https://github.com/JunWeiUp/common-relay.git
cd common-relay

go build -o build/common-relay ./cmd/common-relay
python3 -m venv .venv
.venv/bin/python -m pip install -e sdk/python

.venv/bin/python examples/python/messages.py
.venv/bin/python examples/python/device_groups.py
```

每个示例会自动启动临时回环服务、生成全新身份、验证 SDK 调用，并在退出时清理数据。

| 示例 | 演示内容 |
| --- | --- |
| [messages.py](examples/python/messages.py) | 在线消息、离线投递与确认、双向加密流 |
| [device_groups.py](examples/python/device_groups.py) | 创建设备组、手动审批、自动加入、短邀请与私有配置保存 |

预期输出和接入注意事项见[示例说明](examples/README.md)。

## 运行服务

```sh
build/common-relay serve --data ./data --listen 127.0.0.1:47805
```

公网部署需要 TLS 反向代理，并使用 **WSS/HTTPS**。仓库提供 [Nginx 配置](deploy/nginx.conf)和 [systemd 单元](deploy/common-relay.service)，安装、备份和升级步骤见[部署指南](docs/DEPLOYMENT.md)。

示例显式允许回环地址使用未加密的 WebSocket 传输，仅用于本地测试；应用内容仍由 SDK 加密。

| CLI 命令 | 用途 |
| --- | --- |
| `serve` | 启动中继服务 |
| `check` | 打开存储并检查数据库连接 |
| `device-add` | 使用客户端生成的公钥登记静态设备 |
| `device-revoke` | 撤销静态登记设备 |
| `group-bootstrap` | 为签名设备组生成初始化凭据 |

使用 `<命令> --help` 查看参数。凭据文件使用私有权限、拒绝覆盖已有文件，令牌不输出到终端。签名设备组通过 SDK API 管理成员。

自助创建默认关闭，通过 `serve --self-service-apps example` 启用指定应用命名空间。该白名单**不是账户认证系统**，详见[设备组管理](docs/DEVICE-GROUPS.md)。

## 客户端 SDK

目前通过本仓库源码接入，尚未提供公共包安装命令或稳定版本保证。

| SDK | 源码 | 环境要求 |
| --- | --- | --- |
| Swift | [sdk/swift](sdk/swift) | Swift tools 5.9+，macOS 13+ / iOS 15+ |
| Android Java/Kotlin | [sdk/java](sdk/java) | Android API 26+；构建使用 JDK 17、Gradle 8.13、Android SDK 36 |
| Dart | [sdk/dart](sdk/dart) | Dart 3.11+ 且 <4.0 |
| Python | [sdk/python](sdk/python) | Python 3.11+ |

可使用本地 Swift package、Android library module、Dart path dependency，或快速开始中的 Python 可编辑安装。[SDK 分发指南](docs/REGISTRY.md)介绍源码快照及来源记录。

四类 SDK 共用密码测试向量。应用应安全持久化身份、可信公钥和重试状态；启用自动邀请前，组内全部成员的 SDK 都应支持相应授权链。

## 开发与测试

完成快速开始的环境准备后执行：

```sh
go test -race ./...
.venv/bin/python -m unittest discover -s sdk/python -v
swift test --package-path sdk/swift
(cd sdk/dart && dart pub get && dart analyze && dart test)
(cd sdk/java && gradle testDebugUnitTest lintDebug)
```

Swift、Dart 和 Android 检查需要各自工具链；Java 单测还需要本机 libsodium。环境变量及跨语言测试命令见[开发指南](docs/DEVELOPMENT.md)。

本地互通覆盖离线消息、双向 8 MiB 加密流、签名设备组及邀请。公网 WSS、长时负载和恢复演练属于单独的部署检查，详见[验证指南](docs/VALIDATION.md)。

## 文档

README 和贡献指南提供中英文版本。详细指南目前主要使用中文，协议文档包含英文内容。

| 文档 | 内容 |
| --- | --- |
| [示例](examples/README.md) | 可运行示例与接入说明 |
| [协议 v1](protocol/README.md) | 消息格式、加密和兼容性 |
| [架构](docs/ARCHITECTURE.md) | 模块、存储与资源限制 |
| [设备组](docs/DEVICE-GROUPS.md) | 信任、成员与邀请 |
| [安全](SECURITY.md) | 威胁模型与密钥管理 |
| [可靠性](docs/RELIABILITY.md) | 重试、日志、去重与清理 |
| [部署](docs/DEPLOYMENT.md) | 安装、配置、备份与回滚 |
| [开发](docs/DEVELOPMENT.md) / [验证](docs/VALIDATION.md) | 工具链与验证流程 |
| [SDK 分发](docs/REGISTRY.md) | 源码快照与来源记录 |
| [接口入口](docs/PAGE-STRUCTURE.md) | HTTP 和 WebSocket 路由 |
| [开发计划](TODO.md) / [变更记录](CHANGELOG.md) | 后续工作与版本变化 |

## 参与贡献

欢迎提交问题、改进文档、补充示例和发起 Pull Request。开始前请阅读[贡献指南](CONTRIBUTING.md#简体中文)。可通过 [GitHub Issues](https://github.com/JunWeiUp/common-relay/issues)反馈可复现的问题或提出功能建议，请勿附带凭据或私有配置。

## 许可证

[MIT](LICENSE) © JunWeiUp。第三方依赖保留各自许可证。

基于 [libsodium](https://github.com/jedisct1/libsodium)、[coder/websocket](https://github.com/coder/websocket) 和 [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite) 构建。

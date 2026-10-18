# Common Relay

通用设备中继：一个 Go 服务、一套版本化协议，提供应用与设备组隔离的消息、双向字节流和端到端加密离线文件。提供 Swift、Android Java/Kotlin、Dart 和 Python SDK。

当前为开发版，支持 v1 协议。客户端生成密钥并固定可信公钥；服务端只保存接入令牌哈希，转发密文，不持有解密密钥。静态设备密钥不提供前向保密。

## 快速开始

需要 Go 1.27.1+；Python 示例需要 Python 3.11+。

```sh
go build -o build/common-relay ./cmd/common-relay
python3 -m venv .venv
.venv/bin/pip install -e sdk/python
.venv/bin/python examples/python/messages.py
.venv/bin/python examples/python/device_groups.py
```

示例自动启动临时回环服务，生成独立身份，演示在线/离线消息、双向加密流、手动/自动邀请及短链接，结束后清理。详见[示例说明](examples/README.md)。

## 运行服务

```sh
build/common-relay serve --data ./data --listen 127.0.0.1:47805
```

公网使用 HTTPS 反向代理提供 WSS，见[部署说明](docs/DEPLOYMENT.md)。CLI 提供 `serve`、`check`、`device-add`、`device-revoke`、`group-bootstrap`；运行相应子命令加 `--help` 查看参数。

```sh
build/common-relay device-add --data ./data --app example --group personal \
  --device desktop --public-key <客户端生成的64位十六进制公钥> \
  --credential-out /private/path/device.json
```

凭据文件拒绝覆盖，不向终端打印令牌。设备组支持签名成员管理、手动确认（默认）、一次性自动批准和加密短邀请。自助创建默认关闭，可通过 `--self-service-apps example` 按命名空间启用；命名空间不是用户账户认证。

## 开发

```sh
go test -race ./...
.venv/bin/python -m unittest discover -s sdk/python -v
swift test --package-path sdk/swift
(cd sdk/dart && dart pub get && dart analyze && dart test)
```

Java 工具链、四语言互通与验证边界见[开发指南](docs/DEVELOPMENT.md)和[验证指南](docs/VALIDATION.md)。

[架构](docs/ARCHITECTURE.md) · [协议](protocol/README.md) · [设备组](docs/DEVICE-GROUPS.md) · [安全](SECURITY.md) · [可靠性](docs/RELIABILITY.md) · [SDK 分发](docs/REGISTRY.md) · [接口](docs/PAGE-STRUCTURE.md) · [开发规范](docs/COMPONENT-GUIDELINES.md) · [设计原则](DESIGN.md) · [计划](TODO.md) · [变更](CHANGELOG.md)

依赖包括 [libsodium](https://doc.libsodium.org/)、[coder/websocket](https://github.com/coder/websocket) 和 [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite)。本项目 MIT 许可，各第三方依赖保留自身许可。

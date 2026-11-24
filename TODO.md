# 开发计划

- [ ] SDK 正式版本发布与可复现分发。
- [x] 自动化 CI 覆盖 Go 服务端、各语言 SDK、共享向量与跨语言互通（见 `.github/workflows/ci.yml`）。
- [ ] 扩充文件续传、断线恢复及应用接入示例。
- [ ] 在独立测试环境执行 24 小时混合负载和备份恢复演练。
- [x] Go SDK 消息客户端对齐 v2 帧（发送 `msg`/`presence`、接收 `msg` 与 `ack{event}`），并按 §4.5 处理无法解密的消息。
- [x] Dart/Swift SDK 提供离线消息确认接口与 §4.5 无法解密处理，消息信封 kind 统一为 `message`（向下兼容 `msg`）。
- [x] 各主力消费 SDK（Python / Rust / Dart / Swift / Android Java）提供回调式“发请求前持久化草稿”群组状态机（`GroupStateMachine`）及 `relay.direct.v1` 直连升级约定辅助。

已有能力、接口和测试入口分别见 [README](README.md) 与 [协议](protocol/v2/README.md)。部署验收由使用方针对自己的环境执行。

## 通用 Webhook

- [x] 可选路由、独立令牌哈希、固定设备、公钥校验和标准加密文件投递。
- [x] 持久确认、重启恢复、限时幂等回执、容量控制与 Go/Python 入口互通。

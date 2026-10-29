# Changelog

## Unreleased

- SDK 改为按 Git 标签依赖分发：根目录 `Package.swift`（Swift）、JitPack（Java/Kotlin）、Git 子目录依赖（Dart/Python/Go/Rust）及 Release tgz（TypeScript）；新增 `release.yml` 发布工作流，各 SDK 版本统一为 0.1.0，源码快照降为可选。
- 保持各语言独立 SDK，不依赖共享 Rust 核心或自有多平台原生库。
- 新增 Kotlin Android 协程接口，复用 Java 的完整协议实现。
- 新增 TypeScript（Node.js）及 Go 轻量客户端：加密在线消息、在线设备查询、共享向量与回环互通验证。
- 新增 Rust 轻量客户端（独立 crate，纯 Rust NaCl box 与 rustls）：能力与 TypeScript/Go 一致，并加入回环互通脚本。
- TypeScript、Go、Rust 补齐完整能力：持久化离线消息（日志、ACK、去重、清理）、secretstream 双向流、加密文件、签名设备组（严格载荷、委托授权、自助创建、改名、退出、解散）及加密短邀请；七类 SDK 共用向量，`local-interop.py`、`group-interop.py` 增加三者的互通探针。
- 源码快照工具支持 Kotlin、TypeScript、Go、Rust；保留文件续传偏移检查与 Python 流关闭唤醒修复。

## 未发布

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

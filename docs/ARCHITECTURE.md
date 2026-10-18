# 架构

客户端 SDK → WSS/HTTPS → Nginx → 回环 Go 服务。SQLite WAL 保存设备令牌哈希、消息、收件确认和文件状态；受限数据目录保存密文文件。

`cmd/common-relay` 提供服务和管理员 CLI；`internal/relay` 管理接入、路由、窗口、持久化及清理；`sdk/` 提供四种语言；`protocol/` 定义跨语言契约；`deploy/` 提供 Linux 服务和代理配置。

内存队列有界：最多 128 在线连接，每应用最多 64，每设备最多 8 条流，单流单方向最多 8 条未消费记录。全局发送排队上限 32 MiB。SDK 单条密文记录最多 64 KiB。

服务重启终止所有在线流，客户端显式恢复新会话。离线数据保留；已写入文件块通过 offset 恢复，完整提交并匹配密文 SHA-256 后才允许下载。

可靠性：文件操作使用引用计数的每文件锁，配额依赖短事务；连接心跳回收未接受流。SDK 持久化发送与接收日志，启动及每小时清理，详见 [RELIABILITY.md](RELIABILITY.md)。

设备组管理：`internal/relay/groups.go` 提供初始化、邀请、签名成员变更与撤销。SQLite 追加保存签名名单及短时邀请；四类 SDK 验证信任链并持久化最后验证版本。管理权限属于设备，与手机/桌面类型无关，详见 [设备组管理](DEVICE-GROUPS.md)。

自动邀请：`internal/relay/group_auto.go` 验证管理员一次性授权及委托签名，提供按可信起点分页读取成员链和自动提交接口。`group_invite_grants` 是新增附属表，通过外键随邀请删除；已有邀请无需迁移并保持手动模式。原子登记设备、追加名单及消费邀请；四 SDK 同时验证委托权限边界。

短邀请：`invitation_links.go` 管理加密包发布和按派生能力读取，`group_invite_links` 与邀请级联删除。四 SDK 的 InvitationLinks 辅助模块负责 SecretBox、用途隔离的读取令牌与规范化短 URI；服务端没有解密密钥。

# 接口与模块入口

没有网页路由或管理页面。

- `/relay/v1/ws`：WebSocket，必须声明 `common-relay.v1` 子协议。
- `/relay/v1/files`：文件创建与收件箱。
- `/relay/v1/files/{id}`：文件状态与删除确认。
- `/relay/v1/files/{id}/data`：分块上传、Range 下载。
- `/relay/v1/files/{id}/commit`：完整上传校验与提交。
- `/relay/v1/group`：成员链与在线成员。
- `/relay/v1/group/create`、`/bootstrap`：自助创建与受控初始化。
- `/relay/v1/group/invitations`：邀请创建、查询与取消。
- `/relay/v1/enroll/{id}` 及其 `/auto`、`/link` 子路径：接入申请、自动授权与加密短邀请。
- `/healthz`：本机健康检查，不通过公开 Nginx 路由导出。

设备数据接口使用 Authorization Bearer；初始化、接入和短邀请使用各自限定用途的凭据。详见 protocol/README.md。

SDK 新增 `RelayJournal`（Python 使用 `Client.state_path`）及显式 `cleanup` 接口；离线接入与记录生命周期见 [RELIABILITY.md](RELIABILITY.md)。

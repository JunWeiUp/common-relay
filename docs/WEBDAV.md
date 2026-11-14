# 可选 WebDAV 上传接入

很多手机应用只支持「备份到 WebDAV」。可选的 `/relay/v1/dav/{route}/` 让这类应用直接把文件上传到 Common Relay：服务器收到文件后立即生成现有 v1 加密文件，投递给配置中固定的接收设备。接收端继续使用各 SDK 已有的 Files 收件箱、下载、解密和确认接口，协议与 SDK 都不变。默认不开启，未知路由返回 404。

## 信任边界

与 [Webhook 接入](WEBHOOKS.md) 相同，这是**服务器托管的桥接发送端**：HTTPS 在服务器终止，服务器在接收和加密期间能看到文件明文，并持有桥接身份的私钥。加密只覆盖桥接身份到接收设备这一段，不能宣称上传应用到接收设备的端到端加密。

- 每条路由一个账号和一个授权密码（HTTP Basic）。配置只保存密码的 SHA-256；授权密码应使用至少 16 位的随机字符串，不要复用其他密码。
- 同一路由连续认证失败 20 次后，10 分钟内全部返回 429（含正确密码），防止在线猜测。
- 入口**只收不读**：文件内容加密后只有接收设备能解开，服务器不保留明文，`GET` 文件返回 403。目录列表（PROPFIND）只暴露路径、大小、修改时间和内容摘要前缀，供上传应用确认备份成功。
- 此入口使用自己的账号密码，不要求 `Relay-Access`；接收端取文件仍要求正常设备令牌和服务接入密码。
- 桥接身份必须是专用发送设备，桥接公钥须加入接收端可信列表，接收公钥在配置中固定；每次上传检查双方仍在同一应用 / 组且未撤销。

## 配置

先按既有设备流程注册桥接设备和接收设备，私钥分别在所属端生成。用 `common-relay hash-password` 从标准输入读取授权密码并输出 SHA-256。保存到忽略的私密文件（目录 0700、文件 0600），尖括号占位必须替换：

```json
[
  {
    "route": "phone-backup",
    "app": "archive",
    "group": "personal",
    "sender": "webdav-bridge",
    "recipient": "desktop",
    "username": "<上传应用中填写的账号>",
    "password_sha256": "<授权密码的64位小写十六进制SHA-256>",
    "secret_key": "<桥接发送设备的64位十六进制私钥>",
    "recipient_public_key": "<接收设备的64位十六进制公钥>",
    "max_file_bytes": 67108864
  }
]
```

- `username`：1–64 个可打印 ASCII 字符，不能含冒号。
- `max_file_bytes`：单文件上限，缺省 64 MiB，最大 512 MiB。
- 一个配置文件可有多条路由，每条路由独立账号、目录列表和接收设备。

在现有 `serve` 参数后追加 `--webdav-config /absolute/private/webdav.json`。systemd 部署与 Webhook 相同：用 `LoadCredential=webdav:/etc/common-relay/webdav.json` 并追加 `--webdav-config ${CREDENTIALS_DIRECTORY}/webdav`，保留现有参数和 drop-in。修改配置须重启；配置无效时启动失败，不会降级为匿名接入。

上传应用中填写：

- 服务器地址：`https://<你的域名>/relay/v1/dav/<route>/`
- 账号：配置中的 `username`
- 密码：授权密码明文

## 支持的方法

| 方法 | 行为 |
| --- | --- |
| OPTIONS | `DAV: 1`，列出允许的方法 |
| PROPFIND | Depth 0 / 1；`infinity` 或缺省按 1 处理，避免超大响应。返回固定的活属性：displayname、resourcetype、getlastmodified、creationdate、getcontentlength、getcontenttype、getetag |
| MKCOL | 创建目录；已存在 405，带请求体 415 |
| PUT | 接收文件并加密投递；新建 201，覆盖 204，返回 `ETag`。上级目录不存在时自动创建，上级是文件时 409 |
| HEAD | 返回大小、类型、ETag，不含内容 |
| GET | 目录返回一行说明；文件 403（只收不读） |
| DELETE | 删除列表条目（目录连同子项）；不撤回已投递的文件 |
| MOVE | 在同一路由内改名或移动，支持 `Overwrite: F`；不重复投递 |
| PROPPATCH | 接受并忽略（部分客户端上传后设置修改时间） |
| LOCK / UNLOCK / COPY | 405 |

用 `rclone` 做过真实客户端互通（`COMMON_RELAY_RCLONE=1 go test ./internal/relay -run Rclone`）。`scripts/webdav-interop.py --server <构建的二进制>` 用真实服务端进程验证账号密码、上传、列表、拒绝下载，以及未修改的 Python SDK 解密与确认。不同应用的 WebDAV 实现差异较大，接入新应用前请先用它跑一次备份，确认它没有依赖 GET 读取或 LOCK。

## 投递语义

- 每次成功的 PUT 生成一个加密文件，`expires=253402300799`，保留到接收端明确确认；计入现有应用 / 全局文件配额。配额或磁盘余量不足返回 507，上传应用应稍后重试。
- **同一路径上传完全相同的内容**（大小与 SHA-256 一致）只更新列表，不再投递，适合周期性全量备份。
- **0 字节文件**（应用的连通性探测）只出现在列表中，不投递。
- MOVE 不重新投递，因此常见的「先上传临时名再改名」流程中，接收端看到的是临时名。接收端不得依赖文件名判断内容。
- DELETE 只删除列表条目；已投递但尚未确认的文件仍在接收端收件箱中。
- 同一路由的写操作串行处理，全服务最多同时处理 2 个上传；繁忙返回 503。
- 崩溃恢复与 Webhook 共用同一暂存流程：加密完成且数据库持久后才返回成功；启动时完整的暂存密文恢复投递，残缺的删除。
- 每条路由最多 10,000 个列表条目，超过返回 507。

接收端解密后的元数据：

```json
{"type":"webdav","version":1,"route":"phone-backup","path":"/备份/2026-11-13.zip","name":"2026-11-13.zip","content_type":"application/zip","size":1234567,"sha256":"<明文SHA-256>","received_at":1234567890000}
```

明文是上传的原始字节；`received_at` 是服务器接收时间（毫秒）。接收端应先在自己的事务里按文件 ID 去重并处理内容，再调用文件确认。不得把路径、文件名或内容当作可执行命令。

## 反向代理

`deploy/nginx.conf` 包含独立的 `/relay/v1/dav/` location：请求体上限 64m（与缺省 `max_file_bytes` 一致，调大时两边同步），关闭请求缓冲和访问日志，保留 Authorization、Depth、Destination、Overwrite 请求头。MOVE 的 Destination 只比较路径，代理改写主机名不影响。

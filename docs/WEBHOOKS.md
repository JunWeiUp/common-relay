# 通用 Webhook 接入

可选的 `POST /relay/v1/webhooks/{route}` 接收普通 JSON，直接生成现有 v1 加密文件，交给指定设备。无需常驻 HTTP 适配器或转发 worker；服务不理解任何应用的业务字段。默认不开启，未知路由返回 404。

## 信任边界

这是**服务器托管的桥接发送端**：HTTPS 在服务器终止，服务器能看到请求明文，并持有桥接身份的私钥。普通客户端的私钥仍留在客户端。加密只覆盖桥接身份到接收设备这一段，不能宣称 Webhook 发送方到接收设备的端到端加密。

每个来源使用独立的强随机 Bearer 令牌（至少 32 字符，建议随机 256 位）；配置只保存其 SHA-256。令牌只允许向配置中固定的应用、组、接收设备投递，不允许读取文件或更改路由。此入口使用自己的令牌，不要求 `Relay-Access`；文件接收仍要求正常设备令牌和服务接入密码。可选配置通用 HMAC 签名校验；不转发 Authorization 或其他请求头。

桥接身份是专用发送设备，不能复用用户设备私钥。桥接公钥须加入接收端的可信列表，接收公钥在桥接配置中固定；每次投递检查双方仍在同一应用/组且未撤销。已有签名设备组须通过正常邀请/加入流程授权桥接设备，不绕过成员签名直接写库。

## 配置和启动

先按既有设备配置流程注册桥接设备和接收设备；两端私钥分别在所属端生成。下面只有字段说明，尖括号占位值必须替换。保存到忽略的 `.local/webhooks.json`，目录 0700、文件 0600，不能提交真实配置。

```json
[
  {
    "route": "phone-archive",
    "app": "archive",
    "group": "personal",
    "sender": "webhook-bridge",
    "recipient": "mac",
    "token_sha256": "<接入令牌的64位小写十六进制SHA-256>",
    "secret_key": "<桥接发送设备的64位十六进制私钥>",
    "recipient_public_key": "<Mac设备的64位十六进制公钥>"
  }
]
```

在现有 `serve` 参数后追加 `--webhook-config /absolute/private/webhooks.json`。相同进程和监听端口提供入口；TLS 仍由反向代理负责。代理须允许 POST、保留 Authorization/Idempotency-Key，设置至少 32 MiB 请求上限，并禁止记录请求体和鉴权头。修改配置须重启，不支持热加载；配置无效时启动失败，不降级为匿名接入。

客户端发送 JSON，`Content-Type: application/json`、`Authorization: Bearer <接入令牌>`。可选 `Idempotency-Key` 不超过 128 字节，代表同一个逻辑请求；失败重试复用同一键和完全相同的请求体。不要把密码放在 URL 中。

## 确认、重试和容量

- `202 {"id":"<文件ID>","status":"durably_queued"}` 只表示加密文件与数据库已持久保存，不表示接收端已经入库。
- 接收端轮询现有 Files 收件箱，下载、验证并解密；先在自己的事务里按文件 ID 去重并保存业务数据，再调用现有文件 DELETE/acknowledge。下载本身不会清除队列。应用事务提交后崩溃，重启可再次消费同一 ID 并补确认。
- 同一路由和目标的幂等键保留 7 天；同键同请求返回原 ID，哪怕文件已确认；同键不同字节返回 409。每条路由最多保留 10,000 个有效幂等回执，超限返回 507。不提供幂等键或超出窗口的重试可能产生新文件，消费者仍须按业务规则处理重复。
- 请求最多 32 MiB，最多同时处理 2 个请求；同一路由串行发布。文件列表按持久插入顺序返回，消费者如需来源顺序，应顺序入库和确认。入口不承诺多来源之间的业务顺序。
- Webhook 文件不走普通文件的短期 TTL，`expires=253402300799`（9999 年）代表保留到明确删除。计入现有应用/全局文件配额；接收端长时间离线导致配额满后返回 507，由发送方保留并重试。撤销发送/接收设备仍会触发原有清理规则。
- 401 鉴权失败，403 设备撤销/公钥不匹配，400 JSON 或请求无效，413 过大，415 类型不支持，507 配额/磁盘不足，503 暂时忙或存储失败。忙/存储错误采用退避重试，不把失败响应当作已接收。
- 加密完成前使用权限受限的临时明文文件；正常完成即清除，进程异常后下次启动清除残留。密文先写入暂存状态，持久发布后转 ready。启动恢复校验大小和 SHA-256；完整密文恢复投递，残缺记录删除。严重磁盘错误后可能需要修复磁盘并重启以完成暂存恢复。

## SDK 兼容

不新增接收传输协议，也不修改现有 v1 密码格式。Swift、Java/Kotlin、Dart、Python、TypeScript、Go、Rust 均继续用已有 Files 的收件箱、下载、解密、确认接口。应用需识别解密后的元数据：

```json
{"type":"webhook","version":1,"route":"phone-archive","content_type":"application/json","received_at":1234567890000}
```

明文文件是原始 HTTP JSON 字节；`received_at` 是服务器接收时间（毫秒），不是业务事件时间。不得把文件名、路由或 JSON 内容当作可执行命令。共享样例在 `protocol/webhook-vectors.json`；`scripts/webhook-interop.py` 验证真实 HTTP 入口、Go 加密、未修改的 Python SDK 解密与确认。

服务端直接复用本仓库 Go SDK 的加密实现，根 go.mod 通过本地 replace 引用 `sdk/go`；从完整仓库构建，不单独复制 cmd/internal 后构建。

## 从既有接入迁移与回滚

本能力只提供通用入口。既有接收端若识别的是自定义批次格式，**不能原样消费此处的原始 Webhook JSON**。切换前需在接收端增加该元数据类型的解析、来源映射和事务去重；只在归档成功后确认文件。

迁移顺序：备份配置/密钥/数据库 → 配置并授权桥接身份 → 验证接收端 → 用测试请求跑通新入口 → 修改发送方地址/令牌 → 排空旧队列 → 再停旧服务。旧凭据和队列保留到验收完成。不要同时将两个入口推送到同一归档而缺少业务去重。

回滚发送方地址与旧服务即可；Common Relay 的新密文文件与数据库须保留，不能丢弃尚未入库的请求。只移除 `--webhook-config` 会关闭新接入，已入队文件仍能通过现有 SDK 收取。

### systemd 凭据与代理

仓库 `deploy/nginx.conf` 已包含独立的 Webhook location（32 MiB，关闭请求缓冲和访问日志）。部署模板更新后须 `nginx -t` 验证，再按既有流程 reload；没有路由配置时后端仍返回 404。

默认 unit 使用 DynamicUser，不能直接读取 root 的 0600 配置。可通过 drop-in 增加 `LoadCredential=webhooks:/etc/common-relay/webhooks.json`，并在复制**当前完整 ExecStart 参数**的基础上追加 `--webhook-config ${CREDENTIALS_DIRECTORY}/webhooks`；保留现有 access-password、self-service-apps 和配额参数。不要直接覆盖生产 unit 或丢掉其他 drop-in 设置。配置和桥接密钥必须纳入私密备份。

### 可选请求签名

路由可增加 `signature` 对象：`secret`（至少16字符）、`timestamp_header`、`signature_header`。验证格式为 `sha256=` 加 HMAC-SHA256(secret, timestamp + "." + 原始请求体) 的小写十六进制；时间戳为 Unix 秒，允许前后300秒。配置后签名缺失/错误/过期均返回401。签名密钥必须作为私密凭据保存，不能只保存哈希。头名称可配置，不写死应用名称，例如 `X-Example-Timestamp` 和 `X-Example-Signature`。

systemd 托管凭据在部分 Linux 版本中以 0440 文件、0550 私有凭据目录呈现。加载器仅对 `CREDENTIALS_DIRECTORY` 直接指定的私有目录接受这种只读形式；普通配置文件仍要求 0600/0400，不接受普通目录下的组可读配置。

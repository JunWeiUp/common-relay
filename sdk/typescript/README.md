# TypeScript / Node.js

原生 JavaScript 客户端：固定可信公钥的加密在线/离线消息（持久化日志、ACK、去重、清理）、双向加密流、加密文件传输、在线设备查询和 presence 通知。Node.js 22+；TypeScript 5.9；使用 TweetNaCl（box）、libsodium-wrappers（WebAssembly secretstream）与 `ws`，不需要 Rust、FFI 或预编译平台库。支持 Common Relay v1。

```sh
cd sdk/typescript
npm ci
npm test
```

源码接入：运行 `npm run build`，在应用 package.json 中使用 `"@common-relay/client": "file:../common-relay/sdk/typescript"`（按实际路径修改）并安装依赖。当前不发布 npm 包，`private: true` 用于避免误发布。

```typescript
import { Client, Identity } from '@common-relay/client';

// secretKey、trustedPeers 与 deviceToken 来自应用私有存储和可信配对过程。
const identity = new Identity('example', 'my-group', 'my-device', secretKey, trustedPeers);
const client = await Client.connect('wss://relay.example.com/relay/v1/ws', deviceToken, identity);
try {
  console.log(await client.peers()); // 仅发现信息，不更新 trustedPeers。
  const receipt = await client.message('peer-device', Buffer.from('hello'));
  const event = await client.nextEvent(AbortSignal.timeout(30_000));
  if (event.type === 'message') handleMessage(event.from, event.data);
} finally { client.close(); }
```

首次使用 `Identity.generateKeyPair()` 在本地生成身份，私钥需要安全持久化，公钥经可信渠道固定；独立的中继接入令牌不是加密密钥。已有设备组可从受信任配置导入身份与对端公钥。

离线消息、流与文件：

```typescript
import { Client, Files, Journal, prepareFile, decryptFile, safeFileName } from '@common-relay/client';

const journal = new Journal(privateStateDirectory); // 每个目录只允许一个实例；重连复用，退出时 journal.close()
const client = await Client.connect(url, deviceToken, identity, { journal });
// 应用持久化消息 ID；重试使用同一 ID，复用原密文与首次固定的 expires（默认 24 小时）。
await client.message('peer-device', data, { offline: true, id: savedMessageId }); // stored 或 received
const event = await client.nextEvent();
if (event.type === 'message') { await commitToAppDatabase(event); await client.acknowledge(event); }
if (event.type === 'stream.open') {
  const stream = await client.acceptStream(event); // 或 client.rejectStream(event)
  while (!stream.receivedFinal) await stream.send(await stream.receive(), stream.receivedFinal);
}
const files = new Files(url, deviceToken);       // 接受 wss://…/relay/v1/ws 或 https://…/relay/v1/files
const info = await prepareFile(identity, 'peer-device', sourcePath, stagingPath);
await files.upload(info, stagingPath);            // 409 时严格核对原描述后续传
```

范围与生命周期：

- `message` 默认在线；`forwarded` 仅表示进入中继转发队列。`offline: true` 必须配置 `Journal`：发送前持久化接收方、内容摘要、原密文和绝对 `expires`（同时在信封内认证），同 ID 不同内容/接收方被拒绝；`stored` 表示服务器已保存，`received` 表示对端已确认，终态保留 7 天。
- 接收离线消息需要 `Journal`，否则报错并断开，绝不自动 ACK。应用事务提交后调用 `acknowledge`：先写去重记录再发 ACK；ACK 丢失后的重投会自动重新 ACK，不再交给应用；过期内容不投递。去重保留 7 天。日志打开时与连接期间每小时清理，每轮最多 256 次变更，可调用 `client.cleanup()` / `journal.cleanup()`。日志按应用/组/本机设备/对端/消息 ID 隔离，逐记录临时文件+fsync+rename 原子替换，不保存令牌、私钥或明文。同一目录同一时间只允许一个 `Journal`：靠记录进程号的 `owner.lock` 实现，持有进程已退出时自动接管；若该进程号恰好被其他存活进程复用，打开会一直失败，需确认无实例运行后手动删除 `owner.lock`。
- 流：`openStream`/`acceptStream` 每个方向独立 secretstream 描述，每条记录最多 65519 字节明文，最多 8 条未消费记录（额度耗尽暂停发送，30 秒无额度则关闭）。乱序、重复、篡改和 FINAL 之后的数据会终止流。close/断线是取消，不是可靠半关闭；需要完整结束时发送并检查 FINAL（`receivedFinal`）。
- 文件：密文格式 `length[4 BE] | secretstream 记录`；上传每块 ≤1MiB 并核对 `Upload-Offset` 进度，下载按 Range 续传。`decryptFile` 先核对密文长度与 SHA-256，再逐条认证并要求 FINAL，最后以不覆盖的方式发布到应用指定路径；远端文件名仅经 `safeFileName` 清洗后作为单个路径分量使用。HTTP 禁止重定向。
- 每个 `Client` 实例只拥有一次连接；断开后显式建立新实例，在线消息与流不重放。请求默认 45 秒超时，最多 64 个 pending 请求，事件队列最多 64 条，满时断开并报错。
- `nextEvent` 单消费者；AbortSignal 只取消本次等待。组变更通知不是已验证的成员链，不能据此修改可信公钥。
- 只接受 WSS/HTTPS，拒绝重定向、URL 凭据和查询参数；`allowLocalTest` 仅放行显式的 `ws://127.0.0.1` / `http://127.0.0.1` 回环测试。

### 设备组

`new Groups(config, { allowLocalTest })` 使用与 Python/Dart 相同的 JSON 配置（`app`、`group`、`device`、`secret_key`、`trusted_peers`、`url`、`token` 及 `pending_*` 状态），并就地更新 `groups.config`；应用在每次调用后将其持久化到私有存储。

- 创建/初始化：`prepareCreate(groupName, deviceName)` 生成已签名草稿，应用保存后再 `create()`；运维初始化用 `bootstrap(code, name)`。
- 邀请：`invite('manual' | 'auto', { compact })`（compact 时返回 `short_link`）、`resolveInvitation(link)`、`pending`、`approve(invitation, request, { manager })`、`cancel`。
- 加入：`join(invitation, name)` 后由应用驱动 `finishJoin()`；auto 模式由扫码方验证授权链后自行签署入组，邀请端可离线。
- 成员变更：`refresh`、`remove`、`rename`、`prepareExit({ disband })` + `exit()`（`leave()` / `disband()` 为便捷封装）。

签名载荷执行与服务端相同的字节级严格校验，签名链逐条验证（含委托 `authorization`），不信任未验证的 HTTP 成员列表。`examples/group-probe.mjs` 供 `scripts/group-interop.py` 驱动。

共享密码向量（含流与离线向量）、日志重启/冲突/清理批量/单一所有者、流乱序/重复/篡改/FINAL、连接身份校验、取消、超时与重定向均有单测；`test/integration.test.mjs` 使用 `build/common-relay` 临时回环服务验证离线 stored/received/丢失 ACK 去重、1MiB 双向流和文件续传/篡改拒绝。`examples/echo.mjs` 是互通探针：`scripts/lightweight-interop.py` 验证在线消息与设备查询，配置含 `state_path` 时可用于 Python ↔ Node.js 双向离线消息与 8MiB 双向流互通。均不是公网或长期运行验收。

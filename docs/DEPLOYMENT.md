# 部署与运维

参考部署支持 Linux amd64 / arm64，使用 systemd、Nginx 和已有 HTTPS 证书。服务绑定 `127.0.0.1:47805`，`deploy/nginx.conf` 导出 `/relay/v1` 路径。可以使用其他支持 WebSocket 的 TLS 反向代理。

## 首次安装

从包含服务端附件的 GitHub Release 下载对应架构的 `common-relay-server-<tag>-linux-<arch>.tar.gz` 和 `SHA256SUMS`。先核对归档摘要，再解压；包内包含 `build/`、`deploy/`、本指南、许可证及记录版本、提交、工作区状态和逐文件 SHA-256 的 `SOURCE.json`。旧 Release 若无服务端附件，可从源码构建。

```sh
# 在下载目录中，只校验所选归档；<tag> / <arch> 替换为实际值
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf common-relay-server-<tag>-linux-<arch>.tar.gz
cd common-relay-server-<tag>-linux-<arch>
```

目标服务器需已有 systemd、Nginx、HTTPS 证书、Python 3 和 curl。在目标 Nginx HTTPS `server` 块内加入唯一一行 `# common-relay:include`，然后以 root 执行：

```sh
bash deploy/install.sh /etc/nginx/sites-available/relay.conf
```

安装脚本自动选择本机架构；架构不支持或包内缺少对应二进制时，在替换已安装文件前退出。

也可在仓库根目录本地打包（产物默认位于 `build/server-release/`；未提交改动会标为 `dirty: true`）：

```sh
python3 scripts/package-server.py --version v0.1.4-local
# 或仅构建目标服务器的二进制，保留 build/ 与 deploy/ 目录结构
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o build/common-relay-linux-amd64 ./cmd/common-relay
```

脚本先校验标记、构建产物和工具，再备份已有二进制、单元与配置，插入 `include /etc/nginx/snippets/common-relay.conf;`。已存在该 include 时不会重复插入。脚本执行 `nginx -t`、服务健康检查后重载 Nginx；保留输出的备份目录。Nginx 校验失败会恢复站点配置；其他失败需依据备份检查和恢复，脚本不承诺完整事务回滚。

## 配置与身份

数据位于 `/var/lib/common-relay`，systemd DynamicUser 与 StateDirectory 管理权限。默认内存上限 256 MiB、每应用文件配额 2 GiB、总配额 5 GiB、磁盘保留 2 GiB。使用 unit override 配置 `app-quota`、`global-quota`、`disk-reserve` 等参数，保留原有 ExecStart 参数。

自助创建默认关闭。按需加入 `--self-service-apps example`；多个命名空间用逗号分隔。该开关允许对应命名空间创建组，不提供账户认证。

使用 `device-add` / `device-revoke` 管理静态登记设备，只提供客户端公钥。签名设备组通过 `group-bootstrap` 初始化或由 SDK 自助创建，见[设备组管理](DEVICE-GROUPS.md)。签名组不能用静态 CLI 绕过成员链增删设备。

## 升级、备份与回滚

1. 运行本地测试与互通，校验构建产物摘要，备份二进制、单元和 Nginx 配置。
2. 短暂停服务，复制完整 StateDirectory，保留权限和所有权，再启动。不能只复制运行中的主数据库而遗漏 WAL 与密文文件。
3. 在隔离副本检查数据可恢复性，用新二进制对副本执行 `common-relay check --data <副本目录>`，确认已有签名组记录满足严格载荷规则；原子替换二进制，更新相关代理路由，执行 `nginx -t`。
4. 验证健康检查、真实 WSS、管理权限、应用/组隔离，再发布客户端 SDK。

回滚需使用支持当前签名链和数据库的版本。启用自动邀请前升级组内所有 SDK；产生委托签名记录后，不能回退到不认识该格式的版本。短邀请依赖 `/enroll/{id}/link`，自动加入依赖 `/enroll/{id}/auto`，参考配置已包含两者。

保留当前消息和成员数据，不用旧数据库覆盖新数据。确需恢复备份时，应先停止写入并协调客户端状态。生产凭据、备份路径和发布证据存于仓库外或忽略的 `.local/`，不提交。

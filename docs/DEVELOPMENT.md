# 开发与验证

Go：`go test -race ./...`。Python：创建隔离环境并安装 sdk/python，构建 build/common-relay 后运行 unittest。Swift：`swift test --package-path sdk/swift`。Dart：在 sdk/dart 运行 pub get、analyze 和 test。

Java SDK 为 Android library，用现有 Gradle 8.13/JDK17/Android SDK36 构建；`testDebugUnitTest` 使用本机 libsodium，路径通过 SODIUM_LIBRARY_PATH 提供。测试只使用公开向量，不访问生产设备。

`scripts/provision-qa.py` 是显式运维动作：在本机生成隔离 QA 身份并向指定服务器登记公钥，令牌写入 .local/qa。`scripts/interop.py` 与各 SDK Probe 检查真实加密消息及双向流，不执行桌面控制或 ADB。

变更协议时必须运行共享向量和跨语言互通，真实设备、换网、持续运行与模拟测试分别报告。不得将 401/健康检查当作业务链路验收。

## 本地隔离互通

构建服务端和 Swift Probe 后，使用 Python 虚拟环境运行：

```sh
.venv/bin/python scripts/local-interop.py --server /absolute/path/common-relay --swift /absolute/path/RelayProbe --gradle /absolute/path/gradle
```

通过 `JAVA_HOME`、`ANDROID_HOME`、`SODIUM_LIBRARY_PATH` 提供本机工具链；可用 `--dart` 指定 Dart。脚本只创建临时回环服务、身份和状态，不读取 `.local/qa`，分别验证 Python 与 Swift/Dart/Java 双向离线消息及每方向 8 MiB 加密流。`allow_local_test` 仅允许显式回环 ws 测试，正常客户端仍要求 wss。


设备组验证：构建 `build/common-relay` 后执行 Python `test_groups.py`；四 SDK 读取 `protocol/group-vectors.json`。使用同一套本地工具链运行 `scripts/group-interop.py --swift /absolute/path/RelayProbe --gradle /absolute/path/gradle`，覆盖 Swift/Dart/Java 与 Python 的加入、邀请、批准和移除。脚本自行创建临时服务、短时初始化凭据及身份，不能传入生产配置。

自动邀请测试：`group-vectors.json.auto_admission` 包含正常委托签名及越权、篡改和错误起点向量，Go 与四 SDK 共用。Python 集成覆盖邀请端离线、旧邀请默认手动、错误模式/授权、分页链、过期/取消、竞争重签及响应丢失恢复。`group-interop.py` 同时覆盖四 SDK 双向自动邀请和原手动管理流程。Java 测试的 `SODIUM_LIBRARY_PATH` 应指向库目录（例如 `/opt/homebrew/lib`），不是 dylib 文件。

严格载荷测试：`group-vectors.json.strict_payload` 包含签名正确但编码有歧义的名单与授权反例，Go 与四 SDK 必须全部拒绝、正例必须接受。修改规则时同步五处实现（Go `internal/relay/payload.go` 及各 SDK payload 文件）后，用 `scripts/group-strict-vectors.py`（需 PyNaCl）重新生成向量。

短邀请共享向量位于 `protocol/invitation-link-vectors.json`，验证四语言解密与链接编码。Java 单测与 Lint：

```sh
(cd sdk/java && gradle testDebugUnitTest lintDebug)
```

Swift Probe 构建：`swift build --package-path sdk/swift --product RelayProbe`。Java 需要 Gradle 8.13、JDK 17、Android SDK 36 与本机 libsodium；`SODIUM_LIBRARY_PATH` 指向库目录。

[入门示例](../examples/README.md)只依赖 Go 与 Python，不要求安装其余三类工具链。

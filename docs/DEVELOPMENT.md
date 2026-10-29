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


设备组验证：构建 `build/common-relay` 后执行 Python `test_groups.py`；各 SDK 读取 `protocol/group-vectors.json`。使用同一套本地工具链运行 `scripts/group-interop.py --swift /absolute/path/RelayProbe --gradle /absolute/path/gradle`，覆盖 Swift/Dart/Java 与 Python 的加入、邀请、批准和移除。脚本自行创建临时服务、短时初始化凭据及身份，不能传入生产配置。

自动邀请测试：`group-vectors.json.auto_admission` 包含正常委托签名及越权、篡改和错误起点向量，服务端与全部 SDK 共用。Python 集成覆盖邀请端离线、旧邀请默认手动、错误模式/授权、分页链、过期/取消、竞争重签及响应丢失恢复。`group-interop.py` 同时覆盖各 SDK 双向自动邀请和原手动管理流程。Java 测试的 `SODIUM_LIBRARY_PATH` 应指向库目录（例如 `/opt/homebrew/lib`），不是 dylib 文件。

严格载荷测试：`group-vectors.json.strict_payload` 包含签名正确但编码有歧义的名单与授权反例，服务端与全部 SDK 必须全部拒绝、正例必须接受。修改规则时同步服务端 `internal/relay/payload.go` 及各 SDK payload 实现（含 TypeScript/Go/Rust）后，用 `scripts/group-strict-vectors.py`（需 PyNaCl）重新生成向量。

短邀请共享向量位于 `protocol/invitation-link-vectors.json`，验证四语言解密与链接编码。Java 单测与 Lint：

```sh
(cd sdk/java && gradle testDebugUnitTest lintDebug)
```

Swift Probe 构建：`swift build --package-path sdk/swift --product RelayProbe`。Java 需要 Gradle 8.13、JDK 17、Android SDK 36 与本机 libsodium；`SODIUM_LIBRARY_PATH` 指向库目录。

[入门示例](../examples/README.md)只依赖 Go 与 Python，不要求安装其余三类工具链。

## 新增语言 SDK

无自有 native 构建步骤，只有 Rust SDK 自身需要 cargo。Kotlin 复用 Java 的完整能力；TypeScript/Go/Rust 与其他 SDK 能力一致，分别在各自目录独立测试。

```sh
(cd sdk/kotlin && gradle testDebugUnitTest :java:testDebugUnitTest lintDebug)
(cd sdk/typescript && npm ci && npm test)
(cd sdk/go && go test -race ./...)
(cd sdk/rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

Kotlin 使用 Kotlin Android 2.1.20，其他环境与 Java 相同；TypeScript 需要 Node.js 22+；Go SDK 是独立 module，要求 Go 1.25+，根目录测试不会自动覆盖它；Rust SDK 是独立 crate，要求 Rust 1.85+。源码接入见各 `sdk/<language>/README.md`。

Kotlin 完整回环互通：给上文 `scripts/local-interop.py` 增加 `--kotlin`，或用 `--only kotlin` 单独运行，覆盖 Python ↔ Kotlin 离线消息与每方向 8 MiB 流。设备组逻辑复用 Java，Java 的共享组向量与组互通仍必须运行。

构建 Go 服务端并在 `sdk/typescript` 执行 `npm ci && npm run build` 后（脚本会自行 `cargo build --release --example echo`），运行：

```sh
.venv/bin/python scripts/lightweight-interop.py --server "$PWD/build/common-relay"
```

完整互通：`local-interop.py --only typescript go rust`（离线消息与 8 MiB 双向流）和 `group-interop.py --only typescript go rust`（设备组全流程）；两个脚本的 `--swift`/`--gradle` 仅在选中对应 SDK 时必需。脚本只启动临时回环服务，生成隔离身份，`lightweight-interop.py` 验证 Python ↔ TypeScript/Go/Rust 的设备查询及空消息、Unicode 和 100 KB 二进制消息双向加密传输；不读取生产配置、不操作真实设备。

# Kotlin / Android

Kotlin 协程接口复用同仓库 Java SDK，保留完整消息、离线日志、字节流、文件和设备组能力。不依赖 Rust。最低 Android API 26，构建使用 JDK 17、Android SDK 36、Gradle 8.13+。

在应用的 Gradle settings 中接入两个模块（仓库路径按实际修改）：

```groovy
include ':java', ':relay-kotlin'
project(':java').projectDir = file('vendor/common-relay/java')
project(':relay-kotlin').projectDir = file('vendor/common-relay/kotlin')
```

应用声明 `implementation project(':relay-kotlin')`，并在根构建中配置 Android library 插件与 Kotlin Android 插件。SDK 自带 settings 可用于独立验证，不能替代接入应用的插件配置。

也可以运行 `python3 scripts/vendor-sdk.py /path/to/app kotlin` 生成独立快照；该快照把 Java 实现放在 `kotlin/java` 下，此时上面的 `:java` 路径改为 `vendor/common-relay/kotlin/java`。已有快照不会被覆盖。

```kotlin
import io.github.junweiup.commonrelay.kotlin.*

// client 是完成 onReady 回调的 RelayClient；身份、公钥和令牌由应用私有存储提供。
val peers = client.onlinePeers() // 发现结果不能自动成为可信公钥。
val receipt = client.sendMessage("peer-device", "hello".toByteArray())
// forwarded 仅表示进入中继队列，不代表设备收到或业务完成。
```

`RelayClient`、`RelayJournal`、`RelayGroups`、`RelayFiles` 与 `Crypto` 直接从 `io.github.junweiup.commonrelay` 导入，不复制协议实现。构造 `RelayClient` 时传入 Listener，通过 `onEvent` 接收事件；调用方负责连接及关闭 HTTP 连接池。离线消息必须配置 `RelayJournal`，处理并持久化后才调用 `acknowledgeMessage`；重试复用同一 ID。

协程取消会取消 pending future，但不能撤销已经发出的消息。`readChunk` / `writeChunk` 在 IO dispatcher 运行并在异常或取消时关闭流；`openByteStream` / `acceptByteStream` 返回 Java future，调用方负责接受成功后的流生命周期。设备组与文件的同步 HTTP 方法应在 `Dispatchers.IO` 上调用；应用需保存 pending join / exit 状态。参考 [设备组](../../docs/DEVICE-GROUPS.md)、[可靠性](../../docs/RELIABILITY.md)。

```sh
SODIUM_LIBRARY_PATH=/opt/homebrew/lib gradle testDebugUnitTest :java:testDebugUnitTest lintDebug
```

测试读取仓库共享向量；端到端回环验证使用 `scripts/local-interop.py --kotlin`。无需连接手机或操作真实桌面。

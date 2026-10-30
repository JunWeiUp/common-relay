# SDK 与产物分发

服务端以 Linux amd64 二进制分发。各语言 SDK 通过本仓库的 Git 标签（如 `v0.1.3`）作为依赖接入，不发布到 npm、PyPI、crates.io、pub.dev 或 Maven Central。升级时修改依赖中的标签即可。

## 按 Git 标签接入

以下以 `v0.1.3` 为例。

**Swift**（仓库根目录 `Package.swift` 只导出 `CommonRelay`；SPM 接受带 `v` 的标签）：

```swift
.package(url: "https://github.com/JunWeiUp/common-relay", exact: "0.1.3")
// target 依赖：.product(name: "CommonRelay", package: "common-relay")
```

**Android Java / Kotlin**（JitPack 按标签构建，见根目录 `jitpack.yml`；Kotlin 会传递引入 Java）：

```groovy
// settings.gradle
dependencyResolutionManagement { repositories { google(); mavenCentral(); maven { url 'https://jitpack.io' } } }
// build.gradle
implementation 'com.github.JunWeiUp.common-relay:java:v0.1.3'
implementation 'com.github.JunWeiUp.common-relay:kotlin:v0.1.3'
```

**Dart**：

```yaml
dependencies:
  common_relay:
    git: { url: https://github.com/JunWeiUp/common-relay, ref: v0.1.3, path: sdk/dart }
```

**Python**：

```sh
pip install "git+https://github.com/JunWeiUp/common-relay@v0.1.3#subdirectory=sdk/python"
```

**TypeScript（Node.js）**：npm 不支持 Git 子目录，使用 Release 附带的打包产物（已包含 `dist`）：

```sh
npm install https://github.com/JunWeiUp/common-relay/releases/download/v0.1.3/common-relay-typescript-0.1.3.tgz
```

**Go**（子目录 module 使用 `sdk/go/v0.1.3` 标签）：

```sh
go get github.com/JunWeiUp/common-relay/sdk/go@v0.1.3
```

**Rust**：

```toml
common-relay = { git = "https://github.com/JunWeiUp/common-relay", tag = "v0.1.3" }
```

平台 libsodium 由各 SDK 的固定依赖打包，不依赖用户安装的桌面原生库（Java 单测除外）。

## 发布流程

1. 统一各 SDK 清单中的版本号，合入 main。
2. 在同一提交上创建 `vX.Y.Z` 和 `sdk/go/vX.Y.Z` 两个标签，先推送 Go 标签。
3. `.github/workflows/release.yml` 校验 Go 标签、运行各 SDK 测试与轻量互通，然后创建 GitHub Release，附带 TypeScript tgz、Java/Kotlin release AAR 和 `SHA256SUMS`。仓库需允许工作流使用 `contents: write`。
4. 首次通过 JitPack 拉取时会触发 JitPack 构建，需确认构建成功。

自动邀请扩展需要整组 SDK 升级；默认仍是手动模式。

## 源码快照（可选）

需要审计、离线构建或打本地补丁时，`scripts/vendor-sdk.py <项目> <语言>` 会复制独立源码快照，并生成 SOURCE.json（版本、来源 URL、逐文件 SHA-256）；它拒绝覆盖已有快照。更新快照前要先比对 SOURCE.json 和本地补丁。

Kotlin 快照内包含 `java/`，settings 已改为引用该内嵌实现；宿主应用多模块接入时也要把 `:java` 指向此位置。TypeScript 快照保留 package-lock，接入前执行 `npm ci && npm run build`。Go 快照保留独立 go.mod/go.sum，以本地 module replace 接入。Rust 快照保留 Cargo.toml/Cargo.lock，以 path 依赖接入。快照不带测试、node_modules、dist、target 或编译缓存。

## 实现说明

各 SDK 不依赖共享 Rust 核心，不提供自有 JNI/FFI 桥接，也不提供跨平台 `.a` / `.so` 预构建。TypeScript 使用纯 JavaScript TweetNaCl，另用 libsodium-wrappers（WebAssembly）实现 secretstream。Go 使用纯 Go NaCl 实现，Rust 使用纯 Rust crypto_box 与 rustls；两者的 secretstream 为自有纯语言实现，已对 libsodium 已知答案逐字节验证。

## 本地 Android SDK 候选包

发布前可以分别运行 `gradle -p sdk/java testDebugUnitTest lintDebug assembleRelease`
与 `gradle -p sdk/kotlin testDebugUnitTest :java:testDebugUnitTest lintDebug assembleRelease`。
Java/Kotlin 共用 Java 构建目录，验证与打包应串行进行。取各模块当前
`build/outputs/aar/*-release.aar`，附带 LICENSE、基础提交、未提交状态、源码文件哈希和产物 SHA-256。
候选包必须标注未发布，不覆盖已有 Git 标签或冒充 JitPack 正式版本。
AAR 文件依赖不会传递 POM 中的依赖，宿主仍需声明 OkHttp、JNA、LazySodium；
Kotlin 包另需 Java 包与 kotlinx-coroutines-core。

Android SDK 发布使用 Maven POM 保留 JNA/LazySodium 的 `aar` 类型，禁用会丢失
显式 artifact selector 的 Gradle Module Metadata。发布后应在最小宿主执行
重复类检查并确认 APK 包含 Android 原生库；本地可运行
`python3 scripts/check-android-publication.py --version <版本>` 核对 Maven Local 产物。
TypeScript Release 附件使用明确的 `common-relay-typescript-<版本>.tgz` 名称。

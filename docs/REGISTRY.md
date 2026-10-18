# SDK 与产物分发

本项目没有 UI 组件注册中心。服务端以 Linux amd64 二进制分发；Swift Package、Android library、Dart package 和 Python package 从本仓库源码构建。

当前 0.1.0-dev 不发布到公共包注册表。`scripts/vendor-sdk.py <项目> <语言>` 复制独立源码快照与 SOURCE.json（版本、来源 URL、逐文件 SHA-256）；拒绝覆盖已有快照。应用构建不依赖本机兄弟目录。

正式版本前应固定发布标签和源提交、校验 SHA-256，并更新所有使用该版本的应用。平台 libsodium 由各 SDK 的固定依赖打包，不依赖用户安装的桌面原生库。

自动邀请扩展需要整组 SDK 升级；默认仍是手动模式。发布时应重新固定接入方快照的来源和文件哈希。

# Contributing to Common Relay

[English](#english) · [简体中文](#简体中文)

## English

Thank you for contributing. Documentation, examples, reproducible bug reports, and focused code improvements are welcome.

### Before you start

- Search existing issues and pull requests before opening a new one.
- For a substantial feature or protocol change, open an issue describing the use case and proposed approach first.
- Keep application-specific behavior outside the relay and SDK transport layer.
- Use synthetic identities and temporary directories. Never include access tokens, private keys, production configuration, or personal device data.

### Development workflow

1. Fork and clone the repository. Follow the [README](README.md#quick-start) to build the server and prepare Python.
2. Create a branch such as `fix/message-retry` or `docs/sdk-examples`; use a lowercase kebab-case description.
3. Keep changes focused and update relevant documentation. Keep both README translations aligned.
4. Run the checks appropriate to your change. For code changes, follow the Go race, SDK, and interoperability checks in [DEVELOPMENT.md](docs/DEVELOPMENT.md).
5. Open a pull request describing the problem, resulting behavior, and commands you actually ran. Explain any checks you could not run.

Protocol changes must update all four SDKs, shared test vectors, and protocol documentation together. Tests must not operate real desktops or devices or modify production configuration. Documentation-only changes require link and command review; they do not require the entire SDK test suite.

### Reporting bugs

Include your operating system, toolchain and SDK versions, revision, reproduction steps, expected behavior, actual behavior, and sanitized logs. A small reproduction is preferable to a complete application dump.

Do not publish exploit details or credentials in a public issue. If the repository's **Security → Report a vulnerability** option is available, use it for private disclosure. Otherwise, request a private reporting channel without disclosing sensitive details. See [SECURITY.md](SECURITY.md) for the security model.

### License

Contributions are provided under this repository's [MIT license](LICENSE). Preserve third-party copyright and license notices.

## 简体中文

欢迎改进文档、补充示例、提交可复现问题，以及提供范围明确的代码改进。

### 开始之前

- 先检索已有 Issue 和 Pull Request，避免重复。
- 较大的功能或协议调整，请先通过 Issue 说明使用场景与方案。
- 应用业务逻辑应放在接入应用中，不加入中继或 SDK 传输层。
- 使用测试身份和临时目录，不提交令牌、私钥、生产配置或个人设备数据。

### 开发流程

1. Fork 并克隆仓库，按 [README](README.zh-CN.md#快速开始)构建服务端并准备 Python 环境。
2. 创建 `fix/message-retry`、`docs/sdk-examples` 等分支，描述使用小写 kebab-case。
3. 保持改动范围明确，同步更新相关文档及中英文 README。
4. 按改动范围执行检查；代码改动遵循[开发指南](docs/DEVELOPMENT.md)中的 Go race、SDK 和互通验证要求。
5. 提交 PR，说明问题、改动后的行为，以及实际执行的验证命令；未执行的检查应明确说明原因。

协议变更必须同步四类 SDK、共享测试向量和协议文档。测试不得操作真实桌面或设备，也不得修改生产配置。纯文档改动需检查链接与命令，不要求重跑全部 SDK 测试。

### 问题反馈

请提供操作系统、工具链和 SDK 版本、源码提交、复现步骤、预期行为、实际行为及脱敏日志。优先提供最小复现，避免上传完整应用数据。

不要在公开 Issue 中披露漏洞利用细节或凭据。若仓库提供 **Security → Report a vulnerability**，请通过该入口私下报告；否则先请求私密反馈渠道，不公开敏感细节。安全模型见 [SECURITY.md](SECURITY.md)。

### 许可证

贡献内容遵循本仓库的 [MIT 许可证](LICENSE)，请保留第三方版权及许可证声明。

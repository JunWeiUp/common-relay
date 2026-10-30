# Common Relay

**Self-hosted, end-to-end encrypted device communication.**

English · [简体中文](README.zh-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol: v1](https://img.shields.io/badge/Protocol-v1-2563eb.svg)](protocol/README.md)
[![Status: Development](https://img.shields.io/badge/Status-Development-orange.svg)](CHANGELOG.md)

Common Relay is a Go relay server with Swift, Android Java/Kotlin, Dart, Python, TypeScript (Node.js), Go, and Rust client SDKs. Connect devices across networks using encrypted messages, bidirectional byte streams, and offline file delivery, with isolation between applications and device groups.

**Development status:** the server and SDKs are pre-1.0. SDKs are distributed as Git-tagged dependencies, not public package registries. Only protocol v1 is supported.

[Quick start](#quick-start) · [SDKs](#client-sdks) · [Documentation](#documentation) · [Contributing](CONTRIBUTING.md)

## Features

- **Encrypted transport payloads** — clients generate their own keys and pin trusted peer keys; the relay forwards ciphertext.
- **Online and offline messages** — explicit offline delivery, acknowledgments, persistent retries, and deduplication.
- **Bidirectional streams** — encrypted byte streams with bounded queues and flow control.
- **Offline files** — encrypted temporary storage, chunked uploads, resume support, and integrity checks.
- **Signed device groups** — membership verification, device revocation, manual approval, and one-time automatic admission.
- **Compact invitations** — encrypted invitation packets with decryption keys kept in the link fragment.
- **Self-hosted operation** — a single Go service, SQLite storage, and a TLS reverse proxy.

Application permissions and business logic belong in your application. Common Relay provides the communication layer.

## How it works

```text
Device A                         Your infrastructure                         Device B
Client SDK  ── WSS / HTTPS ──>  TLS proxy → Go relay → SQLite  <── WSS / HTTPS ──  Client SDK
   └────────────────── End-to-end encrypted application payloads ──────────────────┘
```

Devices authenticate with independent access tokens. The server stores token hashes and routes data within an application and device group. SDKs encrypt content using NaCl-compatible algorithms and verify peer identities against locally trusted keys.

The relay can observe routing metadata, timing, and ciphertext sizes. Static identity keys do **not** provide forward secrecy. See the [security model](SECURITY.md) before integrating.

## Quick start

The following commands target macOS or Linux. You need **Go 1.27.1+** and **Python 3.11+**. The Python demos do not require the other SDK toolchains.

```sh
git clone https://github.com/JunWeiUp/common-relay.git
cd common-relay

go build -o build/common-relay ./cmd/common-relay
python3 -m venv .venv
.venv/bin/python -m pip install -e sdk/python

.venv/bin/python examples/python/messages.py
.venv/bin/python examples/python/device_groups.py
```

Each demo starts a temporary loopback server, generates fresh identities, verifies SDK operations, and cleans up on exit.

| Example | What it demonstrates |
| --- | --- |
| [messages.py](examples/python/messages.py) | Online messages, offline delivery and acknowledgment, encrypted streams in both directions |
| [device_groups.py](examples/python/device_groups.py) | Group creation, manual approval, automatic admission, compact invitations, and private configuration storage |

See [example details](examples/README.md) for expected output and integration notes.

## Run a server

```sh
build/common-relay serve --data ./data --listen 127.0.0.1:47805
```

For public access, place the service behind a TLS reverse proxy and use **WSS/HTTPS**. Releases built with the server packaging workflow include Linux amd64 / arm64 deployment archives with binaries, installation scripts, configuration, and source checksums. The repository includes [Nginx configuration](deploy/nginx.conf) and a [systemd unit](deploy/common-relay.service). Follow the [deployment guide](docs/DEPLOYMENT.md) for installation, backups, and upgrades.

The demos explicitly allow unencrypted WebSocket transport on loopback. This setting is for local testing only; payload encryption still applies.

| CLI command | Purpose |
| --- | --- |
| `serve` | Run the relay |
| `check` | Open the store, check database connectivity, and verify stored group records |
| `device-add` | Register a static device using its client-generated public key |
| `device-revoke` | Revoke a statically registered device |
| `group-bootstrap` | Create a bootstrap credential for a signed device group |

Use `<command> --help` for flags. Credential files are private, cannot overwrite existing files, and tokens are not printed to the terminal. Signed groups manage membership through the SDK APIs.

Self-service group creation is disabled by default. Enable selected application namespaces with `serve --self-service-apps example`. This allowlist is **not** an account authentication system. See [device groups](docs/DEVICE-GROUPS.md).

## Client SDKs

SDKs install directly from this repository's Git tags (for example `v0.1.4`); they are not published to npm, PyPI, crates.io, pub.dev, or Maven Central. There are no stable API guarantees before 1.0.

| SDK | Source | Requirements |
| --- | --- | --- |
| Swift | [sdk/swift](sdk/swift) | Swift tools 5.9+, macOS 13+ / iOS 15+ |
| Android Java | [sdk/java](sdk/java) | Android API 26+; build with JDK 17, Gradle 8.13, Android SDK 36 |
| Dart | [sdk/dart](sdk/dart) | Dart 3.11+ and <4.0 |
| Python | [sdk/python](sdk/python) | Python 3.11+ |
| Kotlin | [sdk/kotlin](sdk/kotlin) | Android API 26+; same Java SDK, Kotlin coroutine extensions |
| TypeScript (Node.js) | [sdk/typescript](sdk/typescript) | Node.js 22+ |
| Go client | [sdk/go](sdk/go) | Go 1.25+ (standalone module) |
| Rust client | [sdk/rust](sdk/rust) | Rust 1.89+ (tokio, pure Rust) |

```text
Swift   .package(url: "https://github.com/JunWeiUp/common-relay", exact: "0.1.4")
Android implementation 'com.github.JunWeiUp.common-relay:java:v0.1.4'    // or :kotlin:, via JitPack
Dart    git: { url: https://github.com/JunWeiUp/common-relay, ref: v0.1.4, path: sdk/dart }
Python  pip install "git+https://github.com/JunWeiUp/common-relay@v0.1.4#subdirectory=sdk/python"
Node.js npm install https://github.com/JunWeiUp/common-relay/releases/download/v0.1.4/common-relay-typescript-0.1.4.tgz
Go      go get github.com/JunWeiUp/common-relay/sdk/go@v0.1.4
Rust    common-relay = { git = "https://github.com/JunWeiUp/common-relay", tag = "v0.1.4" }
```

The [SDK distribution guide](docs/REGISTRY.md) covers repository setup, the release process, and optional source snapshots for auditing or local patches.

All SDKs test their supported encryption against shared vectors. All SDKs provide the full feature set: online and offline messages, streams, files, signed device groups and compact invitations. Implementations use their own language runtimes; the Rust SDK is a standalone pure-Rust client, not a shared core, and no platform artifact build is required. Applications must securely persist identities, trusted keys, and retry state. Enable automatic invitations only after all members' SDKs support the authorization chain.

## Development

After completing the quick-start setup:

```sh
go test -race ./...
.venv/bin/python -m unittest discover -s sdk/python -v
swift test --package-path sdk/swift
(cd sdk/dart && dart pub get && dart analyze && dart test)
(cd sdk/java && gradle testDebugUnitTest lintDebug)
(cd sdk/kotlin && gradle testDebugUnitTest lintDebug)
(cd sdk/typescript && npm ci && npm test)
(cd sdk/go && go test -race ./...)
(cd sdk/rust && cargo clippy --all-targets -- -D warnings && cargo test)
```

Swift, Dart, and Android checks require their own toolchains. Java unit tests also require a local libsodium library. See the [development guide](docs/DEVELOPMENT.md) for environment variables and cross-language tests.

Local interoperability tests cover offline messages, bidirectional 8 MiB streams, signed groups, and invitations. Public WSS, long-running load, and recovery testing are separate deployment checks; see the [validation guide](docs/VALIDATION.md).

## Documentation

The READMEs and contribution guide are bilingual. Detailed guides currently contain primarily Chinese text; protocol documentation includes English sections.

| Guide | Contents |
| --- | --- |
| [Examples](examples/README.md) | Runnable demos and integration notes |
| [Protocol v1](protocol/README.md) | Wire format, encryption, and compatibility |
| [Architecture](docs/ARCHITECTURE.md) | Components, storage, and resource limits |
| [Device groups](docs/DEVICE-GROUPS.md) | Trust, membership, and invitations |
| [Security](SECURITY.md) | Threat model and key management |
| [Reliability](docs/RELIABILITY.md) | Retries, journals, deduplication, and cleanup |
| [Deployment](docs/DEPLOYMENT.md) | Installation, configuration, backup, and rollback |
| [Development](docs/DEVELOPMENT.md) / [Validation](docs/VALIDATION.md) | Toolchains and verification |
| [SDK distribution](docs/REGISTRY.md) | Source snapshots and provenance |
| [API entry points](docs/PAGE-STRUCTURE.md) | HTTP and WebSocket routes |
| [Roadmap](TODO.md) / [Changelog](CHANGELOG.md) | Planned work and changes |

## Contributing

Bug reports, documentation improvements, examples, and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before making changes. Use [GitHub Issues](https://github.com/JunWeiUp/common-relay/issues) for reproducible bugs and feature proposals; do not include credentials or private configuration.

## License

[MIT](LICENSE) © JunWeiUp. Third-party dependencies retain their own licenses.

Built with [libsodium](https://github.com/jedisct1/libsodium), [coder/websocket](https://github.com/coder/websocket), and [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite).

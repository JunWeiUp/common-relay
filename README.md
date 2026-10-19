# Common Relay

**Self-hosted, end-to-end encrypted device communication.**

English · [简体中文](README.zh-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol: v1](https://img.shields.io/badge/Protocol-v1-2563eb.svg)](protocol/README.md)
[![Status: Development](https://img.shields.io/badge/Status-Development-orange.svg)](CHANGELOG.md)

Common Relay is a Go relay server with Swift, Android Java/Kotlin, Dart, and Python client SDKs. Connect devices across networks using encrypted messages, bidirectional byte streams, and offline file delivery, with isolation between applications and device groups.

**Development status:** the server and SDKs are available from source. Stable SDK releases and public package distribution are not available yet. Only protocol v1 is supported.

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

Devices authenticate with independent access tokens. The server stores token hashes and routes data within an application and device group. SDKs encrypt content using libsodium and verify peer identities against locally trusted keys.

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

For public access, place the service behind a TLS reverse proxy and use **WSS/HTTPS**. The repository includes [Nginx configuration](deploy/nginx.conf) and a [systemd unit](deploy/common-relay.service). Follow the [deployment guide](docs/DEPLOYMENT.md) for installation, backups, and upgrades.

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

SDKs currently integrate from this repository's source. There are no published registry installation commands or stable release guarantees yet.

| SDK | Source | Requirements |
| --- | --- | --- |
| Swift | [sdk/swift](sdk/swift) | Swift tools 5.9+, macOS 13+ / iOS 15+ |
| Android Java/Kotlin | [sdk/java](sdk/java) | Android API 26+; build with JDK 17, Gradle 8.13, Android SDK 36 |
| Dart | [sdk/dart](sdk/dart) | Dart 3.11+ and <4.0 |
| Python | [sdk/python](sdk/python) | Python 3.11+ |

Use a local Swift package, an Android library module, a Dart path dependency, or the Python editable install shown above. The [SDK distribution guide](docs/REGISTRY.md) describes source snapshots and provenance records.

All four SDKs use shared cryptographic vectors. Applications must securely persist identities, trusted keys, and retry state. Enable automatic invitations only after all members' SDKs support the authorization chain.

## Development

After completing the quick-start setup:

```sh
go test -race ./...
.venv/bin/python -m unittest discover -s sdk/python -v
swift test --package-path sdk/swift
(cd sdk/dart && dart pub get && dart analyze && dart test)
(cd sdk/java && gradle testDebugUnitTest lintDebug)
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

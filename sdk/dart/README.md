# Common Relay Dart SDK

See the repository README and `protocol/README.md` for the protocol.

This SDK speaks Common Relay v2 only: `RelayV2Client` / `RelayV2Pipe` for the `/v2/ws`
pipe, `RelayGroups` for the signed group ledger under `/v2/group` and `/v2/enroll`, and
`RelayFiles` for end-to-end encrypted files under `/v2/files`. The v1 `RelayClient` /
`RelayStream` (`/relay/v1/ws`, `common-relay.v1` subprotocol) were removed together with
v1 on the server; use `RelayV2Pipe` instead. Group URLs must end in `/v2/ws`, and compact
invitations use `common-relay://host/v2/i/...` links.

## Server access password

Relays started with `--access-password-file` require the `Relay-Access` header on every
`/v2` request (pipe, group ledger, enrollment and files). Pass the password (8–128 printable ASCII characters, no spaces):

```dart
final groups = RelayGroups(sodium, {'url': url, 'token': token, 'password': accessPassword, ...});
final files = RelayFiles(Uri.parse('https://relay.example.com/v2/files'), token, password: accessPassword);
```

`resolveInvitation` reuses the caller's configured password. The password is never written into
invitations or short-link packets; distribute it to devices separately.

`groups.withAbort(trigger)` returns a request-scoped view sharing `config`; completing `trigger`
aborts in-flight group, enrollment and short-link requests with `RequestAbortedException`
(an already-completed trigger never contacts the relay). Serialize mutations of the shared config.

# Common Relay Dart SDK

See the repository README and `protocol/README.md` for the protocol.

## Server access password

Relays started with `--access-password-file` require the `Relay-Access` header on every
`/relay/v1` request. Pass the password (8–128 printable ASCII characters, no spaces):

```dart
await client.connect(url, token, password: accessPassword);
final groups = RelayGroups(sodium, {'url': url, 'token': token, 'password': accessPassword, ...});
final files = RelayFiles(Uri.parse('https://relay.example.com/relay/v1/files'), token, password: accessPassword);
```

`resolveInvitation` reuses the caller's configured password. The password is never written into
invitations or short-link packets; distribute it to devices separately.

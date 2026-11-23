part of '../common_relay.dart';

/// Common Relay v2 client for Dart/Flutter.
enum RelayV2Route { lanDirect, pipeStream, boxEphemeral }

class RelayV2BoxItem {
  final String id;
  final String spaceId;
  final String boxName;
  final int seq;
  final String sender;
  final int size;
  final String sha256;
  final String contentType;
  final String metaJson;

  RelayV2BoxItem({
    required this.id,
    required this.spaceId,
    required this.boxName,
    required this.seq,
    required this.sender,
    required this.size,
    required this.sha256,
    required this.contentType,
    required this.metaJson,
  });

  factory RelayV2BoxItem.fromJson(Map<String, dynamic> j) => RelayV2BoxItem(
        id: j['id'] as String? ?? '',
        spaceId: j['space_id'] as String? ?? '',
        boxName: j['box_name'] as String? ?? '',
        seq: (j['seq'] as num?)?.toInt() ?? 0,
        sender: j['sender'] as String? ?? '',
        size: (j['size'] as num?)?.toInt() ?? 0,
        sha256: j['sha256'] as String? ?? '',
        contentType: j['content_type'] as String? ?? 'application/octet-stream',
        metaJson: j['meta_json'] as String? ?? '{}',
      );
}

/// HTTP error from the v2 API carrying the status and (trimmed) response body.
class RelayV2HttpException extends HttpException {
  final int status;
  final String body;
  RelayV2HttpException(String op, this.status, String body)
      : body = body.trim(),
        super('v2 $op http $status');

  /// True when the server predates the endpoint: 405/501, or a plain-text 404
  /// (new servers answer JSON errors). Callers can fall back to the older PUT API.
  bool get isUnsupported => RelayV2Client.isUnsupportedResponse(status, body);
}

class RelayV2PluginBindingSummary {
  final String targetDevice;
  final bool targetOnline;
  final String publicBase;
  final String tag;
  final bool hasHmac;
  final bool hasToken;
  final List<String> corsOrigins;

  RelayV2PluginBindingSummary({
    this.targetDevice = '',
    this.targetOnline = false,
    this.publicBase = '',
    this.tag = '',
    this.hasHmac = false,
    this.hasToken = false,
    this.corsOrigins = const [],
  });

  factory RelayV2PluginBindingSummary.fromJson(Map<String, dynamic> j) => RelayV2PluginBindingSummary(
        targetDevice: j['target_device'] as String? ?? '',
        targetOnline: j['target_online'] as bool? ?? false,
        publicBase: j['public_base'] as String? ?? '',
        tag: j['tag'] as String? ?? '',
        hasHmac: j['has_hmac'] as bool? ?? false,
        hasToken: j['has_token'] as bool? ?? false,
        corsOrigins: [for (final o in (j['cors_origins'] as List? ?? const [])) o as String],
      );
}

class RelayV2PluginAccountView {
  final String scopeKey;
  final String username;
  final String mode;

  RelayV2PluginAccountView({required this.scopeKey, required this.username, required this.mode});

  factory RelayV2PluginAccountView.fromJson(Map<String, dynamic> j) => RelayV2PluginAccountView(
        scopeKey: j['scope_key'] as String? ?? '',
        username: j['username'] as String? ?? '',
        mode: j['mode'] as String? ?? '',
      );
}

class RelayV2PluginBinding {
  final String id;
  final String pluginId;
  final String mount;
  final String spaceId;
  final String boxName;
  final String configJson;
  final bool enabled;
  final int updatedAt;
  final RelayV2PluginBindingSummary? summary;
  final List<RelayV2PluginAccountView> accounts;

  /// Increments on every change; pass it as `ifVersion` for optimistic
  /// concurrency. Zero on servers older than the PATCH API.
  final int configVersion;

  /// Write-only secret keys currently set (values are never returned).
  final List<String> secretKeys;

  /// Bridged payloads are sealed (crs1) to the binding's seal_public_key.
  final bool sealed;

  RelayV2PluginBinding({
    required this.id,
    required this.pluginId,
    required this.mount,
    required this.spaceId,
    required this.boxName,
    required this.configJson,
    required this.enabled,
    required this.updatedAt,
    this.summary,
    this.accounts = const [],
    this.configVersion = 0,
    this.secretKeys = const [],
    this.sealed = false,
  });

  factory RelayV2PluginBinding.fromJson(Map<String, dynamic> j) => RelayV2PluginBinding(
        id: j['id'] as String? ?? '',
        pluginId: j['plugin_id'] as String? ?? '',
        mount: j['mount'] as String? ?? '',
        spaceId: j['space_id'] as String? ?? '',
        boxName: j['box_name'] as String? ?? '',
        configJson: j['config_json'] as String? ?? '{}',
        enabled: j['enabled'] as bool? ?? false,
        updatedAt: (j['updated_at'] as num?)?.toInt() ?? 0,
        summary: j['summary'] is Map<String, dynamic>
            ? RelayV2PluginBindingSummary.fromJson(j['summary'] as Map<String, dynamic>)
            : null,
        accounts: [
          for (final a in (j['accounts'] as List? ?? const []))
            RelayV2PluginAccountView.fromJson(a as Map<String, dynamic>)
        ],
        configVersion: (j['config_version'] as num?)?.toInt() ?? 0,
        secretKeys: [for (final k in (j['secret_keys'] as List? ?? const [])) k as String],
        sealed: j['sealed'] as bool? ?? false,
      );
}

/// One config key a plugin accepts.
class RelayV2PluginFieldSpec {
  final String key;
  final String type;
  final String description;
  final bool secret;
  final bool required;

  RelayV2PluginFieldSpec({
    required this.key,
    required this.type,
    this.description = '',
    this.secret = false,
    this.required = false,
  });

  factory RelayV2PluginFieldSpec.fromJson(Map<String, dynamic> j) => RelayV2PluginFieldSpec(
        key: j['key'] as String? ?? '',
        type: j['type'] as String? ?? '',
        description: j['description'] as String? ?? '',
        secret: j['secret'] as bool? ?? false,
        required: j['required'] as bool? ?? false,
      );
}

/// A registered plugin with its config schema (empty on servers that predate schemas).
class RelayV2PluginInfo {
  final String id;
  final String requiredTrust;
  final List<RelayV2PluginFieldSpec> schema;

  RelayV2PluginInfo({required this.id, required this.requiredTrust, this.schema = const []});

  factory RelayV2PluginInfo.fromJson(Map<String, dynamic> j) => RelayV2PluginInfo(
        id: j['id'] as String? ?? '',
        requiredTrust: j['required_trust'] as String? ?? '',
        schema: [
          for (final f in (j['schema'] as List? ?? const []))
            RelayV2PluginFieldSpec.fromJson(f as Map<String, dynamic>)
        ],
      );
}

/// Partial binding update. Null fields are unchanged; a [config] entry whose
/// value is null deletes that key. Secret keys are write-only: send a plaintext
/// "token" to rotate a Bearer token (it is hashed server-side).
class RelayV2PluginPatch {
  final String? spaceId;
  final String? boxName;
  final bool? enabled;
  final Map<String, Object?>? config;
  final int ifVersion;

  const RelayV2PluginPatch({this.spaceId, this.boxName, this.enabled, this.config, this.ifVersion = 0});

  Map<String, Object?> toJson() => {
        if (spaceId != null) 'space_id': spaceId,
        if (boxName != null) 'box_name': boxName,
        if (enabled != null) 'enabled': enabled,
        if (config != null && config!.isNotEmpty) 'config': config,
        if (ifVersion != 0) 'if_version': ifVersion,
      };
}

class RelayV2PluginAccount {
  final String bindingId;
  final String scopeKey;
  final String username;
  final String mode;
  final String metaJson;
  final int updatedAt;

  RelayV2PluginAccount({
    required this.bindingId,
    required this.scopeKey,
    required this.username,
    required this.mode,
    required this.metaJson,
    required this.updatedAt,
  });

  factory RelayV2PluginAccount.fromJson(Map<String, dynamic> j) => RelayV2PluginAccount(
        bindingId: j['binding_id'] as String? ?? '',
        scopeKey: j['scope_key'] as String? ?? '',
        username: j['username'] as String? ?? '',
        mode: j['mode'] as String? ?? '',
        metaJson: j['meta_json'] as String? ?? '',
        updatedAt: (j['updated_at'] as num?)?.toInt() ?? 0,
      );
}

/// A registered v2 device (never includes the token).
class RelayV2Device {
  final String id;
  final String name;
  final String publicKey;
  final bool isAdmin;
  final bool revoked;
  final int createdAt;

  const RelayV2Device({
    this.id = '',
    this.name = '',
    this.publicKey = '',
    this.isAdmin = false,
    this.revoked = false,
    this.createdAt = 0,
  });

  factory RelayV2Device.fromJson(Map<String, dynamic> j) => RelayV2Device(
        id: j['id'] as String? ?? '',
        name: j['name'] as String? ?? '',
        publicKey: j['public_key'] as String? ?? '',
        isAdmin: j['is_admin'] as bool? ?? false,
        revoked: j['revoked'] as bool? ?? false,
        createdAt: (j['created_at'] as num?)?.toInt() ?? 0,
      );
}

/// Result of [RelayV2Client.me]: the token's device, or [rootAdmin] (and a
/// null [device]) for the Root Admin secret.
class RelayV2Me {
  final RelayV2Device? device;
  final bool rootAdmin;

  const RelayV2Me({this.device, this.rootAdmin = false});

  factory RelayV2Me.fromJson(Map<String, dynamic> j) => RelayV2Me(
        device: j['device'] is Map<String, dynamic> ? RelayV2Device.fromJson(j['device'] as Map<String, dynamic>) : null,
        rootAdmin: j['root_admin'] as bool? ?? false,
      );
}

/// Opens "crs1" sealed bridge payloads (Webhook, Drop, WebDAV queue) that the
/// relay sealed to a recipient X25519 key before writing them to disk.
///
/// Wire format: "CRS1" | crypto_box_seal(32-byte key) (80) | nonce prefix (16) |
/// frames of `uint32 BE length || secretbox(chunk, prefix || uint64 BE counter)`.
/// The final frame sets the counter's high bit, so truncation is detected.
class RelayV2Sealed {
  RelayV2Sealed._();

  static const scheme = 'crs1';

  /// Content type of queue items whose body is sealed; the original content
  /// type is kept in item meta `content_type`.
  static const contentType = 'application/vnd.common-relay.sealed';

  static const _magic = [0x43, 0x52, 0x53, 0x31]; // "CRS1"
  static const _chunkSize = 64 << 10;
  static const _sealedKeyLen = 32 + 48;
  static const _macBytes = 16;
  static const _headerLen = 4 + _sealedKeyLen + 16;

  /// Whether [head] starts with the sealed-payload magic.
  static bool isSealed(List<int> head) =>
      head.length >= 4 && head[0] == _magic[0] && head[1] == _magic[1] && head[2] == _magic[2] && head[3] == _magic[3];

  /// Decodes a 64-char hex X25519 key (public or private).
  static Uint8List parseKey(String hexKey) {
    final Uint8List raw;
    try {
      raw = unhex(hexKey.trim());
    } on FormatException {
      throw ArgumentError('key must be 64 hex characters');
    }
    if (raw.length != 32) throw ArgumentError('key must be 64 hex characters');
    return raw;
  }

  /// Creates a fresh X25519 key pair as lowercase hex.
  static ({String publicKey, String privateKey}) generateKeyPair(Sodium sodium) {
    final kp = sodium.crypto.box.keyPair();
    try {
      return (publicKey: hex(kp.publicKey), privateKey: hex(kp.secretKey.extractBytes()));
    } finally {
      kp.secretKey.dispose();
    }
  }

  /// Decrypts a complete sealed payload; throws [FormatException] when it is
  /// corrupt, truncated or sealed to another key.
  static Uint8List open(Sodium sodium, Uint8List sealed, Uint8List publicKey, Uint8List privateKey) {
    const corrupt = FormatException('sealed payload corrupt or truncated');
    if (sealed.length < _headerLen || !isSealed(sealed)) throw corrupt;
    final sk = SecureKey.fromList(sodium, privateKey);
    Uint8List rawKey;
    try {
      rawKey = sodium.crypto.box.sealOpen(
        cipherText: Uint8List.sublistView(sealed, 4, 4 + _sealedKeyLen),
        publicKey: publicKey,
        secretKey: sk,
      );
    } on SodiumException {
      throw corrupt;
    } finally {
      sk.dispose();
    }
    if (rawKey.length != 32) throw corrupt;
    final key = SecureKey.fromList(sodium, rawKey);
    rawKey.fillRange(0, rawKey.length, 0);
    try {
      final prefix = Uint8List.sublistView(sealed, 4 + _sealedKeyLen, _headerLen);
      final view = ByteData.sublistView(sealed);
      final out = BytesBuilder(copy: false);
      var off = _headerLen;
      for (var ctr = 0;; ctr++) {
        if (sealed.length - off < 4) throw corrupt;
        final l = view.getUint32(off);
        off += 4;
        if (l < _macBytes || l > _chunkSize + _macBytes || l > sealed.length - off) throw corrupt;
        final frame = Uint8List.sublistView(sealed, off, off + l);
        off += l;
        final last = off == sealed.length;
        final nonce = Uint8List(24)..setRange(0, 16, prefix);
        final nd = ByteData.sublistView(nonce);
        // uint64 BE counter, high bit marks the final frame.
        nd.setUint32(16, ((ctr >> 32) & 0x7fffffff) | (last ? 0x80000000 : 0));
        nd.setUint32(20, ctr & 0xffffffff);
        try {
          out.add(sodium.crypto.secretBox.openEasy(cipherText: frame, nonce: nonce, key: key));
        } on SodiumException {
          throw corrupt;
        }
        if (last) return out.takeBytes();
      }
    } finally {
      key.dispose();
    }
  }
}

class RelayV2Client {
  final String baseUrl;
  final String accessPassword;
  final String token;
  final http.Client _http;

  RelayV2Client({
    required String baseUrl,
    required this.accessPassword,
    required this.token,
    bool allowLocal = false,
    http.Client? httpClient,
  })  : baseUrl = _validateV2BaseUrl(baseUrl, allowLocal),
        _http = httpClient ?? http.Client();

  static String _validateV2BaseUrl(String raw, bool allowLocal) {
    final trimmed = raw.trim().replaceAll(RegExp(r'/+$'), '');
    final u = Uri.tryParse(trimmed);
    if (u == null || !u.hasScheme || u.host.isEmpty) {
      throw ArgumentError('invalid v2 BaseURL');
    }
    if (u.scheme == 'http') {
      final h = u.host.toLowerCase();
      if (!allowLocal || (h != '127.0.0.1' && h != 'localhost' && h != '::1')) {
        throw ArgumentError('v2 client requires https');
      }
    } else if (u.scheme != 'https') {
      throw ArgumentError('invalid v2 scheme');
    }
    return trimmed;
  }

  String get wsUrl => baseUrl.startsWith('https://')
      ? 'wss://${baseUrl.substring(8)}/v2/ws'
      : 'ws://${baseUrl.substring(7)}/v2/ws';

  /// Lowercase 64-char hex SHA-256 (matches protocol/v2/vectors.json).
  static String hashSecret(String plain) =>
      hashes.sha256.convert(utf8.encode(plain)).toString();

  /// Encodes `/v2/ws` binary stream frame: `[16-byte stream_id][payload]`.
  static Uint8List encodeStreamFrame(String streamId, Uint8List payload) {
    final sid = utf8.encode(streamId);
    if (sid.length != 16) {
      throw ArgumentError('streamId must be exactly 16 bytes');
    }
    final out = Uint8List(16 + payload.length);
    out.setRange(0, 16, sid);
    out.setRange(16, out.length, payload);
    return out;
  }

  /// Decodes `/v2/ws` binary stream frame into `(streamId, payload)`.
  static ({String streamId, Uint8List payload}) decodeStreamFrame(Uint8List frame) {
    if (frame.length < 16) {
      throw const FormatException('short binary stream frame');
    }
    final sid = utf8.decode(frame.sublist(0, 16));
    return (streamId: sid, payload: frame.sublist(16));
  }

  static RelayV2Route chooseRoute({required bool lanReachable, required bool peerOnline}) {
    if (lanReachable) return RelayV2Route.lanDirect;
    if (peerOnline) return RelayV2Route.pipeStream;
    return RelayV2Route.boxEphemeral;
  }

  Map<String, String> _headers([Map<String, String>? extra]) => {
        if (accessPassword.isNotEmpty) 'Relay-Access': accessPassword,
        'Authorization': 'Bearer $token',
        ...?extra,
      };

  Future<RelayV2BoxItem> putBoxItem(
    String space,
    String box,
    Uint8List data, {
    String contentType = 'application/octet-stream',
    String? metaJson,
    int ttlSec = 86400,
  }) async {
    final suffix = ttlSec > 0 ? '?ttl=$ttlSec' : '';
    final resp = await _http.post(
      Uri.parse('$baseUrl/v2/spaces/$space/boxes/$box/items$suffix'),
      headers: _headers({
        'Content-Type': contentType,
        if (metaJson != null && metaJson.isNotEmpty) 'X-Box-Meta': metaJson,
      }),
      body: data,
    );
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw HttpException('v2 putBoxItem http ${resp.statusCode}');
    }
    final j = jsonDecode(resp.body) as Map<String, dynamic>;
    return RelayV2BoxItem.fromJson(j['item'] as Map<String, dynamic>);
  }

  Future<Uint8List> downloadBoxItem(String space, String box, String itemId) async {
    final resp = await _http.get(
      Uri.parse('$baseUrl/v2/spaces/$space/boxes/$box/items/$itemId'),
      headers: _headers(),
    );
    if (resp.statusCode != 200) {
      throw HttpException('v2 downloadBoxItem http ${resp.statusCode}');
    }
    return resp.bodyBytes;
  }

  Future<List<RelayV2BoxItem>> listBoxItems(String space, String box, {int afterSeq = 0, int limit = 100}) async {
    final resp = await _http.get(
      Uri.parse('$baseUrl/v2/spaces/$space/boxes/$box/items?after=$afterSeq&limit=$limit'),
      headers: _headers(),
    );
    if (resp.statusCode != 200) {
      throw HttpException('v2 listBoxItems http ${resp.statusCode}');
    }
    final j = jsonDecode(resp.body) as Map<String, dynamic>;
    final list = (j['items'] as List? ?? const []);
    return list.map((e) => RelayV2BoxItem.fromJson(e as Map<String, dynamic>)).toList();
  }

  Future<void> ackBoxItem(String space, String box, String itemId) async {
    final resp = await _http.delete(
      Uri.parse('$baseUrl/v2/spaces/$space/boxes/$box/items/$itemId'),
      headers: _headers(),
    );
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw HttpException('v2 ackBoxItem http ${resp.statusCode}');
    }
  }

  /// Reports whether an HTTP failure means the server predates an endpoint:
  /// 405/501, or a 404 whose body is not a JSON error.
  static bool isUnsupportedResponse(int status, String body) =>
      status == 405 || status == 501 || (status == 404 && !body.trim().startsWith('{'));

  /// Whether [error] is a [RelayV2HttpException] for an unsupported endpoint.
  static bool isUnsupported(Object error) => error is RelayV2HttpException && error.isUnsupported;

  String _pluginPath(String pluginId, String mount) =>
      '$baseUrl/v2/admin/plugins/${Uri.encodeComponent(pluginId)}/${Uri.encodeComponent(mount)}';

  Future<Map<String, dynamic>> _adminJson(String op, String method, String url, [Object? body]) async {
    final req = http.Request(method, Uri.parse(url))..headers.addAll(_headers());
    if (body != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(body);
    }
    final resp = await http.Response.fromStream(await _http.send(req));
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw RelayV2HttpException(op, resp.statusCode, resp.body);
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  /// The device the client's token belongs to; [RelayV2Me.rootAdmin] is true
  /// (and [RelayV2Me.device] null) for the Root Admin secret. Older servers
  /// answer an unsupported error (see [isUnsupported]).
  Future<RelayV2Me> me() async => RelayV2Me.fromJson(await _adminJson('me', 'GET', '$baseUrl/v2/me'));

  /// Registered plugins with their config schemas.
  Future<List<RelayV2PluginInfo>> pluginCatalog() async {
    final j = await _adminJson('pluginCatalog', 'GET', '$baseUrl/v2/admin/plugins');
    return [
      for (final p in (j['plugins'] as List? ?? const []))
        RelayV2PluginInfo.fromJson(p as Map<String, dynamic>)
    ];
  }

  /// One binding (public view) regardless of its enabled state.
  Future<RelayV2PluginBinding> getPlugin(String pluginId, String mount) async {
    final j = await _adminJson('getPlugin', 'GET', _pluginPath(pluginId, mount));
    return RelayV2PluginBinding.fromJson(j['binding'] as Map<String, dynamic>);
  }

  /// Merges a partial update into an existing binding. Servers older than the
  /// PATCH API answer 404/405 (see [isUnsupported]).
  Future<RelayV2PluginBinding> patchPlugin(String pluginId, String mount, RelayV2PluginPatch patch) async {
    final j = await _adminJson('patchPlugin', 'PATCH', _pluginPath(pluginId, mount), patch.toJson());
    return RelayV2PluginBinding.fromJson(j['binding'] as Map<String, dynamic>);
  }

  /// Stores an account whose password the server hashes with salted scrypt.
  Future<RelayV2PluginAccount> upsertPluginAccountPassword(
    String pluginId,
    String mount, {
    required String scopeKey,
    required String username,
    required String password,
    required String mode,
  }) async {
    final j = await _adminJson('upsertPluginAccountPassword', 'PUT', '${_pluginPath(pluginId, mount)}/accounts', {
      'scope_key': scopeKey,
      'username': username,
      'password': password,
      'mode': mode,
    });
    return RelayV2PluginAccount.fromJson(j['account'] as Map<String, dynamic>);
  }

  void close() => _http.close();
}

part of '../common_relay.dart';

/// Common Relay v2 client for Dart/Flutter (tailored for SyncApp Android & Windows).
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

  void close() => _http.close();
}

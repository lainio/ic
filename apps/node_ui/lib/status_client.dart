import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

enum NodeChoice { unselected, pending, completed }

class IntroductionCheck {
  const IntroductionCheck({
    required this.subjectPublicKeyHex,
    required this.isSelf,
  });

  final String subjectPublicKeyHex;
  final bool isSelf;
}

class IntroductionSave extends IntroductionCheck {
  const IntroductionSave({
    required super.subjectPublicKeyHex,
    required super.isSelf,
    required this.created,
  });

  final bool created;
}

// Only these fixed messages cross into the UI; exceptions and bodies do not.
enum StatusFailure implements Exception {
  invalidUrl('Use the full local owner status URL printed by node serve.'),
  credentials('Use the absolute owner.header file path printed by node serve.'),
  unauthorized(
    'Credential not accepted; use the current header file from node serve.',
  ),
  nodeState('The node could not inspect saved state.'),
  saveStorage('The node could not save the introduction. Check its storage.'),
  introductionConflict(
    'Introduction was not saved: a different proposal is already saved or the collection is full. Use Load saved introductions to inspect existing evidence.',
  ),
  saveUnreachable('Could not reach the local node; save outcome is unknown.'),
  emptyPeerUrl('Paste a peer introduction URL before fetching.'),
  peerUrlTooLarge(
    'Peer introduction URL exceeds the 2 KiB request limit. Paste the printed peer introduction URL.',
  ),
  invalidPeerUrl(
    "Peer URL is invalid or identifies this node. Paste the other node's printed peer introduction URL.",
  ),
  peerUnavailable(
    "Peer is unavailable or its evidence is invalid for this node's Root. Check the peer listener and URL.",
  ),
  fetchUnknown(
    'Local node request failed; fetch outcome is unknown. Use Load saved introductions to inspect saved evidence.',
  ),
  fetchUnexpected(
    'Unexpected local node response; fetch outcome is unknown. Use Load saved introductions to inspect saved evidence.',
  ),
  notCompleted('The introduction is not yet completed.'),
  invalidIntroduction(
    "Introduction could not be verified for this node's Root.",
  ),
  emptyIntroduction('Paste introduction JSON before checking.'),
  introductionTooLarge('Introduction JSON exceeds the 128 KiB limit.'),
  clipboard('Could not copy the introduction.'),
  unreachable('Could not read the local node.'),
  unexpected('Unexpected node response.');

  const StatusFailure(this.message);
  final String message;
}

/// One owned, direct HTTP client per explicit operation. No settings or token cache.
class StatusClient {
  StatusClient({this.createClient, Duration? timeout, Duration? fetchTimeout})
    : timeout = timeout ?? const Duration(seconds: 5),
      fetchTimeout = fetchTimeout ?? timeout ?? const Duration(seconds: 8);

  final http.Client Function()? createClient;
  final Duration timeout;
  final Duration fetchTimeout;
  void Function()? _cancel;
  bool _closed = false;

  Future<NodeChoice> read(String url, String headerPath) async {
    final json = await _request(_destination(url), headerPath, 4096);
    return switch (json['choice']) {
      'unselected' => NodeChoice.unselected,
      'pending' => NodeChoice.pending,
      'completed' => NodeChoice.completed,
      _ => throw StatusFailure.unexpected,
    };
  }

  /// Validates only the transfer shape, not the evidence's cryptography.
  /// The returned JSON contains only the three validated development fields.
  Future<String> readIntroduction(String url, String headerPath) async {
    // Check the raw URL before Uri can normalize away disallowed components,
    // then derive only the fixed sibling on the same validated origin.
    final destination = _destination(url).replace(path: '/owner/introduction');
    final json = await _request(destination, headerPath, 128 * 1024);
    if (json.length != 3 ||
        json['version'] is! int ||
        json['version'] != 1 ||
        !_standardBase64(json['proposal']) ||
        !_standardBase64(json['acceptance'])) {
      throw StatusFailure.unexpected;
    }
    return jsonEncode({
      'version': 1,
      'proposal': json['proposal'],
      'acceptance': json['acceptance'],
    });
  }

  Future<IntroductionCheck> checkIntroduction(
    String url,
    String headerPath,
    String document,
  ) async {
    final destination = _destination(url)
        .replace(path: '/owner/introduction/check');
    final json = await _request(
      destination,
      headerPath,
      4096,
      introduction: _documentBytes(document),
    );
    return _introductionSummary(json);
  }

  Future<IntroductionSave> saveIntroduction(
    String url,
    String headerPath,
    String document,
  ) async {
    final destination = _destination(url).replace(path: '/owner/introductions');
    final bytes = _documentBytes(document);
    final Map<String, dynamic> json;
    try {
      json = await _request(destination, headerPath, 4096, introduction: bytes);
    } on StatusFailure catch (failure) {
      if (failure == StatusFailure.unreachable) {
        throw StatusFailure.saveUnreachable;
      }
      rethrow;
    }
    return _introductionSave(json);
  }

  Future<IntroductionSave> fetchIntroduction(
    String ownerStatusUrl,
    String headerPath,
    String peerIntroductionUrl,
  ) async {
    final destination = _destination(ownerStatusUrl)
        .replace(path: '/owner/introductions/fetch');
    if (peerIntroductionUrl.trim().isEmpty) throw StatusFailure.emptyPeerUrl;
    // The peer URL is opaque data for Go's strict validation, never a Dart
    // destination. Bound the encoded request, including JSON escaping.
    final bytes = utf8.encode(jsonEncode({'peer_url': peerIntroductionUrl}));
    if (bytes.length > 2048) throw StatusFailure.peerUrlTooLarge;
    try {
      final json = await _request(
        destination,
        headerPath,
        4096,
        introduction: bytes,
        requestTimeout: fetchTimeout,
      );
      final saved = _introductionSave(json);
      if (saved.isSelf) throw StatusFailure.unexpected;
      return saved;
    } on StatusFailure catch (failure) {
      // A save may have committed even if its acknowledgement is lost or bad.
      throw switch (failure) {
        StatusFailure.unreachable => StatusFailure.fetchUnknown,
        StatusFailure.unexpected => StatusFailure.fetchUnexpected,
        _ => failure,
      };
    }
  }

  Future<List<IntroductionCheck>> listIntroductions(
    String url,
    String headerPath,
  ) async {
    final destination = _destination(url).replace(path: '/owner/introductions');
    final json = await _request(destination, headerPath, 256 * 1024);
    final items = json['introductions'];
    if (json.length != 1 || items is! List || items.length > 32) {
      throw StatusFailure.unexpected;
    }
    return items.map((item) {
      if (item is! Map<String, dynamic> ||
          utf8.encode(jsonEncode(item)).length > 4096) {
        throw StatusFailure.unexpected;
      }
      return _introductionSummary(item);
    }).toList();
  }

  Future<Map<String, dynamic>> _request(
    Uri destination,
    String headerPath,
    int maxBytes, {
    List<int>? introduction,
    Duration? requestTimeout,
  }) async {
    if (_closed || _cancel != null) throw StatusFailure.unreachable;
    final operationTimeout = requestTimeout ?? timeout;
    final fetching = destination.path == '/owner/introductions/fetch';

    http.Client? transport;
    StreamIterator<List<int>>? body;
    final abandoned = Completer<Map<String, dynamic>>();
    var finished = false;

    void cancel() {
      if (finished) return;
      finished = true;
      abandoned.completeError(StatusFailure.unreachable);
    }

    Future<Map<String, dynamic>> perform() async {
      final authorization = await _readAuthorization(headerPath);
      if (finished) throw StatusFailure.unreachable;
      transport =
          createClient?.call() ??
          IOClient(
            HttpClient()
              ..connectionTimeout = operationTimeout
              ..findProxy = (_) => 'DIRECT',
          );
      final request =
          http.Request(introduction == null ? 'GET' : 'POST', destination)
            ..followRedirects = false
            ..maxRedirects = 0
            ..persistentConnection = false
            ..headers['Authorization'] = authorization;
      if (introduction != null) {
        request.headers['Content-Type'] = 'application/json';
        request.bodyBytes = introduction;
      }
      final response = await transport!.send(request);
      if (finished) {
        // send() may finish after cancellation, including with a test client.
        await response.stream.listen(null).cancel();
        throw StatusFailure.unreachable;
      }

      if (response.statusCode != 200) {
        await response.stream.listen(null).cancel();
        throw switch (response.statusCode) {
          401 => StatusFailure.unauthorized,
          400 when fetching => StatusFailure.invalidPeerUrl,
          413 when fetching => StatusFailure.peerUrlTooLarge,
          502 when fetching => StatusFailure.peerUnavailable,
          409 when destination.path == '/owner/introduction' =>
            StatusFailure.notCompleted,
          409
              when fetching ||
                  (destination.path == '/owner/introductions' &&
                      introduction != null) =>
            StatusFailure.introductionConflict,
          400 when introduction != null => StatusFailure.invalidIntroduction,
          413 when introduction != null => StatusFailure.introductionTooLarge,
          500
              when fetching ||
                  (destination.path == '/owner/introductions' &&
                      introduction != null) =>
            StatusFailure.saveStorage,
          500 => StatusFailure.nodeState,
          _ => StatusFailure.unexpected,
        };
      }
      final mediaType = response.headers['content-type']
          ?.split(';')
          .first
          .trim()
          .toLowerCase();
      if (mediaType != 'application/json') {
        await response.stream.listen(null).cancel();
        throw StatusFailure.unexpected;
      }

      body = StreamIterator(response.stream);
      final bytes = <int>[];
      while (await body!.moveNext()) {
        final chunk = body!.current;
        if (bytes.length + chunk.length > maxBytes) {
          throw StatusFailure.unexpected;
        }
        bytes.addAll(chunk);
      }
      if (finished) throw StatusFailure.unreachable;
      try {
        final json = jsonDecode(utf8.decode(bytes));
        if (json is! Map<String, dynamic>) throw StatusFailure.unexpected;
        return json;
      } on FormatException {
        throw StatusFailure.unexpected;
      }
    }

    _cancel = cancel;
    final deadline = Timer(operationTimeout, cancel);
    try {
      return await Future.any([perform(), abandoned.future]);
    } on StatusFailure {
      rethrow;
    } catch (_) {
      throw StatusFailure.unreachable;
    } finally {
      finished = true;
      deadline.cancel();
      transport?.close();
      await body?.cancel();
      _cancel = null;
    }
  }

  /// Abandon an in-flight operation when the screen is disposed.
  void close() {
    _closed = true;
    _cancel?.call();
  }
}

List<int> _documentBytes(String document) {
  if (document.trim().isEmpty) throw StatusFailure.emptyIntroduction;
  final bytes = utf8.encode(document);
  if (bytes.length > 128 * 1024) throw StatusFailure.introductionTooLarge;
  return bytes;
}

IntroductionSave _introductionSave(Map<String, dynamic> json) {
  if (json.length != 3 || json['created'] is! bool) {
    throw StatusFailure.unexpected;
  }
  final summary = _introductionSummary({
    'subject_public_key_hex': json['subject_public_key_hex'],
    'is_self': json['is_self'],
  });
  return IntroductionSave(
    subjectPublicKeyHex: summary.subjectPublicKeyHex,
    isSelf: summary.isSelf,
    created: json['created'] as bool,
  );
}

IntroductionCheck _introductionSummary(Map<String, dynamic> json) {
  final subject = json['subject_public_key_hex'];
  final self = json['is_self'];
  if (json.length != 2 ||
      subject is! String ||
      subject.isEmpty ||
      subject.length.isOdd ||
      RegExp(r'[^0-9a-f]').hasMatch(subject) ||
      self is! bool) {
    throw StatusFailure.unexpected;
  }
  return IntroductionCheck(subjectPublicKeyHex: subject, isSelf: self);
}

bool _standardBase64(dynamic value) {
  if (value is! String || value.isEmpty) return false;
  try {
    // Dart accepts some alternate encodings; round-trip equality requires
    // standard alphabet, padding, and canonical pad bits without whitespace.
    return base64.encode(base64.decode(value)) == value;
  } on FormatException {
    return false;
  }
}

Uri _destination(String input) {
  final match = RegExp(
    r'^http://(localhost|[0-9.]+|\[[0-9a-fA-F:]+\]):([0-9]+)/owner/status$',
  ).firstMatch(input);
  if (match == null || match.end != input.length) {
    throw StatusFailure.invalidUrl;
  }
  final port = int.tryParse(match[2]!);
  if (port == null || port < 1 || port > 65535) {
    throw StatusFailure.invalidUrl;
  }
  var host = match[1]!;
  if (host == 'localhost') host = '127.0.0.1';
  if (host.startsWith('[')) host = host.substring(1, host.length - 1);
  final address = InternetAddress.tryParse(host);
  if (address == null || !address.isLoopback) throw StatusFailure.invalidUrl;
  return Uri(
    scheme: 'http',
    host: address.address,
    port: port,
    path: '/owner/status',
  );
}

Future<String> _readAuthorization(String path) async {
  // The service prints this basename. Refuse identity/unlock/storage paths
  // without opening them, and do not follow a final symlink to another file.
  if (!path.startsWith('/') || path.split('/').last != 'owner.header') {
    throw StatusFailure.credentials;
  }
  try {
    if (await FileSystemEntity.type(path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw StatusFailure.credentials;
    }
    final file = await File(path).open();
    try {
      if (await file.length() > 1024) throw StatusFailure.credentials;
      final bytes = await file.read(1024);
      if (await file.length() != bytes.length) throw StatusFailure.credentials;
      final text = ascii.decode(bytes);
      final match = RegExp(r'^Authorization: (Bearer [0-9a-f]{64})(?:\r?\n)?$')
          .firstMatch(text);
      if (match == null || match.end != text.length) {
        throw StatusFailure.credentials;
      }
      return match[1]!;
    } finally {
      await file.close();
    }
  } catch (_) {
    throw StatusFailure.credentials;
  }
}

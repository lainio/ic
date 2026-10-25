import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

enum NodeChoice { unselected, pending, completed }

// Only these fixed messages cross into the UI; exceptions and bodies do not.
enum StatusFailure implements Exception {
  invalidUrl('Use the full local owner status URL printed by node serve.'),
  credentials('Use the absolute owner.header file path printed by node serve.'),
  unauthorized(
    'Credential not accepted; use the current header file from node serve.',
  ),
  nodeState('The node could not inspect saved state.'),
  notCompleted('The introduction is not yet completed.'),
  clipboard('Could not copy the introduction.'),
  unreachable('Could not read the local node.'),
  unexpected('Unexpected node response.');

  const StatusFailure(this.message);
  final String message;
}

/// One owned, direct HTTP client per explicit read. No settings or token cache.
class StatusClient {
  StatusClient({this.createClient, this.timeout = const Duration(seconds: 5)});

  final http.Client Function()? createClient;
  final Duration timeout;
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

  Future<Map<String, dynamic>> _request(
    Uri destination,
    String headerPath,
    int maxBytes,
  ) async {
    if (_closed || _cancel != null) throw StatusFailure.unreachable;

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
              ..connectionTimeout = timeout
              ..findProxy = (_) => 'DIRECT',
          );
      final request = http.Request('GET', destination)
        ..followRedirects = false
        ..maxRedirects = 0
        ..persistentConnection = false
        ..headers['Authorization'] = authorization;
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
          409 when destination.path == '/owner/introduction' =>
            StatusFailure.notCompleted,
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
    final deadline = Timer(timeout, cancel);
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

  /// Abandon an in-flight read when the screen is disposed.
  void close() {
    _closed = true;
    _cancel?.call();
  }
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

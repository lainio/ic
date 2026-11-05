import 'dart:convert';

import 'pairing_types.dart';
import 'private_config_file.dart';
import 'status_client.dart';

const demoConfigLimit = 8192;
const demoConfigAttribution =
    'Configuration supplied by demo harness; '
    'not independently authenticated by Flutter.';

enum StartupFailure {
  arguments(
    'Use no arguments, or exactly --config /absolute/path/to/config.json.',
  ),
  config(
    'Configuration could not be loaded safely. Expected a private, valid '
    'version 1 demo configuration (at most 8 KiB). No owner request was sent.',
  );

  const StartupFailure(this.message);
  final String message;
}

/// Launch metadata only. No claim about current identity or node state.
class DemoConfig {
  const DemoConfig._(
    this.role,
    this.publicKeyHex,
    this.ownerStatusUrl,
    this.ownerHeaderFile,
  );

  final String role;
  final String publicKeyHex;
  final String ownerStatusUrl;
  final String ownerHeaderFile;

  String get roleLabel => role == 'alice'
      ? 'alice — requester'
      : 'bob — invitation issuer/acceptor';

  static DemoConfig? fromArguments(List<String> args) {
    if (args.isEmpty) return null;
    if (args.length != 2 ||
        args.first != '--config' ||
        !canonicalAbsolutePath(args[1])) {
      throw StartupFailure.arguments;
    }
    try {
      return DemoConfig.parse(
        utf8.decode(readPrivateConfig(args[1], demoConfigLimit)),
      );
    } catch (_) {
      throw StartupFailure.config;
    }
  }

  factory DemoConfig.parse(String text) {
    if (text.length > demoConfigLimit ||
        utf8.encode(text).length > demoConfigLimit) {
      throw const FormatException('Configuration too large');
    }
    final json = _flatObject(text);
    const fields = {
      'version',
      'role',
      'node_public_key_hex',
      'owner_status_url',
      'owner_header_file',
    };
    if (json.length != fields.length ||
        !fields.every(json.containsKey) ||
        json['version'] is! int ||
        json['version'] != 1 ||
        !['alice', 'bob'].contains(json['role']) ||
        !pairingPublicKeyHex(json['node_public_key_hex']) ||
        json['owner_status_url'] is! String ||
        json['owner_header_file'] is! String) {
      throw const FormatException('Invalid configuration fields');
    }
    final url = json['owner_status_url'] as String;
    final header = json['owner_header_file'] as String;
    StatusClient.validateOwnerStatusUrl(url);
    StatusClient.validateOwnerHeaderPath(header);
    if (!canonicalAbsolutePath(header)) {
      throw const FormatException('Invalid header path');
    }
    return DemoConfig._(
      json['role'] as String,
      json['node_public_key_hex'] as String,
      url,
      header,
    );
  }
}

// Tokenize this tiny flat object before decoding can discard duplicate fields.
// Decode individual names to catch escaped aliases too. No nested values,
// coercions, unknown fields, trailing documents or non-JSON whitespace.
Map<String, Object?> _flatObject(String text) {
  const string = r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"';
  final field = RegExp(
    '($string)[ \\t\\r\\n]*:[ \\t\\r\\n]*'
    '($string|-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)',
  );
  final whitespace = RegExp(r'[ \t\r\n]*');
  var offset = 0;
  void skipSpace() => offset = whitespace.matchAsPrefix(text, offset)!.end;
  void consume(String character) {
    skipSpace();
    if (offset >= text.length || text[offset++] != character) {
      throw const FormatException('Invalid configuration JSON');
    }
  }

  consume('{');
  final result = <String, Object?>{};
  while (true) {
    skipSpace();
    final match = field.matchAsPrefix(text, offset);
    if (match == null) {
      throw const FormatException('Invalid configuration JSON');
    }
    final name = jsonDecode(match[1]!) as String;
    if (result.containsKey(name)) {
      throw const FormatException('Duplicate configuration field');
    }
    result[name] = jsonDecode(match[2]!);
    offset = match.end;
    skipSpace();
    if (offset < text.length && text[offset] == '}') break;
    consume(',');
  }
  consume('}');
  skipSpace();
  if (offset != text.length) throw const FormatException('Trailing JSON');
  return result;
}

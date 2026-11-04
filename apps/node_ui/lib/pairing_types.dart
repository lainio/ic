import 'dart:convert';

// Shape validation only. Go validates canonical COSE, signatures and eligibility.
bool pairingPublicKeyHex(Object? value) =>
    value is String &&
    value.isNotEmpty &&
    value.length <= 256 &&
    value.length.isEven &&
    !RegExp(r'[^0-9a-f]').hasMatch(value);

bool _invitationId(Object? value) =>
    value is String &&
    value.length == 64 &&
    !RegExp(r'[^0-9a-f]').hasMatch(value);

/// Manual clipboard convenience, never a signed invitation wire format.
class DirectedRedemption {
  DirectedRedemption({
    required this.targetPublicKeyHex,
    required this.invitationIdHex,
  }) {
    if (!pairingPublicKeyHex(targetPublicKeyHex) ||
        !_invitationId(invitationIdHex)) {
      throw const FormatException('Invalid directed redemption shape');
    }
  }

  factory DirectedRedemption.parse(String document) {
    if (document.length > 512 ||
        utf8.encode(document).length > 512 ||
        !_exactObject(document, const {
          'target_public_key_hex': _hex,
          'invitation_id_hex': _hex,
          'audience': '"Directed"',
        })) {
      throw const FormatException('Invalid directed redemption shape');
    }
    final json = jsonDecode(document) as Map<String, dynamic>;
    return DirectedRedemption(
      targetPublicKeyHex: json['target_public_key_hex'] as String,
      invitationIdHex: json['invitation_id_hex'] as String,
    );
  }

  final String targetPublicKeyHex;
  final String invitationIdHex;

  String toJson() => jsonEncode({
    'target_public_key_hex': targetPublicKeyHex,
    'invitation_id_hex': invitationIdHex,
    'audience': 'Directed',
  });
}

/// Committed issue receipt, not a current eligibility or identity observation.
class DirectedInvitationReceipt {
  const DirectedInvitationReceipt._({
    required this.invitationIdHex,
    required this.recipientPublicKeyHex,
    required this.expiresUnixNano,
  });

  factory DirectedInvitationReceipt.fromJson(
    Map<String, dynamic> json,
    String expectedRecipient,
  ) {
    final expires = json['expires_unix_nano'];
    if (json.length != 4 ||
        !_invitationId(json['invitation_id_hex']) ||
        json['audience'] != 'Directed' ||
        !pairingPublicKeyHex(json['recipient_public_key_hex']) ||
        json['recipient_public_key_hex'] != expectedRecipient ||
        expires is! int ||
        expires < -0x8000000000000000 ||
        expires > 0x7fffffffffffffff) {
      throw const FormatException('Invalid directed invitation receipt');
    }
    return DirectedInvitationReceipt._(
      invitationIdHex: json['invitation_id_hex'] as String,
      recipientPublicKeyHex: expectedRecipient,
      expiresUnixNano: expires,
    );
  }

  final String invitationIdHex;
  final String recipientPublicKeyHex;
  final int expiresUnixNano;

  // Retain all nine fractional digits, including negative signed-int64 dates.
  String get expiryUtc {
    final fraction = expiresUnixNano % 1000000000;
    var seconds = expiresUnixNano ~/ 1000000000;
    if (expiresUnixNano < 0 && fraction != 0) seconds--;
    final date = DateTime.fromMillisecondsSinceEpoch(
      seconds * 1000,
      isUtc: true,
    ).toIso8601String().split('.').first;
    return '$date.${fraction.toString().padLeft(9, '0')}Z';
  }
}

/// Only retained state in the requesting owner's Vault.
class RedemptionReceipt {
  const RedemptionReceipt({required this.localHeld});

  final bool localHeld;
}

/// Alice's local historical observation, never current mutual readiness.
class FirstUseReceipt {
  const FirstUseReceipt();
}

bool firstUseResponseEnvelope(String text) =>
    _exactObject(text, const {'local_ready': 'true'});

const _hex = r'"[0-9a-f]+"';

bool pairingResponseEnvelope(String text, {required bool issuing}) =>
    _exactObject(
      text,
      issuing
          ? const {
              'invitation_id_hex': _hex,
              'expires_unix_nano': r'-?(?:0|[1-9][0-9]*)',
              'audience': '"Directed"',
              'recipient_public_key_hex': _hex,
            }
          : const {'acceptance_saved': 'true', 'local_held': '(?:true|false)'},
    );

// These flat envelopes have fixed primitive values. Check the whole wire shape
// and unique literal names before jsonDecode can discard duplicate properties.
// Escaped aliases, unknown fields, extra documents and coercions are rejected.
bool _exactObject(String text, Map<String, String> fields) {
  final alternatives = fields.entries
      .map((entry) => '"${entry.key}"\\s*:\\s*(?:${entry.value})')
      .join('|');
  final field = '(?:$alternatives)';
  final match = RegExp(
    '^\\s*\\{\\s*$field(?:\\s*,\\s*$field)'
    '{${fields.length - 1}}\\s*\\}\\s*\$',
  ).firstMatch(text);
  if (match == null || match.end != text.length) return false;
  final names = RegExp('"(${fields.keys.join('|')})"\\s*:')
      .allMatches(text)
      .map((m) => m[1])
      .toSet();
  return names.length == fields.length;
}

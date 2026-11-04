import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/pairing_types.dart';
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;

const owner = 'http://localhost:12345/owner/status';
const media = {'content-type': 'application/json'};
final aliceKey = 'a5010203262001215820${'11' * 32}225820${'22' * 32}';
final bobKey = 'a5010203262001215820${'33' * 32}225820${'44' * 32}';
final invitationId = 'cd' * 32;
final redemption = DirectedRedemption(
  targetPublicKeyHex: bobKey,
  invitationIdHex: invitationId,
);
String issueBody({int expires = 1800000000123456789}) => jsonEncode({
  'invitation_id_hex': invitationId,
  'expires_unix_nano': expires,
  'audience': 'Directed',
  'recipient_public_key_hex': aliceKey,
});
String redeemBody(bool held) => '{"acceptance_saved":true,"local_held":$held}';

void main() {
  late Directory directory;
  late File header;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('pairing-client-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
  });
  tearDown(() => directory.delete(recursive: true));

  test(
    'strict manual JSON rejects extras, aliases, duplicates and bad values',
    () {
      final valid = redemption.toJson();
      expect(DirectedRedemption.parse(valid).toJson(), valid);
      expect(DirectedRedemption.parse(' $valid\n').toJson(), valid);
      for (final invalid in [
        '',
        '{}',
        '[]',
        '$valid{}',
        '$valid trailing',
        valid.replaceFirst('}', ',"extra":true}'),
        valid.replaceFirst('}', ',"audience":"Directed"}'),
        valid.replaceFirst('audience', r'\u0061udience'),
        valid.replaceFirst('Directed', 'Any'),
        valid.replaceFirst(bobKey, 'AB'),
        valid.replaceFirst(bobKey, 'a'),
        valid.replaceFirst(bobKey, ''),
        valid.replaceFirst(bobKey, 'aa' * 129),
        valid.replaceFirst(invitationId, 'cd' * 31),
        valid.replaceFirst(invitationId, 'CD' * 32),
        valid.replaceFirst('"Directed"', 'true'),
        valid.replaceFirst(bobKey, 'http://127.0.0.1:23456/peer/pw/establish'),
        '$valid${' ' * 512}',
      ]) {
        expect(() => DirectedRedemption.parse(invalid), throwsFormatException);
      }
      final padded = valid.padRight(512);
      expect(DirectedRedemption.parse(padded).toJson(), valid);
      expect(
        utf8
            .encode(
              DirectedRedemption(
                targetPublicKeyHex: 'ab' * 128,
                invitationIdHex: invitationId,
              ).toJson(),
            )
            .length,
        lessThanOrEqualTo(512),
      );
    },
  );

  test(
    'issue validates signed int64 UTC nanoseconds without precision loss',
    () async {
      for (final expires in [
        -0x8000000000000000,
        -1,
        0,
        1800000000123456789,
        0x7fffffffffffffff,
      ]) {
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async =>
                http.Response(issueBody(expires: expires), 200, headers: media),
          ),
        );
        final result = await client.issueDirectedInvitation(
          owner,
          header.path,
          aliceKey,
        );
        expect(result.expiresUnixNano, expires);
        expect(result.invitationIdHex, invitationId);
        expect(result.recipientPublicKeyHex, aliceKey);
        expect(result.expiryUtc, endsWith('Z'));
        if (expires == -1) {
          expect(result.expiryUtc, '1969-12-31T23:59:59.999999999Z');
        }
        if (expires == 1800000000123456789) {
          expect(result.expiryUtc, '2027-01-15T08:00:00.123456789Z');
        }
      }
    },
  );

  test('redemption preserves both local holding values', () async {
    for (final held in [true, false]) {
      final client = StatusClient(
        createClient: () => ObservedClient(
          (_) async => http.Response(redeemBody(held), 200, headers: media),
        ),
      );
      expect(
        (await client.redeemInvitation(
          owner,
          header.path,
          redemption,
        )).localHeld,
        held,
      );
    }
  });

  for (final issuing in [true, false]) {
    final operation = issuing ? 'issue' : 'redeem';
    final success = issuing ? issueBody() : redeemBody(true);
    final unknown = issuing
        ? StatusFailure.issueUnknown
        : StatusFailure.redeemUnknown;
    final malformed = issuing
        ? StatusFailure.issueInvalidResponse
        : StatusFailure.redeemInvalidResponse;
    Future<Object> invoke(
      StatusClient client, {
      String url = owner,
      String? path,
    }) => issuing
        ? client.issueDirectedInvitation(url, path ?? header.path, aliceKey)
        : client.redeemInvitation(url, path ?? header.path, redemption);

    test(
      '$operation exact single POST, fresh credential, normalized loopback',
      () async {
        final requests = <http.Request>[];
        final transports = <ObservedClient>[];
        final client = StatusClient(
          createClient: () {
            final transport = ObservedClient((request) async {
              requests.add(request);
              return http.Response(success, 200, headers: media);
            });
            transports.add(transport);
            return transport;
          },
        );
        for (final token in ['ab' * 32, 'ef' * 32]) {
          await header.writeAsString('Authorization: Bearer $token\n');
          await invoke(client);
          final request = requests.last;
          expect(
            request.url.toString(),
            'http://127.0.0.1:12345/owner/pw/invitations/$operation',
          );
          expect(request.method, 'POST');
          expect(request.headers['Authorization'], 'Bearer $token');
          expect(request.headers['Content-Type'], 'application/json');
          expect(request.followRedirects, isFalse);
          expect(request.maxRedirects, 0);
          expect(request.persistentConnection, isFalse);
          expect(
            request.body,
            issuing
                ? jsonEncode({'recipient_public_key_hex': aliceKey})
                : redemption.toJson(),
          );
          expect(request.bodyBytes.length, lessThanOrEqualTo(512));
          expect(transports.last.closed, isTrue);
        }
        expect(requests, hasLength(2));
      },
    );

    test('$operation uses direct IO transport without a proxy', () async {
      final transport = _DirectTransport();
      await HttpOverrides.runZoned(
        () => expectLater(invoke(StatusClient()), throwsA(unknown)),
        createHttpClient: (_) => transport,
      );
      expect(
        transport.destination.toString(),
        'http://127.0.0.1:12345/owner/pw/invitations/$operation',
      );
      expect(transport.connectionTimeout, Duration(seconds: issuing ? 5 : 8));
      expect(transport.closed, isTrue);
    });

    test('$operation invalid origin or credentials sends nothing', () async {
      var created = 0;
      final client = StatusClient(
        createClient: () {
          created++;
          throw StateError('transport must not be created');
        },
      );
      for (final url in [
        'https://localhost:12345/owner/status',
        'http://example.com:12345/owner/status',
        'http://192.168.1.1:12345/owner/status',
        'http://127.0.0.1/owner/status',
        'http://user@127.0.0.1:12345/owner/status',
        '$owner?',
        '$owner#',
        '$owner/',
        '$owner\n',
        'http://127.0.0.1:23456/peer/pw/establish',
      ]) {
        await expectLater(
          invoke(client, url: url),
          throwsA(StatusFailure.pairingOwnerUrl),
        );
      }
      await expectLater(
        invoke(client, path: '/missing/owner.header'),
        throwsA(StatusFailure.pairingCredentials),
      );
      await header.writeAsString('untrusted credential diagnostic');
      await expectLater(
        invoke(client),
        throwsA(StatusFailure.pairingCredentials),
      );
      expect(created, 0);
    });

    test(
      '$operation fixed status failures never use untrusted error bodies',
      () async {
        final statuses = <int, StatusFailure>{
          400: issuing
              ? StatusFailure.issueRejected
              : StatusFailure.redeemRejected,
          413: issuing
              ? StatusFailure.issueRejected
              : StatusFailure.redeemRejected,
          415: issuing
              ? StatusFailure.issueRejected
              : StatusFailure.redeemRejected,
          401: issuing
              ? StatusFailure.issueUnavailable
              : StatusFailure.redeemUnavailable,
          404: issuing
              ? StatusFailure.issueUnavailable
              : StatusFailure.redeemUnavailable,
          409: issuing
              ? StatusFailure.issueExists
              : StatusFailure.redeemUnknown,
          502: issuing ? unknown : StatusFailure.redeemRemote,
          500: unknown,
          503: unknown,
          504: unknown,
          302: unknown,
          307: unknown,
        };
        for (final entry in statuses.entries) {
          var calls = 0;
          final client = StatusClient(
            createClient: () => ObservedClient((_) async {
              calls++;
              return http.Response(
                'private body $invitationId',
                entry.key,
                headers: {'location': 'http://example.com', ...media},
              );
            }),
          );
          await expectLater(invoke(client), throwsA(entry.value));
          expect(entry.value.message, isNot(contains(invitationId)));
          expect(calls, 1);
        }
      },
    );

    test('$operation rejects malformed, mismatched or oversized success', () async {
      final invalid = [
        '',
        '{}',
        '[]',
        '$success{}',
        success.replaceFirst('}', ',"extra":false}'),
        ' ' * 1025,
        if (issuing) ...[
          success.replaceFirst('}', ',"audience":"Directed"}'),
          success.replaceFirst('audience', r'\u0061udience'),
          success.replaceFirst(aliceKey, bobKey),
          success.replaceFirst(aliceKey, aliceKey.toUpperCase()),
          success.replaceFirst('"$aliceKey"', 'null'),
          success.replaceFirst(invitationId, 'cd'),
          success.replaceFirst('Directed', 'Any'),
          success.replaceFirst('1800000000123456789', '9223372036854775808'),
          success.replaceFirst('1800000000123456789', '-9223372036854775809'),
          success.replaceFirst('1800000000123456789', '1.5'),
          success.replaceFirst('1800000000123456789', '1e3'),
          success.replaceFirst('1800000000123456789', '"12"'),
        ] else ...[
          '{"acceptance_saved":true,"acceptance_saved":true,"local_held":true}',
          '{"acceptance_saved":false,"local_held":true}',
          '{"acceptance_saved":true,"local_held":"true"}',
          '{"acceptance_saved":1,"local_held":false}',
          success.replaceFirst('local_held', r'local_\u0068eld'),
        ],
      ];
      for (final body in invalid) {
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async => http.Response(body, 200, headers: media),
          ),
        );
        await expectLater(invoke(client), throwsA(malformed));
      }
      final client = StatusClient(
        createClient: () => ObservedClient(
          (_) async => http.Response(
            success,
            200,
            headers: {'content-type': 'text/plain'},
          ),
        ),
      );
      await expectLater(invoke(client), throwsA(malformed));
    });

    test(
      '$operation timeout and cancellation discard late reply without retry',
      () async {
        for (final cancel in [false, true]) {
          final started = Completer<void>();
          final response = Completer<http.Response>();
          var calls = 0;
          final transport = ObservedClient((_) {
            calls++;
            started.complete();
            return response.future;
          });
          final client = StatusClient(
            createClient: () => transport,
            timeout: const Duration(milliseconds: 40),
          );
          final result = expectLater(invoke(client), throwsA(unknown));
          await started.future;
          if (cancel) client.close();
          await result;
          response.complete(http.Response(success, 200, headers: media));
          await Future<void>.delayed(Duration.zero);
          expect(calls, 1);
          expect(transport.closed, isTrue);
        }
      },
    );
  }

  test('bad recipient and closed transport are explicitly not sent', () async {
    var calls = 0;
    final client = StatusClient(
      createClient: () {
        calls++;
        throw StateError('must not open');
      },
    );
    for (final key in ['', 'AABB', 'a', 'ab ', 'ab\n', 'ab' * 129]) {
      await expectLater(
        client.issueDirectedInvitation(owner, header.path, key),
        throwsA(StatusFailure.issueInput),
      );
    }
    client.close();
    await expectLater(
      client.issueDirectedInvitation(owner, header.path, aliceKey),
      throwsA(StatusFailure.pairingNotSent),
    );
    expect(calls, 0);
  });
}

class _DirectTransport implements HttpClient {
  @override
  Duration? connectionTimeout;
  String Function(Uri)? proxy;
  Uri? destination;
  bool closed = false;
  @override
  set findProxy(String Function(Uri)? callback) => proxy = callback;
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    expect(destination, isNull);
    expect(method, 'POST');
    expect(proxy?.call(url), 'DIRECT');
    destination = url;
    throw const SocketException('private diagnostic');
  }

  @override
  void close({bool force = false}) => closed = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

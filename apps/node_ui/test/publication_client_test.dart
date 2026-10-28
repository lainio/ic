import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;

const _owner = 'http://localhost:12345/owner/status';
const _endpoint = 'http://127.0.0.1:23456/peer/introduction';
const _bootstrap = '{"authorized":true,"usable":true}';
const _publish =
    '{"published":true,"slot":1,"epoch":0,'
    '"expires_unix_nano":1793192400123456789,'
    '"peer_introduction_url":"$_endpoint"}';
const _media = {'content-type': 'application/json; charset=utf-8'};

void main() {
  late Directory directory;
  late File header;
  final token = 'ab' * 32;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('publication-client-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer $token\n');
  });
  tearDown(() => directory.delete(recursive: true));

  for (final bootstrap in [true, false]) {
    final name = bootstrap ? 'authorization' : 'publication';
    final success = bootstrap ? _bootstrap : _publish;
    final path = bootstrap ? '/owner/device/bootstrap' : '/owner/ads/publish';
    final invalid = bootstrap
        ? StatusFailure.bootstrapInvalidResponse
        : StatusFailure.publishInvalidResponse;
    final unknown = bootstrap
        ? StatusFailure.bootstrapUnknown
        : StatusFailure.publishUnknown;
    Future<Object> invoke(StatusClient client, String url, String file) =>
        bootstrap
        ? client.bootstrapDevice(url, file)
        : client.publishAd(url, file);

    testWidgets('$name click sends only its exact POST with fresh credentials', (
      tester,
    ) async {
      final requests = <http.Request>[];
      final transports = <ObservedClient>[];
      final client = StatusClient(
        createClient: () {
          final transport = ObservedClient((request) async {
            requests.add(request);
            return http.Response(success, 200, headers: _media);
          });
          transports.add(transport);
          return transport;
        },
      );
      addTearDown(client.close);
      Future<Object>? pending;
      await tester.pumpWidget(
        IntroTreeApp(
          bootstrapDevice: (url, path) {
            final result = client.bootstrapDevice(url, path);
            pending = result;
            return result;
          },
          publishAd: (url, path) {
            final result = client.publishAd(url, path);
            pending = result;
            return result;
          },
        ),
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Owner status URL'),
        _owner,
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Authorization header file'),
        header.path,
      );
      final button = bootstrap
          ? find.widgetWithText(OutlinedButton, 'Authorize local device')
          : find.widgetWithText(FilledButton, 'Publish advertisement');
      expect(requests, isEmpty);
      // Publication's second deliberate click is another POST, even in one UI.
      for (final freshToken in [token, 'cd' * 32]) {
        await tester.ensureVisible(button);
        await tester.runAsync(() async {
          await header.writeAsString('Authorization: Bearer $freshToken\n');
          await tester.tap(button);
          await pending!.timeout(const Duration(seconds: 2));
        });
        await tester.pumpAndSettle();
        final request = requests.last;
        expect(request.method, 'POST');
        expect(request.url.toString(), 'http://127.0.0.1:12345$path');
        expect(request.headers['Authorization'], 'Bearer $freshToken');
        expect(request.headers['content-type'], 'application/json');
        expect(request.bodyBytes, [123, 125]);
        expect(request.followRedirects, isFalse);
        expect(request.maxRedirects, 0);
        expect(request.persistentConnection, isFalse);
        expect(transports.last.closed, isTrue);
      }
      expect(requests, hasLength(2));
      expect(
        find.text(
          bootstrap ? 'Local device authorized' : 'Advertisement published',
        ),
        findsOneWidget,
      );
      expect(
        find.text(
          bootstrap ? 'Advertisement published' : 'Local device authorized',
        ),
        findsNothing,
      );
      if (!bootstrap) {
        expect(find.widgetWithText(SelectableText, _endpoint), findsOneWidget);
      }
    });

    test(
      '$name validates owner before credentials and credentials before HTTP',
      () async {
        var created = 0;
        final client = StatusClient(
          createClient: () {
            created++;
            return ObservedClient((_) async => http.Response(success, 200));
          },
        );
        for (final url in [
          '',
          '$_owner?',
          '$_owner#',
          '$_owner/',
          '$_owner\n',
          'https://127.0.0.1:12345/owner/status',
          'http://127.0.0.1/owner/status',
          'http://127.0.0.1:0/owner/status',
          'http://127.0.0.1:65536/owner/status',
          'http://192.0.2.1:12345/owner/status',
          'http://user@127.0.0.1:12345/owner/status',
          'http://example.test:12345/owner/status',
          'http://127.0.0.1:12345/x/../owner/status',
          'http://127.0.0.1:12345/owner/%73tatus',
          _endpoint,
        ]) {
          await expectLater(
            invoke(client, url, '/missing/owner.header'),
            throwsA(StatusFailure.invalidUrl),
          );
        }
        for (final file in [
          'owner.header',
          '${directory.path}/identity',
          '${directory.path}/unlock',
          '${directory.path}/storage.key',
          '${directory.path}/missing/owner.header',
        ]) {
          await expectLater(
            invoke(client, _owner, file),
            throwsA(StatusFailure.credentials),
          );
        }
        for (final contents in [
          '',
          'private invalid token',
          'x' * 1025,
          'Authorization: Bearer $token\nX-Extra: secret\n',
        ]) {
          await header.writeAsString(contents);
          await expectLater(
            invoke(client, _owner, header.path),
            throwsA(StatusFailure.credentials),
          );
        }
        await header.delete();
        await Link(header.path).create('${directory.path}/identity');
        await expectLater(
          invoke(client, _owner, header.path),
          throwsA(StatusFailure.credentials),
        );
        expect(created, 0);
      },
    );

    test(
      '$name rejects malformed JSON and exact-field/type violations',
      () async {
        final valid = jsonDecode(success) as Map<String, dynamic>;
        final malformed = <String>[
          '',
          'null',
          '[]',
          '{}',
          '$success {}',
          jsonEncode({...valid, 'extra': true}),
          for (final field in valid.keys) jsonEncode({...valid}..remove(field)),
          if (bootstrap) ...[
            for (final field in ['authorized', 'usable'])
              for (final value in [false, null, 1, 'true', [], {}])
                jsonEncode({...valid, field: value}),
          ] else ...[
            for (final value in [false, null, 1, 'true'])
              jsonEncode({...valid, 'published': value}),
            for (final value in [null, false, '1', 1.0, 0, 2])
              jsonEncode({...valid, 'slot': value}),
            for (final value in [null, false, '0', 0.0, -1, 1])
              jsonEncode({...valid, 'epoch': value}),
            for (final value in [null, false, '1', 1.0, -1, 1e30])
              jsonEncode({...valid, 'expires_unix_nano': value}),
            success.replaceFirst('1793192400123456789', '9223372036854775808'),
            success.replaceFirst('1793192400123456789', '1e3'),
            for (final value in [null, false, 1, [], {}])
              jsonEncode({...valid, 'peer_introduction_url': value}),
          ],
        ];
        for (final body in malformed) {
          var calls = 0;
          final transport = ObservedClient((_) async {
            calls++;
            return http.Response(body, 200, headers: _media);
          });
          await expectLater(
            invoke(
              StatusClient(createClient: () => transport),
              _owner,
              header.path,
            ),
            throwsA(invalid),
            reason: body,
          );
          expect(calls, 1);
          expect(transport.closed, isTrue);
        }
      },
    );

    test(
      '$name bounds actual streamed bytes at 1 KiB and checks media',
      () async {
        final boundary = utf8.encode(
          '$success${' ' * (1024 - success.length)}',
        );
        final transport = ObservedClient(
          (_) async => http.Response.bytes(boundary, 200, headers: _media),
        );
        await invoke(
          StatusClient(createClient: () => transport),
          _owner,
          header.path,
        );
        expect(transport.closed, isTrue);
        var cancelled = false;
        final body = StreamController<List<int>>(
          onCancel: () {
            cancelled = true;
          },
        );
        final overflow = ObservedClient.streaming(
          (_, _) async => http.StreamedResponse(
            body.stream,
            200,
            contentLength: 1,
            headers: _media,
          ),
        );
        final result = expectLater(
          invoke(
            StatusClient(createClient: () => overflow),
            _owner,
            header.path,
          ),
          throwsA(invalid),
        );
        body.add(boundary);
        body.add([32]);
        await result;
        expect(cancelled, isTrue);
        expect(overflow.closed, isTrue);
        await body.close();
        for (final response in [
          http.Response(success, 200),
          http.Response(success, 200, headers: {'content-type': 'text/plain'}),
          http.Response.bytes([255], 200, headers: _media),
        ]) {
          final transport = ObservedClient((_) async => response);
          await expectLater(
            invoke(
              StatusClient(createClient: () => transport),
              _owner,
              header.path,
            ),
            throwsA(invalid),
          );
          expect(transport.closed, isTrue);
        }
      },
    );

    test('$name reports fixed operation-specific HTTP failures', () async {
      for (final (code, failure) in [
        (401, StatusFailure.unauthorized),
        (
          404,
          bootstrap
              ? StatusFailure.bootstrapUnavailable
              : StatusFailure.publishUnavailable,
        ),
        (
          409,
          bootstrap
              ? StatusFailure.bootstrapRejected
              : StatusFailure.publishRejected,
        ),
        for (final code in [400, 413, 415, 500, 502, 503, 302, 204])
          (code, unknown),
      ]) {
        var calls = 0;
        final transport = ObservedClient((_) async {
          calls++;
          return http.Response(
            'private body $token /private/path',
            code,
            headers: {'location': _endpoint},
          );
        });
        await expectLater(
          invoke(
            StatusClient(createClient: () => transport),
            _owner,
            header.path,
          ),
          throwsA(failure),
        );
        expect(calls, 1);
        expect(transport.closed, isTrue);
        expect(failure.message, isNot(contains(token)));
        expect(failure.message, isNot(contains('/private/path')));
      }
    });

    test(
      '$name transport loss, bounded timeout and disposal never retry',
      () async {
        expect(StatusClient().timeout, const Duration(seconds: 5));
        for (final finish in ['loss', 'timeout', 'close', 'send loss']) {
          var calls = 0;
          var cancelled = false;
          final started = Completer<void>();
          final body = StreamController<List<int>>(
            onCancel: () {
              cancelled = true;
            },
          );
          final transport = ObservedClient.streaming((_, _) async {
            calls++;
            started.complete();
            if (finish == 'send loss') {
              throw const SocketException('private path');
            }
            return http.StreamedResponse(body.stream, 200, headers: _media);
          });
          final client = StatusClient(
            timeout: const Duration(milliseconds: 100),
            createClient: () => transport,
          );
          final result = expectLater(
            invoke(client, _owner, header.path),
            throwsA(unknown),
          );
          await started.future;
          if (finish == 'loss') {
            body.addError(http.ClientException('private $token'));
          }
          if (finish == 'close') client.close();
          await result;
          expect(calls, 1);
          expect(transport.closed, isTrue);
          if (finish != 'send loss') {
            expect(cancelled, isTrue);
            await body.close();
          }
        }
      },
    );
  }

  test(
    'authorization receipt followed by 409 is not idempotent success',
    () async {
      var calls = 0;
      final client = StatusClient(
        createClient: () => ObservedClient((_) async {
          calls++;
          return http.Response(
            _bootstrap,
            calls == 1 ? 200 : 409,
            headers: _media,
          );
        }),
      );
      final result = await client.bootstrapDevice(_owner, header.path);
      expect(result.authorized, isTrue);
      expect(result.usable, isTrue);
      await expectLater(
        client.bootstrapDevice(_owner, header.path),
        throwsA(StatusFailure.bootstrapRejected),
      );
      expect(calls, 2);
    },
  );

  test(
    'publication retains integer expiry including zero, past and int64 max',
    () async {
      for (final expires in [
        0,
        1,
        999,
        1001,
        1793192400123456789,
        0x7fffffffffffffff,
      ]) {
        for (final endpoint in [
          _endpoint,
          'http://127.0.0.2:80/peer/introduction',
          'http://[::1]:65535/peer/introduction',
          'http://[0:0:0:0:0:0:0:1]:23456/peer/introduction',
        ]) {
          var calls = 0;
          final client = StatusClient(
            createClient: () => ObservedClient((_) async {
              calls++;
              return http.Response(
                jsonEncode({
                  ...jsonDecode(_publish) as Map<String, dynamic>,
                  'expires_unix_nano': expires,
                  'peer_introduction_url': endpoint,
                }),
                200,
                headers: _media,
              );
            }),
          );
          final result = await client.publishAd(_owner, header.path);
          expect(result.published, isTrue);
          expect(result.slot, 1);
          expect(result.epoch, 0);
          expect(result.expiresUnixNano, expires);
          expect(result.peerIntroductionUrl, endpoint);
          expect(calls, 1); // The returned address is never contacted.
        }
      }
    },
  );

  test(
    'publication endpoint must be literal loopback and exact peer path',
    () async {
      for (final endpoint in [
        '',
        '$_endpoint?',
        '$_endpoint#',
        '$_endpoint/',
        '$_endpoint\n',
        '$_endpoint?token=secret',
        '$_endpoint#fragment',
        'https://127.0.0.1:12345/peer/introduction',
        'http://localhost:12345/peer/introduction',
        'http://example.test:12345/peer/introduction',
        'http://192.0.2.1:12345/peer/introduction',
        'http://[::]:12345/peer/introduction',
        'http://[::1%25lo]:12345/peer/introduction',
        'http://user@127.0.0.1:12345/peer/introduction',
        'http://@127.0.0.1:12345/peer/introduction',
        'http://127.0.0.1/peer/introduction',
        'http://127.0.0.1:0/peer/introduction',
        'http://127.0.0.1:65536/peer/introduction',
        'http://127.0.0.1:port/peer/introduction',
        'http://127.0.0.1:12345/owner/status',
        'http://127.0.0.1:12345/x/../peer/introduction',
        'http://127.0.0.1:12345/peer/%69ntroduction',
        'http://${'1' * 1024}:12345/peer/introduction',
      ]) {
        var calls = 0;
        final client = StatusClient(
          createClient: () => ObservedClient((_) async {
            calls++;
            return http.Response(
              jsonEncode({
                ...jsonDecode(_publish) as Map<String, dynamic>,
                'peer_introduction_url': endpoint,
              }),
              200,
              headers: _media,
            );
          }),
        );
        await expectLater(
          client.publishAd(_owner, header.path),
          throwsA(StatusFailure.publishInvalidResponse),
          reason: endpoint,
        );
        expect(calls, 1);
      }
    },
  );
}

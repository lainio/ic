import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;

const _owner = 'http://localhost:12345/owner/status';
const _peer = 'http://127.0.0.1:23456/peer/introduction';
const _media = {'content-type': 'application/json'};
final _subject = 'ab' * 128;
String _fetch(bool introduction, bool ad) => jsonEncode({
  'subject_public_key_hex': _subject,
  'introduction_created': introduction,
  'ad_changed': ad,
});
String _verify(bool changed) => jsonEncode({
  'subject_public_key_hex': _subject,
  'verified': true,
  'changed': changed,
});

void main() {
  late Directory directory;
  late File header;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('ad-client-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
  });
  tearDown(() => directory.delete(recursive: true));

  test('fetch preserves every independent receipt boolean', () async {
    for (final introduction in [true, false]) {
      for (final ad in [true, false]) {
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async =>
                http.Response(_fetch(introduction, ad), 200, headers: _media),
          ),
        );
        final result = await client.fetchPeerAd(_owner, header.path, _peer);
        expect(result.subjectPublicKeyHex, _subject);
        expect(result.introductionCreated, introduction);
        expect(result.adChanged, ad);
      }
    }
  });

  test(
    'only the exact terminal peer suffix changes, with a UTF-8 JSON bound',
    () async {
      final requests = <http.Request>[];
      final client = StatusClient(
        createClient: () => ObservedClient((request) async {
          requests.add(request);
          return http.Response(_fetch(false, false), 200, headers: _media);
        }),
      );
      // Keep raw spelling; Go decides strict loopback admissibility.
      const raw = 'http://[::1]:23456/peer/introduction/peer/introduction';
      await client.fetchPeerAd(_owner, header.path, raw);
      expect(
        requests.single.body,
        '{"peer_url":"http://[::1]:23456/peer/introduction/peer/ad"}',
      );
      const prefix = 'http://127.0.0.1:23456/';
      final overhead = utf8
          .encode(jsonEncode({'peer_url': '${prefix}peer/ad'}))
          .length;
      final boundary = '$prefix${'a' * (2048 - overhead)}/peer/introduction';
      // One extra slash is included above, so this is one byte over the limit.
      await expectLater(
        client.fetchPeerAd(_owner, header.path, boundary),
        throwsA(StatusFailure.adFetchTooLarge),
      );
      await client.fetchPeerAd(
        _owner,
        header.path,
        boundary.replaceFirst('/a', '/'),
      );
      expect(requests.last.bodyBytes, hasLength(2048));
      for (final padding in ['é' * 1020, '"' * 1020]) {
        await expectLater(
          client.fetchPeerAd(
            _owner,
            header.path,
            '$prefix$padding/peer/introduction',
          ),
          throwsA(StatusFailure.adFetchTooLarge),
        );
      }
      expect(requests, hasLength(2));
    },
  );

  test(
    'invalid peer input and subject fail before opening credentials',
    () async {
      var created = 0;
      final client = StatusClient(
        createClient: () {
          created++;
          throw StateError('must not open transport');
        },
      );
      for (final peer in [
        '',
        ' ',
        '/peer/introduction',
        'garbage/peer/introduction',
        'http://[invalid]/peer/introduction',
        'http:///peer/introduction',
        '$_peer/',
        '$_peer?',
        '$_peer#',
        '$_peer?x=/peer/introduction',
        '$_peer#x/peer/introduction',
        '$_peer\n',
        'http://127.0.0.1:23456/peer/ad',
        'http://127.0.0.1:23456/peer/%69ntroduction',
      ]) {
        await expectLater(
          client.fetchPeerAd(_owner, '/missing/owner.header', peer),
          throwsA(StatusFailure.adPeerUrl),
          reason: peer,
        );
      }
      await expectLater(
        client.fetchPeerAd(_owner, '/missing/owner.header', 'a' * 2049),
        throwsA(StatusFailure.adFetchTooLarge),
      );
      for (final key in ['', 'a', 'AB', 'aa ', 'aa\n', 'gg', '00' * 129]) {
        await expectLater(
          client.verifyPeerAd(_owner, '/missing/owner.header', key),
          throwsA(StatusFailure.adSubject),
        );
      }
      expect(created, 0);
    },
  );

  for (final verifying in [false, true]) {
    final name = verifying ? 'verify' : 'fetch';
    final success = verifying ? _verify(true) : _fetch(true, false);
    final invalid = verifying
        ? StatusFailure.adVerifyInvalidResponse
        : StatusFailure.adFetchInvalidResponse;
    final unknown = verifying
        ? StatusFailure.adVerifyUnknown
        : StatusFailure.adFetchUnknown;
    Future<Object> invoke(StatusClient client, String owner, String path) =>
        verifying
        ? client.verifyPeerAd(owner, path, _subject)
        : client.fetchPeerAd(owner, path, _peer);

    test('$name default transport explicitly bypasses proxies', () async {
      final transport = _DirectTransport();
      await HttpOverrides.runZoned(
        () => expectLater(
          invoke(StatusClient(), _owner, header.path),
          throwsA(unknown),
        ),
        createHttpClient: (_) => transport,
      );
      expect(
        transport.destination.toString(),
        'http://127.0.0.1:12345/owner/ads/$name',
      );
      expect(transport.connectionTimeout, const Duration(seconds: 8));
      expect(transport.closed, isTrue);
    });

    test(
      '$name sends one owner POST per call, rereads credentials and closes transport',
      () async {
        final requests = <http.Request>[];
        final transports = <ObservedClient>[];
        final client = StatusClient(
          createClient: () {
            final transport = ObservedClient((request) async {
              requests.add(request);
              return http.Response(
                verifying ? _verify(requests.length == 1) : success,
                200,
                headers: _media,
              );
            });
            transports.add(transport);
            return transport;
          },
        );
        for (final token in ['ab' * 32, 'cd' * 32]) {
          await header.writeAsString('Authorization: Bearer $token\n');
          final result = await invoke(client, _owner, header.path);
          if (result is AdVerificationReceipt) {
            expect(result.verified, isTrue);
            expect(result.changed, requests.length == 1);
            expect(result.subjectPublicKeyHex, _subject);
          }
          final request = requests.last;
          expect(
            request.url.toString(),
            'http://127.0.0.1:12345/owner/ads/$name',
          );
          expect(request.method, 'POST');
          expect(
            request.bodyBytes,
            utf8.encode(
              verifying
                  ? '{"subject_public_key_hex":"$_subject"}'
                  : '{"peer_url":"http://127.0.0.1:23456/peer/ad"}',
            ),
          );
          expect(request.headers, {
            'Authorization': 'Bearer $token',
            'Content-Type': 'application/json',
          });
          expect(request.followRedirects, isFalse);
          expect(request.maxRedirects, 0);
          expect(request.persistentConnection, isFalse);
          expect(transports.last.closed, isTrue);
        }
        expect(requests, hasLength(2));
        expect(transports, hasLength(2));
      },
    );

    test(
      '$name validates owner before header and header before HTTP',
      () async {
        var calls = 0;
        final client = StatusClient(
          createClient: () {
            calls++;
            throw StateError('unexpected HTTP');
          },
        );
        for (final owner in [
          _peer,
          'http://127.0.0.1:23456/peer/ad',
          '',
          'http://example.com:12345/owner/status',
          '$_owner?',
          '$_owner#',
          'http://127.0.0.1:12345/x/../owner/status',
        ]) {
          await expectLater(
            invoke(client, owner, '/missing/owner.header'),
            throwsA(StatusFailure.invalidUrl),
          );
        }
        for (final path in [
          '/missing/owner.header',
          '${directory.path}/identity',
          'owner.header',
        ]) {
          await expectLater(
            invoke(client, _owner, path),
            throwsA(StatusFailure.credentials),
          );
        }
        for (final contents in [
          '',
          'Authorization: Bearer secret\n',
          'x' * 1025,
        ]) {
          await header.writeAsString(contents);
          await expectLater(
            invoke(client, _owner, header.path),
            throwsA(StatusFailure.credentials),
          );
        }
        expect(calls, 0);
      },
    );

    test('$name rejects ambiguous, malformed and mistyped replies', () async {
      final decoded = jsonDecode(success) as Map<String, dynamic>;
      final cases = <String>[
        '{}',
        '[]',
        '$success {}',
        '$success trailing',
        success.replaceFirst('"$_subject"', '"AB"'),
        success.replaceFirst('"$_subject"', '"a"'),
        success.replaceFirst('"$_subject"', '""'),
        success.replaceFirst('"$_subject"', '"${'ab' * 129}"'),
        success.replaceFirst('"$_subject"', '123'),
        success.replaceFirst('}', ',"extra":true}'),
        success.replaceFirst('}', ',"subject_public_key_hex":"$_subject"}'),
        if (verifying) ...[
          success.replaceFirst('"$_subject"', '"cd${_subject.substring(2)}"'),
          success.replaceFirst('"verified":true', '"verified":false'),
        ],
      ];
      for (final field in decoded.keys) {
        cases.add(jsonEncode({...decoded}..remove(field)));
        cases.add(
          success.replaceFirst('}', ',"$field":${jsonEncode(decoded[field])}}'),
        );
        for (final value in [null, [], {}, 1, 'true']) {
          cases.add(jsonEncode({...decoded, field: value}));
        }
      }
      for (final body in cases) {
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
      // Valid reversed order and surrounding JSON whitespace remain accepted.
      final reversed = jsonEncode(
        Map.fromEntries(decoded.entries.toList().reversed),
      );
      await invoke(
        StatusClient(
          createClient: () => ObservedClient(
            (_) async => http.Response(' \n$reversed\t', 200, headers: _media),
          ),
        ),
        _owner,
        header.path,
      );
    });

    test(
      '$name bounds the response and cancels on overflow or wrong media',
      () async {
        final boundary = utf8.encode(success.padRight(1024));
        await invoke(
          StatusClient(
            createClient: () => ObservedClient(
              (_) async => http.Response.bytes(boundary, 200, headers: _media),
            ),
          ),
          _owner,
          header.path,
        );
        var cancelled = false;
        final body = StreamController<List<int>>(
          onCancel: () {
            cancelled = true;
          },
        );
        final transport = ObservedClient.streaming(
          (_, _) async =>
              http.StreamedResponse(body.stream, 200, headers: _media),
        );
        final pending = expectLater(
          invoke(
            StatusClient(createClient: () => transport),
            _owner,
            header.path,
          ),
          throwsA(invalid),
        );
        body.add(boundary);
        body.add([32]);
        await pending;
        expect(cancelled, isTrue);
        expect(transport.closed, isTrue);
        await body.close();
        for (final response in [
          http.Response(success, 200),
          http.Response.bytes([255], 200, headers: _media),
        ]) {
          await expectLater(
            invoke(
              StatusClient(
                createClient: () => ObservedClient((_) async => response),
              ),
              _owner,
              header.path,
            ),
            throwsA(invalid),
          );
        }
      },
    );

    test(
      '$name maps backend errors without exposing bodies or retrying',
      () async {
        final failures = verifying
            ? <int, StatusFailure>{
                400: StatusFailure.adVerifyRejected,
                401: StatusFailure.unauthorized,
                404: StatusFailure.adVerifyUnavailable,
                409: StatusFailure.adVerifyPrecondition,
                413: StatusFailure.adVerifyRejected,
                415: StatusFailure.adVerifyRejected,
                502: StatusFailure.adVerifyRemote,
                504: StatusFailure.adVerifyTimeout,
                500: StatusFailure.adVerifyStorage,
              }
            : <int, StatusFailure>{
                400: StatusFailure.adFetchRejected,
                401: StatusFailure.unauthorized,
                404: StatusFailure.adFetchUnavailable,
                409: StatusFailure.adFetchConflict,
                413: StatusFailure.adFetchTooLarge,
                415: StatusFailure.adFetchRejected,
                502: StatusFailure.adFetchRemote,
                504: StatusFailure.adFetchTimeout,
                500: StatusFailure.adFetchStorage,
              };
        failures.addAll({302: invalid, 503: invalid, 204: invalid});
        for (final entry in failures.entries) {
          var calls = 0;
          final transport = ObservedClient((_) async {
            calls++;
            return http.Response(
              'private peer data /secret',
              entry.key,
              headers: {'location': _peer},
            );
          });
          await expectLater(
            invoke(
              StatusClient(createClient: () => transport),
              _owner,
              header.path,
            ),
            throwsA(entry.value),
          );
          expect(entry.value.message, isNot(contains('private peer data')));
          expect(calls, 1);
          expect(transport.closed, isTrue);
        }
      },
    );

    test(
      '$name longer deadline, transport loss and close clean up without retry',
      () async {
        expect(StatusClient().timeout, const Duration(seconds: 5));
        expect(StatusClient().fetchTimeout, const Duration(seconds: 8));
        for (final finish in ['loss', 'timeout', 'close']) {
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
            return http.StreamedResponse(body.stream, 200, headers: _media);
          });
          final client = StatusClient(
            createClient: () => transport,
            timeout: const Duration(milliseconds: 10),
            fetchTimeout: const Duration(milliseconds: 150),
          );
          final result = expectLater(
            invoke(client, _owner, header.path),
            throwsA(unknown),
          );
          await started.future;
          await Future<void>.delayed(const Duration(milliseconds: 30));
          expect(
            transport.closed,
            isFalse,
          ); // Did not use the ordinary deadline.
          if (finish == 'loss') {
            body.addError(const SocketException('private diagnostics'));
          }
          if (finish == 'close') client.close();
          await result;
          expect(calls, 1);
          expect(transport.closed, isTrue);
          expect(cancelled, isTrue);
          await body.close();
        }
      },
    );
  }
}

// Exercise default IOClient configuration without opening any socket.
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
    expect(destination, isNull); // No retry.
    destination = url;
    expect(method, 'POST');
    expect(proxy?.call(url), 'DIRECT');
    throw const SocketException('private transport diagnostic');
  }

  @override
  void close({bool force = false}) => closed = true;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/live_pairing.dart';
import 'package:ic_node_ui/pairing_types.dart';
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;
import 'live_pairing_test.dart' show click, keyed;

const _owner = 'http://localhost:12345/owner/status';
const _success = '{"local_ready":true}';
const _media = {'content-type': 'application/json'};

void main() {
  late Directory directory;
  late File header;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('first-use-client-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
  });
  tearDown(() => directory.delete(recursive: true));

  testWidgets('confirmation reaches real StatusClient exactly once', (
    tester,
  ) async {
    final requests = <http.Request>[];
    final transport = ObservedClient((request) async {
      requests.add(request);
      return http.Response(_success, 200, headers: _media);
    });
    final client = _TrackedClient(transport);
    await tester.pumpWidget(
      MaterialApp(
        home: LivePairingScreen(
          ownerStatusUrl: _owner,
          headerPath: header.path,
          createClient: () => client,
        ),
      ),
    );
    expect(requests, isEmpty);
    await click(tester, 'run-first-use');
    await tester.pumpAndSettle();
    await click(tester, 'cancel-first-use');
    await tester.pumpAndSettle();
    expect(requests, isEmpty);
    expect(client.result, isNull);

    await tester.runAsync(() async {
      // Start the dialog's async continuation in the real I/O zone too.
      await click(tester, 'run-first-use');
      await tester.pumpAndSettle();
      await header.writeAsString('Authorization: Bearer ${'ef' * 32}\n');
      await tester.tap(keyed('confirm-first-use'));
      await tester.pump();
      expect(client.result, isNotNull);
      await client.result!.timeout(const Duration(seconds: 2));
    });
    await tester.pumpAndSettle();
    expect(requests, hasLength(1));
    final request = requests.single;
    expect(request.url.toString(), 'http://127.0.0.1:12345/owner/pw/first-use');
    expect(request.method, 'POST');
    expect(request.body, '{}');
    expect(request.headers['Content-Type'], 'application/json');
    expect(request.headers['Authorization'], 'Bearer ${'ef' * 32}');
    expect(request.followRedirects, isFalse);
    expect(request.maxRedirects, 0);
    expect(find.text('Authenticated first use completed'), findsOneWidget);
    expect(
      find.text('Local readiness: observed on this exchange (historical)'),
      findsOneWidget,
    );
    await click(tester, 'run-first-use');
    await tester.pump(const Duration(seconds: 30));
    expect(requests, hasLength(1));
    expect(find.byType(AlertDialog), findsNothing);
    expect(transport.closed, isTrue);
  });

  test('one exact owner POST per invocation, with a fresh header', () async {
    final requests = <http.Request>[];
    final transports = <ObservedClient>[];
    final client = StatusClient(
      createClient: () {
        final transport = ObservedClient((request) async {
          requests.add(request);
          return http.Response(_success, 200, headers: _media);
        });
        transports.add(transport);
        return transport;
      },
    );
    for (final (origin, token, host) in [
      (_owner, 'ab' * 32, '127.0.0.1'),
      ('http://[::1]:12345/owner/status', 'cd' * 32, '[::1]'),
    ]) {
      await header.writeAsString('Authorization: Bearer $token\n');
      expect(
        await client.firstUse(origin, header.path),
        isA<FirstUseReceipt>(),
      );
      final request = requests.last;
      expect(request.url.toString(), 'http://$host:12345/owner/pw/first-use');
      expect(request.method, 'POST');
      expect(request.bodyBytes, utf8.encode('{}'));
      expect(request.bodyBytes.length, lessThanOrEqualTo(64));
      expect(request.headers['Content-Type'], 'application/json');
      expect(request.headers['Authorization'], 'Bearer $token');
      expect(request.followRedirects, isFalse);
      expect(request.maxRedirects, 0);
      expect(request.persistentConnection, isFalse);
      expect(transports.last.closed, isTrue);
    }
    expect(requests, hasLength(2));
    expect(client.fetchTimeout, const Duration(seconds: 8));
  });

  test('default IO transport is direct and allows Go five seconds', () async {
    final transport = _DirectTransport();
    await HttpOverrides.runZoned(
      () => expectLater(
        StatusClient().firstUse(_owner, header.path),
        throwsA(StatusFailure.firstUseUnknown),
      ),
      createHttpClient: (_) => transport,
    );
    expect(transport.calls, 1);
    expect(transport.connectionTimeout, const Duration(seconds: 8));
    expect(transport.closed, isTrue);
  });

  test('invalid owner configuration and credentials never dispatch', () async {
    var created = 0;
    final client = StatusClient(
      createClient: () {
        created++;
        throw StateError('private diagnostic');
      },
    );
    for (final url in [
      '',
      'https://localhost:12345/owner/status',
      'http://example.com:12345/owner/status',
      'http://192.168.1.1:12345/owner/status',
      'http://127.0.0.1/owner/status',
      'http://127.0.0.1:0/owner/status',
      'http://user@127.0.0.1:12345/owner/status',
      '$_owner?',
      '$_owner#',
      '$_owner/',
      '$_owner\n',
      'http://127.0.0.1:12345/owner/../owner/status',
      'http://127.0.0.1:23456/peer/pw/first-use',
    ]) {
      await expectLater(
        client.firstUse(url, header.path),
        throwsA(StatusFailure.firstUseOwnerUrl),
      );
    }
    for (final path in ['', 'owner.header', '/missing/owner.header']) {
      await expectLater(
        client.firstUse(_owner, path),
        throwsA(StatusFailure.firstUseCredentials),
      );
    }
    await header.writeAsString('private credential diagnostic');
    await expectLater(
      client.firstUse(_owner, header.path),
      throwsA(StatusFailure.firstUseCredentials),
    );
    expect(created, 0);

    await header.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
    await expectLater(
      client.firstUse(_owner, header.path),
      throwsA(StatusFailure.firstUseNotSent),
    );
    expect(created, 1);
    client.close();
    await expectLater(
      client.firstUse(_owner, header.path),
      throwsA(StatusFailure.firstUseNotSent),
    );
    expect(created, 1);
  });

  for (final (code, failure) in [
    (409, StatusFailure.firstUseRefused),
    (502, StatusFailure.firstUseRemote),
    (401, StatusFailure.firstUseUnavailable),
    (404, StatusFailure.firstUseUnavailable),
    (400, StatusFailure.firstUseRejected),
    (413, StatusFailure.firstUseRejected),
    (415, StatusFailure.firstUseRejected),
    (500, StatusFailure.firstUseUnknown),
    (504, StatusFailure.firstUseUnknown),
    (302, StatusFailure.firstUseUnknown),
    (307, StatusFailure.firstUseUnknown),
  ]) {
    test(
      '$code uses fixed first-use failure, cancels body and never retries',
      () async {
        var calls = 0;
        var cancelled = false;
        final body = StreamController<List<int>>(
          onCancel: () => cancelled = true,
        );
        final transport = ObservedClient.streaming((_, _) async {
          calls++;
          return http.StreamedResponse(
            body.stream,
            code,
            headers: {'location': 'http://example.com', ..._media},
          );
        });
        await expectLater(
          StatusClient(createClient: () => transport)
              .firstUse(_owner, header.path),
          throwsA(failure),
        );
        expect(calls, 1);
        expect(cancelled, isTrue);
        expect(transport.closed, isTrue);
        await body.close();
      },
    );
  }

  test('only exact raw success envelope within 1 KiB is accepted', () async {
    for (final body in [
      _success,
      ' \n{ "local_ready" : true }\r\n',
      _success.padRight(1024),
    ]) {
      final transport = ObservedClient(
        (_) async => http.Response(body, 200, headers: _media),
      );
      expect(
        await StatusClient(createClient: () => transport)
            .firstUse(_owner, header.path),
        isA<FirstUseReceipt>(),
      );
    }
    for (final body in [
      '',
      '{}',
      '[]',
      'null',
      '$_success{}',
      '$_success trailing',
      '{"local_ready":false}',
      '{"local_ready":"true"}',
      '{"local_ready":1}',
      '{"local_ready":null}',
      '{"local_ready":{"local_ready":true}}',
      '{"local_ready":true,"extra":true}',
      '{"local_ready":true,"local_ready":true}',
      '{"local_ready":false,"local_ready":true}',
      r'{"local_\u0072eady":true}',
      r'{"local_ready":false,"local_\u0072eady":true}',
      _success.padRight(1025),
    ]) {
      var calls = 0;
      final transport = ObservedClient((_) async {
        calls++;
        return http.Response(body, 200, headers: _media);
      });
      await expectLater(
        StatusClient(createClient: () => transport)
            .firstUse(_owner, header.path),
        throwsA(StatusFailure.firstUseInvalidResponse),
      );
      expect(calls, 1);
    }
    for (final response in [
      http.Response(_success, 200, headers: {'content-type': 'text/plain'}),
      http.Response(_success, 200),
      http.Response.bytes([0xff], 200, headers: _media),
    ]) {
      await expectLater(
        StatusClient(createClient: () => ObservedClient((_) async => response))
            .firstUse(_owner, header.path),
        throwsA(StatusFailure.firstUseInvalidResponse),
      );
    }
  });

  for (final failure in ['timeout', 'cancel', 'disconnect', 'body loss']) {
    test('$failure leaves unknown outcome with no automatic retry', () async {
      var calls = 0;
      final started = Completer<void>();
      final response = Completer<http.StreamedResponse>();
      final body = StreamController<List<int>>();
      final transport = ObservedClient.streaming((_, _) {
        calls++;
        started.complete();
        return response.future;
      });
      final client = StatusClient(
        createClient: () => transport,
        timeout: const Duration(milliseconds: 50),
      );
      final result = expectLater(
        client.firstUse(_owner, header.path),
        throwsA(StatusFailure.firstUseUnknown),
      );
      await started.future;
      switch (failure) {
        case 'cancel':
          client.close();
        case 'disconnect':
          response.completeError(const SocketException('private diagnostic'));
        case 'body loss':
          response.complete(
            http.StreamedResponse(body.stream, 200, headers: _media),
          );
          body.add(utf8.encode('{"local_ready":'));
          body.addError(http.ClientException('private signature bytes'));
      }
      await result;
      if (!response.isCompleted) {
        response.complete(
          http.StreamedResponse(body.stream, 200, headers: _media),
        );
        body.add(utf8.encode(_success));
      }
      await Future<void>.delayed(Duration.zero);
      if (failure == 'disconnect') await body.stream.listen(null).cancel();
      await body.close();
      expect(calls, 1);
      expect(transport.closed, isTrue);
    });
  }
}

// Observe the actual client's completion while widget time is paused for I/O.
class _TrackedClient extends StatusClient {
  _TrackedClient(http.Client transport) : super(createClient: () => transport);
  Future<FirstUseReceipt>? result;
  @override
  Future<FirstUseReceipt> firstUse(String url, String path) =>
      result = super.firstUse(url, path);
}

class _DirectTransport implements HttpClient {
  @override
  Duration? connectionTimeout;
  String Function(Uri)? proxy;
  var calls = 0;
  var closed = false;
  @override
  set findProxy(String Function(Uri)? callback) => proxy = callback;
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    calls++;
    expect(method, 'POST');
    expect(url.toString(), 'http://127.0.0.1:12345/owner/pw/first-use');
    expect(proxy?.call(url), 'DIRECT');
    throw const SocketException('private diagnostic');
  }

  @override
  void close({bool force = false}) => closed = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

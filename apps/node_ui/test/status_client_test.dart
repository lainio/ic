import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ic_node_ui/status_client.dart';

void main() {
  const url = 'http://127.0.0.1:12345/owner/status';
  final token = 'ab' * 32;
  late Directory directory;
  late File header;

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('node-ui-test-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer $token\n');
  });
  tearDown(() => directory.delete(recursive: true));

  final cases = [
    (200, '{"choice":"unselected"}', NodeChoice.unselected),
    (200, '{"choice":"pending"}', NodeChoice.pending),
    (200, '{"choice":"completed","future":true}', NodeChoice.completed),
    (401, 'private response', StatusFailure.unauthorized),
    (500, 'private response', StatusFailure.nodeState),
    (200, 'invalid JSON', StatusFailure.unexpected),
    (200, '{"choice":"unknown"}', StatusFailure.unexpected),
    (200, '{}', StatusFailure.unexpected),
    (200, '{"choice":3}', StatusFailure.unexpected),
    (200, '[{"choice":"completed"}]', StatusFailure.unexpected),
    (302, '', StatusFailure.unexpected),
    (204, '', StatusFailure.unexpected),
  ];
  for (final (code, body, expected) in cases) {
    test('response $code $body', () async {
      var calls = 0;
      final transport = ObservedClient((request) async {
        calls++;
        expect(request.method, 'GET');
        expect(request.url.toString(), url);
        expect(request.headers['Authorization'], 'Bearer $token');
        expect(
          request.headers.values.where((v) => v.contains(token)),
          hasLength(1),
        );
        expect(request.body, isEmpty);
        expect(request.followRedirects, isFalse);
        expect(request.maxRedirects, 0);
        return http.Response(
          body,
          code,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'location': 'http://192.0.2.1:9000/owner/status',
          },
        );
      });
      final client = StatusClient(createClient: () => transport);
      final result = client.read(url, header.path);
      if (expected is NodeChoice) {
        expect(await result, expected);
      } else {
        await expectLater(result, throwsA(expected));
      }
      expect(calls, 1);
      expect(transport.closed, isTrue);
    });
  }

  test('rejects destinations before touching credentials or HTTP', () async {
    var created = 0;
    final client = StatusClient(
      createClient: () {
        created++;
        return MockClient((_) async => http.Response('{}', 200));
      },
    );
    for (final destination in [
      '',
      'https://127.0.0.1:12345/owner/status',
      'http://127.0.0.1/owner/status',
      'http://127.0.0.1:0/owner/status',
      'http://127.0.0.1:65536/owner/status',
      'http://127.0.0.1:port/owner/status',
      'http://192.0.2.1:12345/owner/status',
      'http://example.test:12345/owner/status',
      'http://localhost.example.test:12345/owner/status',
      'http://[::]:12345/owner/status',
      'http://user@127.0.0.1:12345/owner/status',
      'http://@127.0.0.1:12345/owner/status',
      '$url?',
      '$url#',
      '$url?token=private',
      '$url#fragment',
      '$url/',
      'http://127.0.0.1:12345/intro/offer',
      'http://127.0.0.1:12345/other/../owner/status',
      'http://127.0.0.1:12345/owner/%73tatus',
      'http://127.0.0.1:12345/owner/status\n',
    ]) {
      await expectLater(
        client.read(destination, '/missing/owner.header'),
        throwsA(StatusFailure.invalidUrl),
        reason: destination,
      );
    }
    expect(created, 0);
  });

  test(
    'accepts literal loopback and normalizes localhost without DNS',
    () async {
      for (final (input, normalized) in [
        (url, url),
        ('http://localhost:12345/owner/status', url),
        ('http://127.0.0.2:80/owner/status', 'http://127.0.0.2/owner/status'),
        ('http://[::1]:12345/owner/status', 'http://[::1]:12345/owner/status'),
      ]) {
        final client = StatusClient(
          createClient: () => MockClient((request) async {
            expect(request.url.toString(), normalized);
            return http.Response(
              '{"choice":"pending"}',
              200,
              headers: {'content-type': 'application/json'},
            );
          }),
        );
        expect(await client.read(input, header.path), NodeChoice.pending);
      }
    },
  );

  test(
    'only a regular absolute owner.header with one exact header is read',
    () async {
      var created = 0;
      final client = StatusClient(
        createClient: () {
          created++;
          return MockClient((_) async => http.Response('{}', 200));
        },
      );
      for (final contents in [
        '',
        'Bearer $token',
        'Authorization: Bearer ${token.toUpperCase()}',
        'Authorization: Bearer ${token}a',
        'Authorization: Bearer short',
        'authorization: Bearer $token',
        'Authorization: bearer $token',
        'Authorization: Bearer $token ',
        'Authorization: Bearer $token\r',
        'Authorization: Bearer $token\n\n',
        'Authorization: Bearer $token\nX-Other: value\n',
        'Authorization: Bearer $token\nAuthorization: Bearer $token\n',
        'x' * 1025,
      ]) {
        await header.writeAsString(contents);
        await expectLater(
          client.read(url, header.path),
          throwsA(StatusFailure.credentials),
        );
      }
      await header.delete();
      await expectLater(
        client.read(url, header.path),
        throwsA(StatusFailure.credentials),
      );
      await Directory(header.path).create();
      await expectLater(
        client.read(url, header.path),
        throwsA(StatusFailure.credentials),
      );
      await Directory(header.path).delete();
      final other = File('${directory.path}/identity.json');
      await other.writeAsString('Authorization: Bearer $token\n');
      await expectLater(
        client.read(url, other.path),
        throwsA(StatusFailure.credentials),
      );
      await Link(header.path).create(other.path);
      await expectLater(
        client.read(url, header.path),
        throwsA(StatusFailure.credentials),
      );
      await expectLater(
        client.read(url, 'owner.header'),
        throwsA(StatusFailure.credentials),
      );
      expect(created, 0);
    },
  );

  test('reads credentials afresh with optional LF or CRLF', () async {
    for (final ending in ['', '\n', '\r\n']) {
      final client = StatusClient(
        createClient: () => MockClient((request) async {
          expect(request.headers['Authorization'], 'Bearer ${'cd' * 32}');
          return http.Response(
            '{"choice":"completed"}',
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      await header.writeAsString('Authorization: Bearer ${'cd' * 32}$ending');
      expect(await client.read(url, header.path), NodeChoice.completed);
      await header.writeAsString('invalid');
      await expectLater(
        client.read(url, header.path),
        throwsA(StatusFailure.credentials),
      );
    }
  });

  test('requires JSON media type and UTF-8 JSON', () async {
    for (final mediaType in [null, '', 'text/plain', 'application/jsonp']) {
      final transport = ObservedClient(
        // A string Response parses Content-Type to choose an encoding and
        // throws on the empty header before the client can inspect it.
        (_) async => http.Response.bytes(
          utf8.encode('{"choice":"completed"}'),
          200,
          headers: {if (mediaType != null) 'content-type': mediaType},
        ),
      );
      await expectLater(
        StatusClient(createClient: () => transport).read(url, header.path),
        throwsA(StatusFailure.unexpected),
      );
      expect(transport.closed, isTrue);
    }
    final client = StatusClient(
      createClient: () => MockClient(
        (_) async => http.Response.bytes(
          [0xff],
          200,
          headers: {'content-type': 'application/json'},
        ),
      ),
    );
    await expectLater(
      client.read(url, header.path),
      throwsA(StatusFailure.unexpected),
    );
  });

  test('caps actual response bytes and cancels the oversized stream', () async {
    var cancelled = false;
    final body = StreamController<List<int>>(
      onCancel: () {
        cancelled = true;
      },
    );
    final transport = ObservedClient.streaming(
      (_, _) async => http.StreamedResponse(
        body.stream,
        200,
        contentLength: 1,
        headers: {'content-type': 'application/json'},
      ),
    );
    final result = StatusClient(createClient: () => transport)
        .read(url, header.path);
    final expectation = expectLater(result, throwsA(StatusFailure.unexpected));
    body.add(List.filled(4096, 32));
    body.add([32]);
    await expectation;
    expect(cancelled, isTrue);
    expect(transport.closed, isTrue);
    await body.close();
  });

  test('accepts a valid response at the 4 KiB boundary', () async {
    const json = '{"choice":"pending"}';
    final body = '$json${' ' * (4096 - utf8.encode(json).length)}';
    final client = StatusClient(
      createClient: () => MockClient(
        (_) async => http.Response(
          body,
          200,
          headers: {'content-type': 'application/json'},
        ),
      ),
    );
    expect(await client.read(url, header.path), NodeChoice.pending);
  });

  test('request errors are generic and close the client', () async {
    final transport = ObservedClient(
      (_) async => throw http.ClientException(token),
    );
    await expectLater(
      StatusClient(createClient: () => transport).read(url, header.path),
      throwsA(StatusFailure.unreachable),
    );
    expect(transport.closed, isTrue);
    expect(StatusFailure.unreachable.toString(), isNot(contains(token)));
  });

  test('an error response cancels its body without waiting for it', () async {
    var cancelled = false;
    final body = StreamController<List<int>>(
      onCancel: () {
        cancelled = true;
      },
    );
    final transport = ObservedClient.streaming(
      (_, _) async => http.StreamedResponse(body.stream, 401),
    );
    await expectLater(
      StatusClient(createClient: () => transport).read(url, header.path),
      throwsA(StatusFailure.unauthorized),
    );
    expect(cancelled, isTrue);
    expect(transport.closed, isTrue);
    await body.close();
  });

  test(
    'deadline closes client and cancels a response arriving too late',
    () async {
      final response = Completer<http.StreamedResponse>();
      var cancelled = false;
      final body = StreamController<List<int>>(
        onCancel: () {
          cancelled = true;
        },
      );
      final transport = ObservedClient.streaming((_, _) => response.future);
      final client = StatusClient(
        createClient: () => transport,
        timeout: const Duration(milliseconds: 20),
      );
      await expectLater(
        client.read(url, header.path),
        throwsA(StatusFailure.unreachable),
      );
      expect(transport.closed, isTrue);
      response.complete(
        http.StreamedResponse(
          body.stream,
          200,
          headers: {'content-type': 'application/json'},
        ),
      );
      await Future<void>.delayed(Duration.zero);
      expect(cancelled, isTrue);
      await body.close();
    },
  );

  test('deadline also bounds a stalled response body', () async {
    var cancelled = false;
    final body = StreamController<List<int>>(
      onCancel: () {
        cancelled = true;
      },
    );
    final transport = ObservedClient.streaming(
      (_, _) async => http.StreamedResponse(
        body.stream,
        200,
        headers: {'content-type': 'application/json'},
      ),
    );
    final client = StatusClient(
      createClient: () => transport,
      timeout: const Duration(milliseconds: 20),
    );
    await expectLater(
      client.read(url, header.path),
      throwsA(StatusFailure.unreachable),
    );
    expect(cancelled, isTrue);
    expect(transport.closed, isTrue);
    await body.close();
  });

  test('closing an active read abandons it and releases resources', () async {
    final started = Completer<void>();
    final body = StreamController<List<int>>();
    final transport = ObservedClient.streaming((_, _) async {
      started.complete();
      return http.StreamedResponse(
        body.stream,
        200,
        headers: {'content-type': 'application/json'},
      );
    });
    final client = StatusClient(createClient: () => transport);
    final result = expectLater(
      client.read(url, header.path),
      throwsA(StatusFailure.unreachable),
    );
    await started.future;
    client.close();
    await result;
    expect(transport.closed, isTrue);
    await body.close();
  });

  test(
    'introduction uses the fixed sibling and rereads the credential',
    () async {
      final document = {
        'version': 1,
        'proposal': base64.encode([0, 1, 254, 255]),
        'acceptance': base64.encode([9, 8]),
      };
      var calls = 0;
      final transports = <ObservedClient>[];
      final client = StatusClient(
        createClient: () {
          final transport = ObservedClient((request) async {
            calls++;
            expect(request.method, 'GET');
            expect(
              request.url.toString(),
              'http://127.0.0.1:12345/owner/introduction',
            );
            expect(request.headers, {
              'Authorization': 'Bearer ${calls == 1 ? token : 'cd' * 32}',
            });
            expect(request.followRedirects, isFalse);
            expect(request.maxRedirects, 0);
            expect(request.persistentConnection, isFalse);
            expect(request.body, isEmpty);
            return http.Response(
              jsonEncode(document),
              200,
              headers: {'content-type': 'application/json; charset=utf-8'},
            );
          });
          transports.add(transport);
          return transport;
        },
      );
      expect(
        jsonDecode(await client.readIntroduction(url, header.path)),
        document,
      );
      await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
      expect(
        jsonDecode(
          await client.readIntroduction(
            'http://localhost:12345/owner/status',
            header.path,
          ),
        ),
        document,
      );
      for (final invalid in [
        'http://127.0.0.1:12345/owner/introduction',
        'http://192.0.2.1:12345/owner/status',
        '$url?path=/owner/introduction',
      ]) {
        await expectLater(
          client.readIntroduction(invalid, '/missing/owner.header'),
          throwsA(StatusFailure.invalidUrl),
        );
      }
      expect(calls, 2);
      expect(transports.every((transport) => transport.closed), isTrue);
    },
  );

  test(
    'introduction refuses pending, redirects and malformed envelopes',
    () async {
      for (final (code, body, media, failure) in [
        (409, 'private error', 'application/json', StatusFailure.notCompleted),
        (302, '', 'application/json', StatusFailure.unexpected),
        (
          200,
          '{"version":1,"proposal":"AQ==","acceptance":"Ag=="}',
          'text/plain',
          StatusFailure.unexpected,
        ),
        (200, '[]', 'application/json', StatusFailure.unexpected),
        (
          200,
          '{"version":2,"proposal":"AQ==","acceptance":"Ag=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1.0,"proposal":"AQ==","acceptance":"Ag=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":"AQ=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":"AQ==","acceptance":"Ag==","extra":true}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":"","acceptance":"Ag=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":"AQ","acceptance":"Ag=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":"_w==","acceptance":"Ag=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":"AQ==","acceptance":"bad!"}',
          'application/json',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"version":1,"proposal":null,"acceptance":"Ag=="}',
          'application/json',
          StatusFailure.unexpected,
        ),
      ]) {
        final transport = ObservedClient(
          (_) async => http.Response(
            body,
            code,
            headers: {'content-type': media, 'location': url},
          ),
        );
        await expectLater(
          StatusClient(createClient: () => transport)
              .readIntroduction(url, header.path),
          throwsA(failure),
        );
        expect(transport.closed, isTrue);
      }
    },
  );

  test('introduction has its own 128 KiB streamed response limit', () async {
    const document = '{"version":1,"proposal":"AQ==","acceptance":"Ag=="}';
    final boundary = '$document${' ' * (128 * 1024 - document.length)}';
    final client = StatusClient(
      createClient: () => MockClient(
        (_) async => http.Response(
          boundary,
          200,
          headers: {'content-type': 'application/json'},
        ),
      ),
    );
    expect(
      jsonDecode(await client.readIntroduction(url, header.path)),
      jsonDecode(document),
    );

    var cancelled = false;
    final body = StreamController<List<int>>(
      onCancel: () {
        cancelled = true;
      },
    );
    final transport = ObservedClient.streaming(
      (_, _) async => http.StreamedResponse(
        body.stream,
        200,
        contentLength: 1,
        headers: {'content-type': 'application/json'},
      ),
    );
    final result = StatusClient(createClient: () => transport)
        .readIntroduction(url, header.path);
    final expectation = expectLater(result, throwsA(StatusFailure.unexpected));
    body.add(utf8.encode(boundary));
    body.add([32]);
    await expectation;
    expect(cancelled, isTrue);
    expect(transport.closed, isTrue);
    await body.close();
  });
}

class ObservedClient extends MockClient {
  ObservedClient(super.handler);
  ObservedClient.streaming(super.handler) : super.streaming();

  bool closed = false;
  @override
  void close() {
    closed = true;
    super.close();
  }
}

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:ic_node_ui/main.dart';
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
  test(
    'check posts unchanged UTF-8 to the fixed origin and rereads credentials',
    () async {
      const document = ' {"endpoint":"http://evidence.invalid/é"} ';
      var calls = 0;
      final transports = <ObservedClient>[];
      final client = StatusClient(
        createClient: () {
          final transport = ObservedClient((request) async {
            calls++;
            expect(request.method, 'POST');
            expect(
              request.url.toString(),
              'http://127.0.0.1:12345/owner/introduction/check',
            );
            expect(request.headers, {
              'Authorization': 'Bearer ${calls == 1 ? token : 'cd' * 32}',
              'Content-Type': 'application/json',
            });
            expect(request.bodyBytes, utf8.encode(document));
            expect(request.followRedirects, isFalse);
            expect(request.maxRedirects, 0);
            expect(request.persistentConnection, isFalse);
            return http.Response(
              jsonEncode({
                'subject_public_key_hex': '00abcdef',
                'is_self': calls == 2,
              }),
              200,
              headers: {'content-type': 'application/json'},
            );
          });
          transports.add(transport);
          return transport;
        },
      );
      final peer = await client.checkIntroduction(url, header.path, document);
      expect(peer.subjectPublicKeyHex, '00abcdef');
      expect(peer.isSelf, isFalse);
      await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
      final self = await client.checkIntroduction(
        'http://localhost:12345/owner/status',
        header.path,
        document,
      );
      expect(self.subjectPublicKeyHex, peer.subjectPublicKeyHex);
      expect(self.isSelf, isTrue);
      expect(calls, 2);
      expect(transports.every((t) => t.closed), isTrue);
    },
  );

  test(
    'check validates URL and input before credential access or transport',
    () async {
      var created = 0;
      final client = StatusClient(
        createClient: () {
          created++;
          return MockClient((_) async => http.Response('{}', 200));
        },
      );
      for (final destination in [
        'http://192.0.2.1:12345/owner/status',
        'http://127.0.0.1:12345/owner/introduction/check',
        '$url?root=other',
        '$url#',
      ]) {
        await expectLater(
          client.checkIntroduction(destination, '/missing/owner.header', '{}'),
          throwsA(StatusFailure.invalidUrl),
        );
      }
      for (final document in [
        '',
        ' \n\t',
        'x' * (128 * 1024 + 1),
        'é' * (64 * 1024 + 1),
      ]) {
        await expectLater(
          client.checkIntroduction(url, '/missing/owner.header', document),
          throwsA(
            document.trim().isEmpty
                ? StatusFailure.emptyIntroduction
                : StatusFailure.introductionTooLarge,
          ),
        );
      }
      await expectLater(
        client.checkIntroduction(url, '/missing/owner.header', '{}'),
        throwsA(StatusFailure.credentials),
      );
      expect(created, 0);
    },
  );

  test(
    'check distinguishes rejection, authentication and malformed responses',
    () async {
      for (final (code, body, failure) in [
        (400, 'private diagnostics', StatusFailure.invalidIntroduction),
        (401, 'private diagnostics', StatusFailure.unauthorized),
        (413, 'private diagnostics', StatusFailure.introductionTooLarge),
        (500, 'private diagnostics', StatusFailure.nodeState),
        (302, '', StatusFailure.unexpected),
        (415, '', StatusFailure.unexpected),
        (200, 'not json', StatusFailure.unexpected),
        (200, '{}', StatusFailure.unexpected),
        (
          200,
          '{"subject_public_key_hex":"","is_self":false}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"abc","is_self":false}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"AB","is_self":false}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ag","is_self":false}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab\\n","is_self":false}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":12,"is_self":false}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":"false"}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":null}',
          StatusFailure.unexpected,
        ),
        (200, '{"subject_public_key_hex":"ab"}', StatusFailure.unexpected),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":false,"extra":0}',
          StatusFailure.unexpected,
        ),
      ]) {
        final transport = ObservedClient(
          (_) async => http.Response(
            body,
            code,
            headers: {'content-type': 'application/json', 'location': url},
          ),
        );
        await expectLater(
          StatusClient(createClient: () => transport)
              .checkIntroduction(url, header.path, '{}'),
          throwsA(failure),
        );
        expect(transport.closed, isTrue);
      }
      final transport = ObservedClient(
        (_) async => throw http.ClientException('private document'),
      );
      await expectLater(
        StatusClient(createClient: () => transport)
            .checkIntroduction(url, header.path, '{}'),
        throwsA(StatusFailure.unreachable),
      );
      expect(transport.closed, isTrue);
    },
  );

  test(
    'check accepts boundary input and bounds actual response reads to 4 KiB',
    () async {
      const result = '{"subject_public_key_hex":"ab","is_self":false}';
      final response = '$result${' ' * (4096 - result.length)}';
      final client = StatusClient(
        createClient: () => MockClient((request) async {
          expect(request.bodyBytes.length, 128 * 1024);
          return http.Response(
            response,
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      expect(
        (await client.checkIntroduction(
          url,
          header.path,
          'é' * (64 * 1024),
        )).subjectPublicKeyHex,
        'ab',
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
      final expectation = expectLater(
        StatusClient(createClient: () => transport)
            .checkIntroduction(url, header.path, '{}'),
        throwsA(StatusFailure.unexpected),
      );
      body.add(utf8.encode(response));
      body.add([32]);
      await expectation;
      expect(cancelled, isTrue);
      expect(transport.closed, isTrue);
      await body.close();
    },
  );

  test(
    'check cancellation and deadline release the single operation slot',
    () async {
      for (final dispose in [false, true]) {
        final started = Completer<void>();
        var cancelled = false;
        final body = StreamController<List<int>>(
          onCancel: () {
            cancelled = true;
          },
        );
        final transport = ObservedClient.streaming((_, _) async {
          started.complete();
          return http.StreamedResponse(
            body.stream,
            200,
            headers: {'content-type': 'application/json'},
          );
        });
        final client = StatusClient(
          createClient: () => transport,
          timeout: const Duration(milliseconds: 50),
        );
        final pending = expectLater(
          client.checkIntroduction(url, header.path, '{}'),
          throwsA(StatusFailure.unreachable),
        );
        await started.future;
        await expectLater(
          client.read(url, header.path),
          throwsA(StatusFailure.unreachable),
        );
        await expectLater(
          client.readIntroduction(url, header.path),
          throwsA(StatusFailure.unreachable),
        );
        if (dispose) client.close();
        await pending;
        expect(cancelled, isTrue);
        expect(transport.closed, isTrue);
        await body.close();
      }
    },
  );

  test('save and list are explicit fixed sibling requests with fresh credentials', () async {
    const document = '{"version":1,"proposal":"AQ==","acceptance":"Ag=="}';
    var calls = 0;
    final client = StatusClient(
      createClient: () => MockClient((request) async {
        calls++;
        expect(
          request.url.toString(),
          'http://127.0.0.1:12345/owner/introductions',
        );
        expect(request.followRedirects, isFalse);
        expect(request.maxRedirects, 0);
        expect(request.persistentConnection, isFalse);
        expect(
          request.headers['Authorization'],
          'Bearer ${calls == 1 ? token : 'cd' * 32}',
        );
        if (calls == 1) {
          expect(request.method, 'POST');
          expect(request.body, document);
          expect(request.headers['content-type'], 'application/json');
          return http.Response(
            '{"subject_public_key_hex":"00ab","is_self":false,"created":true}',
            200,
            headers: {'content-type': 'application/json'},
          );
        }
        expect(request.method, 'GET');
        expect(request.body, isEmpty);
        return http.Response(
          '{"introductions":[{"subject_public_key_hex":"00ab","is_self":false},{"subject_public_key_hex":"abcd","is_self":true}]}',
          200,
          headers: {'content-type': 'application/json'},
        );
      }),
    );
    final saved = await client.saveIntroduction(url, header.path, document);
    expect(saved.subjectPublicKeyHex, '00ab');
    expect(saved.isSelf, isFalse);
    expect(saved.created, isTrue);
    expect(calls, 1);
    await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
    final listed = await client.listIntroductions(
      'http://localhost:12345/owner/status',
      header.path,
    );
    expect(listed.map((e) => e.subjectPublicKeyHex), ['00ab', 'abcd']);
    expect(listed.map((e) => e.isSelf), [false, true]);
    expect(calls, 2);
  });

  test(
    'save maps results and fixed failures without exposing response bodies',
    () async {
      for (final (code, body, expected) in [
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":true,"created":false}',
          false,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":true,"created":"false"}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":true}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"zz","is_self":true,"created":true}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":0,"created":true}',
          StatusFailure.unexpected,
        ),
        (
          200,
          '{"subject_public_key_hex":"ab","is_self":true,"created":true,"extra":0}',
          StatusFailure.unexpected,
        ),
        (400, 'secret diagnostic', StatusFailure.invalidIntroduction),
        (401, 'secret diagnostic', StatusFailure.unauthorized),
        (409, 'secret diagnostic', StatusFailure.introductionConflict),
        (413, 'secret diagnostic', StatusFailure.introductionTooLarge),
        (415, 'secret diagnostic', StatusFailure.unexpected),
        (500, 'secret diagnostic', StatusFailure.saveStorage),
      ]) {
        final client = StatusClient(
          createClient: () => MockClient(
            (_) async => http.Response(
              body,
              code,
              headers: {'content-type': 'application/json'},
            ),
          ),
        );
        final result = client.saveIntroduction(url, header.path, '{}');
        if (expected is bool) {
          expect((await result).created, expected);
        } else {
          await expectLater(result, throwsA(expected));
        }
      }
      final client = StatusClient(
        createClient: () => MockClient(
          (_) async => throw const SocketException('private diagnostic'),
        ),
      );
      await expectLater(
        client.saveIntroduction(url, header.path, '{}'),
        throwsA(StatusFailure.saveUnreachable),
      );
      await expectLater(
        client.saveIntroduction(url, '/missing/owner.header', '{}'),
        throwsA(StatusFailure.credentials),
      );
      await expectLater(
        client.saveIntroduction('$url?', header.path, '{}'),
        throwsA(StatusFailure.invalidUrl),
      );
      await expectLater(
        client.saveIntroduction(url, header.path, 'é' * (64 * 1024 + 1)),
        throwsA(StatusFailure.introductionTooLarge),
      );
    },
  );

  test('list validates complete bounded summaries and distinguishes empty from failed', () async {
    const item = {'subject_public_key_hex': 'ab', 'is_self': false};
    for (final value in [
      {'introductions': null},
      {'introductions': [], 'extra': 0},
      {
        'introductions': [null],
      },
      {
        'introductions': [
          {'subject_public_key_hex': 'ab'},
        ],
      },
      {
        'introductions': [
          {'subject_public_key_hex': 'a', 'is_self': false},
        ],
      },
      {
        'introductions': [
          {'subject_public_key_hex': 'AB', 'is_self': false},
        ],
      },
      {
        'introductions': [
          {'subject_public_key_hex': 'ab', 'is_self': 'true'},
        ],
      },
      {
        'introductions': [
          {
            'subject_public_key_hex': 'ab',
            'is_self': false,
            'proposal': 'secret',
          },
        ],
      },
      {
        'introductions': [
          {'subject_public_key_hex': 'ab' * 2048, 'is_self': false},
        ],
      },
      {'introductions': List.filled(33, item)},
    ]) {
      final client = StatusClient(
        createClient: () => MockClient(
          (_) async => http.Response(
            jsonEncode(value),
            200,
            headers: {'content-type': 'application/json'},
          ),
        ),
      );
      await expectLater(
        client.listIntroductions(url, header.path),
        throwsA(StatusFailure.unexpected),
      );
    }
    for (final (code, expected) in [
      (200, null),
      (500, StatusFailure.nodeState),
      (401, StatusFailure.unauthorized),
    ]) {
      final client = StatusClient(
        createClient: () => MockClient(
          (_) async => http.Response(
            '{"introductions":[]}',
            code,
            headers: {'content-type': 'application/json'},
          ),
        ),
      );
      if (expected == null) {
        expect(await client.listIntroductions(url, header.path), isEmpty);
      } else {
        await expectLater(
          client.listIntroductions(url, header.path),
          throwsA(expected),
        );
      }
    }
  });

  test(
    'save and list bound actual response bytes, cancelling oversized streams',
    () async {
      for (final save in [true, false]) {
        final limit = save ? 4096 : 256 * 1024;
        final json = save
            ? '{"subject_public_key_hex":"ab","is_self":false,"created":true}'
            : '{"introductions":[]}';
        final boundary = utf8.encode('$json${' ' * (limit - json.length)}');
        Future<Object> request(StatusClient client) => save
            ? client.saveIntroduction(url, header.path, '{}')
            : client.listIntroductions(url, header.path);
        await request(
          StatusClient(
            createClient: () => MockClient(
              (_) async => http.Response.bytes(
                boundary,
                200,
                headers: {'content-type': 'application/json'},
              ),
            ),
          ),
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
        final expectation = expectLater(
          request(StatusClient(createClient: () => transport)),
          throwsA(StatusFailure.unexpected),
        );
        body.add(boundary);
        body.add([32]);
        await expectation;
        expect(cancelled, isTrue);
        expect(transport.closed, isTrue);
        await body.close();
      }
    },
  );
  const peerUrl = 'http://localhost:23456/peer/introduction';
  const fetchResponse =
      '{"subject_public_key_hex":"00abcdef","is_self":false,"created":true}';

  testWidgets('one Fetch click makes exactly one authenticated owner POST', (
    tester,
  ) async {
    final requests = <http.Request>[];
    final client = StatusClient(
      createClient: () => MockClient((request) async {
        requests.add(request);
        return http.Response(
          fetchResponse,
          200,
          headers: {'content-type': 'application/json'},
        );
      }),
    );
    addTearDown(client.close);
    Future<IntroductionSave>? fetching;
    await tester.pumpWidget(
      IntroTreeApp(
        fetchIntroduction: (url, path, peer) =>
            fetching = client.fetchIntroduction(url, path, peer),
      ),
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Owner status URL'),
      url,
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Authorization header file'),
      header.path,
    );
    final peerField = find.widgetWithText(TextField, 'Peer introduction URL');
    await tester.ensureVisible(peerField);
    await tester.enterText(peerField, peerUrl);
    await tester.pumpAndSettle();
    final button = find.widgetWithText(FilledButton, 'Fetch introduction');
    await tester.ensureVisible(button);
    expect(requests, isEmpty);
    await tester.runAsync(() async {
      await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
      await tester.tap(button);
      expect(fetching, isNotNull);
      await fetching!.timeout(const Duration(seconds: 2));
    });
    await tester.pumpAndSettle();
    expect(requests, hasLength(1));
    final request = requests.single;
    expect(request.method, 'POST');
    expect(
      request.url.toString(),
      'http://127.0.0.1:12345/owner/introductions/fetch',
    );
    expect(request.headers['Authorization'], 'Bearer ${'cd' * 32}');
    expect(request.headers['content-type'], 'application/json');
    expect(jsonDecode(request.body), {'peer_url': peerUrl});
    expect(request.followRedirects, isFalse);
    expect(request.maxRedirects, 0);
    expect(find.text('Introduction received'), findsOneWidget);
    expect(find.widgetWithText(SelectableText, '00abcdef'), findsOneWidget);
  });

  test(
    'fetch posts only to owner with exact peer data and fresh credentials',
    () async {
      var calls = 0;
      final transports = <ObservedClient>[];
      final client = StatusClient(
        createClient: () {
          final transport = ObservedClient((request) async {
            calls++;
            expect(request.method, 'POST');
            expect(
              request.url.toString(),
              'http://127.0.0.1:12345/owner/introductions/fetch',
            );
            expect(request.followRedirects, isFalse);
            expect(request.maxRedirects, 0);
            expect(request.persistentConnection, isFalse);
            expect(request.headers, {
              'Authorization': 'Bearer ${calls == 1 ? token : 'cd' * 32}',
              'Content-Type': 'application/json',
            });
            expect(jsonDecode(request.body), {'peer_url': peerUrl});
            expect(request.body, isNot(contains(token)));
            return http.Response(
              fetchResponse.replaceFirst('true', '${calls == 1}'),
              200,
              headers: {'content-type': 'application/json'},
            );
          });
          transports.add(transport);
          return transport;
        },
      );
      for (final created in [true, false]) {
        final saved = await client.fetchIntroduction(
          'http://localhost:12345/owner/status',
          header.path,
          peerUrl,
        );
        expect(saved.subjectPublicKeyHex, '00abcdef');
        expect(saved.isSelf, isFalse);
        expect(saved.created, created);
        expect(calls, created ? 1 : 2);
        await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
      }
      expect(transports.every((t) => t.closed), isTrue);
    },
  );

  test(
    'fetch validates owner and encoded input before client creation',
    () async {
      var created = 0;
      final client = StatusClient(
        createClient: () {
          created++;
          return MockClient((_) async => http.Response('{}', 200));
        },
      );
      for (final owner in [
        peerUrl,
        '$url?',
        'http://example.test:12345/owner/status',
      ]) {
        await expectLater(
          client.fetchIntroduction(owner, '/missing/owner.header', peerUrl),
          throwsA(StatusFailure.invalidUrl),
        );
      }
      for (final input in ['', ' \n\t', 'x' * 2048, 'é' * 1024, '"' * 1024]) {
        await expectLater(
          client.fetchIntroduction(url, '/missing/owner.header', input),
          throwsA(
            input.trim().isEmpty
                ? StatusFailure.emptyPeerUrl
                : StatusFailure.peerUrlTooLarge,
          ),
        );
      }
      await expectLater(
        client.fetchIntroduction(url, '/missing/owner.header', peerUrl),
        throwsA(StatusFailure.credentials),
      );
      expect(created, 0);
    },
  );

  test('fetch leaves unsupported peer spellings unchanged for Go', () async {
    for (final peer in [
      ' $peerUrl ',
      '$peerUrl?',
      'https://example.test/peer/%69ntroduction',
    ]) {
      var calls = 0;
      final client = StatusClient(
        createClient: () => MockClient((request) async {
          calls++;
          expect(request.url.path, '/owner/introductions/fetch');
          expect(jsonDecode(request.body), {'peer_url': peer});
          return http.Response('private body $token', 400);
        }),
      );
      await expectLater(
        client.fetchIntroduction(url, header.path, peer),
        throwsA(StatusFailure.invalidPeerUrl),
      );
      expect(calls, 1);
    }
  });

  test(
    'fetch maps HTTP failures without leaking bodies or following redirects',
    () async {
      for (final (code, failure) in [
        (400, StatusFailure.invalidPeerUrl),
        (401, StatusFailure.unauthorized),
        (409, StatusFailure.introductionConflict),
        (413, StatusFailure.peerUrlTooLarge),
        (502, StatusFailure.peerUnavailable),
        (500, StatusFailure.saveStorage),
        (302, StatusFailure.fetchUnexpected),
        (204, StatusFailure.fetchUnexpected),
        (404, StatusFailure.fetchUnexpected),
      ]) {
        var calls = 0;
        final transport = ObservedClient((request) async {
          calls++;
          expect(request.followRedirects, isFalse);
          return http.Response(
            'private body $token',
            code,
            headers: {'location': peerUrl},
          );
        });
        await expectLater(
          StatusClient(createClient: () => transport)
              .fetchIntroduction(url, header.path, peerUrl),
          throwsA(failure),
        );
        expect(failure.message, isNot(contains(token)));
        expect(failure.message, isNot(contains('private body')));
        expect(failure.message, isNot(contains(peerUrl)));
        expect(calls, 1);
        expect(transport.closed, isTrue);
      }
    },
  );

  test(
    'fetch requires an exact non-self save summary and JSON response',
    () async {
      final valid = jsonDecode(fetchResponse) as Map<String, dynamic>;
      for (final body in [
        'private body $token',
        '[]',
        '{}',
        for (final key in valid.keys) jsonEncode({...valid}..remove(key)),
        for (final subject in ['', 'abc', 'AB', 'ag', 'ab\n', 12, null])
          jsonEncode({...valid, 'subject_public_key_hex': subject}),
        for (final self in [true, 'false', 0, null])
          jsonEncode({...valid, 'is_self': self}),
        for (final created in ['true', 1, null])
          jsonEncode({...valid, 'created': created}),
        jsonEncode({...valid, 'extra': 0}),
      ]) {
        final client = StatusClient(
          createClient: () => MockClient(
            (_) async => http.Response(
              body,
              200,
              headers: {'content-type': 'application/json'},
            ),
          ),
        );
        await expectLater(
          client.fetchIntroduction(url, header.path, peerUrl),
          throwsA(StatusFailure.fetchUnexpected),
        );
      }
      for (final media in ['', 'text/plain']) {
        final client = StatusClient(
          createClient: () => MockClient(
            (_) async => http.Response.bytes(
              utf8.encode(fetchResponse),
              200,
              headers: {'content-type': media},
            ),
          ),
        );
        await expectLater(
          client.fetchIntroduction(url, header.path, peerUrl),
          throwsA(StatusFailure.fetchUnexpected),
        );
      }
    },
  );

  test(
    'fetch bounds encoded POST at 2 KiB and streamed response at 4 KiB',
    () async {
      final input =
          'x' * (2048 - utf8.encode(jsonEncode({'peer_url': ''})).length);
      final boundary = utf8.encode(
        '$fetchResponse${' ' * (4096 - fetchResponse.length)}',
      );
      final client = StatusClient(
        createClient: () => MockClient((request) async {
          expect(request.bodyBytes.length, 2048);
          return http.Response.bytes(
            boundary,
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      expect(
        (await client.fetchIntroduction(url, header.path, input)).created,
        isTrue,
      );
      await expectLater(
        client.fetchIntroduction(url, header.path, '${input}x'),
        throwsA(StatusFailure.peerUrlTooLarge),
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
      final result = expectLater(
        StatusClient(createClient: () => transport)
            .fetchIntroduction(url, header.path, peerUrl),
        throwsA(StatusFailure.fetchUnexpected),
      );
      body.add(boundary);
      body.add([32]);
      await result;
      expect(cancelled, isTrue);
      expect(transport.closed, isTrue);
      await body.close();
    },
  );

  test('fetch alone uses the longer injectable deadline', () async {
    expect(StatusClient().timeout, const Duration(seconds: 5));
    expect(StatusClient().fetchTimeout, const Duration(seconds: 8));
    var calls = 0;
    final client = StatusClient(
      timeout: Duration.zero,
      fetchTimeout: const Duration(seconds: 1),
      createClient: () => MockClient((_) async {
        calls++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return http.Response(
          fetchResponse,
          200,
          headers: {'content-type': 'application/json'},
        );
      }),
    );
    await expectLater(
      client.read(url, header.path),
      throwsA(StatusFailure.unreachable),
    );
    expect(
      (await client.fetchIntroduction(url, header.path, peerUrl)).created,
      isTrue,
    );
    expect(calls, 1);
  });

  test('fetch loss, deadline and close report unknown without retry', () async {
    for (final finish in ['loss', 'deadline', 'close']) {
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
        return http.StreamedResponse(
          body.stream,
          200,
          headers: {'content-type': 'application/json'},
        );
      });
      final client = StatusClient(
        createClient: () => transport,
        timeout: const Duration(milliseconds: 100),
      );
      final result = expectLater(
        client.fetchIntroduction(url, header.path, peerUrl),
        throwsA(StatusFailure.fetchUnknown),
      );
      await started.future;
      await expectLater(
        client.read(url, header.path),
        throwsA(StatusFailure.unreachable),
      );
      if (finish == 'loss') {
        body.addError(http.ClientException('private body $token'));
      }
      if (finish == 'close') client.close();
      await result;
      expect(calls, 1);
      expect(cancelled, isTrue);
      expect(transport.closed, isTrue);
      expect(
        StatusFailure.fetchUnknown.message,
        contains('outcome is unknown'),
      );
      expect(
        StatusFailure.fetchUnknown.message,
        contains('Load saved introductions'),
      );
      await body.close();
      if (finish == 'close') {
        await expectLater(
          client.fetchIntroduction(url, header.path, peerUrl),
          throwsA(StatusFailure.fetchUnknown),
        );
        expect(calls, 1);
      }
    }
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

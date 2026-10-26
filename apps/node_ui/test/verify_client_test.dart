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
  const url = 'http://localhost:12345/owner/status';
  const subject = 'a5010203262001215820abcdef0123456789abcdef0123456789';
  const success = '{"newly_known":1,"known_subjects":["$subject"]}';
  const media = {'content-type': 'application/json'};
  late Directory directory;
  late File header;
  final token = 'ab' * 32;

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('verify-client-test-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer $token\n');
  });
  tearDown(() => directory.delete(recursive: true));

  testWidgets('one explicit click makes only one authenticated owner POST', (
    tester,
  ) async {
    final requests = <http.Request>[];
    final client = StatusClient(
      createClient: () => MockClient((request) async {
        requests.add(request);
        return http.Response(success, 200, headers: media);
      }),
    );
    addTearDown(client.close);
    Future<IntroductionVerification>? verifying;
    await tester.pumpWidget(
      IntroTreeApp(
        verifyReceived: (url, path) =>
            verifying = client.verifyReceived(url, path),
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
    final button = find.widgetWithText(
      FilledButton,
      'Verify received introductions',
    );
    await tester.ensureVisible(button);
    expect(requests, isEmpty);
    await tester.runAsync(() async {
      await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
      await tester.tap(button);
      await verifying!.timeout(const Duration(seconds: 2));
    });
    await tester.pumpAndSettle();
    expect(requests, hasLength(1));
    final request = requests.single;
    expect(request.method, 'POST');
    expect(
      request.url.toString(),
      'http://127.0.0.1:12345/owner/introductions/verify',
    );
    expect(request.headers['Authorization'], 'Bearer ${'cd' * 32}');
    expect(request.headers['content-type'], 'application/json');
    expect(request.body, '{}');
    expect(request.followRedirects, isFalse);
    expect(request.maxRedirects, 0);
    expect(find.text('1 newly verified'), findsOneWidget);
    expect(find.widgetWithText(SelectableText, subject), findsOneWidget);
  });

  test(
    'success, explicit retry and empty retain complete sorted keys',
    () async {
      var calls = 0;
      final responses = [
        success,
        '{"known_subjects":["$subject"], "newly_known":0}',
        '{"newly_known":0,"known_subjects":[]}',
        jsonEncode({
          'newly_known': 32,
          'known_subjects': List.generate(
            32,
            (i) => i.toRadixString(16).padLeft(2, '0'),
          ),
        }),
      ];
      final client = StatusClient(
        createClient: () => MockClient((request) async {
          expect(request.body, '{}');
          expect(
            request.headers['Authorization'],
            'Bearer ${calls == 0 ? token : 'cd' * 32}',
          );
          return http.Response(responses[calls++], 200, headers: media);
        }),
      );
      expect((await client.verifyReceived(url, header.path)).newlyKnown, 1);
      await header.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
      final retry = await client.verifyReceived(url, header.path);
      expect(retry.newlyKnown, 0);
      expect(retry.knownSubjects, [subject]);
      expect(
        (await client.verifyReceived(url, header.path)).knownSubjects,
        isEmpty,
      );
      expect(
        (await client.verifyReceived(url, header.path)).knownSubjects,
        hasLength(32),
      );
      expect(calls, 4);
    },
  );

  test(
    'requires exact fields, integer count and unique sorted full hex keys',
    () async {
      final valid = jsonDecode(success) as Map<String, dynamic>;
      final malformed = <String>[
        '',
        'null',
        '[]',
        '{}',
        '$success {}',
        '$success private',
        '{"newly_known":0,"newly_known":1,"known_subjects":["$subject"]}',
        '{"known_subjects":[],"newly_known":1,"known_subjects":["$subject"]}',
        '{"newly_known":1,"newly_know\\u006e":1,"known_subjects":["$subject"]}',
        '{"newly_known":1.0,"known_subjects":["$subject"]}',
        '{"newly_known":1e0,"known_subjects":["$subject"]}',
        jsonEncode({...valid, 'extra': true}),
        for (final count in [-1, 2, 33, '1', null, true, [], 1e30])
          jsonEncode({...valid, 'newly_known': count}),
        for (final keys in [
          null,
          {},
          subject,
          [1],
          [true],
          [[]],
          [''],
          ['a'],
          ['AB'],
          ['aZ'],
          ['00…aa'],
          ['aa\n'],
          [' aa'],
          ['0xaa'],
          ['aa', 'aa'],
          ['bb', 'aa'],
          List.generate(33, (i) => i.toRadixString(16).padLeft(2, '0')),
        ])
          jsonEncode({...valid, 'known_subjects': keys}),
      ];
      for (final body in malformed) {
        var calls = 0;
        final client = StatusClient(
          createClient: () => MockClient((_) async {
            calls++;
            return http.Response(body, 200, headers: media);
          }),
        );
        await expectLater(
          client.verifyReceived(url, header.path),
          throwsA(StatusFailure.verifyInvalidResponse),
          reason: body,
        );
        expect(calls, 1);
      }
    },
  );

  test(
    'bounds streamed JSON at 16 KiB regardless of declared length',
    () async {
      final boundary = utf8.encode('$success${' ' * (16384 - success.length)}');
      final client = StatusClient(
        createClient: () => MockClient(
          (_) async => http.Response.bytes(boundary, 200, headers: media),
        ),
      );
      expect((await client.verifyReceived(url, header.path)).knownSubjects, [
        subject,
      ]);
      var cancelled = false;
      final body = StreamController<List<int>>(
        onCancel: () {
          cancelled = true;
        },
      );
      final transport = MockClient.streaming(
        (_, _) async => http.StreamedResponse(
          body.stream,
          200,
          contentLength: 1,
          headers: media,
        ),
      );
      final result = expectLater(
        StatusClient(createClient: () => transport)
            .verifyReceived(url, header.path),
        throwsA(StatusFailure.verifyInvalidResponse),
      );
      body.add(boundary);
      body.add([32]);
      await result;
      expect(cancelled, isTrue);
      await body.close();
      for (final response in [
        http.Response(success, 200),
        http.Response(success, 200, headers: {'content-type': 'text/plain'}),
        http.Response.bytes([255], 200, headers: media),
      ]) {
        await expectLater(
          StatusClient(createClient: () => MockClient((_) async => response))
              .verifyReceived(url, header.path),
          throwsA(StatusFailure.verifyInvalidResponse),
        );
      }
    },
  );

  test('rejects owner selectors and missing credentials before HTTP', () async {
    var calls = 0;
    final client = StatusClient(
      createClient: () {
        calls++;
        return MockClient(
          (_) async => http.Response(success, 200, headers: media),
        );
      },
    );
    for (final invalid in [
      '',
      '$url?',
      '$url#',
      '$url?root=aa',
      '$url/',
      'http://192.0.2.1:12345/owner/status',
      'http://localhost:12345/peer/introduction',
    ]) {
      await expectLater(
        client.verifyReceived(invalid, header.path),
        throwsA(StatusFailure.invalidUrl),
      );
    }
    await expectLater(
      client.verifyReceived(url, '${directory.path}/missing/owner.header'),
      throwsA(StatusFailure.credentials),
    );
    await header.writeAsString('private invalid token');
    await expectLater(
      client.verifyReceived(url, header.path),
      throwsA(StatusFailure.credentials),
    );
    expect(calls, 0);
  });

  test(
    'fixed failures distinguish credential, unavailable, rejection and unknown',
    () async {
      for (final (code, failure) in [
        (401, StatusFailure.unauthorized),
        (404, StatusFailure.verifyUnavailable),
        (400, StatusFailure.verifyRejected),
        (409, StatusFailure.verifyRejected),
        (413, StatusFailure.verifyRejected),
        (415, StatusFailure.verifyRejected),
        (500, StatusFailure.verifyUnknown),
        (302, StatusFailure.verifyInvalidResponse),
        (204, StatusFailure.verifyInvalidResponse),
      ]) {
        var calls = 0;
        final client = StatusClient(
          createClient: () => MockClient((_) async {
            calls++;
            return http.Response(
              'private body $token /private/path',
              code,
              headers: {'location': 'http://peer.invalid/'},
            );
          }),
        );
        await expectLater(
          client.verifyReceived(url, header.path),
          throwsA(failure),
        );
        expect(calls, 1);
        expect(failure.message, isNot(contains(token)));
      }
    },
  );

  test('lost response, normal timeout and disposal never retry', () async {
    expect(StatusClient().timeout, const Duration(seconds: 5));
    for (final finish in ['loss', 'timeout', 'close']) {
      var calls = 0;
      var cancelled = false;
      final started = Completer<void>();
      final body = StreamController<List<int>>(
        onCancel: () {
          cancelled = true;
        },
      );
      final client = StatusClient(
        timeout: const Duration(milliseconds: 100),
        createClient: () => MockClient.streaming((_, _) async {
          calls++;
          started.complete();
          return http.StreamedResponse(body.stream, 200, headers: media);
        }),
      );
      final result = expectLater(
        client.verifyReceived(url, header.path),
        throwsA(StatusFailure.verifyUnknown),
      );
      await started.future;
      if (finish == 'loss') {
        body.addError(http.ClientException('private $token'));
      }
      if (finish == 'close') client.close();
      await result;
      expect(calls, 1);
      expect(cancelled, isTrue);
      await body.close();
    }
  });
}

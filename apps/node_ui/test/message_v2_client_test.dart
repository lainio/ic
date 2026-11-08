import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;

const _owner = 'http://localhost:12345/owner/status';
const _ack = '{"local_acknowledgement_saved":true}';
const _id = '0123456789abcdef0123456789abcdef';
const _headers = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
};

void main() {
  late Directory directory;
  late File credential;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('message-v2-');
    credential = File('${directory.path}/owner.header');
    await credential.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
  });
  tearDown(() => directory.delete(recursive: true));

  test('v2 exact owner requests, fresh credentials, no routing hint', () async {
    final requests = <http.Request>[];
    final transports = <ObservedClient>[];
    final client = StatusClient(
      createClient: () {
        final transport = ObservedClient((request) async {
          requests.add(request);
          return http.Response(
            request.method == 'POST'
                ? _ack
                : jsonEncode({
                    'text': ' Hei Alice 🌍\n',
                    'present': true,
                    'message_id_hex': _id,
                  }),
            200,
            headers: _headers,
          );
        });
        transports.add(transport);
        return transport;
      },
    );
    await client.sendMessageV2(_owner, credential.path, ' Hei Bob 🌍\n');
    final send = requests.single;
    expect(send.method, 'POST');
    expect(send.url.toString(), 'http://127.0.0.1:12345/owner/pw/message/send');
    expect(
      send.bodyBytes,
      utf8.encode('{"version":2,"text":" Hei Bob 🌍\\n"}'),
    );
    expect(jsonDecode(send.body), isNot(contains('peer_message_url')));
    expect(send.headers['Authorization'], 'Bearer ${'ab' * 32}');
    await credential.writeAsString('Authorization: Bearer ${'cd' * 32}\n');
    final inbox = await client.readMessageInboxV2(_owner, credential.path);
    final read = requests.last;
    expect(read.method, 'GET');
    expect(
      read.url.toString(),
      'http://127.0.0.1:12345/owner/pw/message/inbox?version=2',
    );
    expect(read.bodyBytes, isEmpty);
    expect(read.headers['Authorization'], 'Bearer ${'cd' * 32}');
    expect((inbox.messageIdHex, inbox.text), (_id, ' Hei Alice 🌍\n'));
    expect(
      requests.every((r) => !r.followRedirects && !r.persistentConnection),
      isTrue,
    );
    expect(transports.every((t) => t.closed), isTrue);
  });

  test('v2 UTF-8 and encoded request bounds reject before HTTP', () async {
    var calls = 0;
    final client = StatusClient(
      createClient: () => ObservedClient((_) async {
        calls++;
        return http.Response(_ack, 200, headers: _headers);
      }),
    );
    for (final text in [' ', 'x' * 1024, '🌍' * 256]) {
      await client.sendMessageV2(_owner, credential.path, text);
    }
    for (final text in ['', 'x' * 1025, '🌍' * 257, '\ud800']) {
      await expectLater(
        client.sendMessageV2(_owner, credential.path, text),
        throwsA(StatusFailure.messageInput),
      );
    }
    await expectLater(
      client.sendMessageV2(_owner, credential.path, '\u0000' * 1024),
      throwsA(StatusFailure.messageRequestTooLarge),
    );
    await expectLater(
      client.sendMessageV2('https://peer.invalid', '', 'text'),
      throwsA(StatusFailure.messageOwnerUrl),
    );
    await expectLater(
      client.sendMessageV2(_owner, '', 'text'),
      throwsA(StatusFailure.messageCredentials),
    );
    expect(calls, 3);
  });

  test('v2 inbox strict envelope, field types, ID and text bounds', () async {
    var body = '{"present":false}';
    final client = StatusClient(
      createClient: () => ObservedClient(
        (_) async => http.Response(body, 200, headers: _headers),
      ),
    );
    expect(
      (await client.readMessageInboxV2(_owner, credential.path)).present,
      isFalse,
    );
    for (final invalid in [
      '{"present":true}',
      '{"present":"false"}',
      '{"present":false,"present":false}',
      r'{"pres\u0065nt":false}',
      '{"present":false,"text":"invented"}',
      '{"present":false}{}',
      '[]',
      '{"present":true,"message_id_hex":"bad","text":"text"}',
      '{"present":true,"message_id_hex":"$_id","text":null}',
      '{"present":true,"message_id_hex":"$_id","text":{"nested":true}}',
      '{"present":true,"message_id_hex":"$_id","text":""}',
      jsonEncode({'present': true, 'message_id_hex': _id, 'text': 'é' * 513}),
      '{"present":false}'.padRight(2049),
    ]) {
      body = invalid;
      await expectLater(
        client.readMessageInboxV2(_owner, credential.path),
        throwsA(StatusFailure.inboxInvalidResponse),
      );
    }
  });

  test(
    'v2 unknown send and refused inbox never become success/absence',
    () async {
      for (final (body, code, failure) in [
        ('private diagnostics', 502, StatusFailure.messageUnknown),
        (
          '{"local_acknowledgement_saved":false}',
          200,
          StatusFailure.messageUnknown,
        ),
      ]) {
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async => http.Response(body, code, headers: _headers),
          ),
        );
        await expectLater(
          client.sendMessageV2(_owner, credential.path, 'exact'),
          throwsA(failure),
        );
      }
      final refused = StatusClient(
        createClient: () => ObservedClient(
          (_) async => http.Response('private diagnostics', 409),
        ),
      );
      await expectLater(
        refused.readMessageInboxV2(_owner, credential.path),
        throwsA(StatusFailure.inboxConflict),
      );

      final pending = Completer<http.Response>();
      final started = Completer<void>();
      var calls = 0;
      final client = StatusClient(
        timeout: const Duration(milliseconds: 80),
        createClient: () => ObservedClient((_) {
          calls++;
          started.complete();
          return pending.future;
        }),
      );
      final result = expectLater(
        client.sendMessageV2(_owner, credential.path, 'exact'),
        throwsA(StatusFailure.messageUnknown),
      );
      await started.future;
      await result;
      pending.complete(http.Response(_ack, 200, headers: _headers));
      expect(calls, 1);
    },
  );
}

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;

const _owner = 'http://localhost:12345/owner/status';
const _peer = 'http://127.0.0.1:23456/peer/pw/message';
const _ack = '{"local_acknowledgement_saved":true}';
const _empty = '{"present":false}';
const _id = '0123456789abcdef0123456789abcdef';
const _media = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
};

String _inbox(String text) =>
    jsonEncode({'present': true, 'message_id_hex': _id, 'text': text});

Future<Object> _invoke(StatusClient client, String path, bool sending) =>
    sending
    ? client.sendMessage(_owner, path, 'Hello, Bob 🌍', _peer)
    : client.readMessageInbox(_owner, path);

void main() {
  late Directory directory;
  late File header;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('message-client-');
    header = File('${directory.path}/owner.header');
    await header.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
  });
  tearDown(() => directory.delete(recursive: true));

  test(
    'fixed owner siblings, fresh bearer, one closed client per click',
    () async {
      final requests = <http.Request>[];
      final transports = <ObservedClient>[];
      final client = StatusClient(
        createClient: () {
          final transport = ObservedClient((request) async {
            requests.add(request);
            return http.Response(
              request.method == 'POST'
                  ? _ack
                  : _inbox('Actual incoming text 🌍'),
              200,
              headers: _media,
            );
          });
          transports.add(transport);
          return transport;
        },
      );
      for (final (owner, host, token) in [
        (_owner, '127.0.0.1', 'cd' * 32),
        ('http://[::1]:12345/owner/status', '[::1]', 'ef' * 32),
      ]) {
        for (final sending in [true, false]) {
          final currentToken = sending ? token : '12' * 32;
          await header.writeAsString('Authorization: Bearer $currentToken\n');
          final result = sending
              ? await client.sendMessage(
                  owner,
                  header.path,
                  'Hello, Bob 🌍',
                  _peer,
                )
              : await client.readMessageInbox(owner, header.path);
          final request = requests.last;
          expect(
            request.url.toString(),
            'http://$host:12345/owner/pw/message/${sending ? 'send' : 'inbox'}',
          );
          expect(request.method, sending ? 'POST' : 'GET');
          expect(request.headers['Authorization'], 'Bearer $currentToken');
          expect(request.followRedirects, isFalse);
          expect(request.maxRedirects, 0);
          expect(request.persistentConnection, isFalse);
          if (sending) {
            expect(result, isA<MessageSendReceipt>());
            expect(request.headers['Content-Type'], 'application/json');
            expect(
              request.bodyBytes,
              utf8.encode(
                jsonEncode({
                  'text': 'Hello, Bob 🌍',
                  'peer_message_url': _peer,
                }),
              ),
            );
            expect(request.body, isNot(contains(currentToken)));
          } else {
            expect(request.bodyBytes, isEmpty);
            expect(request.headers.containsKey('Content-Type'), isFalse);
            expect((result as MessageInbox).text, 'Actual incoming text 🌍');
            expect(result.messageIdHex, _id);
            expect(result.present, isTrue);
          }
          expect(transports.last.closed, isTrue);
        }
      }
      expect(requests, hasLength(4));
      expect(
        requests.any((request) => request.url.toString() == _peer),
        isFalse,
      );
      expect(client.fetchTimeout, const Duration(seconds: 8));
    },
  );

  test('UTF-8 and JSON boundaries, without trimming or replacement', () async {
    var calls = 0;
    final client = StatusClient(
      createClient: () => ObservedClient((request) async {
        calls++;
        expect(request.bodyBytes.length, lessThanOrEqualTo(2048));
        return http.Response(_ack, 200, headers: _media);
      }),
    );
    for (final text in ['a', ' ', 'x' * 1024, 'é' * 512, '🌍' * 256]) {
      await client.sendMessage(_owner, header.path, text, _peer);
    }
    final overhead = utf8
        .encode(jsonEncode({'text': '', 'peer_message_url': _peer}))
        .length;
    final quotes = 2048 - overhead - 1024;
    final exact = '"' * quotes + 'a' * (1024 - quotes);
    await client.sendMessage(_owner, header.path, exact, _peer);
    expect(calls, 6);
    for (final text in ['', 'x' * 1025, 'é' * 513, '🌍' * 257, '\ud800']) {
      await expectLater(
        client.sendMessage(_owner, header.path, text, _peer),
        throwsA(StatusFailure.messageInput),
      );
    }
    for (final text in [
      '"' * (quotes + 1) + 'a' * (1023 - quotes),
      '\u0000' * 1024,
    ]) {
      await expectLater(
        client.sendMessage(_owner, header.path, text, _peer),
        throwsA(StatusFailure.messageRequestTooLarge),
      );
    }
    expect(calls, 6);
  });

  test('strict canonical numeric loopback peer URL is data only', () async {
    var calls = 0;
    final client = StatusClient(
      createClient: () => ObservedClient((_) async {
        calls++;
        return http.Response(_ack, 200, headers: _media);
      }),
    );
    for (final peer in [
      _peer,
      'http://[::1]:1/peer/pw/message',
      'http://127.255.255.255:65535/peer/pw/message',
      'http://127.0.0.2:80/peer/pw/message',
    ]) {
      await client.sendMessage(_owner, header.path, 'message', peer);
    }
    for (final peer in [
      '',
      _owner,
      '$_peer/',
      '$_peer?',
      '$_peer#',
      '$_peer\n',
      ' $_peer',
      '$_peer?text=secret',
      '$_peer#secret',
      'http://localhost:23456/peer/pw/message',
      'http://example.com:23456/peer/pw/message',
      'http://192.168.1.1:23456/peer/pw/message',
      'https://127.0.0.1:23456/peer/pw/message',
      'HTTP://127.0.0.1:23456/peer/pw/message',
      'http://user@127.0.0.1:23456/peer/pw/message',
      'http://127.0.0.1/peer/pw/message',
      'http://127.0.0.1:0/peer/pw/message',
      'http://127.0.0.1:65536/peer/pw/message',
      'http://127.0.0.1:023456/peer/pw/message',
      'http://127.00.0.1:23456/peer/pw/message',
      'http://127.256.0.1:23456/peer/pw/message',
      'http://127.1:23456/peer/pw/message',
      'http://2130706433:23456/peer/pw/message',
      'http://[0:0:0:0:0:0:0:1]:23456/peer/pw/message',
      'http://[::ffff:127.0.0.1]:23456/peer/pw/message',
      'http://[::1%25lo]:23456/peer/pw/message',
      'http://127.0.0.1:23456/peer/other/../pw/message',
      'http://127.0.0.1:23456/peer/pw/%6dessage',
      'http://${'1' * 257}:1/peer/pw/message',
    ]) {
      await expectLater(
        client.sendMessage(_owner, header.path, 'message', peer),
        throwsA(StatusFailure.messagePeerUrl),
        reason: peer,
      );
    }
    expect(calls, 4);
  });

  for (final sending in [true, false]) {
    final action = sending ? 'send' : 'inbox';
    test(
      '$action invalid owner/credentials, closed client never dispatch',
      () async {
        var created = 0;
        final client = StatusClient(
          createClient: () {
            created++;
            throw StateError('private diagnostic');
          },
        );
        for (final owner in [
          '',
          _peer,
          '$_owner?',
          '$_owner#',
          '$_owner\n',
          'http://example.com:12345/owner/status',
        ]) {
          await expectLater(
            sending
                ? client.sendMessage(owner, header.path, 'message', _peer)
                : client.readMessageInbox(owner, header.path),
            throwsA(StatusFailure.messageOwnerUrl),
          );
        }
        for (final path in ['', 'owner.header', '/absent/owner.header']) {
          await expectLater(
            _invoke(client, path, sending),
            throwsA(StatusFailure.messageCredentials),
          );
        }
        await header.writeAsString('private bearer');
        await expectLater(
          _invoke(client, header.path, sending),
          throwsA(StatusFailure.messageCredentials),
        );
        expect(created, 0);
        await header.writeAsString('Authorization: Bearer ${'ab' * 32}\n');
        await expectLater(
          _invoke(client, header.path, sending),
          throwsA(StatusFailure.messageNotSent),
        );
        expect(created, 1);
        client.close();
        await expectLater(
          _invoke(client, header.path, sending),
          throwsA(StatusFailure.messageNotSent),
        );
        expect(created, 1);
      },
    );

    test(
      '$action default transport uses DIRECT and closes on failure',
      () async {
        final transport = _DirectTransport(sending);
        await HttpOverrides.runZoned(
          () => expectLater(
            _invoke(StatusClient(), header.path, sending),
            throwsA(
              sending
                  ? StatusFailure.messageUnknown
                  : StatusFailure.inboxFailed,
            ),
          ),
          createHttpClient: (_) => transport,
        );
        expect(transport.calls, 1);
        expect(transport.closed, isTrue);
        expect(transport.connectionTimeout, Duration(seconds: sending ? 8 : 5));
      },
    );

    for (final code in [
      401,
      404,
      400,
      409,
      413,
      415,
      502,
      500,
      504,
      204,
      201,
      302,
      307,
    ]) {
      test(
        '$action HTTP $code: fixed failure, no retry, cancelled body',
        () async {
          final expected = sending
              ? switch (code) {
                  401 || 404 => StatusFailure.messageUnavailable,
                  400 || 409 || 413 || 415 => StatusFailure.messageRefused,
                  _ => StatusFailure.messageUnknown,
                }
              : switch (code) {
                  401 || 404 => StatusFailure.inboxUnavailable,
                  409 => StatusFailure.inboxConflict,
                  _ => StatusFailure.inboxFailed,
                };
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
              headers: {..._media, 'location': _peer},
            );
          });
          await expectLater(
            _invoke(
              StatusClient(createClient: () => transport),
              header.path,
              sending,
            ),
            throwsA(expected),
          );
          expect(calls, 1);
          expect(cancelled, isTrue);
          expect(transport.closed, isTrue);
          await body.close();
        },
      );
    }

    test(
      '$action bad headers, UTF-8 and over-2-KiB response fail closed',
      () async {
        final valid = sending ? _ack : _empty;
        for (final response in [
          http.Response(valid, 200),
          http.Response(
            valid,
            200,
            headers: {..._media, 'content-type': 'text/plain'},
          ),
          http.Response(
            valid,
            200,
            headers: {'content-type': 'application/json'},
          ),
          http.Response(
            valid,
            200,
            headers: {..._media, 'cache-control': 'public'},
          ),
          http.Response(
            valid,
            200,
            headers: {..._media, 'content-encoding': 'gzip'},
          ),
          http.Response.bytes([0xff], 200, headers: _media),
          http.Response.bytes([0xc0, 0x80], 200, headers: _media),
          http.Response(valid.padRight(2049), 200, headers: _media),
        ]) {
          final transport = ObservedClient((_) async => response);
          await expectLater(
            _invoke(
              StatusClient(createClient: () => transport),
              header.path,
              sending,
            ),
            throwsA(
              sending
                  ? StatusFailure.messageUnknown
                  : StatusFailure.inboxInvalidResponse,
            ),
          );
          expect(transport.closed, isTrue);
        }
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async =>
                http.Response(valid.padRight(2048), 200, headers: _media),
          ),
        );
        await _invoke(client, header.path, sending);
      },
    );

    for (final failure in [
      'timeout',
      'close',
      'disconnect',
      'body loss',
      'body timeout',
    ]) {
      test(
        '$action $failure cancels without retry or raw error leaks',
        () async {
          var calls = 0;
          var cancelled = false;
          final started = Completer<void>();
          final response = Completer<http.StreamedResponse>();
          final body = StreamController<List<int>>(
            onCancel: () => cancelled = true,
          );
          final transport = ObservedClient.streaming((_, _) {
            calls++;
            started.complete();
            return response.future;
          });
          final client = StatusClient(
            createClient: () => transport,
            timeout: const Duration(milliseconds: 80),
          );
          final result = expectLater(
            _invoke(client, header.path, sending),
            throwsA(
              sending
                  ? StatusFailure.messageUnknown
                  : StatusFailure.inboxFailed,
            ),
          );
          await started.future;
          await expectLater(
            _invoke(client, header.path, !sending),
            throwsA(StatusFailure.messageNotSent),
          );
          switch (failure) {
            case 'close':
              client.close();
            case 'disconnect':
              response.completeError(
                const SocketException('private token and text'),
              );
            case 'body loss':
            case 'body timeout':
              response.complete(
                http.StreamedResponse(body.stream, 200, headers: _media),
              );
              body.add(utf8.encode('{"'));
              if (failure == 'body loss') {
                body.addError(http.ClientException('private URL and message'));
              }
          }
          await result;
          if (!response.isCompleted) {
            response.complete(
              http.StreamedResponse(body.stream, 200, headers: _media),
            );
            body.add(utf8.encode(sending ? _ack : _empty));
          }
          await Future<void>.delayed(Duration.zero);
          if (failure == 'disconnect') await body.stream.listen(null).cancel();
          await body.close();
          expect(cancelled, isTrue);
          expect(calls, 1);
          expect(transport.closed, isTrue);
        },
      );
    }
  }

  test('ACK requires the single literal true field before decoding', () async {
    for (final body in [
      '',
      '{}',
      '[]',
      'null',
      '$_ack{}',
      '$_ack trailing',
      '{"local_acknowledgement_saved":false}',
      '{"local_acknowledgement_saved":"true"}',
      '{"local_acknowledgement_saved":1}',
      '{"local_acknowledgement_saved":null}',
      '{"local_acknowledgement_saved":true,"extra":true}',
      '{"local_acknowledgement_saved":true,"local_acknowledgement_saved":true}',
      '{"local_acknowledgement_saved":false,"local_acknowledgement_saved":true}',
      r'{"local_acknowledgement_save\u0064":true}',
      r'{"local_acknowledgement_saved":false,"local_acknowledgement_save\u0064":true}',
      '{"local_acknowledgement_saved":{"local_acknowledgement_saved":true}}',
      '\u00a0$_ack',
      '$_ack\u000b',
    ]) {
      final client = StatusClient(
        createClient: () => ObservedClient(
          (_) async => http.Response(body, 200, headers: _media),
        ),
      );
      await expectLater(
        _invoke(client, header.path, true),
        throwsA(StatusFailure.messageUnknown),
        reason: body,
      );
    }
    final client = StatusClient(
      createClient: () => ObservedClient(
        (_) async => http.Response(
          ' \n{ "local_acknowledgement_saved" : true }\r\n',
          200,
          headers: _media,
        ),
      ),
    );
    expect(await _invoke(client, header.path, true), isA<MessageSendReceipt>());
  });

  test(
    'inbox accepts exactly empty or saved text in any field order',
    () async {
      const text = 'Real café 🌍\n"present":false, "text":"quoted" \\ \u0000';
      for (final body in [
        _inbox(text),
        '{"text":${jsonEncode(text)},"message_id_hex":"$_id","present":true}',
        '{"message_id_hex":"$_id","present":true,"text":${jsonEncode(text)}}',
        _inbox('é' * 512),
      ]) {
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async => http.Response(body, 200, headers: _media),
          ),
        );
        final result = await client.readMessageInbox(_owner, header.path);
        expect(result.present, isTrue);
        expect(result.messageIdHex, _id);
        expect(result.text, (jsonDecode(body) as Map)['text']);
      }
      final client = StatusClient(
        createClient: () => ObservedClient(
          (_) async =>
              http.Response(' \n{ "present" : false }\t', 200, headers: _media),
        ),
      );
      final result = await client.readMessageInbox(_owner, header.path);
      expect(result.present, isFalse);
      expect(result.text, isNull);
      expect(result.messageIdHex, isNull);
    },
  );

  test(
    'inbox rejects duplicate/escaped names, IDs, types and extra data',
    () async {
      for (final body in [
        '',
        '{}',
        '[]',
        'null',
        '$_empty{}',
        '$_empty trailing',
        '{"present":true}',
        '{"present":"false"}',
        '{"present":0}',
        '{"present":false,"text":"invented"}',
        '{"present":false,"message_id_hex":"$_id","text":"invented"}',
        '{"present":false,"present":false}',
        '{"present":true,"present":false}',
        r'{"pres\u0065nt":false}',
        r'{"present":true,"pres\u0065nt":false}',
        '{"present":true,"message_id_hex":"$_id","text":"a","text":"b"}',
        '{"present":true,"message_id_hex":"$_id","text":"a","extra":false}',
        '{"present":true,"message_id_hex":"$_id","message_id_hex":"$_id"}',
        '{"present":true,"message_id_hex":null,"text":"a"}',
        '{"present":true,"message_id_hex":32,"text":"a"}',
        for (final id in [
          '',
          'a' * 31,
          'a' * 33,
          'A' * 32,
          'g' * 32,
          '${'a' * 31}\n',
        ])
          '{"present":true,"message_id_hex":${jsonEncode(id)},"text":"a"}',
        for (final value in [
          'false',
          'null',
          '12',
          '{}',
          '[]',
          '""',
          r'"\ud800"',
        ])
          '{"present":true,"message_id_hex":"$_id","text":$value}',
        '{"present":true,"message_id_hex":"$_id","te\\u0078t":"a"}',
        _inbox('é' * 513),
        _inbox('x' * 1025),
        '\u00a0$_empty',
        '$_empty\u000b',
      ]) {
        final client = StatusClient(
          createClient: () => ObservedClient(
            (_) async => http.Response(body, 200, headers: _media),
          ),
        );
        await expectLater(
          client.readMessageInbox(_owner, header.path),
          throwsA(StatusFailure.inboxInvalidResponse),
          reason: body,
        );
      }
    },
  );
}

class _DirectTransport implements HttpClient {
  _DirectTransport(this.sending);
  final bool sending;
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
    expect(method, sending ? 'POST' : 'GET');
    expect(
      url.toString(),
      'http://127.0.0.1:12345/owner/pw/message/${sending ? 'send' : 'inbox'}',
    );
    expect(proxy?.call(url), 'DIRECT');
    throw const SocketException('private diagnostic');
  }

  @override
  void close({bool force = false}) => closed = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

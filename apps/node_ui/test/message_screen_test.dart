import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/live_pairing.dart';
import 'package:ic_node_ui/pairing_types.dart';
import 'package:ic_node_ui/status_client.dart';
import 'package:ic_node_ui/wallet_demo.dart';
import 'package:ic_node_ui/wallet_demo_fixtures.dart';
import 'package:ic_node_ui/wallet_demo_graph.dart';

import 'live_pairing_test.dart' show click, enter, keyed, panel;
import 'status_client_test.dart' show ObservedClient;
import 'wallet_demo_test.dart' show viewport, selectPeer;

const _owner = 'http://127.0.0.1:12345/owner/status';
const _header = '/bob/owner.header';
const _peer = 'http://127.0.0.1:23456/peer/pw/message';
const _text = 'Actual saved message: Hei Bob 🌍\nNo fixture text.';
const _saved = MessageInbox.saved(
  messageIdHex: '0123456789abcdef0123456789abcdef',
  text: _text,
);

class _Client extends StatusClient {
  _Client({this.send, this.readInbox});
  final Future<MessageSendReceipt> Function(String, String, String, String)?
  send;
  final Future<MessageInbox> Function(String, String)? readInbox;
  bool closed = false;
  int firstUses = 0;
  @override
  Future<MessageSendReceipt> sendMessage(
    String url,
    String path,
    String text,
    String peer,
  ) => send!(url, path, text, peer);
  @override
  Future<MessageInbox> readMessageInbox(String url, String path) =>
      readInbox!(url, path);
  @override
  Future<FirstUseReceipt> firstUse(String url, String path) async {
    firstUses++;
    return const FirstUseReceipt();
  }

  // Deliberately allow late completions to test the widget's own guards.
  @override
  void close() => closed = true;
}

Future<void> _compose(WidgetTester tester) async {
  await enter(tester, 'message-text', _text);
  await enter(tester, 'message-peer-url', _peer);
}

void _disabled(WidgetTester tester) {
  for (final key in [
    'issue-invitation',
    'redeem-invitation',
    'run-first-use',
    'send-message',
  ]) {
    expect(tester.widget<FilledButton>(keyed(key)).onPressed, isNull);
  }
  expect(
    tester.widget<OutlinedButton>(keyed('refresh-message-inbox')).onPressed,
    isNull,
  );
  expect(tester.widget<TextField>(keyed('message-text')).enabled, isFalse);
  expect(tester.widget<TextField>(keyed('message-peer-url')).enabled, isFalse);
}

void main() {
  for (final sender in ['alice', 'bob']) {
    testWidgets('two windows: $sender sends first via real StatusClient', (
      tester,
    ) async {
      viewport(tester, const Size(1600, 1000));
      final directory = Directory.systemTemp.createTempSync('message-screen-');
      addTearDown(() => directory.delete(recursive: true));
      final headers = <String, File>{};
      await tester.runAsync(() async {
        for (final name in ['alice', 'bob']) {
          await Directory('${directory.path}/$name').create();
          headers[name] = await File('${directory.path}/$name/owner.header')
              .writeAsString('Authorization: Bearer ${'ab' * 32}\n');
        }
      });
      const owners = {
        'alice': 'http://127.0.0.1:11111/owner/status',
        'bob': 'http://127.0.0.1:22222/owner/status',
      };
      final receiver = sender == 'alice' ? 'bob' : 'alice';
      final peer = sender == 'alice'
          ? 'http://127.0.0.1:22223/peer/pw/message'
          : 'http://127.0.0.1:11112/peer/pw/message';
      final requests = <http.Request>[];
      final clients = <_TrackedClient>[];
      final transports = <ObservedClient>[];
      StatusClient create() {
        final transport = ObservedClient((request) async {
          requests.add(request);
          return http.Response(
            request.method == 'POST'
                ? '{"local_acknowledgement_saved":true}'
                : jsonEncode({
                    'present': true,
                    'message_id_hex': _saved.messageIdHex,
                    'text': _text,
                  }),
            200,
            headers: {
              'content-type': 'application/json; charset=utf-8',
              'cache-control': 'no-store',
            },
          );
        });
        transports.add(transport);
        final client = _TrackedClient(transport);
        clients.add(client);
        return client;
      }

      await tester.pumpWidget(
        Directionality(
          textDirection: TextDirection.ltr,
          child: Row(
            children: [
              for (final name in ['alice', 'bob'])
                Expanded(
                  child: MaterialApp(
                    key: ValueKey(name),
                    home: LivePairingScreen(
                      ownerStatusUrl: owners[name]!,
                      headerPath: headers[name]!.path,
                      createClient: create,
                    ),
                  ),
                ),
            ],
          ),
        ),
      );
      Finder inside(String window, String key) =>
          find.descendant(of: keyed(window), matching: keyed(key));
      expect(clients, isEmpty);
      expect(requests, isEmpty);
      for (final (key, text) in [
        ('message-text', _text),
        ('message-peer-url', peer),
      ]) {
        final field = inside(sender, key);
        await tester.ensureVisible(field);
        await tester.enterText(field, text);
      }
      await tester.runAsync(() async {
        await headers[sender]!.writeAsString(
          'Authorization: Bearer ${'cd' * 32}\n',
        );
        await tester.ensureVisible(inside(sender, 'send-message'));
        await tester.tap(inside(sender, 'send-message'));
        await clients.last.result!.timeout(const Duration(seconds: 2));
      });
      await tester.pumpAndSettle();
      expect(requests, hasLength(1));
      expect(
        requests.single.url.toString(),
        owners[sender]!.replaceFirst('/status', '/pw/message/send'),
      );
      expect(requests.single.headers['Authorization'], 'Bearer ${'cd' * 32}');
      expect(jsonDecode(requests.single.body), {
        'text': _text,
        'peer_message_url': peer,
      });
      expect(find.text('Local acknowledgement saved'), findsOneWidget);
      expect(keyed('received-message-text'), findsNothing);
      await tester.pump(const Duration(seconds: 30));
      expect(requests, hasLength(1));
      await tester.runAsync(() async {
        await tester.ensureVisible(inside(receiver, 'refresh-message-inbox'));
        await tester.tap(inside(receiver, 'refresh-message-inbox'));
        await clients.last.result!.timeout(const Duration(seconds: 2));
      });
      await tester.pumpAndSettle();
      expect(requests, hasLength(2));
      expect(
        requests.last.url.toString(),
        owners[receiver]!.replaceFirst('/status', '/pw/message/inbox'),
      );
      expect(requests.last.method, 'GET');
      expect(requests.last.body, isEmpty);
      expect(requests.last.headers['Authorization'], 'Bearer ${'ab' * 32}');
      expect(
        tester
            .widget<SelectableText>(inside(receiver, 'received-message-text'))
            .data,
        _text,
      );
      expect(inside(sender, 'received-message-text'), findsNothing);
      expect(find.text('Saved in this node’s Vault'), findsOneWidget);
      expect(transports.every((transport) => transport.closed), isTrue);
      expect(tester.takeException(), isNull);
    });
  }

  for (final failure in [
    StatusFailure.messageUnknown,
    StatusFailure.messageRefused,
    StatusFailure.messageUnavailable,
    StatusFailure.messageInput,
    StateError('secret bearer URL and diagnostic text'),
  ]) {
    testWidgets('$failure preserves text; only explicit exact retry can ACK', (
      tester,
    ) async {
      var calls = 0;
      final client = _Client(
        send: (url, path, text, peer) async {
          calls++;
          expect((url, path, text, peer), (_owner, _header, _text, _peer));
          if (calls == 1) throw failure;
          return const MessageSendReceipt();
        },
      );
      await panel(tester, () => client);
      await _compose(tester);
      await click(tester, 'send-message');
      await tester.pumpAndSettle();
      final expected = failure is StatusFailure
          ? failure
          : StatusFailure.messageUnknown;
      expect(find.text(expected.message), findsOneWidget);
      expect(find.text('Local acknowledgement saved'), findsNothing);
      expect(find.textContaining('secret bearer'), findsNothing);
      final field = tester.widget<TextField>(keyed('message-text'));
      expect(field.controller!.text, _text);
      expect(
        field.readOnly,
        expected == StatusFailure.messageUnknown ||
            expected == StatusFailure.messageRefused,
      );
      await tester.pump(const Duration(seconds: 30));
      expect(calls, 1);
      await click(tester, 'send-message');
      await tester.pumpAndSettle();
      expect(calls, 2);
      expect(find.text('Local acknowledgement saved'), findsOneWidget);
      expect(find.text(expected.message), findsNothing);
      expect(
        tester.widget<FilledButton>(keyed('send-message')).onPressed,
        isNull,
      );
      expect(
        tester.widget<TextField>(keyed('message-text')).controller!.text,
        _text,
      );
      expect(client.closed, isTrue);
    });
  }

  testWidgets('empty inbox, saved text and failed refresh stay distinct', (
    tester,
  ) async {
    var calls = 0;
    final pending = Completer<MessageInbox>();
    final client = _Client(
      readInbox: (url, path) {
        expect((url, path), (_owner, _header));
        calls++;
        return switch (calls) {
          1 => Future.value(const MessageInbox.empty()),
          2 => Future.value(_saved),
          _ => pending.future,
        };
      },
    );
    await panel(tester, () => client);
    expect(find.text('No message received locally'), findsNothing);
    await click(tester, 'refresh-message-inbox');
    await tester.pumpAndSettle();
    expect(find.text('No message received locally'), findsOneWidget);
    expect(keyed('received-message-text'), findsNothing);
    await click(tester, 'refresh-message-inbox');
    await tester.pumpAndSettle();
    expect(find.text('No message received locally'), findsNothing);
    expect(
      tester.widget<SelectableText>(keyed('received-message-text')).data,
      _text,
    );
    expect(find.text('Local acknowledgement saved'), findsNothing);
    await click(tester, 'refresh-message-inbox');
    _disabled(tester);
    expect(keyed('received-message-text'), findsNothing);
    pending.completeError(StatusFailure.inboxConflict);
    await tester.pumpAndSettle();
    expect(find.text(StatusFailure.inboxConflict.message), findsOneWidget);
    expect(find.text('No message received locally'), findsNothing);
    expect(find.text('Saved in this node’s Vault'), findsNothing);
    await tester.pump(const Duration(seconds: 30));
    expect(calls, 3);
  });

  testWidgets('pending send blocks every local owner action', (tester) async {
    final pending = Completer<MessageSendReceipt>();
    var sends = 0;
    var reads = 0;
    final client = _Client(
      send: (_, _, _, _) {
        sends++;
        return pending.future;
      },
      readInbox: (_, _) async {
        reads++;
        return const MessageInbox.empty();
      },
    );
    await panel(tester, () => client);
    await _compose(tester);
    await click(tester, 'send-message');
    _disabled(tester);
    await click(tester, 'send-message');
    await click(tester, 'refresh-message-inbox');
    expect((sends, reads), (1, 0));
    pending.complete(const MessageSendReceipt());
    await tester.pumpAndSettle();
    expect(find.text('Local acknowledgement saved'), findsOneWidget);
  });

  testWidgets('missing owner config never constructs a message client', (
    tester,
  ) async {
    var clients = 0;
    for (final (url, path) in [('', ''), (_owner, ''), ('', _header)]) {
      await panel(
        tester,
        () {
          clients++;
          return _Client();
        },
        url: url,
        path: path,
      );
      expect(
        tester.widget<FilledButton>(keyed('send-message')).onPressed,
        isNull,
      );
      expect(
        tester.widget<OutlinedButton>(keyed('refresh-message-inbox')).onPressed,
        isNull,
      );
      await click(tester, 'send-message');
      await click(tester, 'refresh-message-inbox');
    }
    expect(clients, 0);
  });

  for (final sending in [true, false]) {
    for (final change in ['url', 'header', 'factory', 'identity', 'dispose']) {
      testWidgets(
        'late ${sending ? 'send' : 'inbox'} discarded after $change',
        (tester) async {
          final send = Completer<MessageSendReceipt>();
          final inbox = Completer<MessageInbox>();
          final client = _Client(
            send: (_, _, _, _) => send.future,
            readInbox: (_, _) => inbox.future,
          );
          StatusClient create() => client;
          await panel(tester, create);
          await _compose(tester);
          await click(
            tester,
            sending ? 'send-message' : 'refresh-message-inbox',
          );
          switch (change) {
            case 'url':
              await panel(
                tester,
                create,
                url: 'http://127.0.0.1:34567/owner/status',
              );
              await panel(tester, create);
            case 'header':
              await panel(tester, create, path: '/alice/owner.header');
              await panel(tester, create);
            case 'factory':
              await panel(tester, () => client);
            case 'identity':
              await panel(tester, create, identity: 'new-panel');
            case 'dispose':
              await tester.pumpWidget(const MaterialApp(home: SizedBox()));
          }
          expect(client.closed, isTrue);
          if (sending) {
            send.complete(const MessageSendReceipt());
          } else {
            inbox.complete(_saved);
          }
          await tester.pumpAndSettle();
          expect(find.text('Local acknowledgement saved'), findsNothing);
          expect(keyed('received-message-text'), findsNothing);
          expect(tester.takeException(), isNull);
        },
      );
    }
  }

  testWidgets('stale failure cannot clear a newer pending action', (
    tester,
  ) async {
    final oldSend = Completer<MessageSendReceipt>();
    final newRead = Completer<MessageInbox>();
    final oldClient = _Client(send: (_, _, _, _) => oldSend.future);
    final newClient = _Client(readInbox: (_, _) => newRead.future);
    await panel(tester, () => oldClient);
    await _compose(tester);
    await click(tester, 'send-message');
    await panel(tester, () => newClient, path: '/new/owner.header');
    await click(tester, 'refresh-message-inbox');
    oldSend.completeError(StatusFailure.messageUnknown);
    await tester.pumpAndSettle();
    _disabled(tester);
    expect(find.text(StatusFailure.messageUnknown.message), findsNothing);
    expect(newClient.closed, isFalse);
    newRead.complete(_saved);
    await tester.pumpAndSettle();
    expect(keyed('received-message-text'), findsOneWidget);
    expect(newClient.closed, isTrue);
  });

  for (final fixture in [aliceDemoWallet, bobDemoWallet]) {
    testWidgets(
      'reopened panel messages ignore first-use flag and ${fixture.owner} fixture',
      (tester) async {
        viewport(tester, const Size(1440, 1000));
        final original = (
          List.of(fixture.links),
          List.of(fixture.trust),
          List.of(fixture.readiness),
          List.of(fixture.messages),
        );
        var sends = 0;
        var reads = 0;
        final client = _Client(
          send: (url, path, text, peer) async {
            sends++;
            expect((url, path, text, peer), (_owner, _header, _text, _peer));
            return const MessageSendReceipt();
          },
          readInbox: (url, path) async {
            reads++;
            expect((url, path), (_owner, _header));
            return _saved;
          },
        );
        await tester.pumpWidget(
          MaterialApp(
            home: WalletDemoScreen(
              fixtures: [fixture],
              ownerStatusUrl: _owner,
              headerPath: _header,
              createPairingClient: () => client,
            ),
          ),
        );
        await selectPeer(tester, fixture.owner == 'alice' ? 'bob' : 'alice');
        await click(tester, 'open-live-pairing');
        await tester.pumpAndSettle();
        await click(tester, 'run-first-use');
        await tester.pumpAndSettle();
        await click(tester, 'confirm-first-use');
        await tester.pumpAndSettle();
        expect(client.firstUses, 1);
        await tester.pageBack();
        await tester.pumpAndSettle();
        await click(tester, 'open-live-pairing');
        await tester.pumpAndSettle();
        expect(find.text('Authenticated first use completed'), findsNothing);
        expect((sends, reads), (0, 0));
        expect(find.text('LIVE OWNER MESSAGE'), findsOneWidget);
        expect(find.textContaining('SCRIPTED GRAPH AND CHAT'), findsOneWidget);
        await _compose(tester);
        await click(tester, 'send-message');
        await tester.pumpAndSettle();
        await click(tester, 'refresh-message-inbox');
        await tester.pumpAndSettle();
        expect((sends, reads), (1, 1));
        expect(client.firstUses, 1);
        await tester.pageBack();
        await tester.pumpAndSettle();
        expect(
          tester.widget<WalletDemoGraph>(find.byType(WalletDemoGraph)).fixture,
          same(fixture),
        );
        expect(fixture.links, original.$1);
        expect(fixture.trust, original.$2);
        expect(fixture.readiness, original.$3);
        expect(fixture.messages, original.$4);
        expect(
          tester.widget<TextField>(keyed('sample-composer')).enabled,
          isFalse,
        );
        expect(
          tester.widget<IconButton>(keyed('sample-send')).onPressed,
          isNull,
        );
        expect(find.text(_text), findsNothing);
      },
    );
  }

  for (final size in [const Size(390, 700), const Size(320, 640)]) {
    testWidgets('message controls fit $size without startup requests', (
      tester,
    ) async {
      viewport(tester, size);
      var clients = 0;
      await panel(tester, () {
        clients++;
        return _Client();
      });
      await _compose(tester);
      await tester.ensureVisible(keyed('send-message'));
      await tester.ensureVisible(keyed('refresh-message-inbox'));
      expect(clients, 0);
      expect(tester.takeException(), isNull);
    });
  }
}

class _TrackedClient extends StatusClient {
  _TrackedClient(http.Client transport) : super(createClient: () => transport);
  Future<Object>? result;
  @override
  Future<MessageSendReceipt> sendMessage(
    String url,
    String path,
    String text,
    String peer,
  ) {
    final pending = super.sendMessage(url, path, text, peer);
    result = pending;
    return pending;
  }

  @override
  Future<MessageInbox> readMessageInbox(String url, String path) {
    final pending = super.readMessageInbox(url, path);
    result = pending;
    return pending;
  }
}

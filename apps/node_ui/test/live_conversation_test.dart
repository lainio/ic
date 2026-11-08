import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/demo_config.dart';
import 'package:ic_node_ui/live_conversation.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/status_client.dart';
import 'package:ic_node_ui/wallet_demo.dart';
import 'package:ic_node_ui/wallet_demo_fixtures.dart';
import 'package:ic_node_ui/wallet_demo_graph.dart';

import 'demo_config_test.dart' show configJson;
import 'wallet_demo_test.dart' show keyed, viewport, selectPeer, switchWallet;

const _text = ' Exact user text 🌍\nwith whitespace. ';
const _id = '0123456789abcdef0123456789abcdef';
const _incoming = MessageInbox.saved(messageIdHex: _id, text: 'Real reply 🌍');

class _Client extends StatusClient {
  _Client(this.harness);
  final _Harness harness;
  bool closed = false;

  @override
  Future<MessageSendReceipt> sendMessageV2(
    String url,
    String header,
    String text,
  ) {
    expect(
      (url, header),
      (harness.config.ownerStatusUrl, harness.config.ownerHeaderFile),
    );
    harness.sent.add(text);
    return harness.send();
  }

  @override
  Future<MessageInbox> readMessageInboxV2(String url, String header) {
    expect(
      (url, header),
      (harness.config.ownerStatusUrl, harness.config.ownerHeaderFile),
    );
    harness.reads++;
    return harness.read();
  }

  // Allow late completion so the UI's own cancellation guards are exercised.
  @override
  void close() => closed = true;
}

class _Harness {
  _Harness([String role = 'alice'])
    : config = DemoConfig.parse(jsonEncode(configJson(role)));
  final DemoConfig config;
  final sent = <String>[];
  final clients = <_Client>[];
  int reads = 0;
  Future<MessageSendReceipt> Function() send = () async =>
      const MessageSendReceipt();
  Future<MessageInbox> Function() read = () async => const MessageInbox.empty();
  StatusClient create() {
    final client = _Client(this);
    clients.add(client);
    return client;
  }

  LiveConversation session() =>
      LiveConversation(config: config, createClient: create);
}

Future<void> _click(WidgetTester tester, String key) async {
  await tester.ensureVisible(keyed(key));
  await tester.tap(keyed(key));
  await tester.pumpAndSettle();
}

Future<void> _open(WidgetTester tester, _Harness harness) async {
  await tester.pumpWidget(
    IntroTreeApp(config: harness.config, createPairingClient: harness.create),
  );
  await _click(tester, 'open-wallet-demo');
  final name = harness.config.role == 'alice' ? 'Alice' : 'Bob';
  expect(find.text("$name's wallet / local perspective"), findsOneWidget);
  await selectPeer(tester, harness.config.role == 'alice' ? 'bob' : 'alice');
  expect(harness.clients, isEmpty);
  await _click(tester, 'open-live-conversation');
}

Future<void> _compose(WidgetTester tester, [String text = _text]) async {
  await tester.ensureVisible(keyed('live-composer'));
  await tester.enterText(keyed('live-composer'), text);
  await _click(tester, 'live-send');
}

void main() {
  testWidgets('two windows send and reply through their own polled inboxes', (
    tester,
  ) async {
    viewport(tester, const Size(2400, 1100));
    final alice = _Harness('alice');
    final bob = _Harness('bob');
    final received = <String, MessageInbox>{};
    final sessions = [alice.session(), bob.session()];
    for (final harness in [alice, bob]) {
      final role = harness.config.role;
      final peer = role == 'alice' ? 'bob' : 'alice';
      harness.read = () async => received[role] ?? const MessageInbox.empty();
      harness.send = () async {
        received[peer] = MessageInbox.saved(
          messageIdHex: role == 'alice' ? _id : 'f' * 32,
          text: harness.sent.single,
        );
        return const MessageSendReceipt();
      };
    }
    await tester.pumpWidget(
      Directionality(
        textDirection: TextDirection.ltr,
        child: Row(
          children: [
            for (final session in sessions)
              Expanded(
                child: MaterialApp(
                  key: ValueKey(session.config.role),
                  home: WalletDemoScreen(
                    ownerStatusUrl: session.config.ownerStatusUrl,
                    headerPath: session.config.ownerHeaderFile,
                    liveConversation: session,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
    Finder inside(String role, String key) =>
        find.descendant(of: keyed(role), matching: keyed(key));
    Future<void> click(String role, String key) async {
      await tester.ensureVisible(inside(role, key));
      await tester.tap(inside(role, key));
      await tester.pumpAndSettle();
    }

    expect(alice.clients, isEmpty);
    expect(bob.clients, isEmpty);
    await click('alice', 'node-bob');
    await click('bob', 'node-alice');
    expect(alice.clients, isEmpty);
    expect(bob.clients, isEmpty);
    await click('alice', 'open-live-conversation');
    await click('bob', 'open-live-conversation');
    for (final (role, peer, text, id) in [
      ('alice', 'bob', 'Hello Bob 🌍', _id),
      ('bob', 'alice', 'Hello Alice 🌍', 'f' * 32),
    ]) {
      await tester.ensureVisible(inside(role, 'live-composer'));
      await tester.enterText(inside(role, 'live-composer'), text);
      await click(role, 'live-send');
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(
        find.descendant(
          of: inside(peer, 'live-incoming-$id'),
          matching: find.text(text),
        ),
        findsOneWidget,
      );
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(inside(peer, 'live-incoming-$id'), findsOneWidget);
    }
    expect(alice.sent, ['Hello Bob 🌍']);
    expect(bob.sent, ['Hello Alice 🌍']);
    expect(find.text('Local acknowledgement saved'), findsNWidgets(2));
    expect(find.text('Coffee on Friday?'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    for (final session in sessions) {
      session.dispose();
    }
  });

  testWidgets('fixture mode and other graph peers make no message requests', (
    tester,
  ) async {
    viewport(tester, const Size(1440, 1000));
    final harness = _Harness();
    await tester.pumpWidget(IntroTreeApp(createPairingClient: harness.create));
    await _click(tester, 'open-wallet-demo');
    await selectPeer(tester, 'bob');
    expect(keyed('open-live-conversation'), findsNothing);
    expect(keyed('sample-composer'), findsOneWidget);
    await tester.pump(const Duration(seconds: 3));
    expect(harness.clients, isEmpty);

    await tester.pumpWidget(const SizedBox());
    await tester.pumpWidget(
      IntroTreeApp(config: harness.config, createPairingClient: harness.create),
    );
    await _click(tester, 'open-wallet-demo');
    await selectPeer(tester, 'carol');
    expect(keyed('open-live-conversation'), findsNothing);
    await switchWallet(tester, 'Bob');
    await selectPeer(tester, 'alice');
    expect(keyed('open-live-conversation'), findsNothing);
    await tester.pump(const Duration(seconds: 3));
    expect(harness.clients, isEmpty);
  });

  for (final (role, size) in [
    ('alice', const Size(1440, 1000)),
    ('bob', const Size(390, 700)),
    ('alice', const Size(320, 640)),
  ]) {
    testWidgets('$role live composer, ACK and fixture boundaries at $size', (
      tester,
    ) async {
      viewport(tester, size);
      final harness = _Harness(role);
      final fixture = role == 'alice' ? aliceDemoWallet : bobDemoWallet;
      final original = (
        List.of(fixture.links),
        List.of(fixture.trust),
        List.of(fixture.readiness),
        List.of(fixture.messages),
      );
      await _open(tester, harness);
      expect(keyed('sample-composer'), findsNothing);
      expect(find.text('Coffee on Friday?'), findsNothing);
      expect(find.text('SCRIPTED CONVERSATION'), findsNothing);
      expect(find.textContaining('ILLUSTRATIVE GRAPH'), findsOneWidget);
      expect(
        find.textContaining('Historical fixture observations'),
        findsOneWidget,
      );
      expect(
        tester.widget<DropdownButton<int>>(keyed('wallet-switcher')).onChanged,
        isNull,
      );
      if (size.width >= 1050) {
        expect(
          tester.widget<WalletDemoGraph>(find.byType(WalletDemoGraph)).fixture,
          same(fixture),
        );
      }
      await _compose(tester);
      expect(harness.sent, [_text]);
      expect(find.text('Local acknowledgement saved'), findsOneWidget);
      expect(
        find.descendant(of: keyed('live-outgoing'), matching: find.text(_text)),
        findsOneWidget,
      );
      expect(tester.widget<TextField>(keyed('live-composer')).readOnly, isTrue);
      expect(tester.widget<FilledButton>(keyed('live-send')).onPressed, isNull);
      for (final claim in [
        'Delivered',
        'Read',
        'Connected',
        'Trusted',
        'PWOpen',
      ]) {
        expect(find.text(claim), findsNothing);
      }
      expect(fixture.links, original.$1);
      expect(fixture.trust, original.$2);
      expect(fixture.readiness, original.$3);
      expect(fixture.messages, original.$4);
      await _click(tester, 'close-peer-details');
      final reads = harness.reads;
      await tester.pump(const Duration(seconds: 3));
      expect(harness.reads, reads);
      expect(keyed('relationship-graph'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
    });
  }

  testWidgets('unknown text stays immutable across retry and route reopening', (
    tester,
  ) async {
    viewport(tester, const Size(1440, 1000));
    final harness = _Harness();
    harness.send = () async {
      if (harness.sent.length == 1) {
        throw StateError('private bearer diagnostics');
      }
      if (harness.sent.length == 2) throw StatusFailure.messageUnavailable;
      return const MessageSendReceipt();
    };
    await _open(tester, harness);
    await _compose(tester);
    expect(find.text(StatusFailure.messageUnknown.message), findsOneWidget);
    expect(find.textContaining('private bearer'), findsNothing);
    expect(tester.widget<TextField>(keyed('live-composer')).readOnly, isTrue);
    await tester.pump(const Duration(seconds: 5));
    expect(harness.sent, [_text]);
    await _click(tester, 'close-wallet-demo');
    await _click(tester, 'open-wallet-demo');
    await selectPeer(tester, 'bob');
    await _click(tester, 'open-live-conversation');
    expect(
      tester.widget<TextField>(keyed('live-composer')).controller!.text,
      _text,
    );
    await _click(tester, 'live-send');
    expect(
      find.text('Previous submission outcome remains unknown.'),
      findsOneWidget,
    );
    await _click(tester, 'live-send');
    expect(harness.sent, [_text, _text, _text]);
    expect(find.text('Local acknowledgement saved'), findsOneWidget);
    await _click(tester, 'close-wallet-demo');
    await _click(tester, 'open-wallet-demo');
    await selectPeer(tester, 'bob');
    await _click(tester, 'open-live-conversation');
    expect(tester.widget<FilledButton>(keyed('live-send')).onPressed, isNull);
    expect(harness.sent, hasLength(3));
    await tester.pumpWidget(const SizedBox());

    // A new window cannot reconstruct outgoing history from the inbox.
    harness.read = () async => _incoming;
    await tester.pumpWidget(
      IntroTreeApp(config: harness.config, createPairingClient: harness.create),
    );
    await _click(tester, 'open-wallet-demo');
    await selectPeer(tester, 'bob');
    await _click(tester, 'open-live-conversation');
    expect(keyed('live-outgoing'), findsNothing);
    expect(keyed('live-incoming-$_id'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    'polling uses one ID and distinguishes unknown, empty and invalid',
    (tester) async {
      viewport(tester, const Size(1440, 1000));
      final harness = _Harness();
      final pending = Completer<MessageInbox>();
      harness.read = () => pending.future;
      await _open(tester, harness);
      expect(find.text('No message received locally'), findsNothing);
      await tester.pump(const Duration(seconds: 5));
      expect(harness.reads, 1); // No overlap while the first read is pending.
      pending.complete(const MessageInbox.empty());
      await tester.pumpAndSettle();
      expect(find.text('No message received locally'), findsOneWidget);
      harness.read = () async => _incoming;
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(keyed('live-incoming-$_id'), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(keyed('live-incoming-$_id'), findsOneWidget);
      expect(find.text(_incoming.text!), findsOneWidget);
      harness.read = () async => throw StatusFailure.inboxConflict;
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(find.text(StatusFailure.inboxConflict.message), findsOneWidget);
      expect(find.text('No message received locally'), findsNothing);
      expect(keyed('live-incoming-$_id'), findsNothing);
      harness.read = () async => const MessageInbox.empty();
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(
        find.text(StatusFailure.inboxInvalidResponse.message),
        findsOneWidget,
      );
      expect(find.text('No message received locally'), findsNothing);
      expect(harness.sent, isEmpty);
      await tester.pumpWidget(const SizedBox());
    },
  );

  for (final exit in [
    'close',
    'peer',
    'navigation',
    'dispose',
    'configuration',
  ]) {
    testWidgets('$exit stops polling and rejects obsolete inbox completion', (
      tester,
    ) async {
      viewport(tester, const Size(1440, 1000));
      final harness = _Harness();
      final pending = Completer<MessageInbox>();
      harness.read = () => pending.future;
      final session = harness.session();
      Widget screen({String? url}) => MaterialApp(
        home: WalletDemoScreen(
          ownerStatusUrl: url ?? harness.config.ownerStatusUrl,
          headerPath: harness.config.ownerHeaderFile,
          liveConversation: session,
        ),
      );
      await tester.pumpWidget(screen());
      await selectPeer(tester, 'bob');
      await _click(tester, 'open-live-conversation');
      final client = harness.clients.single;
      switch (exit) {
        case 'close':
          await _click(tester, 'close-live-conversation');
          await _click(tester, 'open-live-conversation');
        case 'peer':
          await selectPeer(tester, 'carol');
        case 'navigation':
          Navigator.of(tester.element(keyed('wallet-demo'))).push(
            MaterialPageRoute<void>(
              builder: (_) => const Scaffold(body: Text('Away')),
            ),
          );
          await tester.pumpAndSettle();
        case 'dispose':
          await tester.pumpWidget(const SizedBox());
        case 'configuration':
          await tester.pumpWidget(
            screen(url: 'http://127.0.0.1:12399/owner/status'),
          );
          await tester.pumpWidget(screen());
          expect(keyed('open-live-conversation'), findsNothing);
      }
      expect(client.closed, isTrue);
      await tester.pump(const Duration(seconds: 3));
      expect(harness.reads, 1);
      pending.complete(_incoming);
      await tester.pumpAndSettle();
      expect(keyed('live-incoming-$_id'), findsNothing);
      if (exit == 'close') {
        harness.read = () async => const MessageInbox.empty();
        await tester.pump(const Duration(seconds: 1));
        await tester.pump();
        expect(harness.reads, 2);
        expect(find.text('No message received locally'), findsOneWidget);
      } else {
        await tester.pump(const Duration(seconds: 3));
        expect(harness.reads, 1);
      }
      await tester.pumpWidget(const SizedBox());
      session.dispose();
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('inactive app cancels send, ignores late ACK and pauses inbox', (
    tester,
  ) async {
    viewport(tester, const Size(1440, 1000));
    final harness = _Harness();
    final pending = Completer<MessageSendReceipt>();
    harness.send = () => pending.future;
    await _open(tester, harness);
    await _compose(tester);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    final reads = harness.reads;
    expect(harness.clients.every((client) => client.closed), isTrue);
    pending.complete(const MessageSendReceipt());
    await tester.pump(const Duration(seconds: 3));
    expect(harness.reads, reads);
    expect(find.text('Local acknowledgement saved'), findsNothing);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(find.text(StatusFailure.messageUnknown.message), findsOneWidget);
    expect(harness.reads, reads + 1);
    expect(harness.sent, [_text]);
    await tester.pumpWidget(const SizedBox());
  });
}

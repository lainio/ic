import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/live_pairing.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/pairing_types.dart';
import 'package:ic_node_ui/status_client.dart';
import 'package:ic_node_ui/wallet_demo.dart';
import 'package:ic_node_ui/wallet_demo_fixtures.dart';
import 'package:ic_node_ui/wallet_demo_graph.dart';

import 'pairing_client_test.dart'
    show aliceKey, bobKey, invitationId, issueBody, redemption;
import 'wallet_demo_test.dart' show viewport, selectPeer, switchWallet;

const _owner = 'http://127.0.0.1:12345/owner/status';
const _header = '/bob/owner.header';
Finder keyed(String key) => find.byKey(ValueKey(key));
DirectedInvitationReceipt receipt() => DirectedInvitationReceipt.fromJson(
  jsonDecode(issueBody()) as Map<String, dynamic>,
  aliceKey,
);
Future<void> click(WidgetTester tester, String key) async {
  final finder = keyed(key);
  await tester.ensureVisible(finder);
  await tester.tap(finder);
  await tester.pump();
}

Future<void> enter(WidgetTester tester, String key, String text) async {
  await tester.ensureVisible(keyed(key));
  await tester.enterText(keyed(key), text);
  await tester.pump();
}

Future<void> panel(
  WidgetTester tester,
  StatusClient Function() create, {
  String url = _owner,
  String path = _header,
  String identity = 'panel',
}) => tester.pumpWidget(
  MaterialApp(
    home: LivePairingScreen(
      key: ValueKey(identity),
      ownerStatusUrl: url,
      headerPath: path,
      createClient: create,
    ),
  ),
);

class _Client extends StatusClient {
  _Client({this.issue, this.redeem});
  final Future<DirectedInvitationReceipt> Function(String, String, String)?
  issue;
  final Future<RedemptionReceipt> Function(String, String, DirectedRedemption)?
  redeem;
  bool closed = false;
  @override
  Future<DirectedInvitationReceipt> issueDirectedInvitation(
    String url,
    String path,
    String recipient,
  ) => issue!(url, path, recipient);
  @override
  Future<RedemptionReceipt> redeemInvitation(
    String url,
    String path,
    DirectedRedemption input,
  ) => redeem!(url, path, input);
  // Deliberately allow late completion to exercise the view's revision guards.
  @override
  void close() => closed = true;
}

void main() {
  testWidgets('missing owner configuration disables both live submissions', (
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
      expect(find.textContaining('Set the owner status URL'), findsOneWidget);
      for (final key in ['issue-invitation', 'redeem-invitation']) {
        expect(tester.widget<FilledButton>(keyed(key)).onPressed, isNull);
      }
      expect(
        tester.widget<OutlinedButton>(keyed('copy-redeem-json')).onPressed,
        isNull,
      );
    }
    expect(clients, 0);
  });

  testWidgets(
    'issue receipt and explicit operator key produce only manual JSON',
    (tester) async {
      final copies = <String>[];
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (call) async {
          if (call.method == 'Clipboard.setData') {
            copies.add((call.arguments as Map)['text'] as String);
          }
          return null;
        },
      );
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          SystemChannels.platform,
          null,
        ),
      );
      var issues = 0;
      final pending = Completer<DirectedInvitationReceipt>();
      final client = _Client(
        issue: (url, path, recipient) {
          issues++;
          expect((url, path, recipient), (_owner, _header, aliceKey));
          return issues == 1 ? Future.value(receipt()) : pending.future;
        },
      );
      await panel(tester, () => client);
      expect(find.textContaining('Only one invitation row'), findsOneWidget);
      await enter(tester, 'pairing-recipient', aliceKey);
      expect(copies, isEmpty);
      await click(tester, 'issue-invitation');
      await tester.pumpAndSettle();
      expect(
        find.text('Invitation issued · committed receipt'),
        findsOneWidget,
      );
      expect(find.widgetWithText(SelectableText, invitationId), findsOneWidget);
      expect(find.text('Audience: Directed'), findsOneWidget);
      expect(find.widgetWithText(SelectableText, aliceKey), findsOneWidget);
      expect(
        find.textContaining('UTC expiry: 2027-01-15T08:00:00.123456789Z'),
        findsOneWidget,
      );
      expect(
        tester.widget<TextField>(keyed('pairing-bob-key')).controller!.text,
        isEmpty,
      );
      expect(
        tester.widget<OutlinedButton>(keyed('copy-redeem-json')).onPressed,
        isNull,
      );
      expect(copies, isEmpty);
      await enter(tester, 'pairing-bob-key', 'ABCD');
      expect(
        tester.widget<OutlinedButton>(keyed('copy-redeem-json')).onPressed,
        isNull,
      );
      await enter(tester, 'pairing-bob-key', bobKey);
      expect(
        find.textContaining('operator-supplied, not confirmed'),
        findsOneWidget,
      );
      expect(copies, isEmpty);
      await click(tester, 'copy-redeem-json');
      await tester.pumpAndSettle();
      expect(copies, [redemption.toJson()]);
      expect(jsonDecode(copies.single), {
        'target_public_key_hex': bobKey,
        'invitation_id_hex': invitationId,
        'audience': 'Directed',
      });
      expect(copies.single, isNot(contains('owner.header')));
      expect(copies.single, isNot(contains('Bearer')));
      expect(find.text('Manual redeem JSON copied'), findsOneWidget);
      await enter(tester, 'pairing-bob-key', aliceKey);
      expect(find.text('Manual redeem JSON copied'), findsNothing);
      await click(tester, 'issue-invitation');
      expect(keyed('issued-id'), findsNothing);
      expect(
        tester.widget<OutlinedButton>(keyed('copy-redeem-json')).onPressed,
        isNull,
      );
      expect(
        tester.widget<FilledButton>(keyed('issue-invitation')).onPressed,
        isNull,
      );
      expect(
        tester.widget<FilledButton>(keyed('redeem-invitation')).onPressed,
        isNull,
      );
      await click(tester, 'issue-invitation');
      expect(issues, 2);
      pending.completeError(StatusFailure.issueExists);
      await tester.pumpAndSettle();
      expect(find.text(StatusFailure.issueExists.message), findsOneWidget);
      expect(keyed('issued-id'), findsNothing);
      expect(copies, hasLength(1));
    },
  );

  for (final held in [true, false]) {
    testWidgets(
      'redeem renders local held=$held without modifying any fixture',
      (tester) async {
        viewport(tester, const Size(1440, 1000));
        final original = (
          List.of(aliceDemoWallet.links),
          List.of(aliceDemoWallet.trust),
          List.of(aliceDemoWallet.readiness),
          List.of(aliceDemoWallet.messages),
        );
        var calls = 0;
        final client = _Client(
          redeem: (url, path, input) async {
            calls++;
            expect((url, path), (_owner, _header));
            expect(input.toJson(), redemption.toJson());
            return RedemptionReceipt(localHeld: held);
          },
        );
        await tester.pumpWidget(
          MaterialApp(
            home: WalletDemoScreen(
              ownerStatusUrl: _owner,
              headerPath: _header,
              createPairingClient: () => client,
            ),
          ),
        );
        await selectPeer(tester, 'bob');
        await click(tester, 'open-live-pairing');
        await tester.pumpAndSettle();
        expect(calls, 0);
        await enter(tester, 'pairing-redeem-json', redemption.toJson());
        await click(tester, 'redeem-invitation');
        await tester.pumpAndSettle();
        expect(calls, 1);
        expect(find.text('Acceptance saved locally'), findsOneWidget);
        expect(
          find.text('Local PW held: ${held ? 'yes' : 'no'}'),
          findsOneWidget,
        );
        expect(
          find.textContaining('not a usable relationship'),
          held ? findsNothing : findsOneWidget,
        );
        expect(
          find.textContaining('authenticated first use or chat'),
          findsOneWidget,
        );
        await tester.pageBack();
        await tester.pumpAndSettle();
        expect(
          tester.widget<WalletDemoGraph>(find.byType(WalletDemoGraph)).fixture,
          same(aliceDemoWallet),
        );
        expect(aliceDemoWallet.links, original.$1);
        expect(aliceDemoWallet.trust, original.$2);
        expect(aliceDemoWallet.readiness, original.$3);
        expect(aliceDemoWallet.messages, original.$4);
        expect(find.text('Hi Alice! Good to see you here.'), findsOneWidget);
        expect(
          tester.widget<TextField>(keyed('sample-composer')).enabled,
          isFalse,
        );
        expect(find.text('Local trust: not assigned'), findsOneWidget);
        await click(tester, 'open-live-pairing');
        await tester.pumpAndSettle();
        expect(find.text('Acceptance saved locally'), findsNothing);
        expect(calls, 1);
      },
    );
  }

  testWidgets(
    'local malformed JSON sends nothing; failures show no exception data',
    (tester) async {
      var calls = 0;
      var failure = StatusFailure.redeemUnknown;
      final client = _Client(
        redeem: (_, _, _) async {
          calls++;
          throw failure;
        },
      );
      await panel(tester, () => client);
      await enter(tester, 'pairing-redeem-json', '{"audience":"Directed"}');
      await click(tester, 'redeem-invitation');
      expect(calls, 0);
      expect(find.text(StatusFailure.redeemInput.message), findsOneWidget);
      await enter(tester, 'pairing-redeem-json', redemption.toJson());
      for (final error in [
        StatusFailure.redeemUnknown,
        StatusFailure.redeemRemote,
        StatusFailure.redeemInvalidResponse,
      ]) {
        failure = error;
        await click(tester, 'redeem-invitation');
        await tester.pumpAndSettle();
        expect(find.text(error.message), findsOneWidget);
        expect(keyed('local-held'), findsNothing);
        expect(find.text('Acceptance saved locally'), findsNothing);
        final count = calls;
        await tester.pump(const Duration(seconds: 30));
        expect(calls, count);
      }
      await panel(
        tester,
        () => _Client(
          redeem: (_, _, _) async {
            throw StateError('Authorization: Bearer secret $invitationId');
          },
        ),
      );
      await click(tester, 'redeem-invitation');
      await tester.pumpAndSettle();
      expect(find.text(StatusFailure.redeemUnknown.message), findsOneWidget);
      expect(find.textContaining('Bearer'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  for (final issuing in [true, false]) {
    for (final change in ['input', 'url', 'header', 'identity', 'dispose']) {
      testWidgets(
        '${issuing ? 'issue' : 'redeem'} late success discarded after $change',
        (tester) async {
          final issue = Completer<DirectedInvitationReceipt>();
          final redeem = Completer<RedemptionReceipt>();
          var calls = 0;
          final client = _Client(
            issue: (_, _, _) {
              calls++;
              return issue.future;
            },
            redeem: (_, _, _) {
              calls++;
              return redeem.future;
            },
          );
          StatusClient create() => client;
          await panel(tester, create);
          final inputKey = issuing
              ? 'pairing-recipient'
              : 'pairing-redeem-json';
          final text = issuing ? aliceKey : redemption.toJson();
          final button = issuing ? 'issue-invitation' : 'redeem-invitation';
          await enter(tester, inputKey, text);
          await click(tester, button);
          expect(calls, 1);
          expect(tester.widget<FilledButton>(keyed(button)).onPressed, isNull);
          switch (change) {
            case 'input':
              await enter(tester, inputKey, 'changed');
              await enter(tester, inputKey, text);
            case 'url':
              await panel(
                tester,
                create,
                url: 'http://127.0.0.1:23456/owner/status',
              );
              await panel(tester, create);
            case 'header':
              await panel(tester, create, path: '/alice/owner.header');
              await panel(tester, create);
            case 'identity':
              await panel(tester, create, identity: 'replacement-panel');
            case 'dispose':
              await tester.pumpWidget(const MaterialApp(home: SizedBox()));
          }
          expect(client.closed, isTrue);
          if (issuing) {
            issue.complete(receipt());
          } else {
            redeem.complete(const RedemptionReceipt(localHeld: true));
          }
          await tester.pumpAndSettle();
          expect(keyed('issued-id'), findsNothing);
          expect(keyed('local-held'), findsNothing);
          expect(find.text('Acceptance saved locally'), findsNothing);
          expect(calls, 1);
          expect(tester.takeException(), isNull);
        },
      );
    }
  }

  testWidgets(
    'two owner windows retain separate snapshots regardless of fixture',
    (tester) async {
      viewport(tester, const Size(1600, 1000));
      final requests = <(String, String, String)>[];
      StatusClient create() => _Client(
        issue: (url, path, recipient) async {
          requests.add((url, path, recipient));
          return receipt();
        },
        redeem: (url, path, input) async {
          requests.add((url, path, input.toJson()));
          return const RedemptionReceipt(localHeld: false);
        },
      );
      await tester.pumpWidget(
        Directionality(
          textDirection: TextDirection.ltr,
          child: Row(
            children: [
              Expanded(
                child: IntroTreeApp(
                  key: const ValueKey('bob-window'),
                  createPairingClient: create,
                ),
              ),
              Expanded(
                child: IntroTreeApp(
                  key: const ValueKey('alice-window'),
                  createPairingClient: create,
                ),
              ),
            ],
          ),
        ),
      );
      for (final (window, url, path) in [
        ('bob-window', _owner, _header),
        (
          'alice-window',
          'http://127.0.0.1:23456/owner/status',
          '/alice/owner.header',
        ),
      ]) {
        Finder inside(Finder finder) =>
            find.descendant(of: keyed(window), matching: finder);
        await tester.enterText(
          inside(find.widgetWithText(TextField, 'Owner status URL')),
          url,
        );
        await tester.enterText(
          inside(find.widgetWithText(TextField, 'Authorization header file')),
          path,
        );
        await tester.tap(inside(keyed('open-wallet-demo')));
        await tester.pumpAndSettle();
        // Both start as the Alice fixture; this never supplies a real identity.
        expect(
          inside(find.text("Alice's wallet / local perspective")),
          findsOneWidget,
        );
        await tester.tap(inside(keyed('open-live-pairing')));
        await tester.pumpAndSettle();
        expect(requests, hasLength(window == 'bob-window' ? 0 : 1));
        final issuing = window == 'bob-window';
        final input = inside(
          keyed(issuing ? 'pairing-recipient' : 'pairing-redeem-json'),
        );
        final button = inside(
          keyed(issuing ? 'issue-invitation' : 'redeem-invitation'),
        );
        final text = issuing ? aliceKey : redemption.toJson();
        await tester.ensureVisible(input);
        await tester.enterText(input, text);
        await tester.ensureVisible(button);
        await tester.tap(button);
        await tester.pumpAndSettle();
        expect(requests.last, (url, path, text));
        expect(
          inside(keyed(issuing ? 'issued-id' : 'local-held')),
          findsOneWidget,
        );
      }
      expect(requests, hasLength(2));
      expect(tester.takeException(), isNull);
    },
  );

  for (final size in [
    const Size(1440, 900),
    const Size(390, 700),
    const Size(320, 640),
  ]) {
    testWidgets(
      'live panel reachable without overflow or startup work at $size',
      (tester) async {
        viewport(tester, size);
        var clients = 0;
        await tester.pumpWidget(
          IntroTreeApp(
            createPairingClient: () {
              clients++;
              return _Client();
            },
          ),
        );
        expect(find.text('My node'), findsOneWidget);
        await click(tester, 'open-wallet-demo');
        await tester.pumpAndSettle();
        await switchWallet(tester, 'Bob');
        await selectPeer(tester, 'alice');
        await click(tester, 'open-live-pairing');
        await tester.pumpAndSettle();
        expect(find.text('LIVE LOCAL OWNER ACTIONS'), findsOneWidget);
        await tester.ensureVisible(keyed('issue-invitation'));
        await tester.ensureVisible(keyed('redeem-invitation'));
        await tester.pageBack();
        await tester.pumpAndSettle();
        expect(find.textContaining('SCRIPTED GRAPH AND CHAT'), findsOneWidget);
        expect(clients, 0);
        expect(tester.takeException(), isNull);
      },
    );
  }
}

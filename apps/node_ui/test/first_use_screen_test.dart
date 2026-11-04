import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/live_pairing.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/pairing_types.dart';
import 'package:ic_node_ui/status_client.dart';
import 'package:ic_node_ui/wallet_demo.dart';
import 'package:ic_node_ui/wallet_demo_fixtures.dart';
import 'package:ic_node_ui/wallet_demo_graph.dart';

import 'live_pairing_test.dart' show click, enter, keyed, panel, receipt;
import 'pairing_client_test.dart' show aliceKey, redemption;
import 'wallet_demo_test.dart' show viewport, selectPeer, switchWallet;

const _owner = 'http://127.0.0.1:23456/owner/status';
const _header = '/alice/owner.header';
const _completed = 'Authenticated first use completed';
const _historical = 'Local readiness: observed on this exchange (historical)';

class _Client extends StatusClient {
  _Client({this.use});
  final Future<FirstUseReceipt> Function()? use;
  final calls = <String>[];
  final owners = <(String, String)>[];
  bool closed = false;

  @override
  Future<FirstUseReceipt> firstUse(String url, String path) {
    calls.add('first-use');
    owners.add((url, path));
    return use?.call() ?? Future.value(const FirstUseReceipt());
  }

  @override
  Future<DirectedInvitationReceipt> issueDirectedInvitation(
    String url,
    String path,
    String recipient,
  ) async {
    calls.add('issue');
    return receipt();
  }

  @override
  Future<RedemptionReceipt> redeemInvitation(
    String url,
    String path,
    DirectedRedemption input,
  ) async {
    calls.add('redeem');
    return const RedemptionReceipt(localHeld: true);
  }

  // Permit late completion so the widget's own revision guards are exercised.
  @override
  void close() => closed = true;
}

Future<void> _confirm(WidgetTester tester) async {
  await click(tester, 'run-first-use');
  await tester.pumpAndSettle();
  expect(find.byType(AlertDialog), findsOneWidget);
  await click(tester, 'confirm-first-use');
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('startup, selection, open, issue, redeem and Cancel do not use', (
    tester,
  ) async {
    viewport(tester, const Size(1440, 1000));
    final client = _Client();
    await tester.pumpWidget(IntroTreeApp(createPairingClient: () => client));
    expect(client.calls, isEmpty);
    await tester.enterText(
      find.widgetWithText(TextField, 'Owner status URL'),
      _owner,
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Authorization header file'),
      _header,
    );
    await click(tester, 'open-wallet-demo');
    await tester.pumpAndSettle();
    await switchWallet(tester, 'Bob');
    await selectPeer(tester, 'alice');
    expect(client.calls, isEmpty);
    await click(tester, 'open-live-pairing');
    await tester.pumpAndSettle();
    expect(client.calls, isEmpty);
    await enter(tester, 'pairing-recipient', aliceKey);
    await click(tester, 'issue-invitation');
    await tester.pumpAndSettle();
    expect(client.calls, ['issue']);
    await enter(tester, 'pairing-redeem-json', redemption.toJson());
    await click(tester, 'redeem-invitation');
    await tester.pumpAndSettle();
    expect(client.calls, ['issue', 'redeem']);
    await click(tester, 'run-first-use');
    await tester.pumpAndSettle();
    expect(find.textContaining('This is not chat.'), findsOneWidget);
    expect(client.calls, ['issue', 'redeem']);
    await click(tester, 'cancel-first-use');
    await tester.pumpAndSettle();
    expect(client.calls, ['issue', 'redeem']);
    expect(
      tester.widget<FilledButton>(keyed('run-first-use')).onPressed,
      isNotNull,
    );

    await tester.pageBack();
    await tester.pumpAndSettle();
    await click(tester, 'open-live-pairing');
    await tester.pumpAndSettle();
    expect(find.text('Acceptance saved locally'), findsNothing);
    expect(client.calls, ['issue', 'redeem']);
    await _confirm(tester);
    expect(client.calls, ['issue', 'redeem', 'first-use']);
    expect(client.owners, [(_owner, _header)]);
    expect(find.text(_historical), findsOneWidget);
  });

  for (final fixture in [aliceDemoWallet, bobDemoWallet]) {
    testWidgets(
      'success leaves ${fixture.owner} graph, readiness and chat intact',
      (tester) async {
        viewport(tester, const Size(1440, 1000));
        final original = (
          List.of(fixture.links),
          List.of(fixture.trust),
          List.of(fixture.readiness),
          List.of(fixture.messages),
        );
        final client = _Client();
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
        expect(find.text('Acceptance saved locally'), findsNothing);
        expect(
          find.textContaining('Alice’s actual requester node'),
          findsOneWidget,
        );
        await _confirm(tester);
        expect(find.text(_completed), findsOneWidget);
        expect(find.text(_historical), findsOneWidget);
        expect(client.calls, ['first-use']);
        expect(client.owners, [(_owner, _header)]);
        expect(client.closed, isTrue);
        await click(tester, 'run-first-use');
        expect(find.byType(AlertDialog), findsNothing);
        expect(client.calls, ['first-use']);
        expect(find.textContaining('No second submission'), findsOneWidget);
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
          keyed(
            'edge-retainedPW-${fixture.owner}-${fixture.owner == 'alice' ? 'bob' : 'alice'}',
          ),
          findsOneWidget,
        );
        expect(find.text('Local trust: not assigned'), findsOneWidget);
        expect(
          find.text(
            fixture.owner == 'alice'
                ? 'Last readiness: sample authenticated response'
                : 'Last readiness: no observation in fixture',
          ),
          findsOneWidget,
        );
        expect(
          tester.widget<TextField>(keyed('sample-composer')).enabled,
          isFalse,
        );
        expect(
          tester.widget<IconButton>(keyed('sample-send')).onPressed,
          isNull,
        );
        expect(
          find.text('Hi Alice! Good to see you here.'),
          fixture.owner == 'alice' ? findsOneWidget : findsNothing,
        );
      },
    );
  }

  for (final failure in [
    StatusFailure.firstUseRefused,
    StatusFailure.firstUseRemote,
    StatusFailure.firstUseUnknown,
    StatusFailure.firstUseInvalidResponse,
    StatusFailure.firstUseUnavailable,
    StatusFailure.firstUseRejected,
    StatusFailure.firstUseOwnerUrl,
    StatusFailure.firstUseCredentials,
    StatusFailure.firstUseNotSent,
    StateError('Authorization: Bearer secret signature private handle'),
  ]) {
    testWidgets('$failure has no success or second submission', (tester) async {
      final client = _Client(use: () => Future.error(failure));
      await panel(tester, () => client);
      await _confirm(tester);
      final expected = failure is StatusFailure
          ? failure
          : StatusFailure.firstUseUnknown;
      expect(find.text(expected.message), findsOneWidget);
      expect(find.text(_completed), findsNothing);
      expect(find.text(_historical), findsNothing);
      expect(find.textContaining('Bearer'), findsNothing);
      expect(keyed('first-use-warning'), findsOneWidget);
      expect(find.textContaining('No second submission'), findsOneWidget);
      expect(
        tester.widget<FilledButton>(keyed('run-first-use')).onPressed,
        isNull,
      );
      await click(tester, 'run-first-use');
      await tester.pump(const Duration(seconds: 30));
      expect(find.byType(AlertDialog), findsNothing);
      expect(client.calls, ['first-use']);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('pending first use disables all owner submissions', (
    tester,
  ) async {
    final pending = Completer<FirstUseReceipt>();
    final client = _Client(use: () => pending.future);
    await panel(tester, () => client);
    await _confirm(tester);
    expect(find.text('Authenticating…'), findsOneWidget);
    for (final key in [
      'run-first-use',
      'issue-invitation',
      'redeem-invitation',
    ]) {
      expect(tester.widget<FilledButton>(keyed(key)).onPressed, isNull);
      await click(tester, key);
    }
    expect(client.calls, ['first-use']);
    pending.completeError(StatusFailure.firstUseUnknown);
    await tester.pumpAndSettle();
    await click(tester, 'run-first-use');
    expect(client.calls, ['first-use']);
  });

  testWidgets('missing owner configuration disables first use', (tester) async {
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
        tester.widget<FilledButton>(keyed('run-first-use')).onPressed,
        isNull,
      );
      await click(tester, 'run-first-use');
      expect(find.byType(AlertDialog), findsNothing);
    }
    expect(clients, 0);
  });

  for (final late in [true, false]) {
    for (final change in ['url', 'header', 'factory', 'identity', 'dispose']) {
      testWidgets('${late ? 'late' : 'old'} receipt discarded after $change', (
        tester,
      ) async {
        final pending = Completer<FirstUseReceipt>();
        final client = _Client(use: () => pending.future);
        StatusClient create() => client;
        await panel(tester, create);
        await _confirm(tester);
        if (!late) {
          pending.complete(const FirstUseReceipt());
          await tester.pumpAndSettle();
          expect(find.text(_completed), findsOneWidget);
        }
        switch (change) {
          case 'url':
            await panel(tester, create, url: _owner);
            await panel(tester, create);
          case 'header':
            await panel(tester, create, path: _header);
            await panel(tester, create);
          case 'factory':
            await panel(tester, () => client);
          case 'identity':
            await panel(tester, create, identity: 'new-panel');
          case 'dispose':
            await tester.pumpWidget(const MaterialApp(home: SizedBox()));
        }
        expect(client.closed, isTrue);
        if (late) pending.complete(const FirstUseReceipt());
        await tester.pumpAndSettle();
        expect(find.text(_completed), findsNothing);
        expect(find.text(_historical), findsNothing);
        if (change != 'identity' && change != 'dispose') {
          expect(
            tester.widget<FilledButton>(keyed('run-first-use')).onPressed,
            isNull,
          );
          expect(find.textContaining('No second submission'), findsOneWidget);
        }
        expect(client.calls, ['first-use']);
        expect(tester.takeException(), isNull);
      });
    }
  }

  testWidgets(
    'owner change during confirmation cannot authorize either owner',
    (tester) async {
      final client = _Client();
      StatusClient create() => client;
      await panel(tester, create);
      await click(tester, 'run-first-use');
      await tester.pumpAndSettle();
      await panel(tester, create, url: _owner);
      await click(tester, 'confirm-first-use');
      await tester.pumpAndSettle();
      expect(client.calls, isEmpty);
      expect(find.text(_completed), findsNothing);
      expect(
        tester.widget<FilledButton>(keyed('run-first-use')).onPressed,
        isNull,
      );
    },
  );

  for (final size in [const Size(390, 700), const Size(320, 640)]) {
    testWidgets(
      'first-use warning and dialog reachable without overflow $size',
      (tester) async {
        viewport(tester, size);
        final client = _Client();
        await panel(tester, () => client);
        await tester.ensureVisible(keyed('first-use-warning'));
        expect(find.byType(LivePairingScreen), findsOneWidget);
        await _confirm(tester);
        await tester.ensureVisible(keyed('first-use-readiness'));
        expect(find.text(_historical), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );
  }
}

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/wallet_demo.dart';
import 'package:ic_node_ui/wallet_demo_fixtures.dart';
import 'package:ic_node_ui/wallet_demo_graph.dart';

Finder keyed(String key) => find.byKey(ValueKey(key));

void viewport(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

Future<void> showDemo(
  WidgetTester tester, {
  List<WalletDemoFixture>? fixtures,
}) async {
  await tester.pumpWidget(
    MaterialApp(home: WalletDemoScreen(fixtures: fixtures)),
  );
  await tester.pumpAndSettle();
}

Future<void> selectPeer(WidgetTester tester, String id) async {
  await tester.ensureVisible(keyed('node-$id'));
  await tester.tap(keyed('node-$id'));
  await tester.pumpAndSettle();
}

Future<void> switchWallet(WidgetTester tester, String name) async {
  await tester.tap(keyed('wallet-switcher'));
  await tester.pumpAndSettle();
  await tester.tap(find.text("$name's wallet").last);
  await tester.pumpAndSettle();
}

void main() {
  test(
    'Alice fixture records only local evidence and independent holdings',
    () {
      final paths = aliceDemoWallet.links
          .where((link) => link.kind == DemoLinkKind.verifiedIntroduction)
          .map((link) => '${link.from}->${link.to}');
      expect(
        paths,
        unorderedEquals([
          'root->maya',
          'maya->alice',
          'maya->carol',
          'root->noah',
          'noah->bob',
        ]),
      );
      final holdings = aliceDemoWallet.links
          .where((link) => link.kind == DemoLinkKind.retainedPW)
          .map((link) => '${link.from}->${link.to}');
      expect(holdings, unorderedEquals(['alice->bob', 'alice->carol']));
      expect(aliceDemoWallet.trust.map((item) => item.peer), ['carol']);
      expect(aliceDemoWallet.trusts('bob'), isFalse);
      expect(aliceDemoWallet.readiness.map((item) => item.peer), ['bob']);
      expect(
        aliceDemoWallet.links.every(
          (link) => link.provenance.startsWith('Alice fixture'),
        ),
        isTrue,
      );
      expect(() => aliceDemoWallet.links.clear(), throwsUnsupportedError);
      expect(() => aliceDemoWallet.trust.clear(), throwsUnsupportedError);

      expect(
        bobDemoWallet.people.map((p) => p.id),
        unorderedEquals(['root', 'noah', 'maya', 'bob', 'alice']),
      );
      expect(
        bobDemoWallet.links.map((link) => link.id),
        unorderedEquals([
          'verifiedIntroduction-root-noah',
          'verifiedIntroduction-noah-bob',
          'verifiedIntroduction-root-maya',
          'verifiedIntroduction-maya-alice',
          'retainedPW-bob-alice',
        ]),
      );
      expect(bobDemoWallet.trust, isEmpty);
      expect(bobDemoWallet.readiness, isEmpty);
      expect(
        bobDemoWallet.links.every(
          (link) => link.provenance.startsWith('Bob fixture'),
        ),
        isTrue,
      );
    },
  );

  testWidgets(
    'owner startup is preserved; demo navigation makes no owner calls',
    (tester) async {
      viewport(tester, const Size(1440, 900));
      var calls = 0;
      Future<T> unexpected<T>() async {
        calls++;
        throw StateError('No owner operations belong in the demo');
      }

      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) => unexpected(),
          readIntroduction: (_, _) => unexpected(),
          checkIntroduction: (_, _, _) => unexpected(),
          saveIntroduction: (_, _, _) => unexpected(),
          listIntroductions: (_, _) => unexpected(),
          fetchIntroduction: (_, _, _) => unexpected(),
          verifyReceived: (_, _) => unexpected(),
          bootstrapDevice: (_, _) => unexpected(),
          publishAd: (_, _) => unexpected(),
          fetchPeerAd: (_, _, _) => unexpected(),
          verifyPeerAd: (_, _, _) => unexpected(),
        ),
      );
      expect(find.text('My node'), findsOneWidget);
      expect(find.text('Not checked'), findsOneWidget);
      expect(find.byType(TextField), findsNWidgets(4));
      expect(find.byType(WalletDemoScreen), findsNothing);
      final url = find.widgetWithText(TextField, 'Owner status URL');
      await tester.enterText(url, 'http://127.0.0.1:12345/owner/status');

      await tester.tap(keyed('open-wallet-demo'));
      await tester.pumpAndSettle();
      expect(keyed('relationship-graph'), findsOneWidget);
      expect(keyed('sample-composer'), findsNothing);
      await selectPeer(tester, 'bob');
      final composer = keyed('sample-composer');
      await tester.ensureVisible(composer);
      expect(tester.widget<TextField>(composer).enabled, isFalse);
      expect(tester.widget<TextField>(composer).onSubmitted, isNull);
      expect(tester.widget<IconButton>(keyed('sample-send')).onPressed, isNull);
      await tester.tap(composer);
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.tap(keyed('layer-pw'));
      await switchWallet(tester, 'Bob');
      await selectPeer(tester, 'alice');
      await tester.pump(const Duration(seconds: 20));
      await tester.tap(keyed('close-wallet-demo'));
      await tester.pumpAndSettle();

      expect(find.text('My node'), findsOneWidget);
      expect(
        tester.widget<TextField>(url).controller!.text,
        'http://127.0.0.1:12345/owner/status',
      );
      expect(calls, 0);
      expect(tester.takeException(), isNull);
    },
  );

  for (final width in [1440.0, 1650.0]) {
    testWidgets(
      'Bob selection retains graph and distinct observations at $width',
      (tester) async {
        viewport(tester, Size(width, 900));
        await showDemo(tester);
        expect(find.text("Alice's wallet / local perspective"), findsOneWidget);
        expect(keyed('trust-carol'), findsOneWidget);
        expect(keyed('trust-bob'), findsNothing);
        expect(keyed('edge-verifiedIntroduction-noah-bob'), findsOneWidget);
        expect(keyed('edge-retainedPW-alice-bob'), findsOneWidget);

        await selectPeer(tester, 'bob');
        expect(keyed('relationship-graph'), findsOneWidget);
        expect(
          tester.widget<Semantics>(keyed('node-bob')).properties.selected,
          isTrue,
        );
        expect(
          tester.widget<Semantics>(keyed('node-carol')).properties.selected,
          isFalse,
        );
        expect(find.text('Hi Alice! Good to see you here.'), findsOneWidget);
        expect(find.text('Coffee on Friday?'), findsOneWidget);
        expect(find.text('Retained PW: held locally'), findsOneWidget);
        expect(
          find.text('Last readiness: sample authenticated response'),
          findsOneWidget,
        );
        expect(find.text('Local trust: not assigned'), findsOneWidget);
        expect(keyed('retained-pw'), findsOneWidget);
        expect(keyed('last-readiness'), findsOneWidget);
        expect(keyed('local-trust'), findsOneWidget);
        expect(find.text('DEMO DATA · UI CONCEPT'), findsOneWidget);
        expect(find.textContaining('No live network'), findsOneWidget);
        expect(
          find.text('Scripted conversation · no live transport'),
          findsOneWidget,
        );
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets(
    'each layer changes only presentation, even with a peer selected',
    (tester) async {
      viewport(tester, const Size(1440, 900));
      await showDemo(tester);
      await selectPeer(tester, 'carol');
      final links = List.of(aliceDemoWallet.links);
      final trust = List.of(aliceDemoWallet.trust);
      final readiness = List.of(aliceDemoWallet.readiness);
      for (final (layer, key) in [
        ('introductions', 'edge-verifiedIntroduction-noah-bob'),
        ('pw', 'edge-retainedPW-alice-carol'),
        ('trust', 'trust-carol'),
      ]) {
        await tester.tap(keyed('layer-$layer'));
        await tester.pumpAndSettle();
        expect(keyed(key), findsNothing);
        expect(find.text('Retained PW: held locally'), findsOneWidget);
        expect(find.text('Local trust: assigned by Alice'), findsOneWidget);
        expect(
          tester.widget<WalletDemoGraph>(find.byType(WalletDemoGraph)).fixture,
          same(aliceDemoWallet),
        );
        expect(aliceDemoWallet.links, links);
        expect(aliceDemoWallet.trust, trust);
        expect(aliceDemoWallet.readiness, readiness);
        await tester.tap(keyed('layer-$layer'));
        await tester.pumpAndSettle();
        expect(keyed(key), findsOneWidget);
      }
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('received invitation alone creates no known path, PW or trust', (
    tester,
  ) async {
    viewport(tester, const Size(1440, 900));
    final invitationOnly = WalletDemoFixture(
      owner: 'alice',
      people: const [
        DemoPerson(
          'alice',
          'Alice',
          Offset(.2, .5),
          DemoPersonKind.localIdentity,
        ),
        DemoPerson(
          'bob',
          'Bob',
          Offset(.8, .5),
          DemoPersonKind.receivedClaimSubject,
        ),
      ],
      links: const [],
      invitations: const [
        DemoInvitation('bob', 'Test fixture · unverified received claim'),
      ],
    );
    await showDemo(tester, fixtures: [invitationOnly]);
    await selectPeer(tester, 'bob');
    expect(keyed('received-invitation'), findsOneWidget);
    expect(find.text('Retained PW: not held locally'), findsOneWidget);
    expect(find.text('Local trust: not assigned'), findsOneWidget);
    expect(
      find.text('Last readiness: no observation in fixture'),
      findsOneWidget,
    );
    for (final layer in ['introductions', 'pw', 'trust']) {
      for (var i = 0; i < 2; i++) {
        await tester.tap(keyed('layer-$layer'));
        await tester.pumpAndSettle();
        expect(keyed('edge-retainedPW-alice-bob'), findsNothing);
        expect(keyed('edge-verifiedIntroduction-alice-bob'), findsNothing);
        expect(keyed('trust-bob'), findsNothing);
      }
    }
    expect(invitationOnly.links, isEmpty);
    expect(invitationOnly.trust, isEmpty);
    expect(invitationOnly.readiness, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('wallet switch clears selection and never mirrors Alice state', (
    tester,
  ) async {
    viewport(tester, const Size(1440, 900));
    await showDemo(tester);
    await selectPeer(tester, 'carol');
    expect(find.text('Local trust: assigned by Alice'), findsOneWidget);
    await switchWallet(tester, 'Bob');
    expect(keyed('retained-pw'), findsNothing);
    expect(keyed('sample-composer'), findsNothing);
    expect(keyed('node-carol'), findsNothing);
    expect(keyed('trust-carol'), findsNothing);
    expect(keyed('edge-retainedPW-alice-carol'), findsNothing);
    expect(keyed('edge-verifiedIntroduction-maya-carol'), findsNothing);
    expect(keyed('edge-retainedPW-bob-alice'), findsOneWidget);
    expect(find.text("Bob's wallet / local perspective"), findsOneWidget);
    await selectPeer(tester, 'alice');
    expect(find.text('Retained PW: held locally'), findsOneWidget);
    expect(find.text('Local trust: not assigned'), findsOneWidget);
    expect(
      find.text('Last readiness: no observation in fixture'),
      findsOneWidget,
    );
    expect(find.text('Hi Alice! Good to see you here.'), findsNothing);
    await switchWallet(tester, 'Alice');
    expect(keyed('retained-pw'), findsNothing);
    expect(keyed('trust-carol'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  for (final size in [const Size(700, 900), const Size(390, 700)]) {
    testWidgets('graph and chat remain reachable without overflow at $size', (
      tester,
    ) async {
      viewport(tester, size);
      await showDemo(tester);
      await selectPeer(tester, 'bob');
      expect(keyed('relationship-graph'), findsNothing);
      expect(find.text('DEMO DATA · UI CONCEPT'), findsOneWidget);
      expect(find.textContaining('No live network'), findsOneWidget);
      await tester.ensureVisible(keyed('sample-composer'));
      expect(
        tester.widget<TextField>(keyed('sample-composer')).enabled,
        isFalse,
      );
      expect(tester.widget<IconButton>(keyed('sample-send')).onPressed, isNull);
      await tester.ensureVisible(keyed('close-peer-details'));
      await tester.tap(keyed('close-peer-details'));
      await tester.pumpAndSettle();
      expect(keyed('relationship-graph'), findsOneWidget);
      expect(keyed('sample-composer'), findsNothing);
      await switchWallet(tester, 'Bob');
      expect(keyed('node-carol'), findsNothing);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('graph selection is reachable by keyboard', (tester) async {
    viewport(tester, const Size(1440, 900));
    await showDemo(tester);
    final bobButton = find.descendant(
      of: keyed('node-bob'),
      matching: find.byType(TextButton),
    );
    final label = find.descendant(of: bobButton, matching: find.text('Bob'));
    final focus = Focus.of(tester.element(label));
    for (var step = 0; step < 20 && !focus.hasFocus; step++) {
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pump();
    }
    expect(focus.hasFocus, isTrue);
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(find.text('Retained PW: held locally'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

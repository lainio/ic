import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/demo_config.dart';
import 'package:ic_node_ui/live_pairing.dart';
import 'package:ic_node_ui/main.dart' as app;

import 'demo_config_test.dart' show ConfigFiles, configJson;
import 'wallet_demo_test.dart' show viewport, switchWallet;

final _url = find.widgetWithText(TextField, 'Owner status URL');
final _header = find.widgetWithText(TextField, 'Authorization header file');
Finder keyed(String name) => find.byKey(ValueKey(name));

String value(WidgetTester tester, Finder field) =>
    tester.widget<TextField>(field).controller!.text;

void main() {
  testWidgets('no-argument entrypoint preserves the empty owner screen', (
    tester,
  ) async {
    app.main([]);
    await tester.pumpAndSettle();
    expect(find.text('My node'), findsOneWidget);
    expect(find.text('Not checked'), findsOneWidget);
    expect(value(tester, _url), '');
    expect(value(tester, _header), '');
    expect(find.text(demoConfigAttribution), findsNothing);
    expect(find.byType(TextField), findsNWidgets(4));
  });

  for (final role in ['alice', 'bob']) {
    testWidgets(
      '$role config startup and fixture switching make no owner HTTP',
      (tester) async {
        viewport(tester, const Size(1440, 1100));
        final files = ConfigFiles();
        addTearDown(files.dispose);
        final path = files.write(role).path;
        final expected = configJson(role);
        var requests = 0;
        await HttpOverrides.runZoned(
          () async {
            app.main(['--config', path]);
            await tester.pumpAndSettle();
            expect(value(tester, _url), expected['owner_status_url']);
            expect(value(tester, _header), expected['owner_header_file']);
            expect(find.text(demoConfigAttribution), findsOneWidget);
            expect(
              find.widgetWithText(
                SelectableText,
                expected['node_public_key_hex']! as String,
              ),
              findsOneWidget,
            );
            expect(
              find.textContaining('Configured role: $role'),
              findsOneWidget,
            );
            expect(find.text('Not checked'), findsOneWidget);

            await tester.tap(keyed('open-wallet-demo'));
            await tester.pumpAndSettle();
            await switchWallet(tester, 'Bob');
            await tester.tap(keyed('open-live-pairing'));
            await tester.pumpAndSettle();
            final pairing = tester.widget<LivePairingScreen>(
              find.byType(LivePairingScreen),
            );
            expect(pairing.ownerStatusUrl, expected['owner_status_url']);
            expect(pairing.headerPath, expected['owner_header_file']);
            await tester.pageBack();
            await tester.pumpAndSettle();
            await tester.tap(keyed('close-wallet-demo'));
            await tester.pumpAndSettle();
            expect(value(tester, _url), expected['owner_status_url']);
            expect(value(tester, _header), expected['owner_header_file']);
            expect(find.text(demoConfigAttribution), findsOneWidget);
            await tester.pump(const Duration(seconds: 20));
          },
          createHttpClient: (_) {
            requests++;
            throw StateError('Startup and fixtures must never open HTTP');
          },
        );
        expect(requests, 0);
        expect(tester.takeException(), isNull);
      },
    );
  }

  for (final field in ['url', 'header']) {
    testWidgets(
      '$field editing clears config identity; pairing takes current settings',
      (tester) async {
        viewport(tester, const Size(1440, 1100));
        final files = ConfigFiles();
        addTearDown(files.dispose);
        app.main(['--config', files.write('alice').path]);
        await tester.pumpAndSettle();
        final input = field == 'url' ? _url : _header;
        final original = value(tester, input);
        final changed = field == 'url'
            ? 'http://127.0.0.1:12399/owner/status'
            : '/different/owner.header';
        await tester.enterText(input, changed);
        await tester.pumpAndSettle();
        expect(
          find.textContaining(
            'Configuration no longer matches edited owner settings',
          ),
          findsOneWidget,
        );
        expect(find.text(demoConfigAttribution), findsNothing);
        expect(find.textContaining('Configured role:'), findsNothing);
        expect(
          find.text(configJson('alice')['node_public_key_hex']! as String),
          findsNothing,
        );

        await tester.tap(keyed('open-wallet-demo'));
        await tester.pumpAndSettle();
        await tester.tap(keyed('open-live-pairing'));
        await tester.pumpAndSettle();
        final pairing = tester.widget<LivePairingScreen>(
          find.byType(LivePairingScreen),
        );
        expect(
          pairing.ownerStatusUrl,
          field == 'url' ? changed : configJson('alice')['owner_status_url'],
        );
        expect(
          pairing.headerPath,
          field == 'header'
              ? changed
              : configJson('alice')['owner_header_file'],
        );
        await tester.pageBack();
        await tester.pumpAndSettle();
        await tester.tap(keyed('close-wallet-demo'));
        await tester.pumpAndSettle();
        await tester.enterText(input, original);
        await tester.pumpAndSettle();
        expect(find.textContaining('Configured role:'), findsNothing);
        expect(
          find.textContaining(
            'Configuration no longer matches edited owner settings',
          ),
          findsOneWidget,
        );
      },
    );
  }

  for (final failure in ['arguments', 'invalid', 'missing', 'permissions']) {
    testWidgets(
      '$failure has a visible startup error with no fallback or HTTP',
      (tester) async {
        final files = ConfigFiles();
        addTearDown(files.dispose);
        final file = files.write(
          'alice',
          text: failure == 'invalid' ? '{"token":"never-display-this"}' : null,
        );
        if (failure == 'permissions') {
          expect(Process.runSync('chmod', ['644', file.path]).exitCode, 0);
        }
        if (failure == 'missing') file.deleteSync();
        var requests = 0;
        await HttpOverrides.runZoned(
          () async {
            app.main([
              '--config',
              file.path,
              if (failure == 'arguments') 'extra',
            ]);
            await tester.pumpAndSettle();
            expect(find.text('Startup configuration error'), findsOneWidget);
            expect(find.text('My node'), findsNothing);
            expect(find.byType(TextField), findsNothing);
            expect(keyed('open-wallet-demo'), findsNothing);
            expect(find.textContaining('never-display-this'), findsNothing);
            await tester.pump(const Duration(seconds: 20));
          },
          createHttpClient: (_) {
            requests++;
            throw StateError('Failed startup must never open HTTP');
          },
        );
        expect(requests, 0);
      },
    );
  }
}

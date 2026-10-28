import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/status_client.dart';

void main() {
  final ownerField = find.widgetWithText(TextField, 'Owner status URL');
  final headerField = find.widgetWithText(
    TextField,
    'Authorization header file',
  );
  final documentField = find.widgetWithText(TextField, 'Introduction JSON');
  final peerField = find.widgetWithText(TextField, 'Peer introduction URL');
  final authorizeButton = find.widgetWithText(
    OutlinedButton,
    'Authorize local device',
  );
  final publishButton = find.widgetWithText(
    FilledButton,
    'Publish advertisement',
  );
  final readButton = find.widgetWithText(FilledButton, 'Read status');
  final checkButton = find.widgetWithText(FilledButton, 'Check introduction');
  final copyButton = find.widgetWithText(OutlinedButton, 'Copy introduction');
  final saveButton = find.widgetWithText(OutlinedButton, 'Save introduction');
  final loadButton = find.widgetWithText(
    OutlinedButton,
    'Load saved introductions',
  );
  final fetchButton = find.widgetWithText(FilledButton, 'Fetch introduction');
  final verifyButton = find.widgetWithText(
    FilledButton,
    'Verify received introductions',
  );
  const owner = 'http://127.0.0.1:12345/owner/status';
  const header = '/synthetic/owner.header';
  const authorized = DeviceAuthorization(authorized: true, usable: true);
  const published = AdPublication(
    published: true,
    slot: 1,
    epoch: 0,
    expiresUnixNano: 1793192400123456789,
    peerIntroductionUrl: 'http://127.0.0.1:23456/peer/introduction',
  );
  const entry = IntroductionCheck(subjectPublicKeyHex: 'aabb', isSelf: true);
  const saved = IntroductionSave(
    subjectPublicKeyHex: 'aabb',
    isSelf: true,
    created: true,
  );
  const verified = IntroductionVerification(
    newlyKnown: 1,
    knownSubjects: ['aabb'],
  );

  Future<void> click(WidgetTester tester, Finder button) async {
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pump();
  }

  Future<void> inputs(WidgetTester tester) async {
    await tester.enterText(ownerField, owner);
    await tester.enterText(headerField, header);
    await tester.pumpAndSettle();
  }

  void expectDisabled(WidgetTester tester) {
    for (final button in [
      readButton,
      checkButton,
      fetchButton,
      verifyButton,
      publishButton,
    ]) {
      expect(tester.widget<FilledButton>(button).onPressed, isNull);
    }
    for (final button in [
      copyButton,
      saveButton,
      loadButton,
      authorizeButton,
    ]) {
      expect(tester.widget<OutlinedButton>(button).onPressed, isNull);
    }
  }

  testWidgets('authorization is explicit and never publishes or reads status', (
    tester,
  ) async {
    var authorizations = 0;
    var publications = 0;
    var reads = 0;
    await tester.pumpWidget(
      IntroTreeApp(
        readStatus: (_, _) async {
          reads++;
          return NodeChoice.completed;
        },
        bootstrapDevice: (url, path) async {
          expect((url, path), (owner, header));
          authorizations++;
          return authorized;
        },
        publishAd: (_, _) async {
          publications++;
          return published;
        },
      ),
    );
    await inputs(tester);
    expect(authorizations, 0);
    expect(publications, 0);
    await click(tester, authorizeButton);
    await tester.pumpAndSettle();
    expect(authorizations, 1);
    expect(publications, 0);
    expect(reads, 0);
    expect(find.text('Local device authorized'), findsOneWidget);
    expect(
      find.text('Signer usability was checked during that request.'),
      findsOneWidget,
    );
    expect(find.text('Advertisement published'), findsNothing);
  });

  for (final choice in [null, ...NodeChoice.values]) {
    testWidgets(
      'publication needs no session authorization with choice $choice',
      (tester) async {
        var authorizations = 0;
        var publications = 0;
        var reads = 0;
        IntroTreeApp app() => IntroTreeApp(
          readStatus: (_, _) async {
            reads++;
            return choice!;
          },
          bootstrapDevice: (_, _) async {
            authorizations++;
            return authorized;
          },
          publishAd: (url, path) async {
            expect((url, path), (owner, header));
            publications++;
            return published;
          },
        );
        await tester.pumpWidget(app());
        await inputs(tester);
        if (choice != null) {
          await click(tester, readButton);
          await tester.pumpAndSettle();
        }
        for (var i = 1; i <= 2; i++) {
          await click(tester, publishButton);
          await tester.pumpAndSettle();
          expect(publications, i);
          expect(find.text('Advertisement published'), findsOneWidget);
          expect(
            find.widgetWithText(SelectableText, published.peerIntroductionUrl),
            findsOneWidget,
          );
          expect(find.text('Expires (UTC)'), findsOneWidget);
          expect(find.text('2026-10-28T13:00:00.123456Z'), findsOneWidget);
        }
        expect(authorizations, 0);
        expect(reads, choice == null ? 0 : 1);
        await tester.pumpWidget(const SizedBox());
        await tester.pumpWidget(app());
        await inputs(tester);
        expect(find.text('Advertisement published'), findsNothing);
        await click(tester, publishButton);
        await tester.pumpAndSettle();
        expect(publications, 3);
        expect(authorizations, 0);
        expect(find.text('Advertisement published'), findsOneWidget);
      },
    );
  }

  testWidgets(
    'past expiry and int64 maximum display UTC using integer division',
    (tester) async {
      for (final (expires, text) in [
        (0, '1970-01-01T00:00:00.000Z'),
        (1001, '1970-01-01T00:00:00.000001Z'),
        (0x7fffffffffffffff, '2262-04-11T23:47:16.854775Z'),
      ]) {
        await tester.pumpWidget(
          IntroTreeApp(
            publishAd: (_, _) async => AdPublication(
              published: true,
              slot: 1,
              epoch: 0,
              expiresUnixNano: expires,
              peerIntroductionUrl: published.peerIntroductionUrl,
            ),
          ),
        );
        await click(tester, publishButton);
        await tester.pumpAndSettle();
        expect(find.text('Advertisement published'), findsOneWidget);
        expect(find.text(text), findsOneWidget);
      }
    },
  );

  for (final bootstrap in [true, false]) {
    final button = bootstrap ? authorizeButton : publishButton;
    final title = bootstrap
        ? 'Local device authorized'
        : 'Advertisement published';
    final rejected = bootstrap
        ? StatusFailure.bootstrapRejected
        : StatusFailure.publishRejected;
    final unknown = bootstrap
        ? StatusFailure.bootstrapUnknown
        : StatusFailure.publishUnknown;
    testWidgets(
      '$title clears on new attempts and failures never chain actions',
      (tester) async {
        var pending = Completer<Object>();
        var calls = 0;
        var otherCalls = 0;
        await tester.pumpWidget(
          IntroTreeApp(
            bootstrapDevice: (_, _) async {
              if (!bootstrap) {
                otherCalls++;
                return authorized;
              }
              calls++;
              return await pending.future as DeviceAuthorization;
            },
            publishAd: (_, _) async {
              if (bootstrap) {
                otherCalls++;
                return published;
              }
              calls++;
              return await pending.future as AdPublication;
            },
          ),
        );
        await inputs(tester);
        for (final failure in [
          StatusFailure.invalidUrl,
          StatusFailure.credentials,
          StatusFailure.unauthorized,
          bootstrap
              ? StatusFailure.bootstrapUnavailable
              : StatusFailure.publishUnavailable,
          rejected,
          unknown,
          bootstrap
              ? StatusFailure.bootstrapInvalidResponse
              : StatusFailure.publishInvalidResponse,
          StateError('private path and token'),
        ]) {
          pending = Completer<Object>();
          await click(tester, button);
          pending.complete(bootstrap ? authorized : published);
          await tester.pumpAndSettle();
          expect(find.text(title), findsOneWidget);
          pending = Completer<Object>();
          await click(tester, button);
          expect(find.text(title), findsNothing);
          pending.completeError(failure);
          await tester.pumpAndSettle();
          expect(find.text(title), findsNothing);
          expect(find.text(published.peerIntroductionUrl), findsNothing);
          expect(
            find.text((failure is StatusFailure ? failure : unknown).message),
            findsOneWidget,
          );
          expect(find.textContaining('private path'), findsNothing);
        }
        expect(calls, 16);
        expect(otherCalls, 0);
      },
    );

    for (final change in ['owner', 'header', 'dispose']) {
      testWidgets('$change suppresses late $title success and failure', (
        tester,
      ) async {
        var pending = Completer<Object>();
        var edits = 0;
        IntroTreeApp app() => IntroTreeApp(
          bootstrapDevice: (_, _) async =>
              await pending.future as DeviceAuthorization,
          publishAd: (_, _) async => await pending.future as AdPublication,
        );
        await tester.pumpWidget(app());
        await inputs(tester);
        for (final fails in [false, true]) {
          if (change == 'dispose') await tester.pumpWidget(app());
          pending = Completer<Object>();
          await click(tester, button);
          if (change == 'dispose') {
            await tester.pumpWidget(const SizedBox());
          } else {
            final field = change == 'owner' ? ownerField : headerField;
            await tester.ensureVisible(field);
            await tester.enterText(field, 'changed ${++edits}');
            // Editing back still invalidates this request's owner revision.
            await tester.enterText(field, change == 'owner' ? owner : header);
          }
          if (fails) {
            pending.completeError(rejected);
          } else {
            pending.complete(bootstrap ? authorized : published);
          }
          await tester.pumpAndSettle();
          expect(find.text(title), findsNothing);
          expect(find.text(rejected.message), findsNothing);
          expect(tester.takeException(), isNull);
        }
      });
    }

    testWidgets(
      '$title shares busy discipline and survives unrelated input edits',
      (tester) async {
        final pending = Completer<Object>();
        var calls = 0;
        await tester.pumpWidget(
          IntroTreeApp(
            readStatus: (_, _) async => NodeChoice.completed,
            checkIntroduction: (_, _, _) async => entry,
            bootstrapDevice: (_, _) async {
              calls++;
              return await pending.future as DeviceAuthorization;
            },
            publishAd: (_, _) async {
              calls++;
              return await pending.future as AdPublication;
            },
          ),
        );
        await inputs(tester);
        await click(tester, readButton);
        await tester.pumpAndSettle();
        await click(tester, checkButton);
        await tester.pumpAndSettle();
        // Save and Copy are now present, so check every existing action too.
        await click(tester, button);
        expectDisabled(tester);
        expect(find.text('Reading status…'), findsNothing);
        expect(
          find.text(
            bootstrap
                ? 'Authorizing local device…'
                : 'Publishing advertisement…',
          ),
          findsOneWidget,
        );
        await tester.tap(button);
        expect(calls, 1);
        for (final field in [documentField, peerField]) {
          await tester.ensureVisible(field);
          await tester.enterText(field, 'unrelated edit');
        }
        pending.complete(bootstrap ? authorized : published);
        await tester.pumpAndSettle();
        expect(find.text(title), findsOneWidget);
        expect(calls, 1);
      },
    );
  }

  for (final fieldName in ['owner', 'header']) {
    testWidgets(
      '$fieldName edits clear both receipts but evidence edits preserve them',
      (tester) async {
        await tester.pumpWidget(
          IntroTreeApp(
            bootstrapDevice: (_, _) async => authorized,
            publishAd: (_, _) async => published,
          ),
        );
        await inputs(tester);
        await click(tester, authorizeButton);
        await tester.pumpAndSettle();
        await click(tester, publishButton);
        await tester.pumpAndSettle();
        for (final field in [documentField, peerField]) {
          await tester.ensureVisible(field);
          await tester.enterText(field, 'unrelated document');
          await tester.pump();
          expect(find.text('Local device authorized'), findsOneWidget);
          expect(find.text('Advertisement published'), findsOneWidget);
        }
        final field = fieldName == 'owner' ? ownerField : headerField;
        await tester.ensureVisible(field);
        await tester.enterText(field, 'other connection');
        await tester.pump();
        expect(find.text('Local device authorized'), findsNothing);
        expect(find.text('Advertisement published'), findsNothing);
        expect(find.text(published.peerIntroductionUrl), findsNothing);
      },
    );
  }

  testWidgets(
    'all existing network actions disable authorization and publication',
    (tester) async {
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      messenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (_) async => null,
      );
      addTearDown(
        () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
      );
      var pending = Completer<Object>();
      var holding = false;
      var newCalls = 0;
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => holding
              ? await pending.future as NodeChoice
              : NodeChoice.completed,
          readIntroduction: (_, _) async => await pending.future as String,
          checkIntroduction: (_, _, _) async =>
              holding ? await pending.future as IntroductionCheck : entry,
          saveIntroduction: (_, _, _) async =>
              await pending.future as IntroductionSave,
          listIntroductions: (_, _) async =>
              await pending.future as List<IntroductionCheck>,
          fetchIntroduction: (_, _, _) async =>
              await pending.future as IntroductionSave,
          verifyReceived: (_, _) async =>
              await pending.future as IntroductionVerification,
          bootstrapDevice: (_, _) async {
            newCalls++;
            return authorized;
          },
          publishAd: (_, _) async {
            newCalls++;
            return published;
          },
        ),
      );
      await inputs(tester);
      await click(tester, readButton);
      await tester.pumpAndSettle();
      await click(tester, checkButton);
      await tester.pumpAndSettle();
      holding = true;
      for (final (button, result) in <(Finder, Object)>[
        (copyButton, '{}'),
        (saveButton, saved),
        (loadButton, [entry]),
        (fetchButton, saved),
        (verifyButton, verified),
        (checkButton, entry),
        (readButton, NodeChoice.completed),
      ]) {
        pending = Completer<Object>();
        await click(tester, button);
        expect(
          tester.widget<OutlinedButton>(authorizeButton).onPressed,
          isNull,
        );
        expect(tester.widget<FilledButton>(publishButton).onPressed, isNull);
        pending.complete(result);
        await tester.pumpAndSettle();
        expect(
          tester.widget<OutlinedButton>(authorizeButton).onPressed,
          isNotNull,
        );
        expect(tester.widget<FilledButton>(publishButton).onPressed, isNotNull);
      }
      expect(newCalls, 0);
    },
  );

  testWidgets(
    'publication buttons support keyboard and 2x text in a small window',
    (tester) async {
      tester.view.physicalSize = const Size(420, 520);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.pumpWidget(const IntroTreeApp());
      final original = MediaQuery.of(tester.element(find.byType(Scaffold)));
      var authorizations = 0;
      var publications = 0;
      await tester.pumpWidget(
        MediaQuery(
          data: original.copyWith(textScaler: const TextScaler.linear(2)),
          child: IntroTreeApp(
            bootstrapDevice: (_, _) async {
              authorizations++;
              return authorized;
            },
            publishAd: (_, _) async {
              publications++;
              return published;
            },
          ),
        ),
      );
      await inputs(tester);
      expect(
        MediaQuery.textScalerOf(tester.element(publishButton)).scale(14),
        28,
      );
      // Tab traverses the receiver action before the publication controls.
      await tester.ensureVisible(verifyButton);
      Focus.of(tester.element(find.text('Verify received introductions')))
          .requestFocus();
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      expect(
        Focus.of(tester.element(find.text('Fetch peer advertisement')))
            .hasFocus,
        isTrue,
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      expect(
        Focus.of(tester.element(find.text('Authorize local device'))).hasFocus,
        isTrue,
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(authorizations, 1);
      expect(publications, 0);
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      expect(
        Focus.of(tester.element(find.text('Publish advertisement'))).hasFocus,
        isTrue,
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(publications, 1);
      await tester.ensureVisible(find.text('Expires (UTC)'));
      await tester.pumpAndSettle();
      expect(find.text('Advertisement published'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );
}

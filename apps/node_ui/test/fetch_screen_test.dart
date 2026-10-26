import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/status_client.dart';

void main() {
  final ownerField = find.widgetWithText(TextField, 'Owner status URL');
  final headerField = find.widgetWithText(
    TextField,
    'Authorization header file',
  );
  final peerField = find.widgetWithText(TextField, 'Peer introduction URL');
  final documentField = find.widgetWithText(TextField, 'Introduction JSON');
  final fetchButton = find.widgetWithText(FilledButton, 'Fetch introduction');
  final readButton = find.widgetWithText(FilledButton, 'Read status');
  final checkButton = find.widgetWithText(FilledButton, 'Check introduction');
  final copyButton = find.widgetWithText(OutlinedButton, 'Copy introduction');
  final saveButton = find.widgetWithText(OutlinedButton, 'Save introduction');
  final loadButton = find.widgetWithText(
    OutlinedButton,
    'Load saved introductions',
  );
  const owner = 'http://127.0.0.1:12345/owner/status';
  const header = '/synthetic/owner.header';
  const peer = 'http://localhost:23456/peer/introduction';
  const subject = '00abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const saved = IntroductionSave(
    subjectPublicKeyHex: subject,
    isSelf: false,
    created: true,
  );
  const oldEntry = IntroductionCheck(
    subjectPublicKeyHex: '001122',
    isSelf: false,
  );

  Future<void> click(WidgetTester tester, Finder button) async {
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pump();
  }

  Future<void> enterInputs(WidgetTester tester) async {
    await tester.enterText(ownerField, owner);
    await tester.enterText(headerField, header);
    await tester.ensureVisible(peerField);
    await tester.enterText(peerField, peer);
    await tester.pumpAndSettle();
  }

  for (final choice in [null, ...NodeChoice.values]) {
    testWidgets('fetch is explicit and independent of local choice $choice', (
      tester,
    ) async {
      var calls = 0;
      var reads = 0;
      var loads = 0;
      var pending = Completer<IntroductionSave>();
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async {
            reads++;
            return choice!;
          },
          listIntroductions: (_, _) async {
            loads++;
            return [];
          },
          fetchIntroduction: (url, path, input) {
            calls++;
            expect(url, owner);
            expect(path, header);
            expect(input, peer);
            return pending.future;
          },
        ),
      );
      await enterInputs(tester);
      if (choice != null) {
        await click(tester, readButton);
        await tester.pumpAndSettle();
      }
      expect(calls, 0);
      expect(loads, 0);
      for (final created in [true, false]) {
        pending = Completer<IntroductionSave>();
        await click(tester, fetchButton);
        expect(calls, created ? 1 : 2);
        expect(find.text('Fetching introduction…'), findsOneWidget);
        expect(find.text('Reading status…'), findsNothing);
        expect(find.text('Copying introduction…'), findsNothing);
        expect(find.text('Introduction received'), findsNothing);
        expect(find.text(subject), findsNothing);
        expect(tester.widget<FilledButton>(fetchButton).onPressed, isNull);
        expect(tester.widget<FilledButton>(readButton).onPressed, isNull);
        expect(tester.widget<FilledButton>(checkButton).onPressed, isNull);
        expect(tester.widget<OutlinedButton>(loadButton).onPressed, isNull);
        if (choice == NodeChoice.completed) {
          expect(tester.widget<OutlinedButton>(copyButton).onPressed, isNull);
        }
        await click(tester, fetchButton);
        expect(calls, created ? 1 : 2);
        pending.complete(
          IntroductionSave(
            subjectPublicKeyHex: subject,
            isSelf: false,
            created: created,
          ),
        );
        await tester.pumpAndSettle();
        expect(
          find.text(created ? 'Introduction received' : 'Already received'),
          findsOneWidget,
        );
        expect(
          find.text(created ? 'Already received' : 'Introduction received'),
          findsNothing,
        );
        expect(find.widgetWithText(SelectableText, subject), findsOneWidget);
        expect(
          find.text('Received evidence; no connection or trust created.'),
          findsOneWidget,
        );
        expect(find.text('Path and acceptance verified'), findsNothing);
        expect(loads, 0);
        expect(reads, choice == null ? 0 : 1);
      }
    });
  }

  testWidgets('fetch clears loaded rows and stale success on every failure', (
    tester,
  ) async {
    var pending = Completer<IntroductionSave>();
    var loads = 0;
    await tester.pumpWidget(
      IntroTreeApp(
        fetchIntroduction: (_, _, _) => pending.future,
        listIntroductions: (_, _) async {
          loads++;
          return [oldEntry];
        },
      ),
    );
    await enterInputs(tester);
    for (final failure in [
      StatusFailure.emptyPeerUrl,
      StatusFailure.peerUrlTooLarge,
      StatusFailure.invalidPeerUrl,
      StatusFailure.unauthorized,
      StatusFailure.introductionConflict,
      StatusFailure.peerUnavailable,
      StatusFailure.saveStorage,
      StatusFailure.fetchUnexpected,
      StatusFailure.fetchUnknown,
      StateError('private token and server body'),
    ]) {
      pending = Completer<IntroductionSave>();
      await click(tester, fetchButton);
      pending.complete(saved);
      await tester.pumpAndSettle();
      expect(find.text('Introduction received'), findsOneWidget);
      await click(tester, loadButton);
      await tester.pumpAndSettle();
      expect(find.text(oldEntry.subjectPublicKeyHex), findsOneWidget);
      final previousLoads = loads;
      pending = Completer<IntroductionSave>();
      await click(tester, fetchButton);
      expect(find.text(oldEntry.subjectPublicKeyHex), findsNothing);
      expect(find.text(subject), findsNothing);
      expect(find.text('Introduction received'), findsNothing);
      pending.completeError(failure);
      await tester.pumpAndSettle();
      final expected = failure is StatusFailure
          ? failure
          : StatusFailure.fetchUnknown;
      expect(find.text(expected.message), findsOneWidget);
      expect(find.text('Introduction received'), findsNothing);
      expect(find.text('Already received'), findsNothing);
      expect(find.text(subject), findsNothing);
      expect(find.text(oldEntry.subjectPublicKeyHex), findsNothing);
      expect(find.text('Saved introductions not loaded.'), findsOneWidget);
      expect(find.textContaining('private token'), findsNothing);
      expect(loads, previousLoads);
    }
  });

  for (final change in ['owner', 'header', 'peer', 'dispose']) {
    testWidgets('fetch results and late replies are invalidated by $change', (
      tester,
    ) async {
      var pending = Completer<IntroductionSave>();
      var edits = 0;
      IntroTreeApp app() => IntroTreeApp(
        fetchIntroduction: (_, _, _) => pending.future,
        listIntroductions: (_, _) async => [oldEntry],
      );
      Future<void> edit() async {
        if (change == 'dispose') {
          await tester.pumpWidget(const SizedBox());
        } else {
          final field = switch (change) {
            'owner' => ownerField,
            'header' => headerField,
            _ => peerField,
          };
          await tester.ensureVisible(field);
          await tester.enterText(field, 'changed ${++edits}');
          await tester.pump();
        }
      }

      await tester.pumpWidget(app());
      await enterInputs(tester);
      await click(tester, fetchButton);
      pending.complete(saved);
      await tester.pumpAndSettle();
      await click(tester, loadButton);
      await tester.pumpAndSettle();
      expect(find.text(subject), findsOneWidget);
      expect(find.text(oldEntry.subjectPublicKeyHex), findsOneWidget);
      await edit();
      expect(find.text('Introduction received'), findsNothing);
      expect(find.text(subject), findsNothing);
      expect(
        find.text(oldEntry.subjectPublicKeyHex),
        change == 'peer' ? findsOneWidget : findsNothing,
      );
      for (final fails in [false, true]) {
        if (change == 'dispose') await tester.pumpWidget(app());
        pending = Completer<IntroductionSave>();
        await click(tester, fetchButton);
        await edit();
        if (fails) {
          pending.completeError(StatusFailure.peerUnavailable);
        } else {
          pending.complete(saved);
        }
        await tester.pumpAndSettle();
        expect(find.text('Introduction received'), findsNothing);
        expect(find.text(subject), findsNothing);
        expect(find.text(oldEntry.subjectPublicKeyHex), findsNothing);
        expect(find.text(StatusFailure.peerUnavailable.message), findsNothing);
        expect(tester.takeException(), isNull);
      }
    });
  }

  testWidgets(
    'fetch and existing owner actions exclude each other while fields remain editable',
    (tester) async {
      final fetching = Completer<IntroductionSave>();
      final checking = Completer<IntroductionCheck>();
      await tester.pumpWidget(
        IntroTreeApp(
          fetchIntroduction: (_, _, _) => fetching.future,
          checkIntroduction: (_, _, _) => checking.future,
        ),
      );
      await enterInputs(tester);
      await click(tester, checkButton);
      expect(tester.widget<FilledButton>(fetchButton).onPressed, isNull);
      checking.complete(
        const IntroductionCheck(subjectPublicKeyHex: 'abcd', isSelf: false),
      );
      await tester.pumpAndSettle();
      await click(tester, fetchButton);
      expect(tester.widget<OutlinedButton>(saveButton).onPressed, isNull);
      for (final field in [ownerField, headerField, peerField, documentField]) {
        expect(tester.widget<TextField>(field).enabled, isNot(false));
      }
      // The independent JSON form does not invalidate a peer fetch.
      await tester.ensureVisible(documentField);
      await tester.enterText(documentField, 'edited JSON');
      fetching.complete(saved);
      await tester.pumpAndSettle();
      expect(find.text('Introduction received'), findsOneWidget);
      expect(find.text('Path and acceptance verified'), findsNothing);
    },
  );
}

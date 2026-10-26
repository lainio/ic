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
  final documentField = find.widgetWithText(TextField, 'Introduction JSON');
  final verifyButton = find.widgetWithText(
    FilledButton,
    'Verify received introductions',
  );
  final fetchButton = find.widgetWithText(FilledButton, 'Fetch introduction');
  final checkButton = find.widgetWithText(FilledButton, 'Check introduction');
  final readButton = find.widgetWithText(FilledButton, 'Read status');
  final loadButton = find.widgetWithText(
    OutlinedButton,
    'Load saved introductions',
  );
  final saveButton = find.widgetWithText(OutlinedButton, 'Save introduction');
  const owner = 'http://127.0.0.1:12345/owner/status';
  const header = '/synthetic/owner.header';
  const subject = 'a5010203262001215820abcdef0123456789abcdef0123456789';
  const verified = IntroductionVerification(
    newlyKnown: 1,
    knownSubjects: [subject],
  );
  const entry = IntroductionCheck(subjectPublicKeyHex: '001122', isSelf: false);
  const saved = IntroductionSave(
    subjectPublicKeyHex: '001122',
    isSelf: false,
    created: true,
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

  for (final choice in [null, ...NodeChoice.values]) {
    testWidgets(
      'explicit verify needs only owner settings with choice $choice',
      (tester) async {
        var calls = 0;
        var loads = 0;
        var fetches = 0;
        await tester.pumpWidget(
          IntroTreeApp(
            readStatus: (_, _) async => choice!,
            listIntroductions: (_, _) async {
              loads++;
              return [entry];
            },
            fetchIntroduction: (_, _, _) async {
              fetches++;
              return saved;
            },
            verifyReceived: (url, path) async {
              expect((url, path), (owner, header));
              calls++;
              return switch (calls) {
                1 => verified,
                2 => const IntroductionVerification(
                  newlyKnown: 0,
                  knownSubjects: [subject],
                ),
                _ => const IntroductionVerification(
                  newlyKnown: 0,
                  knownSubjects: [],
                ),
              };
            },
          ),
        );
        await inputs(tester);
        if (choice != null) {
          await click(tester, readButton);
          await tester.pumpAndSettle();
        }
        expect(calls, 0);
        await click(tester, verifyButton);
        await tester.pumpAndSettle();
        expect(calls, 1);
        expect(find.text('1 newly verified'), findsOneWidget);
        expect(find.widgetWithText(SelectableText, subject), findsOneWidget);
        expect(
          find.text(
            'Locally verified evidence; no connection or trust created.',
          ),
          findsOneWidget,
        );
        await click(tester, verifyButton);
        await tester.pumpAndSettle();
        expect(calls, 2);
        expect(find.text('No new introductions verified'), findsOneWidget);
        expect(find.text('1 newly verified'), findsNothing);
        expect(find.widgetWithText(SelectableText, subject), findsOneWidget);
        await click(tester, verifyButton);
        await tester.pumpAndSettle();
        expect(calls, 3);
        expect(find.text('No received introductions verified'), findsOneWidget);
        expect(find.text(subject), findsNothing);
        expect(fetches, 0);
        expect(loads, 0);
      },
    );
  }

  testWidgets(
    'starting another verification and every failure clear old Known success',
    (tester) async {
      var pending = Completer<IntroductionVerification>();
      await tester.pumpWidget(
        IntroTreeApp(verifyReceived: (_, _) => pending.future),
      );
      await inputs(tester);
      for (final failure in [
        StatusFailure.invalidUrl,
        StatusFailure.credentials,
        StatusFailure.unauthorized,
        StatusFailure.verifyUnavailable,
        StatusFailure.verifyRejected,
        StatusFailure.verifyUnknown,
        StatusFailure.verifyInvalidResponse,
        StateError('private exception token /server/path'),
      ]) {
        pending = Completer<IntroductionVerification>();
        await click(tester, verifyButton);
        pending.complete(verified);
        await tester.pumpAndSettle();
        expect(find.text(subject), findsOneWidget);
        pending = Completer<IntroductionVerification>();
        await click(tester, verifyButton);
        expect(find.text(subject), findsNothing);
        expect(find.text('1 newly verified'), findsNothing);
        pending.completeError(failure);
        await tester.pumpAndSettle();
        expect(
          find.text(
            (failure is StatusFailure ? failure : StatusFailure.verifyUnknown)
                .message,
          ),
          findsOneWidget,
        );
        expect(find.text(subject), findsNothing);
        expect(find.text('1 newly verified'), findsNothing);
        expect(find.textContaining('private exception'), findsNothing);
      }
    },
  );

  for (final change in ['owner', 'header', 'dispose']) {
    testWidgets('$change invalidates displayed and late verification results', (
      tester,
    ) async {
      var pending = Completer<IntroductionVerification>();
      var edits = 0;
      IntroTreeApp app() =>
          IntroTreeApp(verifyReceived: (_, _) => pending.future);
      Future<void> edit() async {
        if (change == 'dispose') {
          await tester.pumpWidget(const SizedBox());
        } else {
          final field = change == 'owner' ? ownerField : headerField;
          await tester.ensureVisible(field);
          await tester.enterText(field, 'changed ${++edits}');
          await tester.pump();
        }
      }

      await tester.pumpWidget(app());
      await inputs(tester);
      await click(tester, verifyButton);
      pending.complete(verified);
      await tester.pumpAndSettle();
      expect(find.text(subject), findsOneWidget);
      await edit();
      expect(find.text(subject), findsNothing);
      for (final fails in [false, true]) {
        if (change == 'dispose') await tester.pumpWidget(app());
        pending = Completer<IntroductionVerification>();
        await click(tester, verifyButton);
        await edit();
        if (fails) {
          pending.completeError(StatusFailure.verifyRejected);
        } else {
          pending.complete(verified);
        }
        await tester.pumpAndSettle();
        expect(find.text(subject), findsNothing);
        expect(find.text('1 newly verified'), findsNothing);
        expect(find.text(StatusFailure.verifyRejected.message), findsNothing);
        expect(tester.takeException(), isNull);
      }
    });
  }

  testWidgets(
    'load and JSON edits preserve Known; Save and Fetch invalidate it',
    (tester) async {
      var calls = 0;
      var saves = 0;
      var fetches = 0;
      var pendingSave = Completer<IntroductionSave>();
      var pendingFetch = Completer<IntroductionSave>();
      await tester.pumpWidget(
        IntroTreeApp(
          verifyReceived: (_, _) async {
            calls++;
            return verified;
          },
          listIntroductions: (_, _) async => [entry],
          checkIntroduction: (_, _, _) async => entry,
          saveIntroduction: (_, _, _) {
            saves++;
            return pendingSave.future;
          },
          fetchIntroduction: (_, _, _) {
            fetches++;
            return pendingFetch.future;
          },
        ),
      );
      await inputs(tester);
      await click(tester, loadButton);
      await tester.pumpAndSettle();
      expect(calls, 0);
      await click(tester, verifyButton);
      await tester.pumpAndSettle();
      expect(find.text(entry.subjectPublicKeyHex), findsOneWidget);
      await click(tester, loadButton);
      await tester.pumpAndSettle();
      expect(calls, 1);
      expect(find.text(subject), findsOneWidget);
      await tester.ensureVisible(documentField);
      await tester.enterText(documentField, 'unrelated JSON');
      await tester.pump();
      expect(find.text(subject), findsOneWidget);
      await click(tester, checkButton);
      await tester.pumpAndSettle();
      for (final button in [saveButton, fetchButton]) {
        for (final fails in [false, true]) {
          await click(tester, verifyButton);
          await tester.pumpAndSettle();
          expect(find.text(subject), findsOneWidget);
          pendingSave = Completer<IntroductionSave>();
          pendingFetch = Completer<IntroductionSave>();
          await click(tester, button);
          expect(find.text(subject), findsNothing);
          expect(tester.widget<FilledButton>(verifyButton).onPressed, isNull);
          final pending = button == saveButton ? pendingSave : pendingFetch;
          if (fails) {
            pending.completeError(StatusFailure.saveStorage);
          } else {
            pending.complete(saved);
          }
          await tester.pumpAndSettle();
          expect(find.text(subject), findsNothing);
        }
      }
      expect(saves, 2);
      expect(fetches, 2);
      expect(calls, 5);
    },
  );

  testWidgets(
    'verify disables overlapping actions; unrelated JSON edit permits result',
    (tester) async {
      final pending = Completer<IntroductionVerification>();
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          checkIntroduction: (_, _, _) async => entry,
          verifyReceived: (_, _) => pending.future,
        ),
      );
      await inputs(tester);
      await click(tester, readButton);
      await tester.pumpAndSettle();
      await click(tester, checkButton);
      await tester.pumpAndSettle();
      await click(tester, verifyButton);
      for (final button in [
        verifyButton,
        fetchButton,
        checkButton,
        readButton,
      ]) {
        expect(tester.widget<FilledButton>(button).onPressed, isNull);
      }
      for (final button in [
        saveButton,
        loadButton,
        find.widgetWithText(OutlinedButton, 'Copy introduction'),
      ]) {
        expect(tester.widget<OutlinedButton>(button).onPressed, isNull);
      }
      expect(find.text('Reading status…'), findsNothing);
      await tester.ensureVisible(documentField);
      await tester.enterText(documentField, 'edited JSON');
      pending.complete(verified);
      await tester.pumpAndSettle();
      expect(find.text(subject), findsOneWidget);
    },
  );
}

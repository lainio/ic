import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/status_client.dart';

void main() {
  final urlField = find.widgetWithText(TextField, 'Owner status URL');
  final headerField = find.widgetWithText(
    TextField,
    'Authorization header file',
  );
  final documentField = find.widgetWithText(TextField, 'Introduction JSON');
  final checkButton = find.widgetWithText(FilledButton, 'Check introduction');
  final saveButton = find.widgetWithText(OutlinedButton, 'Save introduction');
  final loadButton = find.widgetWithText(
    OutlinedButton,
    'Load saved introductions',
  );
  const subject = '00abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const document = '{"version":1,"proposal":"AQ==","acceptance":"Ag=="}';
  const checked = IntroductionCheck(subjectPublicKeyHex: subject, isSelf: true);
  const inserted = IntroductionSave(
    subjectPublicKeyHex: subject,
    isSelf: true,
    created: true,
  );

  Future<void> click(WidgetTester tester, Finder button) async {
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pump();
  }

  Future<void> check(WidgetTester tester) async {
    await tester.enterText(urlField, 'http://127.0.0.1:12345/owner/status');
    await tester.enterText(headerField, '/synthetic/owner.header');
    await tester.ensureVisible(documentField);
    await tester.enterText(documentField, document);
    await tester.pumpAndSettle();
    await click(tester, checkButton);
    await tester.pumpAndSettle();
  }

  testWidgets(
    'save needs a current check; list loads only on explicit clicks',
    (tester) async {
      var saves = 0;
      var loads = 0;
      var pending = Completer<IntroductionSave>();
      await tester.pumpWidget(
        IntroTreeApp(
          checkIntroduction: (_, _, _) async => checked,
          saveIntroduction: (url, path, input) {
            saves++;
            expect(url, 'http://127.0.0.1:12345/owner/status');
            expect(path, '/synthetic/owner.header');
            expect(input, document);
            return pending.future;
          },
          listIntroductions: (_, _) async {
            loads++;
            return const [
              IntroductionCheck(subjectPublicKeyHex: 'abcd', isSelf: true),
            ];
          },
        ),
      );
      expect(saveButton, findsNothing);
      expect(find.text('Saved introductions not loaded.'), findsOneWidget);
      expect(
        find.text('Saved evidence; no connection or trust created.'),
        findsOneWidget,
      );
      expect(saves, 0);
      expect(loads, 0);
      await check(tester);
      expect(saveButton, findsOneWidget);
      expect(saves, 0);
      await click(tester, loadButton);
      await tester.pumpAndSettle();
      expect(loads, 1);
      expect(find.widgetWithText(SelectableText, 'abcd'), findsOneWidget);
      expect(find.text('Your own introduction'), findsOneWidget);
      await tester.ensureVisible(documentField);
      await tester.enterText(documentField, '$document ');
      await tester.pumpAndSettle();
      expect(saveButton, findsNothing);
      expect(find.text('abcd'), findsOneWidget);
      await tester.enterText(documentField, document);
      await click(tester, checkButton);
      await tester.pumpAndSettle();
      await click(tester, saveButton);
      expect(saves, 1);
      expect(find.text('Introduction saved'), findsNothing);
      expect(find.text('abcd'), findsNothing);
      expect(find.text('Saved introductions not loaded.'), findsOneWidget);
      expect(tester.widget<OutlinedButton>(saveButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(loadButton).onPressed, isNull);
      expect(tester.widget<FilledButton>(checkButton).onPressed, isNull);
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Read status'),
            )
            .onPressed,
        isNull,
      );
      await click(tester, saveButton);
      expect(saves, 1);
      pending.complete(inserted);
      await tester.pumpAndSettle();
      expect(find.text('Introduction saved'), findsOneWidget);
      expect(
        find.text('Load saved introductions refreshes the list.'),
        findsOneWidget,
      );
      expect(loads, 1);
      await click(tester, loadButton);
      await tester.pumpAndSettle();
      expect(loads, 2);
      expect(find.text('abcd'), findsOneWidget);
      pending = Completer<IntroductionSave>();
      await click(tester, saveButton);
      pending.complete(
        const IntroductionSave(
          subjectPublicKeyHex: subject,
          isSelf: true,
          created: false,
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Already saved'), findsOneWidget);
      expect(find.text('Introduction saved'), findsNothing);
      expect(find.text('abcd'), findsNothing);
      expect(loads, 2);
    },
  );

  for (final change in ['document', 'URL', 'header', 'dispose']) {
    testWidgets('late save cannot apply after $change', (tester) async {
      final pending = Completer<IntroductionSave>();
      await tester.pumpWidget(
        IntroTreeApp(
          checkIntroduction: (_, _, _) async => checked,
          saveIntroduction: (_, _, _) => pending.future,
        ),
      );
      await check(tester);
      await click(tester, saveButton);
      if (change == 'dispose') {
        await tester.pumpWidget(const SizedBox());
      } else {
        final field = switch (change) {
          'document' => documentField,
          'URL' => urlField,
          _ => headerField,
        };
        await tester.ensureVisible(field);
        await tester.enterText(field, 'changed');
        await tester.pump();
      }
      expect(saveButton, findsNothing);
      pending.complete(inserted);
      await tester.pumpAndSettle();
      expect(find.text('Introduction saved'), findsNothing);
      expect(find.text('Already saved'), findsNothing);
      expect(saveButton, findsNothing);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets(
    'empty, failed refresh, connection edits and late lists stay distinct',
    (tester) async {
      var pending = Completer<List<IntroductionCheck>>();
      await tester.pumpWidget(
        IntroTreeApp(listIntroductions: (_, _) => pending.future),
      );
      await click(tester, loadButton);
      expect(find.text('Loading saved introductions…'), findsOneWidget);
      pending.complete([]);
      await tester.pumpAndSettle();
      expect(find.text('No saved introductions.'), findsOneWidget);
      for (final field in [urlField, headerField]) {
        pending = Completer<List<IntroductionCheck>>();
        await click(tester, loadButton);
        pending.complete([checked]);
        await tester.pumpAndSettle();
        expect(find.text('Your own introduction'), findsOneWidget);
        pending = Completer<List<IntroductionCheck>>();
        await click(tester, loadButton);
        expect(find.text(subject), findsNothing);
        pending.completeError(StatusFailure.nodeState);
        await tester.pumpAndSettle();
        expect(find.text(StatusFailure.nodeState.message), findsOneWidget);
        expect(find.text(subject), findsNothing);
        expect(find.text('No saved introductions.'), findsNothing);
        pending = Completer<List<IntroductionCheck>>();
        await click(tester, loadButton);
        await tester.ensureVisible(field);
        await tester.enterText(field, 'changed');
        await tester.pump();
        pending.complete([checked]);
        await tester.pumpAndSettle();
        expect(find.text(subject), findsNothing);
        expect(find.text('Saved introductions not loaded.'), findsOneWidget);
      }
    },
  );

  testWidgets('save conflicts and storage failures never announce success', (
    tester,
  ) async {
    var failure = StatusFailure.introductionConflict;
    await tester.pumpWidget(
      IntroTreeApp(
        checkIntroduction: (_, _, _) async => checked,
        saveIntroduction: (_, _, _) async => throw failure,
      ),
    );
    await check(tester);
    for (final next in [
      StatusFailure.introductionConflict,
      StatusFailure.saveStorage,
    ]) {
      failure = next;
      await click(tester, saveButton);
      await tester.pumpAndSettle();
      expect(find.text(failure.message), findsOneWidget);
      expect(find.text('Introduction saved'), findsNothing);
      expect(find.text('Already saved'), findsNothing);
    }
  });
}

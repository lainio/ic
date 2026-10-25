import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/status_client.dart';

void main() {
  final urlField = find.widgetWithText(TextField, 'Owner status URL');
  final headerField = find.widgetWithText(
    TextField,
    'Authorization header file',
  );
  final readButton = find.widgetWithText(FilledButton, 'Read status');

  Future<void> enterInputs(WidgetTester tester) async {
    await tester.enterText(urlField, 'http://127.0.0.1:12345/owner/status');
    await tester.enterText(headerField, '/synthetic/owner.header');
  }

  testWidgets(
    'initial, loading, success, refresh failure; never displays secrets',
    (tester) async {
      var pending = Completer<NodeChoice>();
      var calls = 0;
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (url, path) {
            calls++;
            expect(url, 'http://127.0.0.1:12345/owner/status');
            expect(path, '/synthetic/owner.header');
            return pending.future;
          },
        ),
      );
      expect(find.text('IntroTree'), findsOneWidget);
      expect(find.text('My node'), findsOneWidget);
      expect(find.text('Not checked'), findsOneWidget);
      expect(find.byType(TextField), findsNWidgets(2));
      expect(calls, 0);
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pump();
      expect(find.byType(LinearProgressIndicator), findsOneWidget);
      expect(tester.widget<FilledButton>(readButton).onPressed, isNull);
      expect(urlField, findsOneWidget);
      expect(headerField, findsOneWidget);
      await tester.tap(readButton);
      expect(calls, 1);
      pending.complete(NodeChoice.completed);
      await tester.pumpAndSettle();
      expect(find.text('Acceptance saved'), findsOneWidget);
      expect(find.text('Node reports verified acceptance.'), findsOneWidget);
      expect(find.text('completed'), findsOneWidget);
      expect(
        find.text(
          'Local acceptance state; not membership, trust, or delivery confirmation.',
        ),
        findsOneWidget,
      );
      await tester.pump(const Duration(seconds: 10));
      expect(calls, 1);

      pending = Completer<NodeChoice>();
      await tester.tap(readButton);
      await tester.pump();
      expect(find.text('Acceptance saved'), findsNothing);
      expect(find.text('completed'), findsNothing);
      final secret = 'ab' * 32;
      pending.completeError(StateError('Authorization: Bearer $secret'));
      await tester.pumpAndSettle();
      expect(calls, 2);
      expect(find.text('Could not read the local node.'), findsOneWidget);
      expect(find.text('Acceptance saved'), findsNothing);
      expect(find.text('No introduction selected'), findsNothing);
      expect(find.textContaining(secret), findsNothing);
      expect(
        tester.element(find.byType(IntroTreeApp)).toStringDeep(),
        isNot(contains(secret)),
      );
      expect(tester.widget<FilledButton>(readButton).onPressed, isNotNull);
    },
  );

  for (final (choice, title, explanation) in [
    (
      NodeChoice.unselected,
      'No introduction selected',
      'No saved introduction choice.',
    ),
    (
      NodeChoice.pending,
      'Acceptance pending',
      'Saved proposal; no saved acceptance.',
    ),
  ]) {
    testWidgets('shows $choice and clears result after either input changes', (
      tester,
    ) async {
      await tester.pumpWidget(IntroTreeApp(readStatus: (_, _) async => choice));
      await enterInputs(tester);
      for (final field in [urlField, headerField]) {
        await tester.tap(readButton);
        await tester.pumpAndSettle();
        expect(find.text(title), findsOneWidget);
        expect(find.text(explanation), findsOneWidget);
        expect(find.text(choice.name), findsOneWidget);
        await tester.enterText(field, 'changed');
        await tester.pump();
        expect(find.text(title), findsNothing);
        expect(find.text(choice.name), findsNothing);
        expect(find.text('Not checked'), findsOneWidget);
      }
    });
  }

  testWidgets(
    'known failure is readable and completion after disposal is ignored',
    (tester) async {
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => throw StatusFailure.unauthorized,
        ),
      );
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      expect(
        find.text(
          'Credential not accepted; use the current header file from node serve.',
        ),
        findsOneWidget,
      );
      final pending = Completer<NodeChoice>();
      await tester.pumpWidget(
        IntroTreeApp(readStatus: (_, _) => pending.future),
      );
      await tester.tap(readButton);
      await tester.pump();
      await tester.pumpWidget(const SizedBox());
      pending.complete(NodeChoice.completed);
      await tester.pump();
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('keyboard navigation and small window with enlarged text', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(420, 520);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    var calls = 0;
    await tester.pumpWidget(
      IntroTreeApp(
        readStatus: (_, _) async {
          calls++;
          return NodeChoice.completed;
        },
      ),
    );
    final context = tester.element(find.byType(Scaffold));
    final original = MediaQuery.of(context);
    await tester.pumpWidget(
      MediaQuery(
        data: original.copyWith(textScaler: const TextScaler.linear(2)),
        child: IntroTreeApp(
          readStatus: (_, _) async {
            calls++;
            return NodeChoice.completed;
          },
        ),
      ),
    );
    expect(MediaQuery.textScalerOf(tester.element(urlField)).scale(14), 28);
    await tester.enterText(urlField, 'http://127.0.0.1:12345/owner/status');
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<EditableText>(
            find.descendant(
              of: headerField,
              matching: find.byType(EditableText),
            ),
          )
          .focusNode
          .hasFocus,
      isTrue,
    );
    await tester.enterText(
      headerField,
      '/${'long directory/' * 12}owner.header',
    );
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(calls, 1);
    await tester.ensureVisible(find.text('Acceptance saved'));
    await tester.pumpAndSettle();
    expect(find.text('Acceptance saved'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

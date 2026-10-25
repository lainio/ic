import 'dart:async';
import 'dart:convert';

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
  final copyButton = find.widgetWithText(OutlinedButton, 'Copy introduction');
  final checkButton = find.widgetWithText(FilledButton, 'Check introduction');
  final saveButton = find.widgetWithText(OutlinedButton, 'Save introduction');
  final loadButton = find.widgetWithText(
    OutlinedButton,
    'Load saved introductions',
  );
  final introductionField = find.widgetWithText(TextField, 'Introduction JSON');
  const subject = '00abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const document = '{"version":1,"proposal":"AQ==","acceptance":"Ag=="}';
  late List<String> clipboardWrites;

  setUp(() {
    clipboardWrites = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
          if (call.method == 'Clipboard.setData') {
            clipboardWrites.add((call.arguments as Map)['text'] as String);
          }
          return null;
        });
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

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
      expect(find.byType(TextField), findsNWidgets(3));
      expect(calls, 0);
      expect(copyButton, findsNothing);
      expect(clipboardWrites, isEmpty);
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
      expect(copyButton, findsNothing);
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
        expect(copyButton, findsNothing);
        expect(clipboardWrites, isEmpty);
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
          readIntroduction: (_, _) async => document,
          saveIntroduction: (_, _, _) async => const IntroductionSave(
            subjectPublicKeyHex: subject,
            isSelf: true,
            created: true,
          ),
          listIntroductions: (_, _) async => const [
            IntroductionCheck(subjectPublicKeyHex: subject, isSelf: true),
          ],
          checkIntroduction: (_, _, _) async => const IntroductionCheck(
            subjectPublicKeyHex: subject,
            isSelf: true,
          ),
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
    await tester.ensureVisible(copyButton);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(clipboardWrites, [document]);
    expect(find.text('Introduction copied'), findsOneWidget);
    await tester.ensureVisible(introductionField);
    await tester.enterText(introductionField, document);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(find.text('Path and acceptance verified'), findsOneWidget);
    await tester.ensureVisible(find.text(subject));
    await tester.pumpAndSettle();
    expect(find.widgetWithText(SelectableText, subject), findsOneWidget);
    expect(find.text('This is your own introduction.'), findsOneWidget);
    await tester.ensureVisible(saveButton);
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    await tester.sendKeyEvent(LogicalKeyboardKey.enter);
    await tester.pumpAndSettle();
    expect(find.text('Introduction saved'), findsOneWidget);
    await tester.ensureVisible(loadButton);
    await tester.tap(loadButton);
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Your own introduction'));
    await tester.pumpAndSettle();
    expect(find.text('Your own introduction'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('copy is explicit, single-flight and waits for platform success', (
    tester,
  ) async {
    var exports = 0;
    var reads = 0;
    final pending = Completer<String>();
    final platform = Completer<void>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
          if (call.method == 'Clipboard.setData') {
            clipboardWrites.add((call.arguments as Map)['text'] as String);
            await platform.future;
          }
          return null;
        });
    await tester.pumpWidget(
      IntroTreeApp(
        readStatus: (_, _) async {
          reads++;
          return NodeChoice.completed;
        },
        readIntroduction: (url, path) {
          exports++;
          expect(url, 'http://127.0.0.1:12345/owner/status');
          expect(path, '/synthetic/owner.header');
          return pending.future;
        },
      ),
    );
    await enterInputs(tester);
    await tester.tap(readButton);
    await tester.pumpAndSettle();
    expect(exports, 0);
    expect(clipboardWrites, isEmpty);
    expect(
      find.text(
        'Contains your public keys and introduction path. Share deliberately.',
      ),
      findsOneWidget,
    );
    await tester.ensureVisible(copyButton);
    await tester.tap(copyButton);
    await tester.pump();
    expect(exports, 1);
    expect(tester.widget<OutlinedButton>(copyButton).onPressed, isNull);
    expect(tester.widget<FilledButton>(readButton).onPressed, isNull);
    await tester.ensureVisible(copyButton);
    await tester.tap(copyButton);
    expect(exports, 1);
    expect(reads, 1);
    expect(clipboardWrites, isEmpty);
    pending.complete(document);
    await tester.pump();
    expect(clipboardWrites, [document]);
    expect(jsonDecode(clipboardWrites.single), {
      'version': 1,
      'proposal': 'AQ==',
      'acceptance': 'Ag==',
    });
    expect(clipboardWrites.single, isNot(contains('Bearer')));
    expect(clipboardWrites.single, isNot(contains('/synthetic/owner.header')));
    expect(find.text('Introduction copied'), findsNothing);
    platform.complete();
    await tester.pumpAndSettle();
    expect(find.text('Introduction copied'), findsOneWidget);
    await tester.ensureVisible(readButton);
    await tester.tap(readButton);
    await tester.pumpAndSettle();
    expect(find.text('Introduction copied'), findsNothing);
    expect(exports, 1);
    expect(clipboardWrites, [document]);
  });

  for (final failure in [
    StatusFailure.notCompleted,
    StatusFailure.unexpected,
    StatusFailure.unreachable,
  ]) {
    testWidgets('failed export $failure leaves clipboard untouched', (
      tester,
    ) async {
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          readIntroduction: (_, _) async => throw failure,
        ),
      );
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      await tester.ensureVisible(copyButton);
      await tester.tap(copyButton);
      await tester.pumpAndSettle();
      expect(clipboardWrites, isEmpty);
      expect(find.text('Introduction copied'), findsNothing);
      expect(find.text(failure.message), findsOneWidget);
      expect(copyButton, findsNothing);
    });
  }

  for (final change in ['URL', 'header', 'dispose']) {
    testWidgets('obsolete export after $change does not copy', (tester) async {
      final pending = Completer<String>();
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          readIntroduction: (_, _) => pending.future,
        ),
      );
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      await tester.ensureVisible(copyButton);
      await tester.tap(copyButton);
      await tester.pump();
      if (change == 'dispose') {
        await tester.pumpWidget(const SizedBox());
      } else {
        await tester.enterText(
          change == 'URL' ? urlField : headerField,
          'changed',
        );
      }
      pending.complete(document);
      await tester.pumpAndSettle();
      expect(clipboardWrites, isEmpty);
      expect(find.text('Introduction copied'), findsNothing);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets(
    'copy feedback clears on new copy, platform failure and input change',
    (tester) async {
      var fail = false;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
            if (call.method == 'Clipboard.setData') {
              if (fail) {
                throw PlatformException(code: 'private platform diagnostic');
              }
              clipboardWrites.add((call.arguments as Map)['text'] as String);
            }
            return null;
          });
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          readIntroduction: (_, _) async => document,
        ),
      );
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      await tester.ensureVisible(copyButton);
      await tester.tap(copyButton);
      await tester.pumpAndSettle();
      expect(find.text('Introduction copied'), findsOneWidget);
      fail = true;
      await tester.tap(copyButton);
      await tester.pumpAndSettle();
      expect(find.text('Introduction copied'), findsNothing);
      expect(find.text('Could not copy the introduction.'), findsOneWidget);
      expect(find.textContaining('private platform diagnostic'), findsNothing);
      expect(clipboardWrites, [document]);

      fail = false;
      await tester.ensureVisible(readButton);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      await tester.ensureVisible(copyButton);
      await tester.tap(copyButton);
      await tester.pumpAndSettle();
      expect(find.text('Introduction copied'), findsOneWidget);
      await tester.enterText(headerField, 'changed');
      await tester.pumpAndSettle();
      expect(find.text('Introduction copied'), findsNothing);
      expect(copyButton, findsNothing);
    },
  );

  testWidgets(
    'late platform acknowledgement does not announce changed inputs',
    (tester) async {
      final platform = Completer<void>();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
            if (call.method == 'Clipboard.setData') await platform.future;
            return null;
          });
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          readIntroduction: (_, _) async => document,
        ),
      );
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      await tester.ensureVisible(copyButton);
      await tester.tap(copyButton);
      await tester.pump();
      await tester.enterText(urlField, 'changed');
      platform.complete();
      await tester.pumpAndSettle();
      expect(find.text('Introduction copied'), findsNothing);
      expect(find.text('Not checked'), findsOneWidget);
    },
  );
  for (final self in [false, true]) {
    testWidgets('check is explicit and shows public subject (self=$self)', (
      tester,
    ) async {
      var calls = 0;
      final pending = Completer<IntroductionCheck>();
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          checkIntroduction: (url, path, input) {
            calls++;
            expect(url, 'http://127.0.0.1:12345/owner/status');
            expect(path, '/synthetic/owner.header');
            expect(input, document);
            return pending.future;
          },
        ),
      );
      await enterInputs(tester);
      await tester.tap(readButton);
      await tester.pumpAndSettle();
      expect(find.text('Acceptance saved'), findsOneWidget);
      await tester.ensureVisible(introductionField);
      await tester.enterText(introductionField, document);
      await tester.pumpAndSettle();
      await tester.pumpAndSettle();
      expect(calls, 0);
      expect(clipboardWrites, isEmpty);
      await tester.ensureVisible(checkButton);
      await tester.tap(checkButton);
      await tester.pump();
      expect(calls, 1);
      expect(tester.widget<FilledButton>(checkButton).onPressed, isNull);
      expect(tester.widget<FilledButton>(readButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(copyButton).onPressed, isNull);
      expect(find.text('Acceptance saved'), findsOneWidget);
      expect(find.text('Path and acceptance verified'), findsNothing);
      pending.complete(
        IntroductionCheck(subjectPublicKeyHex: subject, isSelf: self),
      );
      await tester.pumpAndSettle();
      expect(find.text('Path and acceptance verified'), findsOneWidget);
      expect(find.text('Subject public key'), findsOneWidget);
      expect(find.widgetWithText(SelectableText, subject), findsOneWidget);
      expect(
        find.text('This is your own introduction.'),
        self ? findsOneWidget : findsNothing,
      );
      expect(
        find.text(
          "Checked against this node's configured Root. No connection created.",
        ),
        findsOneWidget,
      );
      expect(find.text('Acceptance saved'), findsOneWidget);
      expect(find.text('completed'), findsOneWidget);
      expect(clipboardWrites, isEmpty);
      expect(calls, 1);
    });
  }

  for (final change in ['document', 'URL', 'header', 'dispose']) {
    testWidgets('check result and late completion invalidated by $change', (
      tester,
    ) async {
      var pending = Completer<IntroductionCheck>();
      var edits = 0;
      await tester.pumpWidget(
        IntroTreeApp(checkIntroduction: (_, _, _) => pending.future),
      );
      await enterInputs(tester);
      await tester.ensureVisible(introductionField);
      await tester.enterText(introductionField, document);
      await tester.pumpAndSettle();

      Future<void> changeInput() async {
        if (change == 'dispose') {
          await tester.pumpWidget(const SizedBox());
        } else {
          final field = switch (change) {
            'document' => introductionField,
            'URL' => urlField,
            _ => headerField,
          };
          await tester.ensureVisible(field);
          await tester.enterText(field, 'changed ${++edits}');
          await tester.pump();
        }
      }

      await tester.ensureVisible(checkButton);
      await tester.tap(checkButton);
      await tester.pump();
      pending.complete(
        const IntroductionCheck(subjectPublicKeyHex: subject, isSelf: true),
      );
      await tester.pumpAndSettle();
      expect(find.text('Path and acceptance verified'), findsOneWidget);
      await changeInput();
      expect(find.text('Path and acceptance verified'), findsNothing);
      expect(find.text(subject), findsNothing);
      expect(find.text('This is your own introduction.'), findsNothing);
      expect(saveButton, findsNothing);

      if (change == 'dispose') {
        await tester.pumpWidget(
          IntroTreeApp(checkIntroduction: (_, _, _) => pending.future),
        );
      }
      pending = Completer<IntroductionCheck>();
      await tester.ensureVisible(checkButton);
      await tester.tap(checkButton);
      await tester.pump();
      await changeInput();
      pending.complete(
        const IntroductionCheck(subjectPublicKeyHex: subject, isSelf: true),
      );
      await tester.pumpAndSettle();
      expect(find.text('Path and acceptance verified'), findsNothing);
      expect(find.text(subject), findsNothing);
      expect(clipboardWrites, isEmpty);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('check works before status; retry and rejection clear success', (
    tester,
  ) async {
    var calls = 0;
    final pending = Completer<IntroductionCheck>();
    await tester.pumpWidget(
      IntroTreeApp(
        checkIntroduction: (_, _, _) {
          calls++;
          return calls == 1
              ? Future.value(
                  const IntroductionCheck(
                    subjectPublicKeyHex: subject,
                    isSelf: false,
                  ),
                )
              : pending.future;
        },
      ),
    );
    await enterInputs(tester);
    await tester.ensureVisible(introductionField);
    await tester.enterText(introductionField, document);
    await tester.pumpAndSettle();
    await tester.ensureVisible(checkButton);
    await tester.tap(checkButton);
    await tester.pumpAndSettle();
    expect(find.text('Path and acceptance verified'), findsOneWidget);
    expect(find.text('Not checked'), findsOneWidget);
    expect(copyButton, findsNothing);
    await tester.tap(checkButton);
    await tester.pump();
    expect(find.text('Path and acceptance verified'), findsNothing);
    expect(find.text(subject), findsNothing);
    pending.completeError(StatusFailure.invalidIntroduction);
    await tester.pumpAndSettle();
    expect(
      find.text(StatusFailure.invalidIntroduction.message),
      findsOneWidget,
    );
    expect(find.text('Not checked'), findsOneWidget);
    expect(find.text('Path and acceptance verified'), findsNothing);
    expect(find.text(subject), findsNothing);
    expect(clipboardWrites, isEmpty);
  });
}

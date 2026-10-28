import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ic_node_ui/main.dart';
import 'package:ic_node_ui/received_ad_section.dart';
import 'package:ic_node_ui/status_client.dart';

import 'status_client_test.dart' show ObservedClient;

const _owner = 'http://127.0.0.1:12345/owner/status';
const _header = '/synthetic/owner.header';
const _peer = 'http://127.0.0.1:23456/peer/introduction';
final _subject = 'ab' * 128;
final _other = '${'ab' * 127}cd';
final _fetchButton = find.widgetWithText(
  FilledButton,
  'Fetch peer advertisement',
);
final _verifyButton = find.widgetWithText(FilledButton, 'Verify advertisement');
final _knownButton = find.widgetWithText(
  FilledButton,
  'Verify received introductions',
);
final _ownerField = find.widgetWithText(TextField, 'Owner status URL');
final _headerField = find.widgetWithText(
  TextField,
  'Authorization header file',
);
final _peerField = find.widgetWithText(TextField, 'Peer introduction URL');
final _documentField = find.widgetWithText(TextField, 'Introduction JSON');
final _section = find.byType(ReceivedAdSection);
const _success = 'Advertisement verified in this exchange';
AdFetchReceipt _fetched([String? subject]) => AdFetchReceipt(
  subjectPublicKeyHex: subject ?? _subject,
  introductionCreated: true,
  adChanged: false,
);
AdVerificationReceipt _verified([bool changed = true]) => AdVerificationReceipt(
  subjectPublicKeyHex: _subject,
  verified: true,
  changed: changed,
);

Future<void> _click(WidgetTester tester, Finder button) async {
  await tester.ensureVisible(button);
  await tester.tap(button);
  await tester.pump();
}

Future<void> _inputs(WidgetTester tester) async {
  await tester.enterText(_ownerField, _owner);
  await tester.enterText(_headerField, _header);
  await tester.ensureVisible(_peerField);
  await tester.enterText(_peerField, _peer);
  await tester.pumpAndSettle();
}

void main() {
  for (final promote in [false, true]) {
    testWidgets(
      'separate clicks use the exact latest full key; promote=$promote',
      (tester) async {
        var fetches = 0;
        var verifications = 0;
        var promotions = 0;
        var reads = 0;
        var loads = 0;
        final targets = <String>[];
        await tester.pumpWidget(
          IntroTreeApp(
            readStatus: (_, _) async {
              reads++;
              return NodeChoice.unselected;
            },
            listIntroductions: (_, _) async {
              loads++;
              return [];
            },
            fetchPeerAd: (url, path, peer) async {
              expect((url, path, peer), (_owner, _header, _peer));
              return _fetched(++fetches == 1 ? _subject : _other);
            },
            verifyReceived: (_, _) async {
              promotions++;
              return IntroductionVerification(
                newlyKnown: 1,
                knownSubjects: [_subject],
              );
            },
            verifyPeerAd: (url, path, subject) async {
              expect((url, path), (_owner, _header));
              targets.add(subject);
              verifications++;
              return AdVerificationReceipt(
                subjectPublicKeyHex: subject,
                verified: true,
                changed: verifications == 1,
              );
            },
          ),
        );
        await _inputs(tester);
        expect(_verifyButton, findsNothing);
        await _click(tester, _fetchButton);
        await tester.pumpAndSettle();
        expect(fetches, 1);
        expect(verifications, 0);
        expect(promotions, 0);
        expect(find.text('Received ad claim, not verified'), findsOneWidget);
        expect(find.widgetWithText(SelectableText, _subject), findsOneWidget);
        expect(find.text('Introduction evidence newly saved'), findsOneWidget);
        expect(find.text('Untrusted ad claim unchanged'), findsOneWidget);
        expect(find.text('Locally known subject public keys'), findsNothing);
        expect(tester.widget<FilledButton>(_verifyButton).onPressed, isNotNull);
        if (promote) {
          await _click(tester, _knownButton);
          await tester.pumpAndSettle();
          expect(verifications, 0);
          expect(promotions, 1);
        }
        for (final changed in [true, false]) {
          await _click(tester, _verifyButton);
          await tester.pumpAndSettle();
          expect(find.text(_success), findsOneWidget);
          expect(
            find.text(
              changed
                  ? 'Historical verified snapshot saved'
                  : 'Historical verified snapshot unchanged',
            ),
            findsOneWidget,
          );
          expect(
            find.text(
              'Validity and reachability are not monitored. CreatePW still needs fresh evidence.',
            ),
            findsOneWidget,
          );
        }
        expect(targets, [_subject, _subject]);
        await _click(tester, _fetchButton);
        await tester.pumpAndSettle();
        expect(find.text(_success), findsNothing);
        expect(find.text('Locally known subject public keys'), findsNothing);
        await _click(tester, _verifyButton);
        await tester.pumpAndSettle();
        expect(targets, [_subject, _subject, _other]);
        expect(fetches, 2);
        expect(promotions, promote ? 1 : 0);
        expect(reads, 0);
        expect(loads, 0);
        expect(
          tester
              .widgetList<Semantics>(
                find.descendant(of: _section, matching: find.byType(Semantics)),
              )
              .where((s) => s.properties.liveRegion == true),
          hasLength(2),
        );
      },
    );
  }

  testWidgets(
    'unselected status works through the real client with only owner requests',
    (tester) async {
      final directory = Directory.systemTemp.createTempSync('ad-screen-');
      addTearDown(() => directory.deleteSync(recursive: true));
      final header = File('${directory.path}/owner.header');
      header.writeAsStringSync('Authorization: Bearer ${'ab' * 32}\n');
      final requests = <http.Request>[];
      final client = StatusClient(
        createClient: () => ObservedClient((request) async {
          requests.add(request);
          final body = switch (request.url.path) {
            '/owner/status' => '{"choice":"unselected"}',
            '/owner/ads/fetch' =>
              '{"subject_public_key_hex":"$_subject","introduction_created":false,"ad_changed":true}',
            '/owner/ads/verify' =>
              '{"subject_public_key_hex":"$_subject","verified":true,"changed":false}',
            _ => throw StateError('unexpected second request'),
          };
          return http.Response(
            body,
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      addTearDown(client.close);
      Future<Object>? pending;
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (url, path) {
            final call = client.read(url, path);
            pending = call;
            return call;
          },
          fetchPeerAd: (url, path, peer) {
            final call = client.fetchPeerAd(url, path, peer);
            pending = call;
            return call;
          },
          verifyPeerAd: (url, path, key) {
            final call = client.verifyPeerAd(url, path, key);
            pending = call;
            return call;
          },
        ),
      );
      await _inputs(tester);
      await tester.ensureVisible(_headerField);
      await tester.enterText(_headerField, header.path);
      for (final button in [
        find.widgetWithText(FilledButton, 'Read status'),
        _fetchButton,
        _verifyButton,
      ]) {
        await tester.ensureVisible(button);
        await tester.runAsync(() async {
          await tester.tap(button);
          await pending!;
        });
        await tester.pumpAndSettle();
      }
      expect(find.text('No introduction selected'), findsOneWidget);
      expect(find.text('Introduction evidence already saved'), findsOneWidget);
      expect(
        find.text('Untrusted ad claim stored or replaced'),
        findsOneWidget,
      );
      expect(find.text(_success), findsOneWidget);
      expect(requests.map((r) => r.url.path), [
        '/owner/status',
        '/owner/ads/fetch',
        '/owner/ads/verify',
      ]);
      expect(
        requests.every((r) => r.url.origin == 'http://127.0.0.1:12345'),
        isTrue,
      );
      expect(requests.last.body, '{"subject_public_key_hex":"$_subject"}');
    },
  );

  testWidgets(
    'fetch failure clears ad success, Known and loaded rows without reloading',
    (tester) async {
      var fail = false;
      var loads = 0;
      final pending = Completer<AdFetchReceipt>();
      await tester.pumpWidget(
        IntroTreeApp(
          fetchPeerAd: (_, _, _) =>
              fail ? pending.future : Future.value(_fetched()),
          verifyPeerAd: (_, _, _) async => _verified(),
          verifyReceived: (_, _) async => const IntroductionVerification(
            newlyKnown: 1,
            knownSubjects: ['0011'],
          ),
          listIntroductions: (_, _) async {
            loads++;
            return [
              const IntroductionCheck(
                subjectPublicKeyHex: '0022',
                isSelf: false,
              ),
            ];
          },
        ),
      );
      await _inputs(tester);
      await _click(tester, _fetchButton);
      await tester.pumpAndSettle();
      await _click(tester, _verifyButton);
      await tester.pumpAndSettle();
      await _click(tester, _knownButton);
      await tester.pumpAndSettle();
      await _click(
        tester,
        find.widgetWithText(OutlinedButton, 'Load saved introductions'),
      );
      await tester.pumpAndSettle();
      expect(find.text('0011'), findsOneWidget);
      expect(find.text('0022'), findsOneWidget);
      fail = true;
      await _click(tester, _fetchButton);
      expect(find.text(_success), findsNothing);
      expect(find.text(_subject), findsNothing);
      expect(find.text('0011'), findsNothing);
      expect(find.text('0022'), findsNothing);
      expect(_verifyButton, findsNothing);
      pending.completeError(StatusFailure.adFetchStorage);
      await tester.pumpAndSettle();
      expect(find.text(StatusFailure.adFetchStorage.message), findsOneWidget);
      expect(_verifyButton, findsNothing);
      expect(loads, 1);
    },
  );

  testWidgets(
    'explicit verification failures clear success and allow another deliberate attempt',
    (tester) async {
      var pending = Completer<AdVerificationReceipt>();
      var calls = 0;
      await tester.pumpWidget(
        IntroTreeApp(
          fetchPeerAd: (_, _, _) async => _fetched(),
          verifyPeerAd: (_, _, _) {
            calls++;
            return pending.future;
          },
        ),
      );
      await _inputs(tester);
      await _click(tester, _fetchButton);
      await tester.pumpAndSettle();
      for (final error in [
        StatusFailure.adVerifyPrecondition,
        StatusFailure.adVerifyRemote,
        StatusFailure.adVerifyUnknown,
        StateError('private diagnostics'),
      ]) {
        pending = Completer<AdVerificationReceipt>();
        await _click(tester, _verifyButton);
        pending.complete(_verified());
        await tester.pumpAndSettle();
        expect(find.text(_success), findsOneWidget);
        pending = Completer<AdVerificationReceipt>();
        await _click(tester, _verifyButton);
        expect(find.text(_success), findsNothing);
        expect(find.text('Historical verified snapshot saved'), findsNothing);
        pending.completeError(error);
        await tester.pumpAndSettle();
        expect(
          find.text(
            (error is StatusFailure ? error : StatusFailure.adVerifyUnknown)
                .message,
          ),
          findsOneWidget,
        );
        expect(find.text(_success), findsNothing);
        expect(find.textContaining('private diagnostics'), findsNothing);
        final text = tester
            .widgetList<Text>(
              find.descendant(of: _section, matching: find.byType(Text)),
            )
            .map((t) => t.data ?? '')
            .join(' ');
        expect(
          text,
          isNot(
            matches(
              RegExp(r'\b(connected|current|online)\b', caseSensitive: false),
            ),
          ),
        );
      }
      expect(calls, 8);
    },
  );

  for (final verifying in [false, true]) {
    for (final change in ['peer', 'owner', 'header', 'dispose']) {
      testWidgets(
        '${verifying ? 'verify' : 'fetch'} ignores success and failure after $change',
        (tester) async {
          for (final fails in [false, true]) {
            final fetching = Completer<AdFetchReceipt>();
            final verification = Completer<AdVerificationReceipt>();
            await tester.pumpWidget(
              IntroTreeApp(
                key: UniqueKey(),
                fetchPeerAd: (_, _, _) =>
                    verifying ? Future.value(_fetched()) : fetching.future,
                verifyPeerAd: (_, _, _) => verification.future,
              ),
            );
            await _inputs(tester);
            await _click(tester, _fetchButton);
            if (verifying) {
              await tester.pumpAndSettle();
              await _click(tester, _verifyButton);
            }
            if (change == 'dispose') {
              await tester.pumpWidget(const SizedBox());
            } else {
              final field = switch (change) {
                'peer' => _peerField,
                'owner' => _ownerField,
                _ => _headerField,
              };
              final old = tester.widget<TextField>(field).controller!.text;
              await tester.ensureVisible(field);
              await tester.enterText(field, 'changed');
              // Changing back must not resurrect the in-flight result.
              await tester.enterText(field, old);
              await tester.pump();
            }
            if (verifying) {
              fails
                  ? verification.completeError(StatusFailure.adVerifyRemote)
                  : verification.complete(_verified());
            } else {
              fails
                  ? fetching.completeError(StatusFailure.adFetchRemote)
                  : fetching.complete(_fetched());
            }
            await tester.pumpAndSettle();
            expect(find.text(_success), findsNothing);
            expect(find.text(_subject), findsNothing);
            expect(_verifyButton, findsNothing);
            expect(
              find.text(StatusFailure.adVerifyRemote.message),
              findsNothing,
            );
            expect(
              find.text(StatusFailure.adFetchRemote.message),
              findsNothing,
            );
            expect(tester.takeException(), isNull);
          }
        },
      );
    }
  }

  testWidgets(
    'busy receiver actions exclude all actions and preserve independent results',
    (tester) async {
      final fetching = Completer<AdFetchReceipt>();
      final verification = Completer<AdVerificationReceipt>();
      final known = Completer<IntroductionVerification>();
      await tester.pumpWidget(
        IntroTreeApp(
          readStatus: (_, _) async => NodeChoice.completed,
          checkIntroduction: (_, _, _) async => const IntroductionCheck(
            subjectPublicKeyHex: '0011',
            isSelf: false,
          ),
          publishAd: (_, _) async => const AdPublication(
            published: true,
            slot: 1,
            epoch: 0,
            expiresUnixNano: 1793192400123456789,
            peerIntroductionUrl: _peer,
          ),
          fetchPeerAd: (_, _, _) => fetching.future,
          verifyPeerAd: (_, _, _) => verification.future,
          verifyReceived: (_, _) => known.future,
        ),
      );
      await _inputs(tester);
      for (final label in [
        'Read status',
        'Check introduction',
        'Publish advertisement',
      ]) {
        await _click(tester, find.widgetWithText(FilledButton, label));
        await tester.pumpAndSettle();
      }
      for (final verifying in [false, true]) {
        await _click(tester, verifying ? _verifyButton : _fetchButton);
        for (final button in tester.widgetList<ButtonStyleButton>(
          find.byWidgetPredicate((w) => w is ButtonStyleButton),
        )) {
          expect(button.onPressed, isNull);
        }
        expect(find.text('Reading status…'), findsNothing);
        expect(find.text('Advertisement published'), findsOneWidget);
        expect(find.text('Acceptance saved'), findsOneWidget);
        expect(find.text('Path and acceptance verified'), findsOneWidget);
        if (verifying) {
          await tester.ensureVisible(_documentField);
          await tester.enterText(_documentField, 'unrelated JSON edit');
          verification.complete(_verified());
        } else {
          fetching.complete(_fetched());
        }
        await tester.pumpAndSettle();
      }
      expect(find.text(_success), findsOneWidget);
      expect(find.text('Advertisement published'), findsOneWidget);
      await _click(tester, _knownButton);
      expect(tester.widget<FilledButton>(_fetchButton).onPressed, isNull);
      expect(tester.widget<FilledButton>(_verifyButton).onPressed, isNull);
      known.complete(
        const IntroductionVerification(newlyKnown: 0, knownSubjects: []),
      );
      await tester.pumpAndSettle();
      // Editing after a completed verification also invalidates the selection.
      await tester.ensureVisible(_peerField);
      await tester.enterText(_peerField, 'another peer');
      await tester.pump();
      expect(find.text(_success), findsNothing);
      expect(_verifyButton, findsNothing);
      expect(find.text('Advertisement published'), findsOneWidget);
    },
  );
}

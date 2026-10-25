# IntroTree node UI

The first screen of the Linux/native application reads saved local acceptance
state from an existing `tdc node serve`. It is read-only and requires a trusted
same-machine loopback connection. Root is not needed and can remain stopped.

Paste only the printed owner status URL and absolute `owner.header` path.
The app reads that header file afresh for each click; it never asks for identity
unlock files, storage keys, identity data, or a Vault. Settings and credentials
are not persisted across app exit.

`Read status` makes one request with a five-second deadline. Only HTTP loopback
`/owner/status` with an explicit port is accepted; `localhost` becomes
`127.0.0.1` without DNS. Connections are direct, with no proxies or redirects.
The credential file is limited to 1 KiB and responses to 4 KiB.

| Wire choice | Screen |
| --- | --- |
| `unselected` | No introduction selected |
| `pending` | Acceptance pending |
| `completed` | Acceptance saved |

These are local acceptance observations, not membership, trust, delivery, or
continuous connection monitoring. An unavailable service produces a failure;
there is no seeded demo data, polling, or automatic retry.

## Validate

Using the installed Flutter SDK and provisioned package cache, in this directory:

```sh
flutter pub get --offline
dart format lib test
flutter analyze --no-pub
flutter test --no-pub
flutter build linux --debug --no-pub
```

The generated application `pubspec.lock` is source; `.dart_tool`, build outputs,
and Linux ephemeral files are ignored. Tests use temporary synthetic header
files and mock HTTP, with no node, NATS, Tor, or external service required.
Flutter's test harness may use local IPC/loopback sockets. The native build
does not launch or validate an interactive GUI.

## One interactive check

1. Leave the existing `tdc node serve` running, or repeat its previous command.
2. In `apps/node_ui`, run `flutter run --no-pub -d linux`.
3. Paste its printed status URL and header-file path; click `Read status`.
   For the owner's completed Alice, expect `Acceptance saved` / `completed`.

Restarting the service changes its credential path and may change its port.
Closing the UI does not stop the service or delete node data.

Reading order: [screen](lib/main.dart), [client](lib/status_client.dart),
[client tests](test/status_client_test.dart),
[screen tests](test/status_screen_test.dart).

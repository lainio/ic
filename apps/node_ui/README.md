# IntroTree node UI

The Linux/native application reads saved local acceptance state from an existing
`tdc node serve` and lets its owner copy or check an introduction. It requires
a trusted same-machine loopback connection. Root can remain stopped.

Paste only the printed owner status URL and absolute `owner.header` path.
The app reads that header file afresh for each click; it never asks for identity
unlock files, storage keys, identity data, or a Vault. Settings and credentials
are not persisted across app exit.

`Read status` makes one request with a five-second deadline. Only HTTP loopback
`/owner/status` with an explicit port is accepted; `localhost` becomes
`127.0.0.1` without DNS. Connections are direct, with no proxies or redirects.
The credential file is limited to 1 KiB and status responses to 4 KiB.

| Wire choice | Screen |
| --- | --- |
| `unselected` | No introduction selected |
| `pending` | Acceptance pending |
| `completed` | Acceptance saved |

After a completed read, `Copy introduction` makes one authenticated GET to the
fixed `/owner/introduction` sibling, with the same deadline and a 128 KiB limit.
The service credential authorizes these two GETs, including evidence disclosure,
and the stateless check POST below. It grants no signing, persistence, enrollment,
peer access, other writes, or general permission for future owner POST operations.
The button copies only after validating a three-field development JSON document:
integer `version: 1`, `proposal`, and `acceptance` (standard padded base64).
The proposal and detached acceptance are the exact saved evidence. The envelope
is not separately signed, a backup, or a permanent interoperability format.
The UI validates shape only; the node verifies the saved evidence and refuses
any path containing a private handle ID.

Contains your public keys and introduction path. Share deliberately.
Keys, ancestor links, and signatures disclose the path even though it is public
evidence. Nothing is copied before the explicit click or automatically sent to
peers. `Introduction copied` appears only after the platform clipboard succeeds.
Clipboard history and other same-user applications remain outside the app's
control.

In `Check an introduction`, paste that JSON into `Introduction JSON` and click
`Check introduction`. This works before reading status and with an unselected
local choice. The app rereads the credential and sends one POST to the fixed
`/owner/introduction/check` sibling of the validated status URL. Input is kept
only in memory, never logged or persisted; empty or over-128-KiB UTF-8 input is
refused locally. The same direct transport and five-second deadline apply;
the result is limited to 4 KiB. Nothing in evidence selects a destination.

The node checks the canonical path and final child's acceptance separately
under its independently configured Root, without a Vault or signer. On success,
the screen shows `Path and acceptance verified`, the full selectable
`Subject public key`, and `This is your own introduction.` for self evidence.
Self means public-key byte equality with the local identity. Editing either
connection field or the document invalidates the result, including late replies.
Rejection is distinct from credential or transport failure.

This is inspection only: no document, contact, `Received`, `Known`, trust, or
pairwise state is saved, and no evidence URL is fetched. It implements neither
V19 `VerifyReceived` nor `CreatePW`. A copied signature proves no presenter's
current key control, freshness, revocation status, globally unique enrollment,
or live authenticated channel. No connection or chat is created.

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

Owner-run only; not part of automated completion:

1. Restart the existing `tdc node serve` with its previous arguments and restart
   the UI (`flutter run --no-pub -d linux` here), without reinitializing identity
   or state. Root remains stopped.
2. Paste the newly printed status URL and header-file path; click `Read status`.
   For the owner's completed Alice, expect `Acceptance saved` / `completed`.
3. Click `Copy introduction`, paste into `Introduction JSON`, and click
   `Check introduction`. Expect `Path and acceptance verified` and
   `This is your own introduction.` This is self-inspection only; independent
   participant and negative cases are covered by automated tests.

Restarting the service changes its credential path and may change its port.
Closing the UI does not stop the service or delete node data.

Reading order: [configured-root check](../../internal/ownerapi/check.go),
[client request](lib/status_client.dart), [screen action](lib/main.dart),
[client tests](test/status_client_test.dart),
[screen tests](test/status_screen_test.dart).

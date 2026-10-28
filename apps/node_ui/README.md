# IntroTree node UI

The Linux/native application reads saved local acceptance state from an existing
`tdc node serve` and lets its owner copy, check, save, or fetch an
introduction, load saved subject keys, and explicitly verify received evidence. It requires
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
The evidence-only credential authorizes these reads, the stateless check POST,
and the introduction save/list/fetch/verify routes below. Existing read/status
constructors keep their earlier scope. The current node serve credential also
authorizes the explicit device and advertisement actions described below.
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
only in memory until an explicit Save click; empty or over-128-KiB UTF-8 input is
refused locally. The same direct transport and five-second deadline apply;
the result is limited to 4 KiB. Nothing in evidence selects a destination.

The node checks the canonical path and final child's acceptance separately
under its independently configured Root, without a Vault or signer. On success,
the screen shows `Path and acceptance verified`, the full selectable
`Subject public key`, and `This is your own introduction.` for self evidence.
Self means public-key byte equality with the local identity. Editing either
connection field or the document invalidates the result, including late replies.
Rejection is distinct from credential or transport failure.

Checking alone saves nothing and fetches no evidence URL. It implements neither
V19 `VerifyReceived` nor `CreatePW`. A copied signature proves no presenter's
current key control, freshness, revocation status, globally unique enrollment,
or live authenticated channel. No connection or chat is created.

After a successful current check, `Save introduction` sends that document in one
POST to `/owner/introductions` on the same validated owner origin. Editing either
connection field or the document removes the save action until checked again.
The backend rechecks under its configured Root, then retains the exact canonical
proposal and detached acceptance in the node's encrypted Vault. It stores at most
32 subjects, keyed by full public-key bytes. An identical proposal retains the
original valid acceptance with no rewrite or encryption, even if the submitted
valid acceptance differs. A different proposal or full collection is refused
locally, without deciding global parenthood. Self evidence is allowed and leaves
the node's own choice unchanged. No signer or peer operation is involved.

`Introduction saved` appears only after successful insertion; `Already saved`
means an idempotent retry. A transport failure can leave the save outcome unknown;
there is no automatic mutation retry. Every save attempt clears the displayed
list, and success reminds you that `Load saved introductions` refreshes it.
Saving does not automatically issue that second request.

Under `Saved introductions`, paste the other node's printed `peer introduction
URL` into `Peer introduction URL` and click `Fetch introduction`. This works
without reading status or checking JSON. The URL comes from `tdc node serve
--peer-listen ...`; it is not an owner status URL or a credential. Flutter sends
one authenticated POST to `/owner/introductions/fetch` on the owner's validated
origin, with exactly `{"peer_url":"..."}` (at most 2 KiB encoded). Only Go
contacts the peer, validates evidence against its pinned Root, and saves it.
Flutter receives no signing key and never sends owner credentials to the peer.
Fetch has an eight-second deadline (Go's peer GET has five); other owner actions
retain five seconds. The response is limited to 4 KiB. `Introduction received`
or `Already received` shows the full selectable subject key and means Received
evidence only, not `VerifyReceived`, present signing-key control, or trust.
Fetch clears the displayed list without loading it. Lost or unexpected replies
leave the outcome unknown: use `Load saved introductions` to inspect it; there
is no automatic retry. Owner connection edits invalidate both results and list;
peer URL edits invalidate only the fetch result, including late replies.

`Saved introductions` stays unpopulated until an explicit `Load saved introductions`
click makes one GET to `/owner/introductions`. Each returned subject is selectable
in full, with self entries marked `Your own introduction`. The list distinguishes
not loaded, empty, and failed. Connection edits and failed refreshes clear old
rows; document edits do not erase a separately loaded list. Responses are bounded
to 4 KiB per summary and 256 KiB overall. The node revalidates every stored record
and returns no partial list when a record is invalid.

Saved evidence; no connection or trust created. The receive-only projection adds
path edges to this receiver's `Received`, preserving all earlier evidence. It never
promotes evidence into `Known` or changes local choice, ads, PW, trust, deny,
device/recovery state, or global introduction truth. The checker is an admission
filter for this owner import, not every possible V19 `ReceiveEdge` action.

`Verify received introductions` is a separate owner action under `Saved
introductions`. With just the owner URL and header configured, it sends one
authenticated POST containing `{}` to `/owner/introductions/verify` (five-second
deadline, 16 KiB response limit). The existing Go `VerifyReceived` rechecks all
saved Received evidence and local parent consistency under the configured Root,
then durably promotes valid subjects into local Known. No peer request, signing,
or implicit self evidence is involved. Fetch, save, load, and startup never
perform this transition.

The result shows `N newly verified` and all locally Known full public keys.
An empty collection shows `No received introductions verified`; an explicit
retry shows `No new introductions verified` and preserves the still-known keys,
without another seal or record rewrite. Save/Fetch attempts and owner connection
edits clear this display. Credential/unavailable, rejected state, invalid reply,
and unknown acknowledgement failures use fixed messages. A lost reply may follow
a committed promotion; there is no automatic retry, but another explicit click
is safe. Locally verified evidence; no connection or trust created. This proves
neither global parent uniqueness, current key possession, usable authorized
devices, fresh ads, nor mutual pairwise state.

`My node publication` adds two separate owner requests using the node's saved
software signer: `Authorize local device` posts `{}` to
`/owner/device/bootstrap`; `Publish advertisement` posts `{}` to
`/owner/ads/publish`. Save and explicitly verify your own introduction first;
publication also requires `node serve --peer-listen`. Each click makes only its
one request, with the ordinary five-second deadline and a 1 KiB response limit.
The node supplies the selectable advertised URL and UTC expiry. Flutter never
contacts that URL. Publication announces an address, not a connection or trust;
another successful publication replaces the previous ad.

Authorization persists on the node across restarts; signer usability is observed
only during the request. Publication remains available in a fresh UI without
repeating authorization. A bootstrap 409 is a refusal, not confirmation of prior
authorization or usability. Lost or invalid acknowledgements leave the outcome
unconfirmed; there is no automatic retry or rollback. Receipts are not current
state polls and are cleared on owner connection edits or app exit. Closing the
UI does not undo committed operations. After a service restart, use its current
owner URL/header; the UI does not save those settings.

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
   `Check introduction`, then `Save introduction` and `Load saved introductions`.
   Expect the full public key listed as `Your own introduction`.
   That completes the manual check. Independent-subject behavior and storage
   reopening are covered by automated tests; no further restart or multi-node
   exercise is required.

Restarting the service changes its credential path and may change its port.
Closing the UI does not stop the service or delete node data.

Reading order: [transactional save](../../internal/onboarding/received.go),
[credential scope](../../internal/ownerapi/credentials.go),
[client request](lib/status_client.dart), [screen action](lib/main.dart),
[client tests](test/status_client_test.dart),
[screen tests](test/status_screen_test.dart).

# IntroTree node UI

The Linux/native application reads saved local acceptance state from an existing
`tdc node serve` and lets its owner copy, check, save, or fetch an
introduction, load saved subject keys, and explicitly verify received evidence. It requires
a trusted same-machine loopback connection. Root can remain stopped.

With no startup arguments, paste the printed owner status URL and absolute
`owner.header` path. A disposable demo can prefill these via `--config` below.
The app reads that header file afresh for each click; it never asks for identity
unlock files, storage keys, identity data, or a Vault. Settings and credentials
are not persisted across app exit.

`Read status` makes one request with a five-second deadline. Only HTTP loopback
`/owner/status` with an explicit port is accepted; `localhost` becomes
`127.0.0.1` without DNS. Connections are direct, with no proxies or redirects.
The credential file is limited to 1 KiB and status responses to 4 KiB.

## Demo launch configuration (UI-02)

For the next disposable two-node trial, run the
[demo harness](../../scripts/README.md) and wait for `READY_FOR_INVITATION`.
It prints two absolute paths: `RUN/config/alice.json` and
`RUN/config/bob.json`. Alice is the **requester**; Bob is the **invitation
issuer/acceptor**. Build once from this package with the installed SDK and
offline cached dependencies:

~~~sh
flutter build linux --debug --no-pub
./build/linux/arm64/debug/bundle/ic_node_ui --config /absolute/RUN/config/alice.json
~~~

Start the second process from this package in another terminal:

~~~sh
./build/linux/arm64/debug/bundle/ic_node_ui --config /absolute/RUN/config/bob.json
~~~

For an x64 build, the binary is `build/linux/x64/debug/bundle/ic_node_ui`.
Use the installed **bundle** executable. The existing Linux runner passes its
arguments directly to Dart and is already `G_APPLICATION_NON_UNIQUE`; neither
native source nor process supervision changes. This is not an assumed
`flutter run` argument-forwarding syntax.

The only accepted argument forms are no arguments and exactly
`--config /absolute/path/to/config.json`. The config is a UTF-8 JSON object,
at most 8 KiB, with exactly these fields:

| Field | Required value |
| --- | --- |
| `version` | Integer `1` |
| `role` | `alice` or `bob` |
| `node_public_key_hex` | Full canonical lowercase hex, even length, 1–128 bytes |
| `owner_status_url` | Existing `StatusClient` loopback owner-status URL format |
| `owner_header_file` | Canonical absolute path ending in `owner.header` |

The harness supplies the actual full COSE bytes independently checked against
each node's `info` and `serve` output. Flutter validates hex shape, not COSE
cryptography, identity or key possession. Duplicate fields (including escaped
aliases), unknown/missing fields, wrong types/versions/roles, extra arguments,
malformed/oversized JSON and invalid owner settings fail closed. There is a
visible startup error and no owner screen, fallback endpoint or owner request.
Errors never display raw file contents or exception data.

The config must be a same-user 0600 regular file with one hard link, in a
same-user 0700 directory. Paths must be absolute and canonical, without symlinks
in any component or untrusted writable ancestors; a system-owned sticky `/tmp`
is allowed. The bounded reader uses the existing Linux libc through `dart:ffi`
(`openat` with no-follow flags and descriptor `statx`) because `dart:io` does
not expose ownership/link counts or no-follow opens. No package dependency,
helper executable or native-runner edit is added. This reader supports Linux
x64/ARM64 with `statx`; unavailable checks fail closed for `--config`.
No-argument startup continues to use the existing manual flow.

`My node` shows the selectable role and full real key, labeled exactly:
**Configuration supplied by demo harness; not independently authenticated by
Flutter.** These are launch configuration snapshots, not proof of current
identity, service availability, invitation state or credential validity.
Startup reads only the config; credentials are still read by `StatusClient`
afresh on each explicit owner action. Neither settings nor credentials are
persisted by Flutter. The config path itself is not a credential.

Both owner fields remain editable. Any edit hides the supplied role/key and
shows `Configuration no longer matches edited owner settings.`, even if the
text is later restored. Live pairing continues to take a transient snapshot of
the current owner fields. Wallet switching never selects the real endpoint;
the wallet, graph and chat remain fictional fixtures. No owner request,
pairing, first use, state refresh or messaging happens on launch.

`down` retains configs as historical artifacts; restarting the node makes old
settings stale. There is no refresh or repair path. Use a fresh disposable run
for the next trial. The existing invitation and first-use demo remains unchanged.

## Owner actions

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
Fetch has an eight-second deadline (Go's peer GET has five); ordinary local owner
actions retain five seconds. The response is limited to 4 KiB. `Introduction received`
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

The receiver's `Peer advertisement` section uses the same `Peer introduction URL`:

1. After the peer publishes, click `Fetch peer advertisement`. Flutter replaces
   only the terminal `/peer/introduction` with `/peer/ad` in the `peer_url` JSON
   sent to the owner's `/owner/ads/fetch`. Go fetches the document and separately
   saves introduction evidence and an **untrusted ReceivedAd claim**. The receipt
   shows the full subject key and both change flags; it never promotes Known.
2. If the subject is not already Known, use the existing separate
   `Verify received introductions` action.
3. Click `Verify advertisement` for the latest successful fetch's exact full key.
   `/owner/ads/verify` checks preexisting Known and obtains a fresh online proof.
   `Advertisement verified in this exchange` records a **historical VerifiedAd
   snapshot**. An unchanged snapshot still required a fresh proof this time.

Each click sends exactly one owner POST, rereads the current operational header,
and uses an eight-second deadline with a 1 KiB response bound. Fetch requests are
limited to 2 KiB; verification keys to 128 decoded bytes. Earlier evidence/device
credentials do not grant these routes. Flutter never contacts a peer directly,
retries automatically, or creates publisher state on the receiver. No status,
list refresh, Known promotion, or ad verification is chained automatically.
An ad-fetch attempt clears previous ad results and saved/Known list projections;
owner or peer input edits also discard late ad results. Receiver actions preserve
the publisher's separate receipt. A failed fetch can leave just the introduction
saved; a lost verification acknowledgement can follow a committed snapshot.
Neither receipt grants trust, a connection, or ongoing availability. Validity and
reachability are not monitored; future `CreatePW` still needs fresh evidence.

These are local acceptance observations, not membership, trust, delivery, or
continuous connection monitoring. An unavailable service produces a failure;
there is no seeded demo data, polling, or automatic retry.

## Wallet demo (UI-01)

The owner screen remains the default. Its app-bar `Wallet demo` action opens
an isolated dark relationship graph, starting with Alice's local fixture.
Select Bob for the scripted conversation; the wallet switcher also offers an
independently defined Bob fixture. At narrow widths, `Back to graph` returns
from peer details. Use Tab and Enter to select identities with a keyboard.

`DEMO DATA · UI CONCEPT` and `SCRIPTED GRAPH AND CHAT` remain visible. Dashed
violet paths are locally verified introduction evidence, solid cyan curves are
local retained PW halves, and amber diamonds are separately assigned local
trust. Layer controls only change visibility. Last readiness is a fictional
historical observation, never current reachability or a shared `PWOpen` flag.
Invitations alone imply no PW or trust. The disabled composer cannot send.
Graph and chat remain fixtures, including after successful live owner actions.

## Live pairing (PW-Go-12 / PW-Go-13)

`Wallet demo` → `Live pairing` opens separate explicit owner controls. The owner
screen remains the default. Its current status URL and header-file path are
passed as a transient snapshot for this window; neither credentials nor settings
are persisted. If either field is absent, submissions are disabled. Return to
the owner screen to change configuration, then reopen the panel. Fixture names
never identify the credential owner, select a signer or supply a public key.
Use two separate windows, configured for Bob's and Alice's respective nodes.

1. **Bob window:** enter Alice's full real lowercase COSE public-key hex and
   explicitly click `Issue invitation`. This makes one authenticated JSON POST
   to `/owner/pw/invitations/issue` with only `recipient_public_key_hex`.
   **Only one invitation row may ever exist per Bob Vault**, even after expiry,
   revocation or consumption. A second issue receives 409; there is no
   replacement. The server sets a 15-minute lifetime. The validated committed
   receipt shows the selectable invitation ID, Directed audience, exact recipient
   and UTC expiry with nanosecond precision. It does not contain Bob's key.
2. Optionally enter Bob's full real public key separately, **operator-supplied,
   not confirmed by the issue receipt**. After a successful current issue,
   `Copy manual redeem JSON` explicitly copies exactly the object below. This
   is a manual clipboard convenience, not a signed invitation wire format.
   The ID is sensitive eligibility material; share deliberately. Clipboard
   history and other same-user applications are outside the app's control.
3. **Alice window:** paste that JSON and explicitly click `Redeem invitation`.
   The exact three-field shape, Directed audience and canonical lowercase hex
   are checked locally, with a 512-byte UTF-8 input limit. One authenticated
   POST goes to Alice's `/owner/pw/invitations/redeem`; Flutter never contacts
   Bob's peer listener. Go uses Alice's locally verified ad to choose the endpoint
   and remains authoritative for COSE, signatures, Root, evidence and acceptance.

~~~json
{"target_public_key_hex":"<operator-supplied Bob full public key hex>","invitation_id_hex":"<64 lowercase hex characters>","audience":"Directed"}
~~~

Alice must already know Bob and have matching received and verified current ad
evidence. Bob requires an opt-in `--peer-listen`; Alice needs no peer listener.
There is only one saved requester attempt per Alice Vault. Conflicting target,
invitation or audience is refused. These invitation controls add no prerequisite
wizard or messaging; authenticated first use is a separate step below.

`Acceptance saved locally` and `Local PW held: yes/no` are separate receipt
observations. A false holding is not a usable relationship. Neither result
establishes current peer permission, readiness, a shared `PWOpen`, Trust,
authenticated first use or chat. No response changes the scripted graph,
readiness markers, trust or chat bubbles.

Both requests reuse `StatusClient`'s validated loopback owner origin, fresh
per-click `owner.header`, direct/no-proxy transport and no-redirect policy.
Request bodies are at most 512 bytes and success responses at most 1 KiB.
Issue has a five-second deadline; redeem has eight seconds, allowing Go's
five-second peer exchange. Exact success envelopes reject duplicate/unknown
fields, wrong types, noncanonical hex and mismatched issue recipients.
Only fixed failure messages reach the UI; bodies, exceptions, invitation IDs
and owner credentials are never logged. Credentials are never copied.

Client validation and credential-read failures say that no request was sent.
Issue 409 reports the existing invitation row without claiming a new issuance.
400/413/415 report rejected input, and 401/404 report credential/scope or route
failure. Redeem 409 leaves local redemption unconfirmed: it does not prove Bob
refused. Redeem 502 explicitly reports the retained attempt and unknown peer
outcome. Transport failure, timeout, 5xx, or malformed/mismatched success after
submission leave the outcome unknown or unconfirmed; commits are not rolled
back by missing acknowledgements. There is no automatic retry. The presenter
may explicitly repeat redemption with the same input using Go's durable exact
attempt, subject to current guards, without a recovery guarantee.

Pending submissions disable the operation buttons. Relevant input changes,
owner configuration changes and panel disposal invalidate receipts and late
results; Bob-key edits invalidate clipboard confirmation. Each explicit action
clears the older receipt for that operation. Closing the panel discards its
in-memory inputs and receipts without undoing node operations. Startup, wallet
switching, graph selection and opening/closing the panel perform no live action.

### Step 3 — Authenticate first use (requester window)

Use **Alice's actual requester node**, regardless of the selected wallet fixture.
`Run first use` opens a short confirmation; Cancel sends nothing. Confirm sends
one authenticated `POST /owner/pw/first-use` with exactly `{}` to this window's
configured owner loopback origin. It rereads `owner.header`, uses direct transport
without redirects, allows eight seconds for Go's five-second peer POST, and
bounds the response to 1 KiB. Duplicate/extra fields, invalid types and
`local_ready:false` are rejected before JSON decoding can erase duplicate keys.
Go alone chooses the saved relationship, target, endpoint and signed material.
No transient redemption receipt is required: Go checks its saved holding and
current guards, including when the panel is reopened.

**This is an explicit one-shot authenticated exchange, not chat.** Go commits
Alice's `Await` before sending; Bob can independently commit his one-time receipt
before Alice receives the response. Failure can consume the session. Missing
acknowledgement does not undo remote effects. One session exists per accepted
attempt; it cannot be retried or replaced after failure or expiry. After
confirmation this panel offers no second submission, regardless of outcome.
Reopening the UI cannot reset a consumed node session.

Only the exact success envelope `{"local_ready":true}` displays
`Authenticated first use completed` and the separate line
`Local readiness: observed on this exchange (historical)`. This is Alice's local
historical observation, never shared `PWOpen`, a live pipe, current Bob permission,
Trust, a session key or usable text-message transport. Graph, readiness, trust
and chat stay fixtures, and the sample composer remains disabled.

409 reports local refusal or failed response acceptance without deciding whether
Bob processed the request. 502 reports unknown outcome with Alice's `Await`
retained. Timeout, disconnection, response loss and malformed success also report
unknown outcome. Credential/scope/route rejection is separate from local URL or
credential-read failures that dispatched no POST. Only fixed messages are shown.
Owner configuration or panel identity changes and disposal discard pending/old
receipts; late responses cannot restore them. State remains in memory only.
Startup, issue and redemption never initiate first use or any chained action.

The next trial is a **disposable-Vault real two-node UI trial**, including a lost
acknowledgement case on separate disposable state, before any text-message
semantics or implementation. Mocked client/widget tests and a native build do
not establish real two-node interoperability. This increment adds no messages,
local Deny, Delete, Tor or automatic session recovery.
The next research increment is to **specify real text messaging**; first use
is not a chat transport.

## Validate

Using the installed Flutter SDK and provisioned package cache, in this directory:

~~~sh
flutter pub get --offline
flutter analyze --no-pub
flutter test --no-pub
flutter build linux --debug --no-pub
~~~

Format touched Dart files only. Run the root `make lint` before and after changes.

The generated application `pubspec.lock` is source; `.dart_tool`, build outputs,
and Linux ephemeral files are ignored. Tests use temporary synthetic header
files and mock HTTP, with no node, NATS, Tor, or external service required.
Flutter's test harness may use local IPC/loopback sockets. The native build
does not launch or validate an interactive GUI.

## UI-02 verification

On 2026-11-05, the 40 socket-free Python tests passed (the opt-in smoke was
skipped in that command). The separate `PW_DEMO_LIVE=1` smoke passed with real
node setup, independent configs, printed paths and retention after `down`.
`flutter analyze --no-pub`, all 274 tests with `flutter test --no-pub`, and
`flutter build linux --debug --no-pub` passed using cached dependencies.

These bundled executable invocations were exercised from this package on
ARM64, with both processes alive concurrently:

~~~sh
trial_run=/tmp/ic-pw-demo-smoke-6hc_836e/runs/run-2fb2f8b75ee34c839ae5be0eb972e75a
./build/linux/arm64/debug/bundle/ic_node_ui --config "$trial_run/config/alice.json"
~~~

~~~sh
trial_run=/tmp/ic-pw-demo-smoke-6hc_836e/runs/run-2fb2f8b75ee34c839ae5be0eb972e75a
./build/linux/arm64/debug/bundle/ic_node_ui --config "$trial_run/config/bob.json"
~~~

The debug runtime inspector confirmed `My node` and the harness attribution in
both widget trees, with no startup error. The bounded probe stopped both UI
processes afterward. These particular configs are **historical**: the smoke
had already stopped the nodes, so this check makes no availability claim and
performed no owner UI action. Use new configs from the next `up` for the trial.
The native x64 binary was not built or run on this ARM64 host.

The desktop reported read-only dconf and Mesa/EGL warnings. Screenshot capture
was unavailable; runtime inspection and widget tests verified startup, without
claiming a visual desktop review. Socket binding worked; no sandbox permissions
or runner code were changed. This check did not repeat invitation redemption
or authenticated first use.

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

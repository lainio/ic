# One saved signing identity

## Run an existing node

Use `tdc node serve --help` for the local owner service.
Stop the previous Alice accept process to release its Store lock.
Root can be stopped; reuse Alice's existing paths and independently supplied
Root public-key pin:

~~~sh
tdc node serve --dir ALICE_DIR --unlock-file ALICE_UNLOCK_FILE \
    --storage-key-file ALICE_STORAGE_KEY_FILE --root ROOT_PUBLIC_KEY_HEX
~~~

The identity and initialized state must already exist.
All four flags are required and nonempty, with no positional arguments.
The unlock and storage-key files must be distinct and outside the node directory.
`--listen` defaults to `127.0.0.1:0`; it accepts explicit loopback addresses and
normalizes `localhost` without DNS. Port zero selects a free local port.
Startup never contacts a peer, requests an introduction, signs, or resubmits
an acceptance. It does not initialize or repair missing or invalid state.

In a second terminal, use the two printed values (keep the `@`):

~~~sh
curl -q --noproxy '*' --max-time 5 --silent --show-error --include \
    --header '@HEADER_FILE' OWNER_STATUS_URL
~~~

For the already-completed Alice, expect HTTP 200 and `{"choice":"completed"}`
with Root stopped. Unselected and pending choices stay unchanged.
This requires a trusted local host: loopback plaintext only, no forwarding or
remote exposure. The temporary status credential grants no signing permission.
Ctrl+C shuts down HTTP before closing the Store and removes only temporary
credentials. Identity, state, unlock and storage-key files persist, including
after errors. Store opening retains the existing block charge described below;
individual status requests perform no encryption.

Optional `--peer-listen 127.0.0.1:0` binds a separate plaintext loopback socket
and prints its actual `GET /peer/introduction` URL. This discloses only this
node's completed introduction (public keys, ancestor links and signatures) to
**any local caller without a credential**. Without the flag, no peer socket
exists and owner behavior is unchanged. The peer socket has no owner routes.
Both servers finish before the Store closes. This is sender-side disclosure,
not discovery, receiver Received/Known changes, present key control,
mutual authentication, a connection, or chat.
`GET /peer/ad` also discloses the explicitly published signed ad with only this node's completed evidence while unexpired and matching the actual bound endpoint; it never renews state or establishes verified reachability or device usability.

The evidence credential also permits `POST /owner/introductions/fetch` with
only `peer_url` in its JSON body. The Go node fetches that exact loopback
`/peer/introduction` URL and saves validated evidence under its own Root in
Received, without Known promotion. See `node serve --help` for the bounds.

Review order: destination/client boundary in `internal/ownerapi/fetch.go`,
Received-only save and credential routing, then focused two-Vault fetch tests.

The operational `node serve` credential also permits explicit
`POST /owner/pw/invitations/redeem`. Its exact JSON object contains
`target_public_key_hex`, `invitation_id_hex` (64 lowercase hex characters),
and `audience` (`Any` or `Directed`), limited to 512 bytes. Directed means the
requester's pinned identity. The selected peer must already be Known and have
matching received and verified signed ad evidence. The ad supplies the only
permitted endpoint. Earlier credential constructors do not grant redemption.

Redemption saves one canonical signed attempt in Alice's Vault before one
five-second-bounded request to Bob's opt-in `POST /peer/pw/establish`. Bob's
existing commit precedes his response; Alice then verifies it and atomically
saves her acceptance history and local holding in her own Vault. No transaction
or service lock spans HTTP, and no third establishment ACK is sent. A later
Bob Deny cannot recall an already-sent response. Success reports
`acceptance_saved: true` and `local_held: true/false`; this is retained local
state, never shared readiness, current peer consent, `PWOpen`, or Trust.

This slice permits **one saved requester attempt and one acceptance/holding per
Vault**. Conflicting descriptors, peers or roles fail closed. The new
`local-pw-attempt-v1` record contains the full signed request; existing bounded
`local-pw-accepted-v1` and `local-pw-held-v1` formats are reused with exact role
and request-digest checks. Existing Bob records are unchanged. There is no
migration, catalog, replacement, cleanup or repair operation.

Transport failure reports an unknown peer outcome and retains the attempt.
Only a later explicit owner invocation can resend its exact bytes. After a
local commit, owner retries read history without peer confirmation, a new
establishment signature or encryption; history cannot recreate a deleted local
half. Current local guards still apply, including exact ad evidence and local
expiry. Clock rollback is not prevented. Alice needs no peer listener, and
startup/ad discovery never starts redemption. These independent commits are the
bounded invitation extension, not a V19 refinement or cryptographic proof.

## Local PW diagnostics

Enable the existing glog stream separately in Alice's and Bob's terminals:

~~~sh
tdc --v=1 node serve --dir NODE_DIR --unlock-file NODE_UNLOCK_FILE \
    --storage-key-file NODE_STORAGE_KEY_FILE --root ROOT_PUBLIC_KEY_HEX
~~~

This placement is exercised by `TestServePWDiagnosticsCLI`, which builds and
launches the actual CLI and invokes bootstrap over HTTP. Bob also needs the
existing `--peer-listen 127.0.0.1:0` option for publication and peer operations.
Diagnostics go to stderr; the default verbosity remains quiet. Normal startup
output, including the raw COSE public-key hex, is unchanged.

**Device authorization is mandatory for initial PW establishment, not an
optional UI enhancement.** Each node needs its own Known introduction evidence
(or the pinned Root self case), explicit `/owner/device/bootstrap`, and an
invocation-time usable signer. Stored authorization alone does not prove that
the signer is usable. `already_authorized` does not perform a new signer probe.

Example sanitized messages (glog's timestamp/source prefix omitted):

~~~text
intro_pw op=device_bootstrap side=local stage=authorization result=refused reason=own_introduction_not_known
intro_pw op=redeem side=requester stage=attempt result=refused reason=device_not_authorized
intro_pw op=redeem side=requester stage=attempt result=committed
intro_pw op=redeem side=requester stage=peer_exchange result=started
intro_pw op=establish side=acceptor stage=acceptance result=committed
intro_pw op=establish side=acceptor stage=reply result=retained
intro_pw op=redeem side=requester stage=acceptance result=committed
intro_pw op=first_use side=requester stage=await result=committed
intro_pw op=first_use side=requester stage=peer_exchange result=unknown reason=undetermined
~~~

Use the terminal/process to distinguish nodes: `requester` is Alice, `acceptor`
is Bob, and `local` covers bootstrap, publication and invitation issue on the
operating node. No identity or session correlator is logged. Concurrent owner
operations can interleave; these lines are not a distributed trace.

HTTP 409 remains intentionally ambiguous. For redemption, `stage=attempt`
refusal stops before peer HTTP for that invocation; `stage=peer_exchange
result=started` means the saved attempt reached the exchange call.
`result=accepted` admits a request for processing only. `result=committed`
follows successful Vault commit; `retained` reports existing exact state or a
guarded read-only reply. Publication commit is not peer-side verification.
First use separates Alice's `await`, Bob's `receipt`, and Alice's verified
`ready` commit. None creates shared `PWOpen` or Trust.

Proven establishment reasons include missing own/peer Known evidence,
`device_not_authorized`, `signer_unusable`, `policy_deny`, missing/changed ad
evidence, and incompatible invitation/attempt state. Some checks remain grouped:
`ad_invalid_or_expired`, `ad_unavailable_or_mismatched`, and publication's
`device_not_authorized_or_unusable`. First use identifies a failed signer probe
and an already saved session; most first-use guards, Bob's saved-reply checks,
and otherwise indistinguishable failures use `undetermined` at the actual
stage. The stream adds no reads, signer probes, retries, or replacement state.

An HTTP 502 or `peer_exchange result=unknown` cannot distinguish non-delivery,
peer refusal, invalid response, or a lost reply after Bob committed. Alice's
later local refusal also cannot undo or determine Bob's outcome. Bob's
`response result=prepared` proves neither delivery nor Alice's acceptance or
Ready; there is no third acknowledgement. `response_received` alone is not
authenticated acceptance. Local Ready is historical: neither node learns the
other's later Deny/delete from these logs. Never infer remote rollback or
automatically retry; first use is one-shot and invitations/attempts cannot be
replaced.

## Authenticated first use

After Alice has independently accepted Bob's establishment response, her
operational `node serve` credential permits `POST /owner/pw/first-use` with
exactly `{}` (at most 64 bytes, including surrounding whitespace). This explicit
operation sends one signed ping for the sole saved relationship. Startup,
redemption, discovery and peer requests never initiate it. Older credential
constructors retain their previous scopes. Alice needs no peer listener.

The owner operation commits `Await` before a single outbound POST to the saved
ad's `/peer/pw/first-use` endpoint. Bob's opted-in peer listener authenticates
the request against his own accepted history and holding, then commits his
one-time receipt before returning a separately signed response. Alice verifies
the response against her saved request and commits `Ready` under her own
current guards. Only then does her owner response report
`{"local_ready":true}`. Bob never waits for another acknowledgment.

Each endpoint checks its own current Known, non-Deny, authorized usable software
device, exact acceptance and retained `PWHeld`. The original signed request and
ad remain authenticated historical binding evidence. An expired public ad or
consumed invitation does not demand renewal or re-establishment for first use.
No current-ad lookup or remote policy oracle supplies authority. Existing
establishment and retry guards remain stricter and unchanged.

| Model operator | Go boundary and local effect |
|---|---|
| `SendFirstUse` | `pw.SaveFirstUse` commits Alice's exact signed request and `Await`; `pw.SendFirstUse` sends it after all locks are released. |
| `BobFirstUse` / `BobCanUse` | `pw.BobFirstUse` authenticates, probes and signs under Bob's existing owner lock, rechecks durable guards in one update, and saves his exact receipt before returning response bytes. |
| `ReceiveFirstUse` | `pw.ReceiveFirstUse` authenticates Bob's response, probes Alice's signer, and rechecks her guards, exact outstanding request and deadline in the `Ready` update. |
| `ExpireFirstUse` | `pw.ExpireFirstUse` locally changes `Await`/`Ready` to `Expired` on explicit deadline evaluation or cancellation; evidence remains saved. No HTTP cancellation route or timer is added. |

The session uses 32 random bytes from `crypto/rand` and a fixed 60-second UTC
deadline. That lifetime is engineering policy, not a TLC-proved duration.
Clock input is injectable in private action tests; HTTP callers cannot select
it. Bob and Alice require `issued <= local now < expires`, without clock-skew
allowance. Real-clock rollback is not prevented. Explicitly committed `Expired`
cannot be revived even if the clock later moves backward.

The two additive, encrypted v1 CBOR records are `local-pw-first-use-v1` (Alice's
version, state, exact signed request and optional response) and
`local-pw-use-seen-v1` (Bob's version, exact request and response). Absence of
Alice's record denotes Idle; no earlier record format changes or migration is
needed. A session cannot be replaced, including after failure or expiration.
Bob refuses every duplicate without another write or success. An exact Alice
Ready response duplicate is at most a guarded no-write observation; conflicting
bytes, expiry and deleted holdings fail closed. History never restores a holding.

Transport uses the existing bounded direct loopback HTTP policy: one five-second
POST, version-1 JSON containing base64 canonical CBOR, at most 3 KiB per envelope
and 2 KiB per signed body, no redirects, proxies or forwarded owner credentials,
and `Cache-Control: no-store`. First-use request, response and request digest
have separate signing/hash purposes. The request binds the complete established
binding and original signed request digest; the response also binds the exact
signed first-use request digest. `heldEvidence` is Alice's signed assertion,
not access to her current Vault or proof of future consent.

Network failure reports an unknown peer outcome with `Await` retained. There is
no automatic retry, and another owner invocation cannot resend this session.
Lost success may therefore leave Bob's receipt committed while Alice stays
Await. `Ready` is historical local evidence: Bob may already have denied or
deleted his half when an in-flight response arrives. Neither observation
implies current mutual permission, a live transport connection, shared persisted
`PWOpen`, Trust, V19 `StrongUsePW`, AKE, session keys or liveness. This remains
one session per accepted attempt, not a V19 refinement or cryptographic proof.

Conformance tests are the `FirstUse`/`SendFirstUse` tests in `internal/pw`,
`internal/ownerapi`, `internal/peerapi` and `cmds/node`. They cover ordered
two-Vault loopback commits, exact restart retention in real `nodevault` stores,
lost responses, replay, deadline boundaries with deterministic action clocks,
local guard changes during probing/signing, callback/encryption/Linux backend
commit failures, lock ownership, strict envelopes and credential isolation.
The node scenario compares surrounding logical state to exclude Trust, open
state and unrelated mutations. No TLC run or broad power-loss/rollback proof
is claimed.

## Candidate local outgoing message

PW-Msg-Go-01 projects only the PW-Msg-02 candidate's `CreateOutgoing` into a
private `internal/pw` function. Under the existing owner mutation/signer lock,
either participant can persist one immutable `local-pw-message-outgoing-v1`
canonical CBOR record in its encrypted Vault: random UUIDv4-style ID, 1–1024
UTF-8 bytes, sender/receiver role and exact accepted-request/history digests.
The strict bound is **one outgoing message per Vault**, including Bob first;
no inbox or message from Alice is required. This means `submitted locally`.

Creation and exact repetition require authenticated accepted history, retained
holding, own/peer Known, no local Deny and an authorized, freshly probed usable
installed signer. Alice needs validated Ready or Expired retaining a verified
response; Bob needs validated useSeen. These are historical local observations,
not reachability or remote current permission. Ad/invitation expiry does not
invalidate an accepted relationship. Exact repetition returns the saved bytes
without a new message ID or write; conflicts/corruption fail closed. Missing
records need no migration; unknown versions are refused, never overwritten.
An uncertain result requires storage inspection, with no automatic retry.

PW-Msg-Go-02 adds private `prepareOutgoingEnvelope` under the same owner lock.
It stores one canonical `[1, exactOutgoingBytes, signature]` envelope in
`local-pw-message-envelope-v1`, signing with the installed ES256/P-256 identity
and `pw-message-auth/v1` purpose. The unchanged outgoing payload binds sender,
receiver, role, ID, text and the exact signed request/accepted-history digests;
both independently retained histories agree on these digests. Signing is outside
the transaction; durable guards are rechecked before the single-row commit.
Restart or a lost result reuses identical saved bytes without another message
signature or write, after current guards and a fresh signer-usability probe.
Corruption/conflicts fail closed. Text is **not encrypted by this envelope**.
This preparation does not advance `Transmit`, set `sent`, contact a peer or
establish delivery, Trust or `PWOpen`. Transport, confidentiality,
additional messages, general protocol
concurrency and UI remain unimplemented. No endpoint, CLI or startup exposes
this operation, and no distributed refinement or contract promotion is claimed.

PW-Msg-Go-03 adds private `admitIncomingEnvelope`, projecting only the candidate's
receiver-local `AcceptIncoming` under the same owner lock. Each receiver derives
the peer's binding from its own authenticated acceptance and historical first
use, verifies the unchanged v1 envelope, probes its installed signer outside
transactions, and rechecks current durable guards before one inbox-row commit.
The bounded `local-pw-message-inbox-v1` row retains exact envelope bytes; either
participant may send first without a receiver outgoing message. Exact retries
after reopen are read-only with no seal; conflicts and corrupt rows fail closed.
Local Deny/Delete refuse even identical retries while preserving inbox history.
The boolean outcome means only local durable admission, with no receipt or
remote success guarantee; uncertain outcomes require explicit Vault inspection.
Receipt issuance is separate from admission. No HTTP or UI is added.

PW-Msg-Go-04 adds private `issueMessageReceipt`, projecting only `ReturnReceipt`
under the same owner mutation/signer lock. A prior exact authenticated inbox
commit is mandatory. Receiver-local Known, holding, non-Deny, authorization and
validated historical first use are rechecked before and after signing, with
signer usability probes outside transactions. The canonical receipt is bounded
to 640 bytes and signs the exact envelope hash, original ID and sender/receiver,
Root, role and request/accepted-history digests using ES256/P-256 and
`pw-message-receipt-auth/v1`. It contains no message text. Explicit repetition
may produce different signatures over the same payload, with no Vault update
or seal. The pure verifier uses the trusted saved envelope and independently
authenticated receiver binding; historical receipts remain verifiable after
Deny/Delete without restoring permission. This is a receiver's assertion of
prior commit, not proof of honest storage, sender observation or delivery.
Sender-local observation is separate from issuance.

PW-Msg-Go-05 adds private `observeMessageReceipt`, projecting only historical
`ObserveReceipt` under the existing owner mutation lock. It authenticates local
accepted/first-use history, outgoing bytes, the exact committed signed envelope
and receiver receipt again inside one sender-local ACK transaction. The bounded
canonical `local-pw-message-ack-v1` row preserves the first signed receipt bytes;
equivalent valid signatures repeat read-only with no seal, including after
reopen. Deny, holding deletion, lost Known/device authority or an unusable signer
do not block this history-only write; no signer is needed and no permission or
holding is restored. Corrupt or conflicting evidence fails closed. The receiver's
assertion is not proof of honest remote storage or present permission. Tests
cover both senders, late ACKs, isolation, signature variability, rollback and
Linux backend/reopen behavior. No `sent`, transport or UI is added. The next
separate increment is the explicit transport/`Transmit` boundary, not Flutter
chat; no normative contract promotion or distributed refinement is claimed.

PW-Msg-Go-06 adds only opt-in loopback `POST /peer/pw/message`: bounded JSON
`{"version":1,"envelope":"<canonical-base64>"}` (4 KiB) returns
`{"version":1,"receipt":"<canonical-base64>"}` (2 KiB). The operational
receiver capability holds the existing owner mutation/signer lock across
`AcceptIncoming` then `ReturnReceipt` for the exact envelope, releasing it before
HTTP output. A signing failure or lost reply can leave the inbox committed;
there is no rollback or automatic retry. An authorized exact retry is read-only,
including after reopen; receiver Deny/Delete refuses new processing and retains
history. The owner listener returns 404 without a bearer challenge, and no peer
route is enabled without `--peer-listen`. The signed envelope contains plaintext:
this is loopback-only demo transport, not E2EE, a secure channel or anonymity.
Sender HTTP `Transmit`, explicit `sent` and receipt observation wiring remain
the next increment; this operation writes no sender state and promotes no
candidate semantics or normative contracts.

PW-Msg-Go-07 adds private `saveMessageTransmit` and `sendMessageOnce`, with no
owner action or UI wiring yet. Under the existing owner mutation/signer lock,
current local guards and authenticated history authorize the exact prepared
envelope; one canonical `local-pw-message-sent-v1` row binds its tagged digest.
`sent` means an attempted send was authorized, never proof of dispatch or
admission. An explicit permitted retry returns identical bytes without a write
or seal. After releasing all locks and transactions, the client makes one POST
to an explicit canonical numeric loopback HTTP `/peer/pw/message` URL using the
Go-06 JSON shapes above (padded Base64). It bounds the exchange to five seconds,
1 KiB response headers, 2 KiB response JSON and 640 decoded receipt bytes, with
no redirect, proxy or automatic retry. Invalid preflight input is not dispatched;
transport/response failure leaves the peer outcome unknown. A crash after the
`sent` commit or a lost reply never rolls back history. HTTP 200 returns untrusted
receipt bytes; only a separate Go-05 observation may save ACK, including after
local Deny/Delete. Those changes block new attempts but cannot recall an already
authorized snapshot. The routing hint grants no identity or permission, and
plaintext is suitable only for a trusted-host disposable demo. This remains the
PW-Msg-02 candidate, with no V19 refinement or normative contract promotion.

PW-Msg-Go-08 wires these phases into the operational owner bearer route
`POST /owner/pw/message/send`. After establishment and successful first use,
either node may send first. The sender needs no `--peer-listen`; the receiver
must enable its existing peer listener. Replace `HEADER_FILE` with the sender's
printed header file, `OWNER_PORT` with its owner port, and `PEER_PORT` with the
receiver's peer port:

~~~sh
curl -q --noproxy '*' --max-time 10 --silent --show-error --include \
  --header '@HEADER_FILE' --header 'Content-Type: application/json' \
  --data-raw '{"text":"Hello","peer_message_url":"http://127.0.0.1:PEER_PORT/peer/pw/message"}' \
  'http://127.0.0.1:OWNER_PORT/owner/pw/message/send'
~~~

Exactly those two JSON fields are required (2 KiB request; 1–1024 UTF-8 text
bytes). The URL must use canonical numeric loopback (such as `127.0.0.1` or
`[::1]`), an explicit nonzero port and that exact path, without query/fragment.
It is only a routing
hint, supplying no identity, consent or authority. HTTP 200 with
`{"local_acknowledgement_saved":true}` means the sender authenticated and saved
the historical ACK. A receiver signature asserts acceptance; it cannot prove
honest storage. Each local preparation step commits separately before HTTP;
409 means no POST began, but earlier local commits may remain. After an HTTP
attempt, 502 means the peer outcome is unknown, including when local ACK storage
fails after receiver commit. Nothing is rolled back or retried automatically.
Only an explicit identical-text retry may reuse the saved ID/envelope/sent and
inbox under current guards; different text is refused. Sender Deny/Delete during
HTTP still permits the valid late ACK, but blocks later sends/retries. One
outgoing and one inbox per Vault remain; this is a plaintext local demo, not a
chat API. Startup and reads remain inert; older credentials and peer listeners
exclude this owner action.

PW-Msg-Go-09 adds operational bearer `GET /owner/pw/message/inbox`, with no
body or selectors. It returns exactly `{"present":false}` for valid history
without an inbox, or `{"present":true,"message_id_hex":"<32 lowercase hex>",
"text":"..."}` for the locally committed, authenticated single incoming message.
One read transaction verifies exact accepted history, successful historical
first use and the retained signed envelope. Reads survive Deny, holding deletion,
Known/device loss, signer loss and reopen; they grant no new communication
permission, ACK, Trust or `PWOpen`. No signing, peer contact or Vault write occurs.
Responses are `no-store` and at most 2 KiB; invalid evidence or JSON escaping
beyond that bound returns fixed 409 without plaintext or truncation. Malformed
GET shape returns 400, wrong methods 405 and path variants 404. Older credentials
exclude this read; peers return 404 without a bearer challenge. Startup/status
never inspect the inbox. This remains one message per direction; the next
increment is Flutter send/receive widgets over Go-08 and this GET.

## Local held-half deletion

The operational `NewFirstUseCredentials` composition used by `node serve`
adds exactly `POST /owner/pw/holding/delete` with `{}` and the existing owner
bearer credential. The strict empty-object parser allows surrounding JSON
whitespace, limits the body to 64 bytes, and rejects selectors and extra fields.
No peer, Root, attempt, invitation, endpoint, clock or scope is supplied.
Earlier credential constructors and every peer listener exclude this route.
There is no requirement for `--peer-listen`; startup and binding never delete.

`pw.DeleteHeldLocal` takes the already-bound local Vault and independently
pinned Root/local configuration. Under the owner's existing mutation lock,
one `Vault.Update` authenticates the accepted request/response, its role-specific
consumed invitation or saved attempt, retained first-use observations, and the
canonical holding digest. It deletes only `local-pw-held-v1`. A valid unused
invitation or pending attempt can coexist with no holding; deletion then makes
no change and does not prevent otherwise eligible later acceptance. Inconsistent
or corrupt state fails closed without repair. No persistent format changes,
new tombstones or migration are introduced.

The response is `{"deleted":true}` only after durable commit, or
`{"deleted":false}` for valid absent/already-deleted state. The mutation lock
is released before response I/O. Failure returns the existing generic conflict
response. No-op paths abort the update without backend bookkeeping. Even a
successful deletion needs no encryption allowance: storage deletion performs
no seal. No signer, current ad, expiry, device probe or remote query is needed.

| Invitation model responsibility | Go evidence |
|---|---|
| `ChangeBob(n, "Delete")` / `ChangeRequester(n, "Delete")` | Only the caller's accepted holding is removed; the other Vault is unchanged. |
| `HistoryIsDurable` / `PolicyAndCrashSafety` | Consumed invitation, signed attempt/acceptance, first-use observations and unrelated records retain their exact bytes across deletion/restart. |
| `HistoryNeverResurrects` | Existing immutable acceptance prevents re-creation; Bob retry and current first-use guards reject missing holdings. |
| Checker-only `PWOpen` | No shared flag is written. Retained `Ready`/`useSeen` is historical evidence and cannot override the local holding guard. |

Already-transmitted acceptance may still let Alice accept under her own guards
after Bob deletes; it cannot restore Bob. Alice cannot move from `Await` to
`Ready` after deleting her half, even with a valid delayed response. Existing
local expiry/cancellation remains available. `DenyLocal` retains the holding;
deletion leaves Deny unchanged. Combined Deny-then-Delete tests are engineering
evidence beyond the model's one-invalidation-per-Vault bound.

The `DeleteHeld` tests in `internal/pw`, `internal/ownerapi` and `cmds/node`
cover independent real `nodevault` stores, restart, exact state preservation,
strict owner boundaries, both local commit orders, callback and Linux backend
write failure, and zero encryption allowance. An injected seal failure after
the pending deletion also rolls back; production deletion never seals. This
increment does not implement full V19 `DeleteLocalPW` trust/cache/view/live-pipe
cleanup,
`ReopenPW`, strong use, replacement relationships or remote revocation. It adds
no TLC run, V19 refinement claim or broad crash/backup rollback proof.

## Local Deny

The operational `node serve` owner bearer permits `POST /owner/policy/deny`,
including without `--peer-listen`. Send exactly one JSON field:

~~~json
{"peer_public_key_hex":"<canonical lowercase COSE ES256/P-256 public key hex>"}
~~~

The complete body is limited to 512 bytes. Duplicate, unknown or alias fields,
trailing JSON, invalid/noncanonical/self keys, query/fragment variants, content
encoding and trailers are rejected. Root, local identity and Vault come only
from the pinned service configuration. A peer need not already be Known.
Earlier owner credentials and peer listeners do not expose the route.

The existing `policy.DenyLocal` runs under the same owner mutation lock as
invitation, acceptance, publication and first-use operations. Only the encrypted
`local-denied-peers-v1` row changes, using its existing format and 32-peer bound.
After commit and unlock, the response is `{"changed":true}`. An exact repeat
returns `{"changed":false}` with zero Vault writes, seals or encryption usage,
even with exhausted allowance. Denial makes no signer/device probe, peer request
or background action. All responses are `no-store`; errors contain fixed status
text: malformed input is 400, full policy is 409, unavailable/corrupt state is
500 (method/media/body limits retain the existing 405/415/413 responses).

| Invitation model responsibility | Local implementation and evidence |
|---|---|
| `ChangeBob(n, "Deny")` (205–211), `ChangeRequester(n, "Deny")` (213–219) | Owner-selected peer added only to the operating node's policy. Real independent Vault snapshots show all other records and peer files unchanged. |
| `BobPermits` / `RequesterPermits` (55–62), `ExactRetry` (74–80), `BobCanUse` (169–174) | Existing guards reject new acceptance, exact reply, saved attempt, requester acceptance and first use when their own local policy denies. No alternate guard or state machine is added. |
| `HistoryIsDurable` / `PolicyAndCrashSafety` | Consumed invitation, exact signed request/result, holding, Await/Ready/Expired and useSeen survive Deny and real `nodevault` restart. |
| Checker-only `PWOpen` (308–325) | Persisted Ready remains historical evidence. No shared open flag or remote authorization query exists. |

An already-transmitted acceptance or first-use response can still be accepted
under the recipient's own unchanged guards. Bob Deny prevents his subsequent
current-guard operations; it cannot recall bytes or mutate Alice's Vault.
`DeleteHeldLocal` removes holding without writing Deny; Deny preserves holding
and cannot reconstruct a deleted half. Combined Deny/Delete tests and repeated
targeted denial are engineering behavior beyond the model's one-fault-per-Vault
bound. No multi-peer proof follows.

The `Deny` tests cover strict owner boundaries, exact no-write retries, storage
failure/corruption, restart, local preemption, delayed responses and deterministic
owner-lock/Vault ordering. This increment implements action-map section 3.1 and
conformance matrix section 9's local Deny projection only. It adds no Allow,
live-pipe closure, Trust, peer-view changes, StrongUse or AKE; it claims no full
V19 `DenyPeer` refinement, TLC run or cryptographic proof.

## Create and inspect a saved identity

Use an existing, trusted, user-owned parent outside this repository.
For example, if `/home/alice/playground` already exists and belongs to you,
choose these disposable paths (replace `alice` with your own account):

~~~sh
go run ./cmd/tdc node init --dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock
go run ./cmd/tdc node info --dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock
go run ./cmd/tdc node info --dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock
~~~

Each invocation exits. All three print the same full CBOR public key:

~~~text
node public key (hex): <full CBOR public-key hex>
~~~

Both flags are required and positional arguments are rejected.
`init` creates a new mode-0700 node directory containing mode-0600
`identity.json`, plus a separate, new mode-0600 unlock file.
Both parents must already exist. The unlock file must be outside node state.
Its 32 raw random bytes wrap this one identity; this is not a password file.
Existing paths are never reused or overwritten, including symlinks.
`info` reads existing files only and restores a signer using a fresh backend.
Reads reject final-component symlinks, non-regular files, and group/other
permission bits. Existing permissions are never silently changed.

The record contains only a development format version, public key, and encrypted
private-key representation. That representation and the unlock file are private
local material: never publish them as peer evidence, QR data, or logs.
Keep both files under your ownership. Anyone with both can restore the signer.
Losing the unlock file makes this playground identity unusable.
There are no recovery, export/import, backup/restore, migration, rotation, or
multi-identity key-reuse commands. Incompatible development formats fail
explicitly; no migration or backup/restore support exists before v1.0.

Initialization is not a multi-file transaction. A failed initialization leaves
any exclusively created directory or partial files for explicit operator
inspection/removal. A retry refuses those paths; it never repairs them.
An output failure also reports failure but keeps an already saved identity.
Checked writes and closes do not promise power-loss durability.

This Linux-focused playground provides software key storage on a trusted host,
not hardware protection, UI-controlled delegation, or rollback resistance.
It does not defend against a hostile same-user process replacing ancestor paths
and does not claim secure erasure of all backend or Go-heap copies.
The separate unlock file leaves room for future owner-supplied credentials;
it is not a distributed-key-management decision.

Use this saved identity in the existing HTTP Root command:

~~~sh
go run ./cmd/tdc intro http-demo root \
  --identity-dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock \
  --listen 127.0.0.1:0
~~~

Its public key equals `node info`. Stop with Ctrl+C and repeat the Root command,
without another `init`: the key stays the same and port zero may change the
endpoint. Follow the [HTTP walkthrough](../intro/README.md) for fresh exchanges
and Alice's `--owner-listen` status option.
Both saved-Root flags must be supplied and nonempty; omitting both keeps the
fresh-Root behavior. Failed loading never generates a replacement key.

In that fresh-Alice example only Root's signing identity survives.
Its issued offer stays in memory. For persistent Alice, use `init-state` below
and all three saved-state flags on HTTP accept.
`node init`, `info` and `init-state` start no network service;
`node serve` runs the local service described above.
HTTP shutdown leaves identity files intact.

This operation persists local key material only. It creates no introduction,
membership, `Known`, trust, pairwise, or device-authority transition, does not
resolve V19 global-parent uniqueness, and authorizes no new modeled action.
Saving Root's key does not establish root authority or implement V19 `Introduce`;
Alice's caller still supplies the public expected root independently.

Review order: README -> Root selection in `cmds/intro/http_demo.go` -> shared
loader in `internal/nodeidentity/files.go` -> saved-identity exchange test in
`cmds/intro/http_identity_test.go`. Existing cross-process restore coverage
remains in `TestIdentityAcrossProcesses` in `internal/nodeidentity/identity_test.go`.

## Prepare Alice's persistent local state

The one new command is `tdc node init-state --dir ALICE_DIR
--unlock-file ALICE_UNLOCK_FILE --storage-key-file ALICE_STORAGE_KEY_FILE
--root ROOT_PUBLIC_KEY_HEX`.
All four flags must be supplied and nonempty; positional arguments and `--force`
are rejected. `node init` and `node info` are unchanged.
The identity and both parent directories must already exist.
Root is explicit expected public-key hex (nonempty, at most 16 KiB decoded),
not evidence that the supplied Root is authoritative.
Child comes from the restored identity.

Initialization exclusively creates the private `ALICE_DIR/state` directory
and a new mode-0600 file holding 32 independent random raw storage-secret bytes.
The storage-key file must be outside the entire identity directory and distinct
from the unlock file after parent normalization.
Existing paths, including symlinks, are refused without overwriting or repair.
The identity record and unlock file remain unchanged.
The Store closes before the command prints Alice's actual public key and
`local state initialized: true`.
An error may leave exclusively created partial files for explicit inspection;
it never deletes persistent files or switches keys.

Follow the single [saved-Alice HTTP walkthrough](../intro/README.md#restart-saved-alice-in-the-http-exchange)
for placeholder replacement, explicit preparation, two separate accept
invocations, and authenticated owner status.
Keep Root running for that accept exchange: its retained proposal is in memory.
The status-only `node serve` command needs no running Root.
Restarted Root returns `409` to Alice's saved acceptance; Alice keeps her choice
and never requests a replacement offer.
Owner shutdown removes only that invocation's temporary credentials, retaining
Alice's identity, state, unlock and storage-key files.

`internal/nodevault` now retains one Alice's proposal and acceptance across
process exit, using the saved identity and existing onboarding operations.
`CreateForNode` provisions the independent storage secret;
`OpenForNode` requires existing private material and never provisions it.
The underlying `Create`/`Open` APIs still borrow caller-supplied secrets.
Each invocation supplies expected Root and restores Child; the Store checks
the same binding using private layout IDs `VaultID{1}` and `KeyID{7}`.
These are neither secrets nor global node IDs, and are not CLI options.
A dedicated private directory holds encrypted `vault.db` and plain `usage.db`.
Each opening charges up to 4096 encryptions toward a fixed `1 << 24` limit.
Unused capacity is discarded; exhausting a block requires an explicit reopen.
At the lifetime limit, reads and completed-result reuse still work.
The exclusive usage-file lock permits one active Store for this file pair.
Copies, rollback, backups, restores, migrations, compatible upgrades and full
power-loss recovery are unsupported. There is no migration/backup support
before v1.0. This is temporary trusted-host file provisioning, not final
UI-assisted key management/delegation. Helper processes may sign/decrypt for
their owners within that trust boundary; no remote plaintext exposure or new
authority guarantee follows. HTTP 204 is still an unsigned peer report.
Read `ExampleStore`, then `Create`/`Open`/`Close`, the private provider, and
`TestStoreAcrossProcesses` for the bounded two-process acceptance retry.

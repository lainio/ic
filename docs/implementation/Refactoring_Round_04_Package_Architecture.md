# Refactoring round 04: package architecture and v1 policy

Review date: 2026-11-17. **Recommendations for owner review, not authorization
to implement.** The only repository change in this round is this report.

Recommend retaining `internal/pw` as the owner of the current bounded local
relationship and protocol records, and first extracting its message HTTP
dispatch implementation behind the existing PW entry points. Preserve the
owner-service mutation lock, all transaction boundaries, and both wire
versions. Prefer contact-bound v2 for new demonstrations; retire active v1
protocol use only after replacing its manual callers and deciding how existing
state will be supported. A package split by version would obscure shared
storage ownership and is not recommended.

## 1. Baseline, authority and inspection scope

| Repository | HEAD | Branch | Initial state |
|---|---|---|---|
| Go: `/home/parallels/go/src/github.com/lainio/ic` | `b27f3db9bace612a043a96c9a4a7005afbd82b61` | `tla-spec-based-refactoring-v1` | Clean; exactly the accepted baseline |
| Read-only spec: `/home/parallels/go/src/github.com/optechlab/intro-tree` | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | `break-demo` | Modified `models/active/IntroTreeV19.tla` only |

Read the Go root `AGENTS.md`, `internal/core/AGENTS.md`, `storage/AGENTS.md`
and spec root `AGENTS.md`. No further applicable instructions were found under
the inspected package or documentation trees. Read all five requested Go
references: `Current_Go_Implementation_Reality.md`, Round 01 baseline, Round
03B cost inventory, Round 03C fast target and Round 03D receipt verification.
Their historical observations are distinguished below from current source.

Semantic sources, all relative to `SPEC_REPO`:

- `docs/IntroTree_Model_Index.md`, especially section 5.1.
- `docs/contracts/IntroTree_StateSemantics_Contract.md`, especially the
  invitation extension and retained V19 lifecycle contract.
- `docs/contracts/IntroTree_Implementation_Action_Map.md`, especially 3.1.
- `docs/contracts/IntroTree_Conformance_Test_Map.md`, especially section 9.
- `IntroTreePWInvitationV1.tla` and
  `docs/architecture/IntroTreePWInvitationV1.md`, reached through the index.
  This includes the accepted contact amendment, independent local commits,
  checker-only `PWOpen`, and the distinction between safety checks and
  scheduled existence witnesses.
- The invitation documentation's separately referenced
  `docs/architecture/IntroTreePWMessageV1.md`, describing PW-Msg-02's symmetric
  message initiation and late historical ACK. This remains a separate model
  slice with assumed establishment/first-use history.

The dirty V19 mutation restores `SnapshotRecoveryGrant` into `RecoveryGrant`.
It is **not accepted semantics**. The committed V19 restore action, inspected
with read-only `git show`, leaves both recovery authority sets unchanged.
The initial working-file SHA-256 is
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`.
No model execution or modification is part of this review.

The model's `V1` suffix does not select a Go wire version. The older statements
that `PW-Contact-Go-01` is unimplemented are stale at this Go HEAD. For example,
`internal/ownerapi/establishment.go:93` invokes `pw.BobAcceptV2`, and
`redeem.go:162` prepares a v2 request from the bound local listener.
The comment in `internal/pw/bob_accept_v2.go` saying it is unwired to HTTP is
also stale. No existing comment or report was edited.

Inspection began with PW declarations, implementations and imports, then
followed production callers, transaction helpers, HTTP composition, demo
setup, Flutter requests and relevant compatibility tests. `go doc
./internal/pw` cross-checked the exported surface. Import relationships below
come from live production imports, with concrete calls/types checked in source;
test-only dependencies are discussed separately.

## 2. Actual implementation architecture

### 2.1 `internal/pw`: responsibilities and API

There are 44 production Go files in this package. It is substantially more
than the local-prerequisite helper described by its package comment.

| Exported API family | Current responsibility and caller |
|---|---|
| `CheckLocalAcceptor`, `ProveLocalAcceptance`, `VerifyLocalAcceptanceProof`, `RequestRemoteAcceptance` | Momentary local eligibility, challenge-bound signatures and the earlier two-POST observation protocol. `ownerapi/acceptance*.go` and `peerapi/acceptance.go` use these; they do not establish a held relationship. |
| `IssueInvitation`, `ReadInvitation`, `RevokeInvitation`, `Invitation` and audience/state/TTL constants | One owner-issued local invitation. Owner HTTP issuance/revocation and the bound establishment capability call them. The stored row remains version 1 for both establishment versions. |
| `SaveAttempt`, `SendEstablish`, `BobAccept`, `BobReply`, `ReceiveAcceptance`, and their `V2` counterparts | Persist requester attempt, transport it, commit Bob, retrieve guarded exact success, independently commit Alice. `ownerapi/redeem.go` coordinates Alice; `ownerapi/establishment.go` coordinates Bob. |
| `Establishment`, `Accepted`, signed wrappers, and v2 equivalents; purpose/size constants | Canonical CBOR evidence, exact request digest and signature domains. V2 adds both service contacts; v1 types are not aliases for v2. Exporting these representations does not make them authorization capabilities. |
| `SavedAttempt` / `SavedAttemptV2` | Owned snapshots with private request/routing data and public local `Accepted`/`Held` observations. Callers cannot construct a useful send snapshot from arbitrary bytes through public fields. |
| `BobContactV2`, `RequesterContactV2`, usable counterparts, `ContactRuntimeV2` | Historical contact projection and separately guarded local eligibility. Runtime is trusted service configuration, not peer input. Direct contact APIs have test callers; production first-use/message code uses the underlying history/guard functions. |
| `SaveFirstUse`, `SendFirstUse`, `BobFirstUse`, `ReceiveFirstUse`, `ExpireFirstUse`, v2 equivalents, saved and signed first-use types | Alice Await, Bob observation, Alice Ready and explicit expiration are distinct local operations. Owner/peer first-use handlers compose them. Expiration APIs also have direct test coverage; they are not a background service. |
| `DeleteHeldLocal` | Deletes only the local held record after authenticating retained history; called by owner deletion. |
| `PrepareMessageSend`, `SendMessageOnce`, `ObserveMessageReceipt`, v2 equivalents, input validators and prepared/receipt types | Compose independent outgoing/envelope/sent preparation, unlocked HTTP, then sender-local historical ACK. `ownerapi/message_send.go` owns the orchestration across those phases. |
| `CreateOutgoingV2`, `PrepareOutgoingEnvelopeV2`, `AdmitIncomingEnvelopeV2`, `IssueMessageReceiptV2` | Explicit individual v2 message actions; called by PW composites and tests. Their v1 individual counterparts are private. This asymmetry is real, not a reason to export all v1 internals. |
| `AcceptMessageAndReceipt` / `V2`, `ValidateLocalMessageReceipt` / `V2`, message byte bounds | Receiver admission followed by receipt issuance; the validation functions check trusted local capability output before HTTP serialization. Owner receiver capability and peer adapter use them. |
| `ReadMessageInbox` / `V2`, `MessageInbox` | Authenticated historical inbox read, used by the owner inbox route. |

Public error families distinguish invalid local prerequisites, invitation
state, establishment refusal versus unknown exchange outcome, first-use
refusal versus unknown exchange outcome, deletion failure and message
pre-dispatch failure. Message action errors and record-conflict sentinels are
mostly private. Exact error identity and sanitization are tested behavior.

### 2.2 Classification of every production file

Categories are nonexclusive: **A** pure representation/encoding/evidence
verification; **B** current local authorization and durable actions;
**C** coordination of independent actions; **D** HTTP processing;
**E** shared implementation infrastructure; **F** other responsibilities,
principally storage-backed historical projections. A read-only history reader
is not a pure function merely because it makes no writes.

The following paths are relative to `internal/pw`. Paired names cover both
files explicitly. Private helpers remain associated with their listed action
unless separately called out.

| Production files | Categories and functions/responsibilities |
|---|---|
| `local.go` | **B** `CheckLocalAcceptor`; **A** canonical P-256 `validPublic`; **E** `localSigner`, sanitized error translation. Legitimate shared preflight and signing boundary. |
| `acceptance.go` | **A** `acceptancePayload`, digest/input checks, `VerifyLocalAcceptanceProof`; **B** `ProveLocalAcceptance` combines current checks with signing. Verification must remain usable without a Vault or permission check. |
| `invitation.go` | **B** issue/revoke/read validation; **A** invitation representation and explicit time predicates; **E** private key, record codec and `thenRet` error translation. Issuance is not remote coordination. |
| `establishment_wire.go` | **A** v1/v2 request/result types, canonical decoding, request/result authentication, contact syntax/ad-origin derivation; **E** shared refusal sentinel and `guardBinding` projection. `ads.ValidateClaim`/`ads.Current` are actual dependencies despite pure execution. |
| `accepted_v2.go` | **A** v2 result types, exact request digest and `verifyAcceptedV2`. Depends on private canonical/key helpers elsewhere in PW. |
| `establishment.go` | **B** `BobAccept`, `newRedemption`, `currentEstablishmentGuards`, atomic `commitAcceptance`; **E** accepted/held record types and keys plus fixed diagnostic reasons shared with v2. |
| `bob_accept_v2.go` | **B** `BobAcceptV2`, preflight/probe/sign and `commitAcceptanceV2`. Uses shared invitation/held/accepted schema and v1-shaped guard projection, not v1 authentication. |
| `reply.go`, `reply_v2.go` | **B** `BobReply` / `BobReplyV2`: current authorization of read-only exact-result retrieval. No network send and no durable action here. |
| `requester.go` | **B** v1/v2 attempt preparation, v1 requester acceptance and commit/read guards; **E** shared attempt key, unchanged sentinel and opaque saved types; **A** construction of signed evidence. Both versions are actually in this file. |
| `requester_accept_v2.go` | **B** independent Alice acceptance, exact duplicate handling and commit. No Bob transaction or callback. |
| `history_v2.go` | **F/A/E** `readLocalHistoryV2`, pending/legacy validation and holding authentication. Checks complete persisted evidence without current permission; invokes version-specific first-use readers. It owns no new contact row. |
| `contact_v2.go` | **F** historical contact projections; **B** usable projections and `contactGuardsV2`; **E** trusted runtime input. Historical/current separation within one file is intentional. |
| `delete_held.go` | **B** `DeleteHeldLocal` / `deleteHeldInTx`; **A/E** version dispatch and full history checks shared across versions. |
| `establishment_client.go` | **D** POST/strict JSON/HTTP bounds; **A** `SendEstablishV2` reauthenticates its opaque request before deriving destination; **E** exchange error. No Vault or signer. Whole-file movement would drag opaque private types and evidence dependencies. |
| `first_use_wire.go`, `first_use_wire_v2.go` | **A** signed arrays, exact binding/digest verification and freshness predicates with explicit time inputs; **E** shared lifetime, byte bound and error. No persisted readiness. |
| `first_use_state.go`, `first_use_state_v2.go` | **F/A** authenticate retained acceptance and first-use evidence; **B** `firstUseGuards` / `firstUseGuardsV2`; **E** private states/record types/keys. History and current guards are distinct functions. |
| `first_use.go`, `first_use_v2.go` | **B** Save/Await, Bob observation, Receive/Ready and Expire, with independent transaction helpers; **A/E** signed preparation and opaque saved snapshots. No dispatch inside these functions. |
| `first_use_client.go` | **D** one versioned POST and strict response decoding; **E** shared establishment POST implementation and opaque saved types. |
| `message_outgoing.go`, `message_outgoing_v2.go` | **B** create/read-exact-retry/commit; **A** outgoing binding/message types, UUID/text/canonical checks and `decodeOutgoing` / `V2`; **F** v1 accepted-history projection; **E** shared outgoing key/bounds. |
| `message_history_v2.go` | **F/A** `outgoingHistoryV2` authenticates accepted contacts, first use and exact historical result digest; **B** `outgoingPrerequisitesV2` adds current local guards. |
| `message_envelope.go`, `message_envelope_v2.go` | **B** prepare/sign/commit exact outgoing envelope; **A** wire arrays and `decodeMessageEnvelope` / `V2`; **E** shared envelope slot and bounds. Envelope bytes are both wire evidence and stored evidence, a legitimate combination. |
| `message_incoming.go`, `message_incoming_v2.go` | **B** admit/check/commit receiver-local inbox under current guards; **A/E** inbox record codec and exact envelope equality. |
| `message_receipt.go`, `message_receipt_v2.go` | **B** receipt issuance from committed inbox with probes and final guards; **A** receipt payload, envelope digest and pure receipt verification; **E** errors/bounds. Issuance signs but never writes a receipt row. |
| `message_ack.go`, `message_ack_v2.go` | **B** sender-local historical ACK commit; **F/A** evidence-only eligibility and duplicate authentication; **E** shared ACK row/key. Current permission is deliberately absent. |
| `message_transmit.go`, `message_transmit_v2.go` | **B** current authorization and sent-marker commit/read-only retry; **E** opaque immutable send snapshot and shared sent row; **D-adjacent** v2 fixed route derivation/validation. Neither file dispatches HTTP. |
| `message_send.go`, `message_send_v2.go` | **C** preparation composes three independent durable actions; **D** public send facades; **B/F** ACK facade in v1; **A/E** input validators and opaque public types. Keeping these facades protects prepared-state provenance. |
| `message_receive.go`, `message_receive_v2.go` | **C** admission then receipt issuance, with no rollback of admission on later failure; **A** local capability-output verification; **E** public byte bounds. |
| `message_inbox.go`, `message_inbox_v2.go` | **F/A** authenticated historical read projections with private record validation, not current-use authorization. |
| `message_client.go` | **D** `sendMessageVersionOnce`, URL policy, response reading/strict JSON; **E** transport error distinction and fixed HTTP caps; existing `sendMessageOnce` bridges the private prepared snapshot. Preferred bounded extraction below. |
| `remote.go` | **C** `RequestRemoteAcceptance` coordinates momentary checks, challenge, proof and final checks; **D** owns client/deadline setup; **B/F** ad/eligibility reads. It performs no durable PW action. |
| `remote_client.go` | **D** `postExchange`, strict `decodeExchangeResponse`; **E** private request/response shapes and sanitized failure. Avoids importing peerapi, which already imports PW. |

This is not a mechanical instruction to put every A function in one package.
For example, receipt issuance and pure verification share an evidence format
but have different authority; envelope storage and wire format intentionally
share exact bytes; `history_v2.go` checks first-use state to reject orphaned or
mixed records. File co-location alone does not collapse those boundaries.

### 2.3 Collaborators and dependency direction

| Existing package | Concrete dependency/call evidence | Ownership and disposition |
|---|---|---|
| `internal/core/wire` | Deterministic CBOR modes, `Marshal`, `UnmarshalCanonical`; consumed by intro, ads, policy and PW | **Keep** byte infrastructure without protocol policy. Decoding is not signature verification. |
| `internal/core/intro` | `Path.ProveFromRoot`, signed `Edge`, acceptance checks, in-memory inbox/choice; imports `hop`, `key`, wire | **Keep** rooted evidence utilities. `verified_edge.go` currently contains only a package declaration, not a verified-evidence capability type. Generic path/rotation utilities do not by themselves implement V19 authority. |
| `internal/onboarding` | `CheckIntroduction`, `SaveIntroduction`, `VerifyReceived`, `IsKnownIntroductionInTx`; uses intro and storage | **Keep** separate Received/Known provenance. PW calls its transaction-local Known checks, not a global introduction graph. |
| `internal/ads` | PW uses `ValidateClaim`, `Current`, `ReadCurrentLocalInTx`, `ReadEstablishmentAdInTx`; ads uses onboarding/device/wire/localhttp/storage | **Keep** current bounded publication/receipt/verification ownership; **Adapt later** for general slots, epochs and device lifecycle. `VerifyReceivedRemote` is already a composite with transport and final local commit. |
| `internal/device` | PW calls `InspectLocal` outside transactions and `IsAuthorizedLocalInTx` inside final snapshots | **Keep** persistent authorization versus fresh probe. **Adapt later** for multiple devices, revocation/recovery; no stored live flag. |
| `internal/policy` | `DenyLocal`, `AllowLocal`, `IsDeniedInTx`; owner Deny and PW guards use the same root/local-bound record | **Keep** policy owner. Allow exists as a Go API; the inspected operational owner surface exposes Deny, not a complete Allow/rebootstrap lifecycle. |
| `internal/ownerapi` | `deviceHandler.mutations`; `establishLocal`, redemption, first-use and message orchestration; capability constructors | **Keep** shared service ordering and owner credential scope. **Defer** separating HTTP from this owner until there is a complete synchronization design. |
| `internal/peerapi` | Calls supplied `establish`, `firstUse`, `receive` capabilities; imports PW for bounds, verification and proof functions | **Keep** inbound transport and challenge-ledger ownership. Establishment/message handlers do not get a general signer or write API. Older challenge handlers also read ad/Known/policy state directly. |
| `internal/localhttp` | `Address`, `Serve`; used by node setup, owner/ads/PW transport | **Keep** loopback addressing and bounded server shutdown. This is not an authority owner or a generic PW wire package. |
| `internal/nodevault` | `OpenForNode`, `Store.Vault`, `Store.Close`; provider and durable encryption reservations | **Keep** root/local storage binding and handle/lease lifecycle. Does not import PW or interpret its records. |
| `storage` | PW uses `Vault.View`, `Vault.Update`, `ReadTx`/`WriteTx`, `Get`/`Put`/`Delete` | **Keep** encrypted scoped transactions. Application keys and record schemas belong to their application packages, not storage. |
| `storage/internal/engine` | Memory/bbolt implementations of local atomic transactions | **Keep** private backend/namespace and rollback rules. No semantic authority or cross-host transaction. |
| `storage/internal/record` | Scope derivation, authenticated encrypted records, names/tokens, seal/open | **Keep** crypto/storage infrastructure. Encryption success proves neither introduction nor current permission. |
| `cmds/node` | `serve.go:309` constructs owner credentials, `:342` onward mounts peer capabilities; opens nodeidentity/nodevault | **Keep** process assembly, actual listener binding and shutdown/join before resource close. It does not import PW or the older `internal/protocol` directly. |
| `key`, `internal/nodeidentity`, `hop` | Shared signature/key primitives; nodeidentity restores independent software handles; intro uses hop distance | **Keep** required primitives. **Defer** separating the legacy global enclave factory from `key`; modern independent handles do not eliminate this shared package dependency. |

Current important relationships are below. Solid arrows are direct production
imports; the one dashed arrow is an injected function call, **not an import**.
Common `key` and wire fan-out and some direct storage imports are omitted for
readability; the table above states those dependencies. No proposed package
appears in this diagram.

~~~mermaid
flowchart TD
    cli["cmd/tdc"] --> node["cmds/node"]
    cli --> demo["cmds/intro"]
    cli --> oldcmd["cmds/id, cmds/pw, cmds/domain"]
    node --> owner["internal/ownerapi"]
    node --> peer["internal/peerapi"]
    node --> vault["internal/nodevault"]
    node --> ident["internal/nodeidentity"]
    node --> http["internal/localhttp"]
    demo --> owner
    demo --> vault
    owner --> pw["internal/pw"]
    peer --> pw
    peer -. "bound local capability" .-> owner
    owner --> ads["internal/ads"]
    owner --> onboard["internal/onboarding"]
    owner --> policy["internal/policy"]
    pw --> ads
    pw --> device["internal/device"]
    pw --> onboard
    pw --> policy
    pw --> http
    pw --> wire["internal/core/wire"]
    ads --> device
    ads --> onboard
    ads --> http
    device --> onboard
    onboard --> intro["internal/core/intro"]
    intro --> wire
    pw --> storage["storage"]
    onboard --> storage
    vault --> storage
    vault --> ident
    storage --> engine["storage/internal/engine"]
    storage --> record["storage/internal/record"]
    oldcmd --> oldprotocol["internal/protocol (id/pw commands)"]
    oldprotocol --> oldpw["top-level pw"]
    oldprotocol --> enclave["enclave"]
~~~

The grouped old-command edge represents imports from `cmds/id` and `cmds/pw`;
`cmds/domain` instead uses `identity`. Being linked into `tdc` is different
from belonging to the modern `node serve` action path. In particular, an
import from PW back into peerapi or ownerapi would introduce a real cycle.

## 3. Semantic owners and non-negotiable boundaries

| Boundary / semantic reference | Current implementation owner and consequence |
|---|---|
| Received evidence versus verified evidence: V19 `ReceiveEdge` | HTTP decodes transfer documents; `onboarding.CheckIntroduction` performs pure rooted path and acceptance verification. `SaveIntroduction` rejects invalid evidence before retaining it. Thus this bounded Received store admits less hostile material than the abstract model permits; it still does not grant Known. |
| Verified evidence versus Known: V19 `VerifyReceived` | `onboarding.VerifyReceived` is the explicit durable promotion. Pure proof success, owner check, peer fetch and Received storage do not write Known. Known reads validate bindings back to received evidence and local parent consistency. Global single-parent truth is not established by these local checks. |
| Received ads versus verified ads: `ReceiveAdClaim`, `VerifyAd` | `ads.ReceiveClaim` performs structural admission and can retain forged/expired signatures. `VerifyReceivedRemote` requires independent Known, an online proof and a final Update checking exact received bytes/expiry. `ReadVerifiedClaim` is historical evidence, not permanent remote currentness. |
| Device authorization versus usability: V19 device rules | `device` owns the durable root/local authorization row. `InspectLocal` probes the installed handle with a fresh discarded signature; final actions reread authorization. The caller keeps signer lifecycle stable. Neither stored authorization nor possession of a Vault proves usable signing. |
| Invitation issue/redeem/revoke: invitation `IssueInvitation`, `RevokeInvitation`, `BobAccept` | Owner route grants issuance permission; PW persists Active, validates audience/expiry and atomically consumes with Bob acceptance. Revoke-before-accept refuses; accept-before-revoke retains Consumed. Revoking Consumed is no-op, not Delete. Owner approval is an implementation requirement abstracted by the formal issue action. |
| Bob acceptance versus Alice acceptance: `AtomicBobCommit`, `AtomicRequesterCommit` | `commitAcceptanceV2` writes Bob's consumed invitation, accepted request/result and held digest in one Update. `commitRequesterAcceptanceV2` independently writes Alice's accepted result and held digest after verifying her saved attempt. No shared transaction, callback or third establishment ACK. |
| Immutable v2 contacts: `ContactOrientation`, `ContactRetryNeverRebinds` | Request/result evidence binds both service origins, root/roles, invitation/audience, attempt, device/epoch and target ad. Alice's declaration is taken from her signature; Bob checks his own target origin against his ad/listener. A validly signed false declaration is an authenticated assertion, not ownership or reachability proof. No mutable contact cache may replace this evidence. |
| Await / Bob observation / Alice Ready: invitation first-use actions | `SaveFirstUseV2` commits Await; transport sends later. `BobFirstUseV2` commits `useSeen` before returning signed bytes. `ReceiveFirstUseV2` verifies exact outstanding fresh session and local guards before Ready. Ready is historical local observation, not knowledge of later Bob policy. `PWOpen` remains checker-only. |
| Historical evidence versus current permission | `readLocalHistoryV2`, `outgoingHistoryV2`, contact/inbox projections and ACK verification authenticate history. Current-use functions separately require held state, Known, non-Deny, authorization, usable signer and appropriate runtime/binding. Historical contact, first use, receipt or ACK never restores these prerequisites. |
| Local Deny versus Delete | `policy.DenyLocal` updates only the deny set and retains holding. `DeleteHeldLocal` removes only `heldKey`, preserving authenticated histories and the peer's state. Allow cannot recreate a deleted holding. This is invitation `ChangeBob/ChangeRequester("Delete")`, not full V19 cache/trust/view/live-pipe cleanup. |
| Prepare / dispatch / receipt observation: separate message candidate | `PrepareMessageSendV2` performs outgoing, signed envelope and sent authorization in separate local commits. `SendMessageOnceV2` performs one unlocked POST. `ObserveMessageReceiptV2` later authenticates and commits ACK under the owner lock. Failure at a later phase retains earlier commits. |
| Receiver admission versus sender ACK | `AdmitIncomingEnvelopeV2` atomically commits the receiver inbox under receiver-local guards; `IssueMessageReceiptV2` checks that inbox and current guards but writes no receipt row. Sender observation may save an exact historical ACK after sender Deny/Delete, without signer/current permission or a sent marker. A receipt signature authenticates the receiver's assertion, not honest physical storage. |
| Transaction commit versus remote delivery | `Vault.Update` success is a local durability boundary. `BobReplyV2` is additionally guarded after commit. HTTP success still requires authentication at the caller; an error may follow a remote commit. Already-authorized/transmitted bytes cannot be recalled by later local policy. No transport retry should reconstruct or replace saved evidence. |
| Local authority versus HTTP adapters | Bearer-protected owner operations supply pinned root/local identities, signer and runtime; peer handlers validate bounded envelopes and invoke narrow capabilities. Neither a peer JSON version nor a caller-supplied route authenticates authority. `ValidateLocalMessageReceiptV2` is local-output validation, not sender ACK or admission authorization. |

Canonical CBOR arrays, COSE ES256/P-256 public-key checks, signature domains,
exact signed-byte comparisons, URL canonicalization, UTC deadlines and real
storage failure handling are **concrete Go obligations**. Symbolic model
authentication/equality and atomic actions do not verify these implementations.
The action map's suggested modules and event names are conceptual ownership
guidance, not instructions to create empty packages or an event framework.

### 3.1 Existing lock and transaction ownership

The mutation mutex is `deviceHandler.mutations` in
[`internal/ownerapi/device.go`](../../internal/ownerapi/device.go), shared
through the embedded handler chain constructed by `NewFirstUseCredentials`.
Despite its enclosing type's name, it orders more than device operations:
Known/evidence writes, bootstrap, publication/proof, invitation operations,
establishment, first use, Deny, Delete and message preparation/admission/receipt
work use this owner-service boundary. Peer capabilities capture the same
`publicationHandler`; they do not create an independent PW lock.

The lock spans local preflight, external signer probes/signing, and final local
guard checks/commit. Signing is outside Vault transactions. Final durable
guards are checked inside the action's Update/View; transaction serialization
also orders independent durable writers, including competing revocation or
acceptance. Callbacks retain their own named error and `err2.Handle`.
`storage/tx.go:42` deliberately runs recovery before transaction finishing,
and the engine aborts on callback or recorded operation failure. Do not alter
that unwind order during relocation.

For redemption, first-use exchange and message sending, owner methods acquire
the mutex for preparation, release it before outbound HTTP, then reacquire for
the returned local action. Receiver admission and receipt issuance stay under
one owner lock while retaining separate effects. Response serialization is
outside those capability calls. A lock per extracted protocol package would
not serialize Deny, signer use and publication together and is therefore
insufficient.

Two qualifications matter when describing the **current** system:

- `ownerapi/ad_verify.go` intentionally does not hold the publisher mutex
  over `VerifyReceivedRemote`; final transaction revalidation owns that
  check. `acceptance_exchange.go` similarly invokes the earlier momentary
  proof exchange without an outer service lock, and promises no durable grant.
- The older `deviceHandler.ServeHTTP` holds the mutex while delegating certain
  Received/Known POST handlers, including introduction fetch, and bootstrap
  retains it through response writing. It is inaccurate to claim that every
  existing handler releases the service lock before all HTTP work. These
  older scopes are not changed by the recommended message-client extraction.

Keep this lock in its current owner. Moving it would require one identified
service object owning the same Vault, pinned identities, signer and runtime;
an inventory of every participating mutation; an ordering design for callback
reentrancy and shutdown; and tests proving the same serialization. This round
does not propose that move or a new service interface.

### 3.2 Gaps and policy tensions, not architecture claims

The implementation is a bounded candidate, not full V19. General device
administration/loss/recovery, helper recovery delivery, safe snapshot restore,
multi-slot/current-epoch evolution, peer-view refresh, strong use, a live pipe,
Trust and full V19 deletion are absent from this modern path. Root-pinned
onboarding does not prove global introduction uniqueness. The separate message
model assumes established history; these packages and tests do not prove model
composition, V19 refinement, AKE or implementation conformance.

One existing policy distinction needs explicit owner review before any future
attempt to unify guards. `BobReplyV2`, requester acceptance/retry, and
`contactGuardsV2` use establishment ad guards. Thus expired or unavailable
bootstrap ads can suppress exact establishment-result retrieval or a
`*UsableContactV2` projection. Historical contacts remain readable. In contrast,
`firstUseGuardsV2` and message use rely on authenticated history plus current
local prerequisites/runtime, without fresh ads or invitation expiry.

This is executable behavior: `TestBobReplyV2ExactLossRestartAndExpiry`
distinguishes invitation expiry from later ad expiry;
`TestContactV2LocalEligibilityAndImmutableHistory` includes expiry;
`TestFirstUseBootstrapExpiryAndNoFreshPairingV2` exercises reuse without fresh
bootstrap. Do not silently replace these guards during extraction. The contract
preserves history and an otherwise eligible exact retry after bootstrap expiry;
whether ad expiry should itself invalidate these contact/reply projections is
an **owner semantic-policy decision**, distinct from changing package layout.

## 4. Explicit v1 and legacy policy

### 4.1 Four independent version axes

1. **`IntroTreePWInvitationV1`** names the accepted formal model, including
   its later contact amendment. Keep this semantic reference.
2. **Go PW v1** is the original establishment/first-use/message encoding.
   It authenticates the target ad but lacks the pair of immutable service
   declarations. V1 message routing accepts an owner-supplied loopback URL.
3. **Go PW v2** signs both contacts, persists them in the existing shared
   slots, and derives first-use/message destinations from accepted history.
4. **WoT/trust-domain playground** uses older commands, `internal/protocol`,
   `enclave`, `identity`, `chain`, `node`, `digest` and top-level `pw`.
   It is not Go PW v1 with a different spelling.

Introduction/ad formats, invitation storage, node files, demo manifests and
Flutter launch configuration also have their own version-1 fields. None alone
means that the relationship uses Go PW v1.

### 4.2 Live entry points and users

| Surface | V1 behavior | V2 behavior / actual caller |
|---|---|---|
| `tdc node serve` | Installs operational routes supporting v1; no separate v1 command is needed | Same composition supports explicit v2. Owner/peer listeners are separately bound; peer surface is opt-in. |
| Owner `/owner/pw/invitations/redeem` | Three fields without `version` select v1 | An additional exact integer `version:2` selects v2. Explicit `version:1` is not accepted as an alias. V2 requires Alice's bound peer listener. |
| Owner `/owner/pw/first-use` | Literal `{}` selects v1 | Literal `{"version":2}` selects v2, with allowed surrounding whitespace. |
| Owner `/owner/pw/message/send` | `text` plus `peer_message_url` | `version:2` plus `text`; rejects a routing hint. |
| Owner `/owner/pw/message/inbox` | No query reads v1 | `?version=2` reads v2; selectors do not migrate stored state. |
| Peer `/peer/pw/establish`, `/peer/pw/first-use`, `/peer/pw/message` | Explicit JSON version 1 | Explicit JSON version 2 on the same paths; inner evidence is independently checked for the selected version. |
| Earlier `/owner/pw/acceptance/exchange`, `/peer/pw/challenge`, `/peer/pw/accept` | Challenge/acceptance observation with version-1 envelopes and volatile challenge ledger | No prerequisite call from v2 redemption. These routes remain installed alongside modern establishment. |
| Ad proof/introduction transfer and invitation issue/revoke | Existing shared formats and owner routes | Still used to prepare v2. They are not obsolete because their formats contain 1. |

The disposable controller's actual sequence is visible in
[`scripts/pw_demo.py`](../../scripts/pw_demo.py), `Harness.setup` and
`prepare_chat` around lines 730 and 865:

- It builds `cmd/tdc`, initializes independent nodes, and uses `intro http-demo`
  to obtain root-issued introduction evidence. This demo command is still a
  dependency of the preferred demonstration.
- Plain `up` stops at `READY_FOR_INVITATION`: introductions Received/Known,
  local devices, Bob publication and Alice ad receipt/verification. It issues
  no invitation and performs no pairing or first use.
- `up --chat-ready` explicitly issues Bob's directed invitation, redeems with
  `version:2`, runs v2 first use, and reads both v2 empty inboxes. It sends no
  application message. It does not invoke the old challenge exchange.
- Flutter `live_conversation.dart:74,129` reads/sends with v2 methods. The
  launch document's `version:1` is a configuration format. Both accepted peer
  listener origins must remain fixed for the run.

Manual pairing remains different. `live_pairing.dart` calls
`StatusClient.redeemInvitation` and `firstUse`; `status_client.dart:717,746`
sends the unversioned redemption object and `{}`. The copied manual JSON in
`pairing_types.dart` also selects v1. Therefore plain setup plus manual pairing
does not prepare v2 conversation history. `StatusClient.sendMessage` and
`readMessageInbox` retain v1 methods with Dart test callers, while the live
conversation widget uses their v2 counterparts. Do not infer a live v1
conversation widget from the continued presence of the older client methods.

### 4.3 Shared persistence and compatibility

All keys below are local to one independently bound Vault, not global peer
indexes. Their suffixes are historical names, not a decoder selection rule.

| Existing key(s) | Schema and shared use |
|---|---|
| `local-pw-invitation-v1` | `Invitation.Version == 1` for both protocols; single issuance, never replaced after expiry/revoke/consume. |
| `local-pw-attempt-v1` | Exact signed request bytes; distinct v1/v2 array layouts. A v1 attempt occupies the same slot a v2 attempt would need. |
| `local-pw-accepted-v1`, `local-pw-held-v1` | Shared `acceptedRecord` and `heldRecord` types with explicit Version 1 or 2. Held is separately deletable; accepted history prevents resurrection. |
| `local-pw-first-use-v1`, `local-pw-use-seen-v1` | Shared `firstUseRecord` / `firstUseReceipt` with explicit record version; signed inner evidence must match. |
| `local-pw-message-outgoing-v1`, `local-pw-message-envelope-v1` | Same singleton slots; distinct outgoing/envelope types and version-specific signature/history purposes. |
| `local-pw-message-inbox-v1`, `local-pw-message-sent-v1`, `local-pw-message-ack-v1` | Shared `inboxMessage`, `messageSent`, `messageACK` record types with version dispatch and exact evidence verification. One incoming/outgoing per node, not one per version. |
| Known/Received namespaces, ad tables, local-device authorization, `local-denied-peers-v1` | Shared prerequisites for both protocols; no second v2 policy or device database. |

`EstablishmentV2.guardBinding` produces a v1-shaped value only to reuse local
guards such as `newRedemption`, `matchesInvitation`, `requesterGuards` and
`currentEstablishmentGuards`. It must never be encoded/signed as v1 evidence.
`history_v2.go:133` authenticates genuine legacy history before reporting no
v2 contact. Missing, corrupt, wrong-role and wrong-version state are distinct.

Existing coverage is substantive compatibility evidence, not disposable old
tests. Examples inspected:

- `bob_compat_v2_test.go`: `TestBobV2SharedSlotsAndVersionIsolation` and
  `TestBobV2MixedVersionCommitOrders` protect the winner's state in both orders,
  including deleted holding and reopen.
- `requester_v2_test.go`: version isolation, mixed-version commit orders,
  contact equality after reopen and refusal of changed service configuration.
- `contact_lifecycle_v2_test.go`: `TestContactV2LegacyAndWrongRoles` distinguishes
  valid legacy absence from wrong-role/corrupt history.
- `first_use_v2_test.go`: `TestFirstUseV1V2SubstitutionV2` rejects cross-version
  evidence; message projection/history tests similarly reject substituted
  accepted history, inbox and ACK records.
- Original `reply_storage_test.go`, `establishment_linux_test.go`,
  `first_use_linux_test.go`, `message_receipt_linux_test.go` and
  `message_ack_linux_test.go` retain v1 corruption, backend failure, read-only
  retry or process-reopen coverage. Newer v2 tests supplement these.
- `internal/nodevault` invitation/establishment/reply tests exercise durable
  Store integration; `storage` tests separately protect transaction and
  cryptographic record behavior. Version-independent infrastructure coverage
  should not be renamed or removed as if it were PW v1 compatibility code.

No automatic migration exists. Changing a version byte, using new key names,
or filling in a missing contact would invent evidence or bypass singleton
guards. Deleting only the holding does not free the accepted-history slot for
a new v2 relationship. A storage migration requires a separately reviewed
protocol/user decision, including retention of old authenticated evidence.

### 4.4 Disposition for each distinct surface

These labels are legacy policy recommendations. **Deprecate** means retain
current behavior while defining an exit; it does not authorize removal now.
No row recommends immediate deletion.

| Surface | Recommendation | Retirement/compatibility decision and evidence |
|---|---|---|
| Formal invitation model `V1` | **Keep** | Accepted contact-inclusive semantic reference. Its name is unrelated to wire retirement. |
| Contact-bound Go v2 establishment, first use and messages | **Keep** | Preferred bounded demonstration path. Preserve independent commits, immutable origins and historical ACK behavior. |
| Shared invitation v1 record, v1 introduction/ad/device/policy formats | **Keep** | Live prerequisites used by v2. No migration justified by the suffix. |
| Active Go v1 establishment and first-use APIs/routes | **Deprecate** | Still used by Flutter manual pairing, unversioned HTTP callers, node tests and persistence tests. Retire only after a v2 manual flow has owner acceptance and existing-state policy is explicit. It lacks the full accepted contact binding and is not the preferred establishment contract. |
| Active Go v1 message send/receive and owner-selected routing | **Deprecate** | Still exposed by owner/peer routes and Dart client/tests. Live v2 conversation no longer needs that route hint, but changing defaults or rejecting old bodies is user-visible. Retire only with an explicit API compatibility checkpoint. |
| V1 persisted-history readers, exact-result behavior and mixed-version rejection tests | **Keep** | Required while v1 state can be opened and while shared keys must reject substitution. Removing active writes does not justify dropping readers or negative version tests. |
| Old challenge/acceptance observation protocol (`remote*.go`, proof APIs, peer ledger/routes) | **Deprecate** | Node API still exposes it and tests cover it; no call from the preferred controller or v2 establishment sequence was found. Retire only after owner confirmation that the diagnostic API is no longer supported and its caller/nonce/guard coverage is accounted for. Preserve independent ad-currentness proof. |
| Flutter live-pairing controls and copied manual v1 JSON | **Deprecate** | Replace with an explicitly selected v2 flow using a bound requester listener and separate fresh state. Do not relabel the current flow as v2 or silently reuse a v1 Vault. |
| Flutter legacy message client methods | **Deprecate** | Test callers remain; production live-conversation widget uses v2. Remove later only after retiring the Go compatibility surface and consciously retaining useful HTTP failure tests on the supported client. |
| Demo manifest/config version 1, controller and `cmds/intro` HTTP onboarding | **Keep** | `--chat-ready` and two-window v2 conversation depend on them. The controller's plain setup remains a useful prerequisite checkpoint. |
| `cmds/id`, `cmds/pw`, `cmds/domain`; `internal/protocol`, `internal/nconn`, top-level `pw`, `enclave` and their WoT state | **Isolate** | Distinct historical playground, still registered in `cmd/tdc`. `cmds/pw/handshake.go` checks `WebOfTrust` then calls `protocol.PairwiseHandshake`; modern node serving does neither. Retain separate commands/semantics until owner chooses whether to support the playground. No claim of V19 authority. |
| `chain`, `identity`, legacy `node`, `digest` algorithms/data | **Isolate** | Real dependencies of the older playground with unit coverage; do not substitute them for modern rooted evidence/Known ownership. A repository-wide removal needs consumer and persisted wallet review. |
| Shared `key`/`hop`, generic intro path/backup/rotation utilities | **Keep** | Modern code still depends on primitives. `onboarding.CheckIntroduction` explicitly rejects backup/rotation options for this scope. Future narrowing of unused legacy features needs a separate caller audit, not blanket deletion. |
| Installed v1 user data, external scripts/API consumers and desired playground support lifetime | **Unknown** | Repository source cannot establish deployment usage or owner retention obligations. This uncertainty blocks deletion, not this report or the behavior-preserving transport extraction. |

Recommended user-visible migration policy: use fresh disposable runs for new
v2 demonstrations, with the original listeners kept alive; retain old stores
as old stores. A persistent-user migration must choose between continued v1
compatibility and explicit new v2 establishment with preserved old history.
The current singleton schema does not implement the latter within the same
Vault. Do not promise a conversion command, automatic port rebinding or
transparent fallback. API default changes, manual UI changes and any eventual
command removal need separate authorization and release notes.

## 5. Three realistic restructuring options

The coherent architecture should follow **authority ownership**, not one
package per model operator. Keep pure introduction/wire primitives below
onboarding; keep ads, device and policy as local prerequisite owners; keep
PW's shared bounded state intact until a useful independent consumer requires
a wider split. Ownerapi currently supplies local serialization and coordination;
peerapi supplies bounded external adapters; nodevault/storage supply lifecycle
and transactions. No helper, recovery, trust or shared-FSM package is invented
to fill unimplemented model areas.

Exactly three options are compared. Option 2's bounded message-client subset
is the selected next increment; broader transport consolidation is deferred.

| Criterion | 1. Pure PW evidence extraction | 2. Isolate transport implementation | 3. Split local state by responsibility |
|---|---|---|---|
| Concrete boundary | Establishment/accepted/first-use wire types and verifiers; later outgoing/envelope/receipt verification | Message HTTP dispatch first; preserve PW public prepared-state facades. Establishment/first-use/old proof clients remain for later review | Relationship/invitation/holding/history owner plus first-use and message action packages |
| Semantic cohesion/ownership | Strong distinction between authenticated bytes and permission. Must not promote Known or accept relationships | HTTP request/response policy is independent of local authority. Returned bytes remain untrusted | Attractive eventual lifecycle versus protocol-instance separation from the message design constraint; current history validation crosses those phases |
| Dependencies/cycles | `establishment_wire.go` depends on ads types/validation and private PW key helpers. A supposedly pure package would still transitively pull storage through ads unless carefully bounded. Cannot import PW back | Leaf can depend only on stdlib/localhttp; PW imports it. Moving entire public clients instead would depend on PW's private snapshots; placing them in peerapi would cycle | Naive split cycles: establishment history calls first-use readers; first use needs accepted history/holding; messages need both. Delete validates both versions and first use. Requires redesign of read ownership |
| Exported API/visibility | Export verifiers, digest construction or expected-binding types; preserve existing public type identity via reviewed aliases if needed. Avoid exporting record keys/guards | Keep existing `pw` APIs and opaque fields. Small nested internal API handles bytes/HTTP only; no new caller-supplied v2 URL at owner boundary | Likely exposes `localHistoryV2`, transaction helpers and record guards, or adds callback/interfaces to avoid cycles. High accidental authority/visibility widening |
| Private records/keys/codecs | Pure wire can move, but several wire types are also persisted types. Exact CBOR arrays and purpose constants must remain unchanged | No record/key/CBOR move. Domain byte bounds remain in PW; fixed HTTP caps belong to transport | Shared accepted/held/attempt/first-use/message keys and version validators must have one owner. A generic records package would spread semantic implementation details |
| Transactions/signer lock | No lock or signer moved into verifier; action callers keep final guards | No lock, Vault or signer crosses new API. Existing owner lock and all commits remain | Must preserve preflight/probe/final checks and owner mutex across all packages. Multiple package-local locks would be incorrect |
| Tests/private fixtures | Pure tests can be independent; integration matrices still need `ready`, `newRequester`, record mutation/reopen helpers. Do not export helpers solely to move tests | Keep full prepared-send/state tests in PW; move only direct private parser tests. Existing cancellation family remains in PW | Large fixture graph spans establishment through ACK and private corruption helpers; moving it risks export-only test APIs or duplicated setup and cross-package test cycles |
| V1/v2/state interaction | Both formats stay distinct; extracting v2 alone still needs legacy absence/version validation at caller | Both versions use the same bounded sender implementation today; retain exact selectors and errors | A version split cannot isolate shared state. Even a responsibility split must keep mixed-version rejection and legacy reader semantics |
| Increment/rollback | Moderate: many type references and signature boundaries; easy byte drift if combined with cleanup | Small: one client implementation, fixed forwarding boundary and parser test. Reverting placement needs no persisted-data rollback | Large coordinated move; rollback must include many imports/tests. Schema or transaction changes must not be bundled |
| Fast feedback | Moving selected wire families would require changing the package-specific verifier contract; leaving action families in PW preserves it | Existing 16 families stay in PW, including cancellation. New parser-package tests are changed-area checks, not automatically part of `test_fast` | Existing exact package/name assumptions would break if families move; fixture scheduling and the two parallel families require renewed audit |
| Supported demo | Preserve both contacts, original listeners and exact bytes; otherwise controller/Flutter unchanged | Same v2 body, destination, receipt and one-POST behavior; controller/Flutter unchanged | Larger risk to independent commits, listener runtime and one-message bound. Would require broad integration rehearsal |
| Decision | **Defer** as a broader extraction; useful only with an explicit evidence API and acceptable dependency closure | **Split**, preferred bounded next increment | **Defer**; retain responsibility separation in functions/files for now |

No option justifies moving guards into HTTP, collapsing independent commits,
putting all shared types in a utility package, or adding a generic protocol
engine. A smaller graph is not evidence of improved ownership.

## 6. Preferred first extraction: message HTTP dispatch

### 6.1 Exact relocation and API proposal

Proposed destination: **`internal/pw/internal/messagehttp`**. This is a private
implementation package under PW, not a new owner/peer API and not a generic
HTTP framework. The nested `internal` restriction prevents ownerapi/peerapi
from importing the low-level sender and bypassing the existing PW facade.

Only the following production responsibilities would move in the separately
authorized increment:

| Current source | Proposed disposition |
|---|---|
| `message_client.go:48`, `sendMessageVersionOnce` | Retain its existing PW preflight for context, version, exact envelope bound and URL. Move the subsequent JSON construction, timeout, request/transport construction, single `Do` and response handling into the leaf's `Send`. Keep the existing private function as the caller of that implementation. |
| `message_client.go:91`, `validMessageURL` | Relocate its implementation as `messagehttp.ValidURL`. Update its existing PW call sites directly; do not add a generic URL abstraction or relax canonical loopback rules. |
| `message_client.go:115`, `readMessageResponse` | Relocate as a private leaf helper, preserving close-error, header/trailer/body/cancellation handling. |
| `message_client.go:146`, `decodeMessageResponse` | Relocate as a private leaf helper; keep strict version spelling, field/alias/duplicate rejection, UTF-8/base64 and receipt-size checks. |
| `message_client.go:20` HTTP path and 4 KiB request / 2 KiB response caps | Move HTTP ownership with the implementation. Export only `Path` where PW's existing v2 destination construction needs it; caps stay private. |
| `message_client.go:26` two transport error values | Leaf owns the two sentinel instances. PW's existing private error names and public `ErrMessageNotDispatched` refer to those same values, preserving identity and owner status mapping. No new public PW error or raw transport diagnostic. |

The leaf's `Send` receives context, immutable envelope string, validated
endpoint, selected version and the version-specific decoded-receipt limit.
It returns raw receipt bytes and the same two outcome classes. These are
concrete inputs for this one existing protocol, not a configurable client,
transport interface, generic callback or retry policy. PW supplies the limit
from `maxMessageReceiptBytes` / `maxMessageReceiptBytesV2` after validating
version; both currently equal 640. Keep `maxMessageEnvelopeBytes` (2176) and
the canonical evidence limits in PW. This avoids a dependency from evidence
definitions onto HTTP or duplicated numeric bounds that could drift.

The trusted-call preconditions are enforced by the retained PW preflight;
they must also be explicit in the private package API documentation. JSON
serialization/HTTP failures retain the original dispatch classification:
errors before `Do` mean not dispatched; any failure once `Do` starts leaves
the peer outcome unknown. No extra remote request is introduced.

Keep `sendMessageOnce` in PW as the existing v1 prepared-snapshot bridge.
Keep `SendMessageOnce`, `SendMessageOnceV2`, `PreparedMessageSend`,
`PreparedMessageSendV2`, `MessageSendReceipt`, `savedMessageTransmit` and
`savedMessageTransmitV2` in PW with their current public/private fields.
`message_send.go` and `message_transmit_v2.go` would call the relocated URL
validator; v2 destination construction uses the relocated fixed path. Their
authorization, record writes and authenticated contact derivation stay put.

No ownerapi, peerapi, CLI, Flutter, controller, storage or spec API change is
required. No schema migration, bytes/signature change, protocol deprecation
enforcement, lock movement or relocation of the other three client families
belongs in this first increment.

This boundary has a purpose beyond reducing file count: transport code can be
reviewed and tested without importing a Vault, a signer, current guards or
cryptographic authority. The narrow forwarding function is necessary to keep
domain bounds and the existing opaque prepared-state contract at PW's boundary.
If implementation requires exporting saved-state internals or adding general
indirection, stop expanding the extraction and return that tradeoff for review.

### 6.2 Test placement and acceptance for the later implementation round

Keep stateful and cross-package scenarios where their current private fixtures
are accessible. In particular, keep `fixtures_test.go`, `newRequester`,
`newFirstUseV2`, `newOutgoingV2`, receipt/ACK fixtures and storage corruption
helpers in PW. They are not a proposed shared test utility package.

`message_client_test.go` has seven families. The one directly testing the
private JSON decoder, `TestMessageClientStrictJSON`, can move with that decoder
to a leaf-package test using only byte fixtures. Retain the other six families
in PW exercising the prepared facade and relocated implementation, including
`TestMessageClientCancellationAfterDispatch`. Update direct URL-constant and
validator references, including `message_transmit_v2_test.go`, as needed.
The retained hostile-HTTP test can use a documented 2049-byte response fixture
to exceed the fixed 2 KiB HTTP contract; do not expose the private cap for it.
Leaf decoder tests exercise the supplied receipt limit with byte fixtures,
without importing PW's evidence constants. Do not export the decoder just to
keep its test at its old location. Preserve `message_transmit_test.go`'s
existing test-only exports used by external tests. No fixture-helper export
is needed.

The two accepted parallel families remain in PW unchanged:
`TestMessageProjectionRequiredHistoryV2` and
`TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2`. Preserve leaf
`defer assert.PushTester(t)()` after `t.Parallel()`, independent Vaults/signers,
callbacks, exact error checks and serial environment/tracer test scheduling.
Do not move the selected fast family or change `scripts/test_fast.py` merely
to make extraction easier.

Required observations for the later increment:

1. Exact v1/v2 JSON envelope, request bytes, HTTP path, receipt bytes and
   version rejection remain unchanged. Test both versions through the sender;
   a v1-only parser test cannot establish v2 response selection.
2. No redirect, proxy, cookie, authorization leakage, compression, automatic
   retry or replayable body; preserve five-second deadline, cancellation,
   caps, strict JSON/base64 and sanitized errors. Retain the deliberately
   unauthenticated response test: HTTP success returns untrusted bytes.
3. Prepared state is committed before dispatch; no owner/Vault lock spans
   sending; refused/failed transport does not undo outgoing/envelope/sent.
   Receipt observation stays a separate exact-history action.
4. Exact sent retry, mixed-version rejection, contact-derived v2 destination,
   remote-policy changes, receipt failure and late historical ACK continue
   through owner/peer integration. No new v2 routing input is exposed.
5. Existing persisted v1/v2 state reopens unchanged. This code-placement
   change needs no data rollback; a code revert restores placement only.

Validation for that authorized change should include baseline/final
`make lint`, fresh `make test_fast TEST_ARGS=-count=1`, the new leaf tests,
complete affected PW/owner/peer/node families, full ordinary regression and
relevant race/integration checks. Use the existing `make test_pwr` scope
(`internal/pw/...`) to include the leaf when running the complete PW race
target; a direct `go test ./internal/pw` alone would not run its tests.
Record any timeout honestly rather than changing sandbox or test policies.
Rehearse the supported `--chat-ready` two-window v2 demonstration and retain
v1 compatibility checks. That rehearsal is future acceptance, not a result
of this report.

Round 03C's fast runner accepts only its exact PW package and 16 family names,
and verifies every emitted descendant. Keeping those names and locations
preserves the contract; the additional parser test must be run separately.
Its historical fresh result was 1.423327 s, versus Round 03B's full ordinary
117.842967 s at that earlier baseline. Round 03D's subsequent full PW pass was
109.969 s package time. These are historical, different scopes/checkpoints,
not new measurements or a promised speedup from package extraction. Preserve
the fast loop without using it as the sole regression criterion.

## 7. Owner decisions and verification of this round

The concrete recommendations for review are:

- Approve only the message HTTP implementation boundary in section 6 as the
  next code increment; defer pure evidence and stateful-package splits.
- Prefer v2 explicitly while retaining current v1 behavior until manual
  callers and persistent-state compatibility have an accepted replacement.
- Keep legacy readers, shared prerequisite formats and version-isolation
  coverage; isolate the WoT playground from modern authority claims.
- Resolve the contact/reply ad-expiry policy separately before unifying those
  guards, and decide support lifetime for external v1 users before removal.

No approval is assumed, and no implementation increment was started.

All shell inspection used `login=false`. Effective inherited settings were
`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GOSUMDB=off`,
with Go `go1.27.1`; no dependency/toolchain/settings change was made.
No exec-metrics, nested Codex execution, agents, Git-writing commands,
dependency downloads or sandbox workarounds were used. The external metrics
artifact path was not supplied; it is not invented here.

Preservation evidence is in
`/tmp/ic-round04-20261117-sy7h1l6b/preservation-before.json`: HEAD/branch,
status/diff and hashes of all 552 original Go tracked files and 313 spec
tracked files, including the dirty V19 file. Temporary evidence is not a
durable archive.

Baseline and final `make lint` both passed, exit 0, with `0 issues`.
The preservation comparison found all 552 original Go tracked files and all
313 spec tracked files byte-for-byte unchanged; both HEADs, branches and
tracked diffs match the initial snapshots. The dirty V19 hash above is
unchanged. The only final Go status entry is this new, untracked report; the
spec status remains its original single modified V19 file. Nothing was staged
or committed. Results are saved beside the initial evidence in
`preservation-after.json`.

Report checks found all 44 PW production files represented, all cited Go test
names present, valid relative Markdown link targets, no trailing whitespace
and a final newline. These checks do not validate Mermaid rendering or prove
the architectural recommendations.

No Go test, benchmark, controller, Flutter, live demo, manual acceptance or
TLA+ run was performed for this documentation-only review. Historical test
reports and source assertions are evidence for the recommendations, not fresh
execution or a conformance/refinement result.

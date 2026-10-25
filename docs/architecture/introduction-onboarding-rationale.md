# Introduction rationale: deliberate admission, easy participation

Date: 2026-10-19

Status: product rationale captured from the owner's design discussion.
Explicit, parent-bound acceptance is the agreed design direction.
Detached acceptance helpers, the in-memory choice, and the stored-choice
application helper are implemented.
One-time enrollment and a human-consent ceremony are not implemented.
This note does not change V19.

## User goal

Introduction is a gateway, not the everyday purpose of the system.
Alice wants to join once and then communicate and establish connections.
An existing member should not need another introduction for each new peer.
The intended experience is deliberate onboarding followed by smoother use.

Introduction does not create trust or guarantee a connection.
Peer decisions and the other protocol checks still apply. [S2]

## Responsible introduction

The introducer should make a deliberate decision to introduce this node.
Alice should explicitly accept the particular introduction and parent.
Neither party's role is merely a background signing operation.

This is not a requirement for KYC, legal identity checks, fees, or a
particular ceremony.
Its seriousness should come from meaningful participation, not arbitrary
difficulty.
An introducer's participation is not a promise that every other member
should trust Alice or that the introducer guarantees her future conduct.

## Working incentive hypothesis

For an ordinary user, one valid introduction provides the desired entry
into the system.
Repeating onboarding for the same node offers little apparent additional
benefit, while requiring more effort and another willing introducer.
The design should make the single-introduction path useful and convenient.

This is the owner's product hypothesis, not measured user behavior or a
security guarantee.
A possible counterexample to investigate is whether another tree position
could change which peers accept a connection.
No conflict-resolution policy follows from this hypothesis.

## Boundaries retained

One node has one permanent introduction parent.
V19 already prevents another modeled introduction after it has a parent.
The relevant guard is `CanIntroduce`'s `¬GlobalHasParent(v)`. [S1]

Explicit acceptance can establish Alice's consent to a particular claim.
It does not establish that she never accepted a conflicting claim.
Enforcement of one-time assignment under conflicting signed acceptances
remains an open implementation/design question.
Benign incentives do not close that question.

This discussion concerns multiple parent assignments for the same node,
not whether one person may control multiple distinct nodes.
No new identity policy, automatic punishment, registry, or protocol
mechanism is authorized by this note.

## Design consequence

The detached helpers implement the bounded signature step below.
Let this user rationale guide the example and eventual CLI interaction.
Do not reopen the entire architecture or add deterrence machinery merely
to record the hypothesis.

**Deliberate admission once; convenient participation afterward.
Introduction is not trust, and low expected incentive is not prevention.**

## Detached acceptance helpers

The low-level `Path.SignAcceptance(child)` produces a detached `key.Signature`;
`Path.VerifyAcceptance(signature)` checks it with the final child's public key.
Both require at least two path entries and a nonempty child public key.
Signing requires a matching handle; verification requires a signature.
Neither method mutates the path.

`Path.SignAcceptanceFor(child, expectedRoot, expectedParent)` is the opt-in
checked workflow: it proves the offered path, matches its immediate parent
by public-key bytes, then delegates to the matching child's signer.
The caller independently establishes both expected keys and controls the key;
the chosen parent may be a descendant of the root.
Success means those checks passed and the child signed, not human approval,
device authority, ancestor consent, or first acceptance.
Inputs remain unchanged, no state is recorded, and errors return no signature.

The development purpose tag is exactly `intro-acceptance/v1`.
`key.HashTagged` binds the whole canonical `Path.Bytes()`, including parent
signatures; its digest goes to the existing signing and verification helpers.
The experimental `test/intro-acceptance/v1` signatures are incompatible.
Acceptance is never inserted into an edge or parent signature.
Exact copies verify repeatedly; changed or re-signed bytes need fresh acceptance.

Low-level signing leaves path proof and parent checking to callers.
Callers of either workflow select the expected root and parent and establish
human consent separately.
These helpers change no modeled state, implement neither `Introduce` nor
`VerifyReceived`, and never promote evidence into `Known`.
One-time enrollment and global parent uniqueness remain unresolved;
a signature cannot replace `GlobalHasParent`.
Only these helper contracts and the scoped local signing aids below are authorized.
The product rationale alone authorizes no registry or further protocol machinery.

## Local acceptance choice

`NewAcceptanceChoice(child, expectedRoot)` creates a narrowly scoped,
auxiliary signing-workflow extension.
It borrows the handle and copies the independently supplied root without I/O,
membership, or human consent.
Use the returned pointer without copying it after use;
the owner must serialize access, including reentrant callbacks.

`Accept(offered, expectedParent)` checks the path, parent, and matching child,
then owns the exact proposal before signing.
Invalid initial attempts reserve nothing.
Selection compares complete `Path.Bytes()` representations.
Exact retries recheck the root and parent;
after success they return independent copies of the cached signature.
A different proposal is refused, including a re-signed same-parent revision.
Signing errors return no signature and retain selection;
only explicit retries can sign again.
There is no reset/recovery API; recovery policy remains unfinished.

Private state is a remembered proposal and cached signature,
not `Edges`, `Received`, `Known`, or proof of membership.
This guard does not implement `¬GlobalHasParent(v)` or establish what other
wallets/devices signed.
A fresh instance, restart, restored state, or direct key use bypasses it.
Global uniqueness and authority remain open.
No trust, tree-position policy, or automatic `Known` promotion follows.
No TLA+ action/source changes are authorized, and no full refinement is claimed.
[S1, S3]

## Stored choice application helper

`internal/onboarding` composes the existing introduction and storage APIs:

~~~go
func SignAfterStoredChoice(
    vault *storage.Vault,
    child key.Handle,
    expectedRoot, expectedParent key.Public,
    offered intro.Path,
) (acceptance key.Signature, err error)
~~~

The caller supplies an open, dedicated Vault for one child/root binding and
independently established expected keys.
Use is owner-serialized, including reentrant access, with an intact Vault.
The function borrows the Vault and signing handle, closes neither, and
stores no key handle or provider secret.

This scoped extension authorizes retaining one verified detached acceptance
alongside the selected proposal, so a completed request can return its saved
result after response loss or reopening.
The private `introduction-choice-demo` namespace keeps `selected-proposal`
and adds `acceptance`; this is not a published wallet schema.
Existing selection-only records remain pending choices, without migration.
Proposal bytes, the acceptance purpose tag, and cryptographic format stay fixed.
The separate in-memory `intro.AcceptanceChoice` contract stays unchanged.

Every call clones the offer and checks shape, proof under the independently
chosen root, expected parent, and matching child handle, including saved retries.
The first `Vault.Update` reads both records consistently and compares complete
canonical proposal bytes. It selects only when both records are absent.
Different or empty selected proposals return `intro.ErrDifferentAcceptance`.
An acceptance without a selection returns `intro.ErrBadAcceptance`.
Present empty values are not absent; storage read errors retain their causes.
After the transaction, an existing acceptance must pass `VerifyAcceptance`
before return. Invalid/empty acceptances are refused without signing or repair.
A valid saved result returns its exact bytes without `Sign`, `Put`, or another
encryption. Public-key access still occurs during preflight.

For a pending choice, `SignAcceptanceFor` runs outside all transactions.
Its successful signature must pass `VerifyAcceptance` before a second
`Vault.Update` saves only the acceptance.
That transaction requires the selection still to exist and match, and no
acceptance to have appeared. A different selection retains
`intro.ErrDifferentAcceptance`; missing selection or unexpected result presence
returns `intro.ErrBadAcceptance`. Lost state is not recreated or overwritten.
All errors retain their causes and return no signature; partial signer output
is neither saved nor returned. Signing or save failure retains the earlier
committed choice, and an explicit retry of that proposal may sign again if no
acceptance was saved. Signing and saving are separate, non-atomic operations:
interruption between them can require another signing call for the same offer.
This is saved-result reuse, not exactly-once signing, enrollment, or delivery.
There is no message delivery implementation in this extension.

Only auxiliary local signing choice and its completed result are persisted.
Neither signifies membership, human consent, or ancestor consent.
No `Edges`, `Received`, `Known`, trust, PW, device, or recovery authority is created.
This implements neither V19 `Introduce` nor `VerifyReceived` and supplies
no global `GlobalHasParent` predicate; its no-existing-parent guard remains
unchanged. Reverification does not promote evidence into `Known`. [S1, S2, S3]
Deletion, copying, restoration, rollback, another Vault/device, or external
key use can bypass the restriction.
Same-process reopen tests establish neither process-restart key custody,
physical crash durability, nor globally unique parenthood.
No concurrency, reentrancy, or rollback-resistance guarantee is added.

`ReadStoredChoice(vault, expectedRoot, expectedChild)` borrows the open Vault
and inspects both records in one `View`, using independently established public
identities and no signing handle. Opening the Vault still needs its provider.
It returns absence (`found == false`), a pending proposal with nil acceptance,
or a completed proposal with its matching verified acceptance; returned data
belongs to the caller. Invalid or inconsistent material returns an error with
no result, retaining storage, parser, and proof causes. Reading never signs,
repairs, rewrites, initializes a namespace, or reserves encryption usage.
`found` means a usable saved proposal, not membership or enrollment; completion
does not prove peer delivery or promote evidence into V19 `Known`.
It establishes no freshness, global uniqueness, current device authority,
human consent, or correctness of the independently configured identity binding.

### Read-only owner status

`ownerapi.NewStatusHandler(vault, expectedRoot, expectedChild)` borrows the
caller's open, dedicated Vault and copies independently established public keys
without I/O or a signing handle; the caller owns the Vault/provider lifecycle.
Each `GET /owner/status` calls `ReadStoredChoice` once and returns only a JSON
`choice`: `unselected` for no saved proposal, `pending` for a valid proposal
without saved acceptance, or `completed` for its saved, verified acceptance.
These labels are derived on each read, not persisted states or transitions;
they imply no enrollment, trust, peer delivery, or V19 `Known`.
Request input cannot select identities or actions.
Inspection errors, including a closed Vault or inconsistent evidence, return
generic HTTP 500 text without a choice or repair; all responses use `no-store`.

The bare constructor adds no authentication and must never be mounted without
protection. `NewAuthenticatedStatusHandler` composes it with a credential check
before routing or inspection: the caller supplies 32 freshly generated random
bytes dedicated to status access, independent of signing keys, identities,
Vault/provider secrets, and transport sessions or addresses. The constructor
validates length, owns a lowercase hex encoding, and performs no Vault I/O.
Exactly one `Authorization: Bearer <token>` header must carry that case-sensitive
64-character encoding; other inputs grant nothing. Rejections return generic
HTTP 401 with a Bearer challenge and `no-store`, without invoking the handler.
This scoped check authorizes only reading this configured status surface, not
human identity, Alice's signing-key control, enrollment, trust, a device grant,
or node-state mutation. No V19 transition changes; it is not a complete owner
authentication system or a claim of full OAuth conformance.

`intro owner-status-demo` mounts only the authenticated constructor on a
dedicated plaintext loopback developer listener, separate from peer HTTP.
It creates a disposable Vault with an `unselected` or genuinely signed and saved
`completed` fixture before serving; requests only read through `ReadStoredChoice`.
A separate random credential lives in an owner-only file for this invocation;
bearer possession is the access check, not the URL or fixture label.
Normal shutdown drains HTTP before closing storage and removing temporary files.
This trusts the local machine and excludes root or another process of the same
OS user from its isolation claim; it permits no remote forwarding or exposure.
The bare constructor remains unprotected. Peer and NATS demos remain unchanged;
restartable identity, remote/mobile access, and production provisioning remain
separate work, with no new V19 authority or signing permission.

### Deliberate public introduction copy

`NewReadCredentials` permits
`GET /owner/status`, disclosure through `GET /owner/introduction`, and stateless
inspection through `POST /owner/introduction/check`.
The three existing status constructors remain status-only. POST carries input;
the credential grants no persistence, signing, other writes, peer access,
enrollment, or permission for future owner POST operations.
Each export reads the configured node's saved choice once with independently
supplied root/child identities and no signer. Only completed verified evidence
is eligible; any nonempty `Body.Child.ID` on any edge is refused because handle
IDs can contain wrapped private signing keys. Signed fields are never stripped.
Absent/pending choices return 409; inconsistent, unreadable, nonpublic, or
oversize evidence returns generic 500, without repair or partial documents.

The explicit UI click copies a JSON object with exactly `version: 1`, `proposal`,
and `acceptance`; the latter two contain standard padded base64 of the complete
canonical saved path and exact detached acceptance. The 128 KiB development
transfer envelope is not separately signed, a backup, or a permanent public
interoperability specification. Existing purpose tags and core encodings remain
unchanged. The UI validates the transfer shape only. Public keys, ancestor links,
and signatures reveal the path; publicly verifiable is not privacy-free.

Export discloses only this node's saved introduction, never all received or known
evidence, and initiates no peer transmission. It changes no stored choice,
`Known`, trust, device, epoch, ad, or pairwise state and uses no encryption per
request; opening the Store retains its charge. This prepares self-presentation
without claiming all guards of V19 `PresentSelf`, `VerifyReceived`, or `CreatePW`.
The check operation parses that same bounded public document, rejects private
handle IDs and unsupported backup/rotation options without rewriting evidence,
and separately proves the path and verifies final-child acceptance. It uses
only the service's independently configured Root and public child identity,
without a Vault, signer, or completed local choice. The final subject can be
another node; self evidence is labeled by public-key byte equality. The UI
shows the full subject only after both checks pass and invalidates stale results
when input changes. No evidence endpoint is fetched or state recorded: this is
neither V19 `VerifyReceived` nor `CreatePW`. A copied signature proves neither
presenter key control, freshness, revocation status, global parent uniqueness,
nor a live authenticated channel. Peer enrollment, connections, and chat remain
separate work.

### Opt-in peer self-presentation

`node serve --peer-listen` explicitly enables a separate plaintext loopback
listener with only `GET /peer/introduction`. Any local caller can obtain this
node's already completed choice, validated by `ReadStoredChoice` under the
independently configured Root and child. The shared pure exporter preserves
the exact canonical proposal and detached acceptance, refuses private handle
IDs throughout the path, and bounds the existing JSON document to 128 KiB.
The peer additionally applies the stateless import admission policy to reject
unsupported backup/rotation fields, preserving existing owner export semantics.
It never exports Received/Known collections,
signs, repairs, or promotes evidence. Owner credentials and routes remain on
the separate bearer-protected listener; both servers and admitted requests
finish before Store cleanup.

This implements only sender-side disclosure from V19 `PresentSelf`
(specification revision `1a9cb30e9fcbcb89cea55c0aed1f6f88a3ea6508`,
`IntroTreeV19.tla`, lines 533–549). The full action also changes the receiver's
`Received`; a peer GET does not. A static signed document does not prove that
the HTTP presenter currently holds its private key. No `VerifyReceived`, device
authorization, `PublishAd`, mutual authentication, `CreatePW`, discovery or chat
is implied, and no modeled state changes.

### Deliberately retained received evidence

The owner may save checked public introductions in a separate encrypted Vault
namespace, keyed by full subject public-key bytes, with exact proposal/acceptance.
The projection adds decoded path edges to this receiver's `Received`, preserving
all existing evidence; duplicate/no-change operations stutter in that projection.
Acceptance signatures and the local index are representation metadata.
The existing checker is an admission filter for this limited owner import,
not every possible `ReceiveEdge` action and not durable `VerifyReceived`.
Checking, saving, and listing never update `Known`, global introduction truth,
the local choice, ads, PW, trust, deny, device, or recovery state.
A conflicting proposal is refused locally, without declaring a canonical parent.
Operational `node serve` uses fresh `NewEvidenceCredentials` for current reads,
check, and save/list only; read/status credentials gain no persistence or routes.
This capability grants no signing, trust, or general future POST permission.

### Explicit local verification

`onboarding.VerifyReceived(vault, expectedRoot)` explicitly promotes saved
Received subjects to durable Known introduction evidence. In one transaction it
rechecks every received record with the shared admission policy, checks all
existing Known bindings, and rejects contradictory parent public-key bytes,
including shared ancestors. Only after validation does it add missing versioned
digest markers bound to the exact received records. Its count is newly promoted
subjects, not modeled edges; retries with nothing new roll back without writes
or seals. `ListKnownIntroductions` revalidates each binding and its evidence in a
read-only query; markers alone confer nothing. Received and Alice's separate
choice remain unchanged. Saving, checking, listing, and reopening never promote
implicitly, and no owner route or UI action exposes promotion.

This is the local cryptographic-validation interpretation of V19
`VerifyReceived` (specification revision
`1a9cb30e9fcbcb89cea55c0aed1f6f88a3ea6508`, lines 413–424).
The model has an abstract genuine `Edges` set; Go has no omniscient oracle and
cannot prove global parent uniqueness. A valid root-pinned signed path and child
acceptance are our local operational evidence test, with local parent consistency.
This proves neither global `Edges` membership nor presenter's current key control,
and makes no node trusted or connected. It prepares a gate for a future explicitly
documented composite connection workflow; usable devices, verified current ads,
mutual acceptance and `CreatePW` remain separate. No PW, ad, trust, or device
authority is created, and V19 is unchanged.

## Source locators

[S1] Specification checkout `2cd914be966ad4bdf36b575e2678cad7441fcd75`,
`models/active/IntroTreeV19.tla`:
`CanIntroduce`, lines 371-379; `Introduce`, lines 381-397.
These specify the existing one-parent guard and modeled state changes,
not Alice's proposed acceptance protocol.

[S2] Project source `IntroTree_StateSemantics_Contract.md`,
section 3, “Core semantic boundaries”, lines 65-72:
“Introduction ≠ trust”, “Current ad ≠ historical authentic ad”,
and “Bootstrap ≠ pairwise reuse”.

[S3] Same specification checkout, `models/active/IntroTreeV19.tla`,
`VerifyReceived`, lines 413-424: explicit promotion into `Known`.

The user-goal, responsibility, and incentive paragraphs record the owner's
discussion of 2026-10-19.
The alternative-position counterexample is an analysis hypothesis,
not an observed behavior.

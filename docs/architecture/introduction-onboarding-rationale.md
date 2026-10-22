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

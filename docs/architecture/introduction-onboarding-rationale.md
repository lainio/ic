# Introduction rationale: deliberate admission, easy participation

Date: 2026-10-19

Status: product rationale captured from the owner's design discussion.
Explicit, parent-bound acceptance is the agreed design direction.
Detached acceptance helpers and the scoped local signing aid are implemented.
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
Only these helper contracts and the scoped local signing aid below are authorized.
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

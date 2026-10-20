# Introduction rationale: deliberate admission, easy participation

Date: 2026-10-19

Status: product rationale captured from the owner's design discussion.
Explicit, parent-bound acceptance is the agreed design direction.
Detached acceptance signature helpers are implemented.
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

`Path.SignAcceptance(child)` produces a detached `key.Signature`;
`Path.VerifyAcceptance(signature)` checks it with the final child's public key.
Both require at least two path entries and a nonempty child public key.
Signing requires a matching handle; verification requires a signature.
Neither method mutates the path.

The development purpose tag is exactly `intro-acceptance/v1`.
`key.HashTagged` binds the whole canonical `Path.Bytes()`, including parent
signatures; its digest goes to the existing signing and verification helpers.
The experimental `test/intro-acceptance/v1` signatures are incompatible.
Acceptance is never inserted into an edge or parent signature.
Exact copies verify repeatedly; changed or re-signed bytes need fresh acceptance.

Callers separately prove the path, select the root and parent, and establish
human consent.
These helpers change no modeled state, implement neither `Introduce` nor
`VerifyReceived`, and never promote evidence into `Known`.
One-time enrollment and global parent uniqueness remain unresolved;
a signature cannot replace `GlobalHasParent`.
Only this helper contract is authorized.
The product rationale alone authorizes no registry or further protocol machinery.

## Source locators

[S1] Project source `IntroTreeV19.tla`, lines 371-397:
`CanIntroduce` and `Introduce`.
These specify the existing one-parent guard and modeled state changes,
not Alice's proposed acceptance protocol.

[S2] Project source `IntroTree_StateSemantics_Contract.md`,
section 3, “Core semantic boundaries”, lines 65-72:
“Introduction ≠ trust”, “Current ad ≠ historical authentic ad”,
and “Bootstrap ≠ pairwise reuse”.

The user-goal, responsibility, and incentive paragraphs record the owner's
discussion of 2026-10-19.
The alternative-position counterexample is an analysis hypothesis,
not an observed behavior.

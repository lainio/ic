# CreatePW distributed-refinement boundary

Run #86 / Core #64. Go baseline: `01207e2023e1e87a73e73682f6cbebe8ac6a0fd5`,
branch `tla-spec-based-refactoring-v1`; initial working tree clean.
Semantic reference: `/home/parallels/go/src/github.com/optechlab/intro-tree`
(`SPEC_REPO`, read-only). Evidence keys below identify repository-relative
`file:line` ranges; **S** denotes the specification repository, **G** the Go repo.

**CreatePW remains blocked.** V19 changes both local relationship halves,
reciprocal views and the shared pipe in one transition [S2]. Operational nodes
restore separate identities and independently bound Vaults; `Vault.Update`
commits within one local database [G6]. HTTP plus two such commits supplies no
atomic distributed transition. The #85 exchange authorizes neither Vault write.

## A. Formal versus implemented

Here `x` is requester, `y` target. “Supplies” describes the inspected honest Go
execution; signature verification authenticates a statement, not remote policy
enforcement. The signature binds Root, ordered acceptor/peer roles and nonce;
ad binding lives in the listener's nonce ledger, not in that signed payload.
Neither signature carries reciprocal epoch/device views [G2, G5].
The target lock serializes participating local mutations only; it spans neither
HTTP nor a cross-node commit [G4].

| V19 obligation | What #85 supplies | Not established; minimal missing obligation |
|---|---|---|
| Initiator `CanAccept(x,y)` and authorized/usable `xDevice` [S1, S2] | Valid distinct identities, own/peer Known, local non-Deny, durable signer authorization and a fresh possession/usability probe; repeated around HTTP [G1, G3]. | Separate instantaneous reads/probes, no common snapshot through commit. Bind these guards and the selected device to the authorized abstract creation point. |
| Target `CanAccept(y,x)`, including target Known/Deny [S1, S2] | Target preflight, then local Known/Deny/device checks under its service mutation lock before signing; requester verifies the opposite-role proof [G1–G4]. | A remote signature cannot establish honest or continuing target policy. Specify how target acceptance holds at the same abstract creation point, including later Deny. |
| `VerifiedAd[x][y][slot] = CurrentAd[y][slot]`, non-expiry, usable ad device [S1] | Requester authenticates matching ReceivedAd/historical VerifiedAd bytes and checks expiry; target checks its exact current ad/endpoint before and after signing and probes its signer [G3, G4, G7]. | Historical VerifiedAd is not globally current. Target checks are momentary; no final shared currentness guarantee. Establish exact slot/ad equality, expiry and device usability at abstract creation. |
| `¬HasMutualPW(x,y)` [S1] | No mutual-PW read or relationship state in the inspected exchange [G3, G4]. | No duplicate/concurrent-create exclusion. Model both halves and competing attempts; revalidate this predicate, which permits rebootstrap when only one half remains. |
| Atomic creation of both `PWHeld` halves [S2] | No PW writes; only local transaction infrastructure exists on this path [G3, G4, G6]. | Neither half is created. Define a refinement mapping or extended actions for independently persisted steps before exposing any committed relationship. |
| Reciprocal `SeenPeerEpoch` / `SeenPeerDevice` [S2] | Role-bound proofs and signed ad fields; current profile is epoch 0, slot 1, Device = Node; no view writes [G2–G4, G7]. | Record both current peer epochs, `x`'s view of the ad device, and `y`'s view of `xDevice` with the abstract creation effects; the proofs do not supply these committed views. |
| `PWOpen`, separate from durable relationship [S2, S3] | Two bounded HTTP POSTs and an ephemeral `exchange_verified` result; no PW pipe or session established [G3, G4]. | Define the observable live pipe and its relation to commit. Never infer an open pipe from stored relationship records or proof success. |

`ClosePW` preserves relationship/views; `ReopenPW` requires mutual halves,
both acceptances and usable devices, but no public ad. `DeleteLocalPW` clears
only the caller's half, views, trust and ad caches, and closes the shared pipe
[S3]. Creation freshness is not a perpetual current-ad requirement on held PW.

## B. Exactly three failure traces

### 1. Proof-to-commit TOCTOU

1. `y` passes its guards and returns a valid acceptor proof to `x`.
2. Before a proposed PW commit, `y` denies `x`, its device becomes unusable,
   or its ad is superseded/expires; `x` retains the proof and historical ad.
3. A proposed writer treats exchange success as permission to create/open PW.

At risk: observable creation without the guards of `CreatePW` at that boundary;
opening after Deny also violates `DenyMeansNoOpenPipe` [S1, S2, S4]. Existing Go
rechecks target state before returning its proof and requester state after HTTP;
it cannot detect all subsequent remote changes [G3, G4]. It avoids the bad PW
effect by making no PW write, not by preserving consent until a later commit.

### 2. Partial commit and restart

1. Neither node holds PW; a proposed writer commits `x`'s half/views locally.
2. `y` crashes or the network fails before its independent commit.
3. Restart exposes `x`'s committed half while `y` still has none.

At risk: the all-effects `CreatePW` transition; exposing a pipe additionally
violates `PWOpenRequiresMutualPW` [S2, S4]. A lone half is not intrinsically an
invariant violation: V19 allows it after `DeleteLocalPW` [S3]. The unsupported
step is creating that half from neither-held state under a direct mapping.
Go's local atomic Update cannot complete or undo another node's commit [G6].
The current exchange avoids this effect by writing neither half; its Store
reopen is not a PW recovery protocol [G3, G4, G6].

### 3. Lost response and ambiguous retry

1. `y` consumes the authenticated challenge and signs; a hypothetical future
   version might also commit PW before replying.
2. The response is lost; `x` cannot distinguish failure from completed effects.
3. An automatic retry resubmits the consumed nonce, or obtains a fresh one
   without knowing whether the earlier proposed creation committed.

At risk: a purported new `CreatePW` while mutual PW already exists, or a late
creation based solely on old acceptance rather than current guards [S1, S2].
An unchanged duplicate needs a justified stuttering mapping; V19 specifies no
request-level exactly-once result. Go performs no automatic retry, and the live
ledger consumes a matching nonce once; restart forgets pending challenges and
retains no outcome record [G3, G5, G8]. This prevents same-ledger reuse, not
durable replay-safe PW establishment. No PW effects currently need recovery.

## C. Smallest next safe implementation step

**One recommended coding increment (test only):** add one deterministic
post-proof target-Deny regression using the existing requester fixture. Hold
the already-produced acceptance response, deny the requester at the target,
then release it. Check that the proof still verifies and the exchange can
succeed while target denial holds, with no exchange-induced Vault changes.
The current in-flight test explicitly skips peer changes at that stage [G9].
This records the observation boundary without adding a protocol or transition;
it must not convert success into a cached grant or change acceptance behavior.

**Blocked prerequisite for any durable PW increment:** human agreement on a
TLA+ extension or explicit refinement mapping, with checked failure behavior.
No durable PW increment is safe yet; partial `PWHeld` writes are excluded [S2, S5].

**Proposal, not authorized semantics:** the smallest distributed model/mapping
must account for per-attempt identity/generation and bindings to peers, ad/slot,
devices and epochs; per-node durable tentative/prepared versus committed state;
and retained outcome/replay information if effects can be retried after restart.
Include message delay/loss/duplication, independent local persistence,
crash/restart, prepare/finalize/abort or recovery actions, and interleaving
Deny, device/ad changes, concurrent attempts and local deletion. These are
modeling obligations, not a prescribed handshake, ledger or commit algorithm.

Tentative records must confer no committed `PWHeld`, peer-view, trust or pipe
authority. The mapping must explain which concrete steps stutter and where
all V19 creation guards/effects hold together, including intermediate reads
and crashes. A durable relation with no live pipe is distinct: if independent
establishment initially leaves it closed, justify that observable behavior
against V19's immediate `PWOpen` effect or explicitly extend the model [S2–S4].
Hiding tentative records alone proves neither that mapping nor crash safety.

Only two decisions require human semantic authority here:

- **Authorization boundary:** preserve V19's simultaneous creation guards, or
  explicitly model bounded consent/reservation with its lifetime and invalidation
  by Deny, ad expiry/replacement and device change; no lifetime is selected here.
- **Observation and failure contract:** approve the commit/pipe mapping or extend
  the lifecycle; define exposed outcomes and permitted abort/resume/retry after
  crashes, loss and deletion. No recovery policy or progress promise is selected.

## D. Evidence and limits

- S1: `IntroTreeV19.tla:157-175`, `IntroTreeV19.tla:276-321`.
- S2: `IntroTreeV19.tla:551-576` (guards and simultaneous effects).
- S3: `IntroTreeV19.tla:578-639` (close, reopen, local delete, deny).
- S4: `IntroTreeV19.tla:1184-1274`, `IntroTreeV19.tla:1335-1354`
  (ad, PW, trust, deny and peer-view invariants).
- S5: `docs/contracts/IntroTree_StateSemantics_Contract.md:113-117,539-583`;
  `docs/contracts/IntroTree_Implementation_Action_Map.md:227-277`;
  `docs/contracts/IntroTree_Conformance_Test_Map.md:121-206`.
- G1: `internal/pw/local.go:53-98`; `internal/device/local.go:86-104,151-172`.
- G2: `internal/pw/acceptance.go:15-29,58-107,124-136`.
- G3: `internal/pw/remote.go:46-159`; `internal/pw/remote_client.go:32-76`.
- G4: `internal/ownerapi/acceptance.go:25-58`;
  `internal/peerapi/challenge.go:129-173`; `internal/peerapi/acceptance.go:48-96`;
  `internal/ownerapi/acceptance_exchange.go:37-66`.
- G5: `internal/peerapi/challenge.go:21-48`;
  `internal/peerapi/challenge_ledger.go:13-98`.
- G6: `cmds/node/serve.go:243-277`; `internal/nodevault/local.go:42-82`;
  `internal/nodevault/vault.go:30-43,84-123`; `storage/tx.go:13-58`;
  `storage/internal/engine/bbolt.go:62-73`.
- G7: `internal/ads/local.go:40-65,128-151`; `internal/ads/verified.go:45-98`.
- G8: `cmds/node/peer_acceptance_test.go:115-164`;
  `internal/pw/remote_proof_test.go:123-197` (inspected, not rerun).
- G9: `internal/pw/remote_concurrency_test.go:23-28,49-64,113-155`.

The owner route is bearer-protected and receives the restored local signer;
the peer gets narrow capabilities [Go `internal/ownerapi/auth.go:63-82`,
`internal/ownerapi/credentials.go:129-192`]. Neither supplies an authenticated
session. Missing-code claims above concern this inspected operational path,
not an inventory of historical playground code. Cryptographic/AKE/session
security, deployment guarantees and network liveness remain outside V19's
state-semantics guarantee [S `docs/IntroTree_Model_Index.md:492-507`;
`IntroTreeV19.tla:1084-1085` has no fairness requirement]. Unknown/unestablished:
a distributed refinement, consent lifetime, recovery policy and handshake security.

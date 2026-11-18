# Round 6A: Advertisement expiry decision

Status: recommended policy; analysis only, 2026-11-18.
Go baseline: `a222e708407f863d08a5baf83d35c5c6465acd3a`.
`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree`, inspected at
`c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` with an existing dirty V19 file.
Go locators below are repository-relative; spec locators are relative to
`SPEC_REPO`. Read both repositories' `AGENTS.md` and
`docs/implementation/Current_Go_Implementation_Reality.md`.

## Decision

**Expiry of the original bootstrap ad alone should prevent none of the three
operations after valid establishment:** Bob's exact acceptance-result retry,
local usable-contact projection, or first use/messages. Treat expiry as a
bootstrap freshness limit. Authenticate retained evidence and enforce current
local authorization separately.

| Expiry timing | Recommended behavior |
|---|---|
| Before Bob's initial commit | Refuse fresh establishment from the expired ad. Fresh attempt preparation also requires unexpired verified discovery evidence. A previously saved request may be retransmitted, but cannot authorize Bob's first commit after expiry. |
| After Bob commits, before Alice observes the result | Bob may return the identical saved success under his current guards. Bob may project Alice's usable contact from his own holding; Alice has no committed contact or first-use eligibility yet. Alice may authenticate the delayed exact acceptance and commit under her own current guards despite ad expiry. |
| After both commits | Preserve both histories and holdings. Expiry alone suppresses neither usable contact nor exact retry. First use still needs its fresh authenticated exchange; messages still need the existing historical first-use evidence and operation-specific guards. |

Bob's commit is the consumption boundary; it does not wait for Alice's commit.
Alice authenticates the saved response as evidence of that commit, without
reading Bob's Vault or comparing cross-host commit timestamps. A lost response
must not turn elapsed bootstrap TTL into an irreversible one-sided outcome.

Historical evidence authenticates what was accepted, including both contacts;
it grants no present permission by itself. Retained holding, current Known
evidence, device authorization/usability, applicable binding checks, local
policy and the bound runtime remain required where the operation requires
them. Deny/delete still block new authorized use or Bob's retry; historical
contact remains readable. A duplicate cannot restore a deleted holding.
First-use session expiry remains distinct from ad expiry. Local usability
proves neither remote permission nor reachability, `PWOpen`, or Trust.

## Semantic basis and limits

- **V19:** `models/active/IntroTreeV19.tla:298`
  (`HasVerifiedCurrentAd`) requires `Now < AdUntil`; `CreatePW:551` uses that
  bootstrap guard. `Tick:522` preserves `PWHeld` and `PWOpen`;
  `ReopenPW:590` requires mutual holdings, usable devices and acceptance,
  with no ad guard. The concrete historical scenario is
  `models/history/MCIntroTreeV7_1_AdExpiryPWReuse.tla:132`: expired-ad creation
  stays disabled while existing PW reopening succeeds. See also
  `docs/contracts/IntroTree_Conformance_Test_Map.md:151`.
- **Accepted establishment extension:**
  `docs/IntroTree_Model_Index.md:447` and
  `docs/contracts/IntroTree_StateSemantics_Contract.md:256` give the invitation
  design precedence for initial establishment. In `IntroTreePWInvitationV1.tla`,
  `NewRedemption:95` checks the invitation clock; `ExactRetry:102` omits it.
  `BobAccept:153`, `BobReply:165` and `ReceiveAcceptance:178` separate Bob's
  commit, read-only result delivery and Alice's independent commit.
  `BobUsableContact:200`, `RequesterUsableContact:203` and first-use actions
  at `:210`, `:219`, `:239` use the same local permission predicates.
  `ContactDoesNotGrantUse:404` links open-use eligibility to usable contacts.
- **Contract expectation:** state contract `:310`, `:325`, `:345` separates
  retained success/contact history from current permission and fresh bootstrap.
  `docs/contracts/IntroTree_Implementation_Action_Map.md:104`, `:105`, `:120`
  and `:147` assign those local responsibilities.
  `docs/contracts/IntroTree_Conformance_Test_Map.md:544` explicitly asks for
  retained history and identical otherwise-eligible retry after bootstrap
  expiry, while refusing fresh creation from expired ads.
- **Model silence:** the invitation model has no separate ad-expiry clock or
  transition. Its `Tick:125` models invitation expiry; `BobPermits:84` and
  `RequesterPermits:87` abstract current prerequisites, including publication
  binding (`:80`). The conformance map `:544` acknowledges that abstraction.
  Therefore the retry contract supports this decision, but assigning elapsed
  ad TTL to historical freshness rather than a `Binding` fault is a concrete
  policy choice, not a demonstrated TLC ad-expiry trace. Alice's delayed
  completion and usable-contact behavior follow the recommended mapping.
- **Messages:** the separate `IntroTreePWMessageV1.tla:41` initializes accepted
  relationship/first-use history. `LocalPermits:56`, `CreateOutgoing:76`,
  `Transmit:84`, `AcceptIncoming:99` and `ReturnReceipt:113` have no ad TTL.
  This supplies no composition/refinement proof with invitation establishment.
  V19 strong-use/peer-view refresh is outside this expiry decision.

## Observed Go behavior and existing tests

| Area / classification | Exact implementation and test evidence |
|---|---|
| Fresh establishment — **Keep** | `internal/pw/bob_accept_v2.go:62` calls `newRedemption` (`internal/pw/establishment.go:146`), which checks fresh current ad and invitation expiry. `currentEstablishmentGuards:172` uses `internal/ads/local.go:180`, where expiry means unavailable. Alice's `requesterGuards` (`internal/pw/requester.go:284`) uses `internal/ads/establishment.go:18`, whose expiry comparison is at `:38`. `TestFirstUseBootstrapExpiryAndNoFreshPairingV2` (`internal/pw/first_use_history_v2_test.go:201`) rejects fresh establishment/preparation after expiry. |
| Bob's result retry — **Adapt** | `internal/pw/reply_v2.go:43` authenticates committed history, exact request and holding, then calls the fresh bootstrap guard at `:46`. `TestBobReplyV2ExactLossRestartAndExpiry` (`internal/pw/reply_v2_test.go:18`) permits retry after invitation expiry/restart, then explicitly requires `ErrEstablishment` after ad expiry at `:61`. Initial response delivery uses this same path (`internal/ownerapi/establishment.go:108`). |
| Alice's delayed acceptance — **Adapt** | `internal/pw/requester_accept_v2.go:68` verifies the exact response, then calls `requesterGuards` at `:79`, including for duplicates. `TestReceiveAcceptanceV2CurrentGuards` (`internal/pw/requester_accept_atomic_v2_test.go:48`) rejects ad expiry before receipt, during the signer probe and during duplicate receipt, preserving local state. |
| Saved-request retrieval — **Adapt** | `readAttemptV2` (`internal/pw/requester.go:404`, expiry-bearing call at `:424`) rechecks fresh discovery even for an existing request. `TestRequesterV2CurrentGuards` (`internal/pw/requester_v2_test.go:231`) includes rejection on `retry/expiry`. The owner retry calls this through `internal/ownerapi/redeem.go:148`; `SendEstablishV2` itself (`internal/pw/establishment_client.go:41`) authenticates saved bytes without a freshness check. |
| Historical contacts — **Keep**; usable contacts — **Adapt** | `internal/pw/history_v2.go:30` authenticates immutable evidence without live expiry. `internal/pw/contact_v2.go:44` projects history; `:92` adds local eligibility, but `contactGuardsV2:128` calls fresh bootstrap guards for either role. `TestContactV2LocalEligibilityAndImmutableHistory` (`internal/pw/contact_lifecycle_v2_test.go:18`, expiry at `:52`) requires empty usable contact and intact historical contact after expiry/restart, including expiry during the probe. |
| First use — **Keep** for expiry policy | `internal/pw/first_use_state_v2.go:80` checks accepted/held history, runtime, Known, Deny and authorization without refreshing bootstrap. Fresh-session checks remain in `internal/pw/first_use_v2.go:88`, `:161`, `:234`. `TestFirstUseRandomSessionAndRetainedBindingV2` (`internal/pw/first_use_v2_test.go:99`) succeeds after ad/invitation expiry. `TestFirstUseBootstrapExpiryAndNoFreshPairingV2` additionally removes Alice's discovery caches. |
| Messages — **Keep** for expiry policy | `internal/pw/message_history_v2.go:19` authenticates relationship and historical first use; `:55` adds current local guards. `internal/pw/message_transmit_v2.go:95` uses those guards and the committed contact. Existing positive tests: `TestMessageNoBootstrapRefreshOrRemotePermissionV2` (`internal/pw/message_outgoing_v2_test.go:259`), `TestIncomingNoBootstrapOrRemotePolicyGuardV2` (`internal/pw/message_incoming_v2_test.go:169`), `TestMessageSendV2ExpiredBootstrapAndSnapshotPolicy` (`internal/pw/message_transmit_v2_test.go:136`). |

Thus the current code retains holdings/history but can report no usable contact
while first use and messaging remain locally eligible. Post-commit ad-expiry
gating is inconsistent with the recommended bootstrap/reuse boundary and the
retry conformance expectation. This is not a claim of a proved V19 refinement
violation: the invitation extension and concrete clock mapping have that limit.

## Smallest subsequent implementation increment

1. **Split freshness from binding validation only where necessary.** Keep
   fresh-ad checks for new attempt creation and Bob's first redemption.
   Give v2 Bob reply, usable-contact projection and Alice acceptance validation
   an expiry-independent path that still authenticates exact evidence and
   rechecks current non-expiry prerequisites at the existing serialization
   boundary. Preserve publication/claim mismatch and corruption checks; this
   decision does not settle cache removal, supersession or rotation. Do not
   globally weaken the existing fresh-ad readers or simulate an earlier clock.
2. Apply that distinction to the **existing-request read** in `readAttemptV2`,
   so restart can recover exact retry bytes. Alice cannot know whether Bob
   committed when a response is lost; reading/resending her saved request
   creates no authority. Bob still refuses initial redemption after expiry.
   Include `checkRequesterAcceptanceV2`: changing only Bob's reply and contacts
   would leave Alice unable to complete the delayed exchange.
3. Replace the post-commit/retry expiry cases in the four affected test groups
   with focused positives; keep new-attempt and other guard refusals.
   Add one lost-response/restart sequence:
   Bob commits while the ad is fresh, ad expires, Alice reloads the exact
   attempt, Bob returns unchanged bytes with no write or acceptance re-signing,
   Alice commits once, both usable projections and fresh first use succeed.
   Cover expiry after both commits and expiry crossing a signer probe.
   Keep Deny/delete, binding-conflict and corrupt-history refusals beside these
   positives, plus unchanged fresh-bootstrap negatives at the exact boundary.

Isolate ad expiry from invitation expiry in the new boundary test:
`TestBobAcceptV2ExpiryBoundary` (`internal/pw/bob_atomic_v2_test.go:105`) tests
the **invitation** deadline, and the fixture's ad expires one minute later
(`internal/pw/establishment_test.go:37`). The existing fresh-pairing negative
above advances past both deadlines. No first-use/message redesign, wire/storage
change or TLA+ modification is needed for this narrowly scoped increment.

## Verification and workspace

The nine focused behavior tests in the table, plus
`TestFirstUseRequiresBothIndependentHoldingsV2`
(`internal/pw/first_use_v2_test.go:121`), were run as ten selected tests with
`go test -mod=readonly -count=1 ./internal/pw -run ...`: pass
(`2.378s`). This confirms present behavior, not the recommended change.
`make lint` passed before and after this note. No TLC run or test edits.

The Go checkout was initially clean; this note is the sole addition.
The specification's existing modification to
`models/active/IntroTreeV19.tla` concerns `RestoreSafeRecoverySnapshot`,
outside the cited expiry/lifecycle operators, and was preserved unchanged.
No Git-writing commands, commits or tags were used.

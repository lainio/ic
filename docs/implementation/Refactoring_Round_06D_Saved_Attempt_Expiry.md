# Round 6D: Saved v2 attempt retrieval after advertisement expiry

Status: scoped implementation, 2026-11-19.
Accepted Go baseline: `8175f1c21a3162aecea68de70dbce7ec87adfe5d`.
Go workspace: `/home/parallels/go/src/github.com/lainio/ic`.
`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree` is a
read-only reference at `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665`, with an
existing dirty `models/active/IntroTreeV19.tla`.
Source locations below refer to this increment's working tree.

## Result and semantic scope

`SaveAttemptV2` can retrieve an existing authenticated v2 request after its
original bootstrap advertisement expires. Both reads, before and after the
signer-usability probe, authenticate the complete retained history and enforce
current local permission. The original Received and Verified ad evidence must
still exist, authenticate, agree byte-for-byte and match the saved request.
Changed or missing evidence does not become acceptable through expiry.

Retrieval returns the original request bytes and current `Accepted`/`Held`
flags. Pending, accepted-and-held, and accepted-but-deleted remain distinct.
It performs no durable write, encryption spend, new attempt, attempt signature,
refresh or contact rebind. The existing discarded signer-usability probe is
still required; this is not a signature-free operation.

Fresh attempt preparation and Bob's first acceptance retain their fresh-ad
guards. V1 behavior and exact `ErrEstablishment` identity are preserved.
BobReplyV2, ReceiveAcceptanceV2, contact projections, first use, messaging,
HTTP APIs, storage schemas and TLA+ behavior were not modified.

Read the applicable repository guidance, `Current_Go_Implementation_Reality.md`,
Round 06A/06B/06C reports, and all four required semantic references. Relevant
locations under `SPEC_REPO` are:

- `docs/IntroTree_Model_Index.md:447`: accepted invitation establishment
  intent, with V19 retained as the general lifecycle baseline.
- `docs/contracts/IntroTree_StateSemantics_Contract.md:276`: exact saved
  attempt and complete contact binding; `:310`: durable history versus
  current permission; `:345`: bootstrap expiry cannot authorize fresh creation.
- `docs/contracts/IntroTree_Implementation_Action_Map.md:101`: SaveAttempt
  and SendEstablish responsibilities, with local serialization at `:92`.
- `docs/contracts/IntroTree_Conformance_Test_Map.md:534`: exact retry and
  restart obligations; `:544`: retained history and otherwise eligible exact
  retry after bootstrap expiry, while fresh creation remains refused.

This implements only Round 6A's saved-request retrieval recommendation.
The invitation model abstracts ad freshness/current binding and supplies no
concrete ad-expiry clock trace. These Go checks do not establish V19 refinement,
general Go conformance, cryptographic proof or model composition. No TLC check
was run.

## Exact source changes

- `internal/pw/requester.go:416`: `readAttemptV2` keeps
  `readLocalHistoryV2` authentication of the complete requester tuple, legacy
  rejection, pinned Root/requester checks, exact invitation/target/audience/
  recipient match, configured requester contact match and expected ad match.
  Request authentication still covers the signed attempt ID, device/epoch,
  both canonical contacts and authenticated target ad/contact binding.
  It replaces only the fresh `requesterGuards` call with
  `requesterPermissions`, `ads.ReadRetainedEstablishmentAdInTx`, and exact
  saved-ad equality. It returns the authenticated original bytes and flags.
  Its unused private clock parameter and the two caller arguments are removed.
  Public signatures remain unchanged; comments describe the expiry policy.
- `internal/ads/establishment.go:34`: documentation only, identifying both
  retained attempt and acceptance callers. Reader behavior is unchanged;
  there is no new validation framework or expiry-switch parameter.
- `internal/pw/requester_v2_test.go`: extends the existing requester tests
  with expiry boundaries, reopen, signer and current-guard refusals, exact
  bindings and history revalidation described below.
- `internal/pw/requester_accept_expiry_v2_test.go:112`: updates the old
  saved-attempt expiry refusal to require identical request bytes and
  accepted/held flags. Its fresh-ad reader refusal and acceptance assertions
  remain. No new real-time wait was added; its existing timer is unchanged.

## Preserved fresh-establishment guards

`saveAttemptV2` at `requester.go:381` still invokes `requesterGuards` whenever
no saved attempt exists, both before and after the signer probe. It derives
the target contact only from that authenticated fresh evidence. The clock
remains injected for fresh preparation and commitment.

`commitAttemptV2` at `requester.go:443` still authenticates the proposed
signed request, refuses any existing attempt, and calls the fresh guard in
the final write transaction before storing the request. An expired retained
attempt cannot become an available creation slot. Expiry during attempt
signing still prevents commitment.

`requesterGuards` and `ads.ReadEstablishmentAdInTx` retain strict
`now < ExpiresUnixNano` validation. BobAcceptV2 still checks fresh evidence
before signing and in its final transaction. The existing Bob ad-boundary
regression isolates ad expiry from invitation expiry. V1 callers retain their
original guards.

## Positive and negative automated evidence

- `TestRequesterV2SavedAttemptAdExpiry` (`requester_v2_test.go:89`): directed
  and undirected requests in pending, accepted/held and deleted-holding states.
  Each retrieves immediately before, exactly at and immediately after the ad
  deadline, across expiry inside the signer probe, and after reopening the
  Vault and signer. Injected clocks require no wait. Every retrieval compares
  the exact request and full signed binding, current flags, all fixture records
  and both encrypted Vault files. Alice has zero encryption allowance.
  Re-signing the attempt digest fails; exactly one probe signature is observed.
  Mutating returned bytes leaves durable evidence intact.
- `TestRequesterV2NewAttemptAdExpiryBoundary` (`:160`): new preparation
  succeeds one nanosecond before expiry and refuses exactly at/after expiry,
  before preflight, during the signer probe and during request signing.
  Refusals return exact `ErrEstablishment` and an empty result, leave encrypted
  files and encryption allowance unchanged, and leave no records after reopen.
- `TestRequesterV2RetainedSigner` (`:275`): an expired saved attempt still
  refuses absent, typed-nil, wrong and failing signers, invalid probe signatures
  and signatures produced by another identity. No persistent changes occur.
- `TestRequesterV2DescriptorConflicts` (`:314`): changed Root, requester,
  target, invitation, audience and configured requester contact refuse both
  before and after expiry, preserving original bytes without probing/signing.
- `TestRequesterV2CurrentGuards` (`:394`): preserves fresh-preparation
  refusals before the call, during the probe and during signing. Retained
  retries additionally test current-guard loss before retrieval and during
  the probe after expiry: own/peer Known, device authorization, Deny, missing
  Received/Verified evidence, independently changed collections, matching
  forged ad signatures, malformed collections, replacement of both ads and
  changed target contact. Every refusal returns exact `ErrEstablishment`,
  an empty result and unchanged attempt/acceptance/holding records.
  Retry/expiry and retry-probe/expiry now require successful exact retrieval.
- `TestRequesterV2CorruptSavedAttemptIsNotRepaired` (`:645`): expired,
  reopened attempts with tampered contact, noncanonical request, corrupt
  acceptance or orphan holding still refuse without repair.
- `TestRequesterV2RetainedHistoryDuringProbe` (`:681`): after expiry,
  corrupting the attempt, acceptance signature, holding digest or first-use
  evidence during the probe causes refusal at the second read. Injected
  records remain after reopen. Deleting the holding during that probe instead
  returns the original request with `Accepted=true, Held=false`, without
  resurrecting it.
- Existing version-isolation, rollback, contact-history authentication,
  Bob/Alice acceptance, fresh-bootstrap expiry and retained-ad evidence tests
  remain in the focused/full regression checks. Usable-contact expiry behavior
  is explicitly included and unchanged.

## Automated validation

All Go checks used `GOTOOLCHAIN=local`, empty `GOEXPERIMENT`, `GOPROXY=off`,
`GOSUMDB=off`, `GOFLAGS=-mod=readonly`, and `go1.27.1 linux/arm64`.
Finite timeouts, lint configuration, dependencies and test-selection policy
were preserved. Touched Go files were formatted with `gofmt`.
Logs are workspace-session evidence under `/tmp/ic-round-06d/`.

| Check | Result | Log |
|---|---|---|
| Baseline `make lint` | PASS, 0 issues, exit 0 | `baseline-lint.log` |
| Focused requester v2 tests, 2m timeout | PASS, PW 2.790s, exit 0 | `focused-requester-final.log` |
| Bob/Alice acceptance and expiry regressions, 2m timeout | PASS, PW 14.654s; ads 0.100s, exit 0 | `focused-regression.log` |
| `make test_fast TEST_ARGS=-count=1` | PASS, 16 families / 36 descendants; PW 0.980s, exit 0 | `test-fast.log` |
| Complete ordinary Go suite, 10m timeout | PASS, all packages; PW 117.803s, ads 9.983s, storage 6.071s, exit 0 | `full-suite.log` |
| Focused race checks, 5m timeout | PASS, PW 37.904s; ads 1.110s; no race report, exit 0 | `focused-race.log` |
| Final `make lint` | PASS, 0 issues, exit 0; cache warnings below | `final-lint.log` |
| `git --no-optional-locks diff --check` | PASS, no whitespace errors, exit 0 | `diff-check.log` |

Final lint warned that it could not persist analysis-cache facts under the
sandbox's read-only `/home/parallels/.cache/golangci-lint`. Analysis completed
successfully with zero issues; no lint settings were relaxed. The full warning
output is retained in `final-lint.log`.

The first requester run failed only the newly added
`CurrentGuards/before/{replaced_ad,changed_contact}` cases (PW 2.831s, exit 1;
`focused-requester.log`). Those cases incorrectly expected refusal when new,
valid discovery evidence replaced the ad before any attempt preparation.
Replacement conflicts require an already bound attempt/ad. The table now
tests replacement during preparation or saved-attempt retrieval; existing
refusal assertions and production code were unchanged by this correction.
The corrected requester run passed.

Exact test commands (with the environment above):

~~~sh
go test -count=1 -timeout=2m ./internal/pw -run '^TestRequesterV2'
go test -count=1 -timeout=2m ./internal/pw ./internal/ads \
  -run '^Test(BobAccept|BobReply|BobV2|ReceiveAcceptance|RequesterCurrentGuards|FirstUseBootstrapExpiryAndNoFreshPairingV2|ContactV2LocalEligibilityAndImmutableHistory|ContactV2CorruptionNeverBecomesAbsenceOrDeletion|RetainedEstablishmentAd)'
make test_fast TEST_ARGS=-count=1
go test -count=1 -timeout=10m ./...
go test -race -count=1 -timeout=5m ./internal/pw ./internal/ads \
  -run '^Test(RequesterV2|RequesterCurrentGuards|ReceiveAcceptanceV2|BobAcceptV2|BobReplyV2|BobV2|RetainedEstablishmentAd|FirstUseBootstrapExpiryAndNoFreshPairingV2|ContactV2LocalEligibilityAndImmutableHistory|ContactV2CorruptionNeverBecomesAbsenceOrDeletion)'
~~~

## Manual acceptance, limitations and repository state

Manual demo/HTTP acceptance was not performed. No HTTP lost-response integration
test was added. These are automated local encrypted-Vault checks; owner
acceptance remains separate. Usable-contact projection behavior and the broader
Round 6A end-to-end scenario remain outside this increment.

Retained evidence removal, corruption, supersession or contact change still
blocks retrieval. Retrieval supplies neither fresh bootstrap authority nor
remote permission/reachability. The existing owner mutation/configuration/
signer serialization requirement remains. No rotation, refresh, rebind or
recovery mechanism was added.

The Go checkout began clean at the accepted baseline. This increment changes
the four Go files listed above and adds this report. No Git-writing commands,
commits, tags, nested Codex or exec-metrics were used. The specification's
existing dirty model has identical before/after SHA-256
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`;
its HEAD and dirty-path status are also unchanged. Read-only evidence is in
`/tmp/ic-round-06d/go-status.log`, `go-head.log`, `spec-status.log`,
`spec-head.log` and `spec-sha256.log`. Go HEAD remains the accepted baseline;
the intended working-tree changes are left uncommitted for review.

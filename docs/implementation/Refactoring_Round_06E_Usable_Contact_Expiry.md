# Round 6E: Usable contacts after advertisement expiry

Status: scoped implementation, 2026-11-19.
Accepted Go baseline: `979ad3b9049f59087f3d93732e2ca909a2297c35`.
Go workspace: `/home/parallels/go/src/github.com/lainio/ic`.
`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree` is a
read-only reference at `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665`, with its
existing dirty `models/active/IntroTreeV19.tla` preserved.
Source locations below refer to this increment's working tree.

## Result and semantic scope

After valid v2 establishment, expiry of the original bootstrap advertisement
alone no longer suppresses `BobUsableContactV2` or `RequesterUsableContactV2`.
Each projection still authenticates its own committed relationship history
and holding, enforces current local permission and signer usability, and
requires its trusted running configuration to match the immutable own contact.
The retained original advertisement must authenticate and match the signed
establishment exactly. Only elapsed advertisement TTL is ignored.

Historical and usable projections return the original peer service contact.
They do not refresh advertisements, rebind contacts, write relationship state
or spend encryption allowance. Usable projection retains its one fresh,
discarded signer-usability probe; it does not re-sign establishment evidence.

Read the applicable repository guidance, implementation reality document,
Round 06A–06D reports, and all four required semantic references. Relevant
locations under `SPEC_REPO` are:

- `docs/IntroTree_Model_Index.md:447`: accepted invitation establishment
  intent, with V19 retained as the general lifecycle baseline.
- `docs/contracts/IntroTree_StateSemantics_Contract.md:325`: historical
  contact versus current local eligibility; `:345`: accepted contact history
  survives bootstrap expiry without authorizing fresh creation.
- `docs/contracts/IntroTree_Implementation_Action_Map.md:120`: local contact
  projection responsibilities, independent of remote state and first use;
  `:147`: stable service contact and bootstrap expiry.
- `docs/contracts/IntroTree_Conformance_Test_Map.md:151`: expired bootstrap
  versus retained reuse; `:543`: historical versus locally usable contacts;
  `:544`: stable service binding and bootstrap expiry.

This implements only Round 6A's usable-contact recommendation. The invitation
model abstracts ad freshness/current binding and supplies no concrete ad-expiry
clock trace. No formal refinement, general Go conformance, cryptographic proof
or model-composition result is claimed. No TLA+ files or checks were changed
or run.

## Exact changes

- `internal/pw/contact_v2.go:129`: `contactGuardsV2` now calls
  `requesterPermissions` plus `ads.ReadRetainedEstablishmentAdInTx` for Alice,
  requiring byte-for-byte equality with the signed establishment ad. For Bob,
  it uses `establishmentPermissions`, `ads.ReadRetainedLocalInTx`, and
  `checkEstablishmentAd`, retaining exact ad and endpoint comparison.
- `internal/pw/contact_v2.go:147`: `contactIneligibleV2` no longer treats
  Alice's `ads.ErrInvalidRecord` as ineligibility. Retained readers do not
  return expiry errors. Explicit eligibility/binding refusals and Alice's
  missing/changed claims still yield empty contact with nil error. Malformed
  or unauthentic evidence remains an error, sanitized to `ErrEstablishment`.
  Bob's partial ad namespace remains corruption, including a missing slot.
- `internal/pw/contact_v2.go:93`: removed only the obsolete private clock
  arguments and `time` import. Public signatures are unchanged. The existing
  signer probe remains outside the View; history authentication, holding,
  trusted runtime, current authorization and exact evidence checks retain
  their existing ordering in the final local snapshot.
- `internal/pw/contact_v2_test.go:16`: the fixture now calls the public
  projection functions. Direct lifecycle callers use the clock-free private
  signature. The old expiry-refusal cases were replaced by the positive
  boundary coverage below; other eligibility refusals remain.
- Extended `contact_lifecycle_v2_test.go`, `contact_history_v2_test.go` and
  `contact_v2_test.go`, and added `contact_expiry_v2_test.go` as detailed below.

Production changes are confined to `contact_v2.go`. Fresh ad readers,
SaveAttemptV2, BobAcceptV2, BobReplyV2, ReceiveAcceptanceV2, v1, first use,
messaging, wire formats, storage, dependencies and package boundaries are
unchanged. No generic validation framework was introduced.

## Automated behavioral evidence

`TestContactV2AdExpiry` (`contact_expiry_v2_test.go:20`) uses the existing
encrypted Bolt Vault fixtures and deterministic fixture clock. For each role,
it checks one nanosecond before, exactly at and one nanosecond after the signed
ad deadline, crossing the deadline inside the signer probe, and reopening the
Vault and signer after expiry. Both public usable projections must equal their
original historical contacts. The unchanged fresh Bob/Alice ad readers agree
that evidence is fresh only before the deadline. The contact API itself no
longer needs a clock, and no real-time wait was added.

Each projection compares both encrypted Vault files and encryption allowances,
with both allowances exhausted, and checks unchanged fixture records. Historical
reads make no signer call; usable reads make exactly one probe. Signing the
original request or acceptance digest again fails the test. Accepted evidence,
holdings and contacts remain identical across expiry and reopen.

Preserved or extended refusal coverage:

- `TestContactV2LocalEligibilityAndImmutableHistory`: Deny, missing own/peer
  Known, device authorization loss, changed ad, deleted holding, stopped or
  changed runtime, and signer failure. Durable changes are also injected
  during the probe; configuration changes remain under the owner-lock
  contract. Reopen cannot restore eligibility; historical contacts remain.
- `TestContactV2RetainedAdAbsenceAndCorruption`: Bob's missing slot,
  malformed ad, corrupt signature, replacement and changed endpoint; Alice's
  missing Received/Verified claims, independently changed collections,
  replacement of both, changed contact, matching forged ads and malformed
  collections. Checks run before projection and during the signer probe,
  then after reopen. Missing/changed claims produce absence; corruption
  produces exact `ErrEstablishment`. Relationship records remain intact.
- `TestContactV2SignerRefusals`: nil, typed-nil and foreign signers, signing
  failure, invalid probe signatures and signatures from another identity.
- `TestContactV2LegacyAndWrongRoles`: legacy isolation and incorrect pinned
  identity/role, now also checking the usable projection's wrong-role refusal.
- `TestContactV2CorruptionNeverBecomesAbsenceOrDeletion`: existing malformed,
  noncanonical, tampered, wrong-role and inconsistent relationship history,
  now checked with both running and stopped usable projections.
- `TestContactV2HistoryChangedDuringProbe`: corrupt request/response
  signatures, holding digest and role changes, plus a validly signed
  substituted acceptance contact. The final read refuses the injected
  evidence, including after reopen, without repairing it.
- Existing `TestBobAcceptV2AdExpiryBoundary` and
  `TestRequesterV2NewAttemptAdExpiryBoundary` still refuse fresh creation
  exactly at/after expiry, including expiry during probe and signing. Bob's
  test isolates ad expiry from invitation expiry. Adjacent v1, acceptance,
  saved-attempt and first-use bootstrap regressions are included below.

## Validation

All Go checks used the existing `GOTOOLCHAIN=local`, empty `GOEXPERIMENT`,
`GOPROXY=off`, `GOSUMDB=off`, `GOFLAGS=-mod=readonly`, and
`go1.27.1 linux/arm64`. Timeouts, dependencies, lint configuration and
test-selection policy were preserved. Touched Go files were formatted with
`gofmt`; no repository-wide formatting was applied.
Session logs are under `/tmp/ic-round-06e/`.

| Check | Result | Log |
|---|---|---|
| Baseline `make lint` | PASS, 0 issues, exit 0 | Direct tool output |
| Focused contacts and DeleteHeldV2, 2m | PASS, PW 4.876s, exit 0 | `focused-contact.log` |
| Adjacent Bob/Alice/ads regressions, 2m | PASS, PW 16.218s; ads 0.103s, exit 0 | `focused-adjacent.log` |
| Fresh `make test_fast TEST_ARGS=-count=1` | PASS, 16 families / 36 descendants; PW 3.950s, exit 0 | `test-fast.log` |
| Complete ordinary Go regression, 10m | PASS, all packages; PW 140.384s, ads 13.547s, storage 7.761s, exit 0 | `full-suite.log` |
| Focused race checks, 5m | PASS, PW 58.239s; ads 1.399s; no race report, exit 0 | `focused-race.log` |
| Final `make lint` | PASS, 0 issues, exit 0; cache warnings below | `final-lint.log` |
| `git --no-optional-locks diff --check` | PASS, exit 0 | Direct tool output |

Final lint could not persist analysis-cache facts under the sandbox's read-only
`/home/parallels/.cache/golangci-lint`. Analysis completed successfully with
zero issues. No lint setting was relaxed.

Earlier incremental contact checks also passed: `^TestContactV2` (2.926s)
and `^TestContactV2RetainedAdAbsenceAndCorruption$` (0.852s), each with
`-count=1 -timeout=2m`. No failing check was hidden or weakened.

Exact principal test commands, with the environment above:

~~~sh
go test -count=1 -timeout=2m ./internal/pw \
  -run '^Test(ContactV2|DeleteHeldV2)'
go test -count=1 -timeout=2m ./internal/pw ./internal/ads \
  -run '^Test(BobAccept|BobReply|BobV2|ReceiveAcceptance|RequesterV2|RequesterCurrentGuards|FirstUseBootstrapExpiryAndNoFreshPairingV2|RetainedEstablishmentAd|ReadRetainedLocalInTx|ReplacementExpiryAndStateBoundary)'
make test_fast TEST_ARGS=-count=1
go test -count=1 -timeout=10m ./...
go test -race -count=1 -timeout=5m ./internal/pw ./internal/ads \
  -run '^Test(ContactV2|DeleteHeldV2|RequesterV2|RequesterCurrentGuards|ReceiveAcceptanceV2|BobAcceptV2|BobReplyV2|BobV2|RetainedEstablishmentAd|ReadRetainedLocalInTx|ReplacementExpiryAndStateBoundary|FirstUseBootstrapExpiryAndNoFreshPairingV2)'
~~~

## Repository state and limitations

The Go checkout began clean at the accepted baseline, and HEAD remains there.
The intended uncommitted changes are four tracked Go files
(`contact_v2.go` and its three existing test files), the new
`contact_expiry_v2_test.go`, and this report. No Git-writing commands, commits,
tags, nested Codex or exec-metrics were used.

The spec HEAD and dirty-path status are unchanged. Its existing dirty V19
file has identical before/after SHA-256:
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`.

Manual demo/HTTP integration acceptance was not performed. These are automated
local encrypted-Vault checks and regressions; no manual acceptance or full
lost-response integration result is claimed. Retained evidence removal,
replacement or corruption still blocks usable projection. Rotation, discovery,
rebind and recovery remain outside this increment. The owner still serializes
mutation, signer and runtime configuration across projection. Local usability
provides no remote permission, reachability, first use, `PWOpen` or Trust.

Work stops at this Round 6E increment without a commit or tag.

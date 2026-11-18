# Round 6C: Alice's delayed v2 acceptance

Status: scoped implementation, 2026-11-18.
Accepted Go baseline: `45b4e6302a2e431972881895543d7dcf0318cc17`.
`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree` is a read-only
reference at `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665`. Its existing dirty
`models/active/IntroTreeV19.tla` is preserved.
Source locations below refer to this increment's working tree.

## Result and scope

After Bob commits a valid v2 acceptance, Alice can authenticate and commit his
exact signed response after the original bootstrap ad expires. The original
Received and Verified ad evidence must still exist, authenticate and match
each other and her exact saved signed request. Expiry alone is ignored;
replaced, missing or corrupt evidence still refuses acceptance.

The exact request, signed acceptance, immutable contacts and requester role are
authenticated as before. Current own/peer Known, Deny, device authorization and
live signer usability remain required. Durable evidence and guards are
rechecked at the existing write transaction for first acceptance, or read
transaction for an exact duplicate. First acceptance writes only Alice's
acceptance and holding. Duplicates are read-only and return the current holding;
after deletion they return `false, nil` without recreating it. Refusals preserve
exact `ErrEstablishment` identity.

This implements only the Alice-acceptance recommendation in Round 6A, following
Round 6B's Bob-reply change. SaveAttemptV2/readAttemptV2, BobAcceptV2/BobReplyV2,
v1 behavior, usable-contact projections, first use and messaging retain their
behavior. Wire formats, signatures, schemas, dependencies and HTTP APIs are
unchanged. No complete HTTP lost-response scenario was added.

## Semantic references

Read the applicable repository guidance, `Current_Go_Implementation_Reality.md`,
both Round 6A/6B reports, and all four required semantic references. Relevant
locations under `SPEC_REPO` are:

- `docs/IntroTree_Model_Index.md:447`: invitation establishment is the accepted
  initial-establishment intent; V19 remains the general lifecycle baseline.
- `docs/contracts/IntroTree_StateSemantics_Contract.md:302`: Alice authenticates
  the complete response against her exact request and commits independently;
  duplicates cannot recreate deleted holdings. `:310` distinguishes durable
  results from current permission; `:345` preserves history after bootstrap
  expiry without authorizing fresh creation.
- `docs/contracts/IntroTree_Implementation_Action_Map.md:105`: Alice's local
  atomic acceptance and read-only duplicate responsibilities, within the
  serialization rules at `:92`.
- `docs/contracts/IntroTree_Conformance_Test_Map.md:533`: Alice's atomicity,
  exact binding, invalid-response and no-resurrection obligations; `:544`:
  retained history and otherwise eligible exact retry after bootstrap expiry,
  with fresh creation still refused.

The invitation model abstracts ad freshness/current binding; it does not supply
a concrete ad-expiry clock trace. These Go tests implement the scoped Round 6A
policy decision. They establish neither full Round 6A completion nor TLA+
refinement, cryptographic proof, composition proof or general Go conformance.
No specification file was modified and no TLC check was run.

## Exact source changes

- `internal/ads/establishment.go:38` adds
  `ReadRetainedEstablishmentAdInTx`. The shared private reader at `:49`
  validates both complete collections and requires identical selected claims.
  Existing collection validation checks canonical encoding, shape, ordering and
  bindings; Verified validation authenticates every original ad signature.
  Returned bytes are owned copies. Only expiry evaluation is omitted.
  `ReadEstablishmentAdInTx` at `:18` retains its public-key/time checks,
  authentication and strict `now < expiry` rule. No generic policy framework
  or `allowExpired` flag was added.
- `internal/pw/requester.go:298` extracts the existing durable permission checks
  into `requesterPermissions`. `requesterGuards` at `:284` retains the same
  order: permission, fresh ad, exact ad comparison. Save/read attempt behavior,
  v1 callers and usable-contact callers continue through that fresh guard.
- `internal/pw/requester_accept_v2.go:64` uses shared permissions plus the
  retained reader and exact saved-ad equality, after authenticating history
  and the complete response. The public operation at `:27` preserves its
  outside-transaction signer probe and final View/Update revalidation. The
  commit at `:83` still writes only the existing accepted/held records.
  Removing expiry evaluation makes its private clock wrapper and propagated
  clock arguments obsolete; they were removed. The public signature is intact.
- `internal/pw/requester_accept_v2_test.go` and
  `internal/pw/requester_accept_atomic_v2_test.go` update directly affected
  private callers to the public operation or clock-free commit helper.
  The latter replaces acceptance-expiry refusals with the positives below,
  retaining all other guards and expanding ad-evidence negatives.
- New `internal/pw/requester_accept_expiry_v2_test.go` and
  `internal/ads/establishment_test.go` supply the expiry/evidence coverage below.

## Positive and negative evidence

`TestReceiveAcceptanceV2AdExpiry` uses the existing encrypted Bolt Vault
fixtures. It sets a signed ad deadline before the active invitation deadline,
commits Bob while the ad is fresh, then uses a real timer to cross the deadline:

1. Before Alice's first acceptance.
2. Inside Alice's signer-usability probe, between preflight and commit.
3. After Alice commits, before duplicate receipt, and inside a duplicate probe.
4. Before reopening Alice's Vault and performing her first acceptance.

Each first acceptance exhausts exactly two permitted encryptions, writes the
same accepted/held bytes as Bob's committed evidence, preserves the saved
request and every other fixture record, and leaves Bob's encrypted file
unchanged. There is exactly one usability-probe signature per tested receipt
and no first-use state. Every duplicate succeeds with zero encryption
allowance and byte-for-byte unchanged Alice storage. Reopen retains the exact
records. Delete followed by reopen and duplicate returns no holding and cannot
resurrect it. Fresh ad reads at the exact deadline and saved-attempt retrieval
still refuse, with no writes.

`TestRetainedEstablishmentAdExpiry` compares retained and fresh readers just
before, exactly at and after the signed deadline, including reopen, caller-byte
mutation and exhausted encryption allowance. `TestRetainedEstablishmentAdEvidence`
rejects missing or changed collections, matching but forged ad signatures,
malformed records, corrupt unrelated subjects, namespace conflicts and invalid
pinned keys. Both readers return no evidence and preserve the encrypted file
on refusal.

Preserved or extended negative evidence:

- `requester_accept_atomic_v2_test.go:69`: Deny, missing own/peer Known,
  missing device authorization, missing Received/Verified evidence, individually
  changed Received/Verified claims, replacement of both claims, changed contact
  and matching corrupt ads. Each is tested before first/duplicate receipt and
  during first/duplicate signer probes; saved relationship records stay intact.
- `requester_accept_atomic_v2_test.go:117`, `:156`, `:200`, `:282`:
  pinned identity/signer refusal, invalid probe signatures, signer failure,
  atomic write/encryption rollback, exact-history substitution during the
  probe, concurrent commit/delete, and no-resurrection behavior.
- `requester_accept_v2_test.go:84`, `:143`, `:173`: signed binding/contact
  conflicts, unauthenticated/noncanonical bytes, newly signed duplicate
  substitutes and mismatched signed declarations. `:195` preserves acceptance
  of already-sent bytes under Alice's own guards after Bob Deny/delete.
- `contact_history_v2_test.go:93` and
  `requester_accept_v2_linux_test.go:11`: corrupt accepted/request/holding
  history is never repaired by receipt; backend failure rolls back and
  duplicate reads need no backend write permission.
- `requester_v2_test.go:231`: fresh attempt preparation still rejects ad expiry
  before preparation, during the probe and during request signing; saved
  attempt retrieval still rejects it. `bob_atomic_v2_test.go:140` retains
  explicit Bob first-acceptance refusal at/after ad expiry, independently of
  invitation expiry, including expiry during probe/signing. These existing
  fresh-bootstrap negatives were not weakened.

## Automated validation

All Go checks used `GOTOOLCHAIN=local`, empty `GOEXPERIMENT`, `GOPROXY=off`,
`GOSUMDB=off` and `GOFLAGS=-mod=readonly`, with `go1.27.1 linux/arm64`.
Existing finite timeouts and test-selection policy were preserved.
Touched Go files were formatted with `gofmt`; `git diff --check` passed.
Logs are retained under `/tmp/ic-round-06c/` for this workspace session.

| Check | Outcome | Log |
|---|---|---|
| Baseline `make lint` | PASS, 0 issues | `baseline-lint.log` |
| Focused Alice/attempt/retained-ad tests, 2m timeout | PASS, PW 8.417s; ads 0.064s | `focused-alice-final.log` |
| Bob and adjacent lifecycle regressions, 2m timeout | PASS, PW 15.350s | `focused-regression.log` |
| Complete `internal/ads` tests, 2m timeout | PASS, 11.377s | `ads.log` |
| `make test_fast TEST_ARGS=-count=1` | PASS, 16 families / 36 descendants, 2.682s | `test-fast.log` |
| Final `make lint` | PASS, 0 issues; cache warnings below | `final-lint.log` |
| Complete ordinary Go suite, 10m timeout | PASS, all packages; PW 116.385s, ads 10.947s, storage 6.244s | `full-suite.log` |
| Focused race tests, 5m timeout | PASS, PW 34.796s; ads 1.147s; no race report | `focused-race.log` |

Focused Alice selection was
`^Test(ReceiveAcceptanceV2|RequesterV2|RetainedEstablishmentAd)` across
`./internal/pw ./internal/ads`. Bob regression selection covered `BobAccept`,
`BobReply` and `BobV2` families, plus `RequesterCurrentGuards`,
`FirstUseBootstrapExpiryAndNoFreshPairingV2`,
`ContactV2LocalEligibilityAndImmutableHistory` and
`ContactV2CorruptionNeverBecomesAbsenceOrDeletion`.
The race selection covered `ReceiveAcceptanceV2`, `RequesterV2CurrentGuards`,
`RequesterCurrentGuards`, `BobAcceptV2`, `BobReplyV2`, `BobV2`,
`RetainedEstablishmentAd` and the same three named lifecycle tests.
Every direct test command used `-count=1`. The full-suite command was:

~~~sh
go test -count=1 -timeout=10m ./...
~~~

The initial focused command failed to build PW because removing the obsolete
clock left an unused `time` import in `requester_accept_atomic_v2_test.go`.
Ads passed (0.057s). The import was removed; the corrected focused command
passed. The initial output remains in `focused-alice.log`.
Final lint exited successfully with `0 issues`, but warned that it could not
persist analysis-cache entries under the sandbox's read-only
`/home/parallels/.cache/golangci-lint`. No lint settings were relaxed and no
check failures were hidden.

## Manual acceptance and remaining Round 6A gaps

Manual demo/HTTP acceptance was not performed. The results above are automated
local encrypted-Vault checks and regressions; owner acceptance of the semantic
increment remains separate. There is no new end-to-end lost-response claim.

`readAttemptV2` still requires fresh ad evidence, so owner retry after expiry
can still fail while loading the saved request, before reaching Bob's reply
or Alice's now-permitted receipt. Both usable-contact projections still apply
their existing expiry guards. Completing those remaining Round 6A behaviors
and the complete HTTP lost-response/restart scenario is deferred. First use
and messaging were not redesigned. Removal/rotation of retained discovery
evidence, new contact binding and broader refinement remain outside scope.

## Repository status

The Go checkout began clean at the accepted baseline. Its only changes are the
seven Go files listed above and this report: five tracked Go modifications,
two new test files and this new report. No Git writes, commits, tags, dependency
changes, nested Codex or exec-metrics were used. `SPEC_REPO` remains unchanged;
its existing dirty model's before/after SHA-256 is
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`.

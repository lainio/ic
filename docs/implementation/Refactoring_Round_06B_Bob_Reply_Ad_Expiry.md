# Round 6B: BobReplyV2 after advertisement expiry

Status: implemented Bob-only increment, 2026-11-18.
Accepted Go baseline: `ef7b3cb53cebeedffba86f1d4cd8dfe676210ca8`.
`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree`, read-only
reference at `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` with its existing
dirty `models/active/IntroTreeV19.tla` preserved.
Source locations below refer to this increment's working tree.

## Result and semantic scope

After Bob commits a v2 acceptance, expiry of the original bootstrap ad alone
no longer prevents `BobReplyV2` from returning the exact committed response.
The original local publication must still be present, authentic and identical
to the signed request's ad, with the same listener/contact binding. Current
Known, Deny, device authorization, signer usability and matching holding
remain mandatory. Retry performs no persistent write, ad refresh, authority
consumption, acceptance re-signing or contact rebinding.

Fresh `BobAcceptV2` still requires an unexpired ad both before signing and at
commit. V1 behavior is unchanged. **Alice's delayed acceptance and both
usable-contact projections have NOT been changed.** Saved-attempt retrieval,
first use and messaging are also unchanged.

This implements only the Bob-reply recommendation in
`Refactoring_Round_06A_Ad_Expiry_Decision.md`. The required model index and
contracts were read along with both repositories' guidance and
`Current_Go_Implementation_Reality.md`. Relevant semantic references under
`SPEC_REPO` are:

- `docs/IntroTree_Model_Index.md:447`: invitation establishment intent and
  the limits of its relationship to V19.
- `docs/contracts/IntroTree_StateSemantics_Contract.md:310`: exact guarded
  read-only retry; `:345`: retained history versus fresh bootstrap.
- `docs/contracts/IntroTree_Implementation_Action_Map.md:105`: Bob's saved
  result retrieval and immutable complete binding.
- `docs/contracts/IntroTree_Conformance_Test_Map.md:544`: otherwise eligible
  exact retry after bootstrap expiry, while expired ads cannot create a PW.

The invitation model abstracts ad freshness/current binding; it does not
provide a concrete ad-expiry clock trace. This is a scoped implementation
policy change, not complete Round 6A implementation or new TLA+ conformance,
refinement, cryptographic or composition evidence. No TLA+ files or checks
were changed or run.

## Code changes

- `internal/ads/local.go:204`, `ReadRetainedLocalInTx`: adds a narrow
  transaction reader for retained publication evidence. It validates the
  pinned public keys and reuses `readStored` (`:154`) for canonical encoding,
  signature, Root/node/device/slot/epoch and namespace-shape authentication.
  It omits only expiry evaluation. Existing `ReadCurrentLocal` and
  `ReadCurrentLocalInTx` (`:180`) are unchanged; no `allowExpired` parameter
  or alternate discovery path was introduced.
- `internal/pw/establishment.go:172`: extracts shared durable authorization
  into `establishmentPermissions` (`:187`) and exact endpoint/ad comparison
  into `checkEstablishmentAd` (`:209`). The existing fresh guard retains its
  authorization, clock, fresh-ad read and binding-check order. Both v1 and
  fresh v2 establishment continue through it.
- `internal/pw/reply_v2.go:22`: uses the shared authorization and binding
  checks with the retained-ad reader. The existing signer probe still runs
  outside the Vault transaction; history, exact request, holding and durable
  guards are checked in the read transaction. It returns a clone of the saved
  response. `readLocalHistoryV2` (`internal/pw/history_v2.go:30`) is unchanged.
  The unnecessary private clock wrapper was removed; the public signature
  is unchanged. The fixture call at `internal/pw/bob_accept_v2_test.go:23`
  and pinned-input test at `internal/pw/bob_compat_v2_test.go:133` now call
  the public function directly.

## Tests and preserved refusals

`TestBobReplyV2ExactLossRestartAndExpiry`
(`internal/pw/reply_v2_test.go:19`) exercises fresh delivery, invitation
expiry/reopen, ad expiry during the signer probe, the exact ad deadline,
later expiry, and reopen after ad expiry. Every retrieval compares the
response bytes and consumed invitation/history/holding with their originals.
The existing encrypted Bolt Vault fixture checks whole-file equality for Bob
and Alice, with Bob's encryption allowance exhausted. Returned bytes are
mutated to check isolation. Exactly one fresh discarded usability-probe
signature occurs per retrieval; signing the acceptance digest again fails
the test. Thus “no new signature” here means no new acceptance signature,
while preserving the required current signer-usability probe.

`TestBobAcceptV2AdExpiryBoundary`
(`internal/pw/bob_atomic_v2_test.go:140`) publishes an ad whose deadline is
before the invitation deadline. With the invitation still active, acceptance
succeeds one nanosecond before ad expiry and refuses at/after expiry, checked
before preflight, during the probe and during acceptance signing. Refusals
leave both encrypted Vaults unchanged and remain unconsumed after reopen.
This separately tests ad expiry rather than relying on invitation expiry.

The existing negative checks remain:

- `internal/pw/reply_v2_test.go:89`: wrong exact request, newly signed
  substitutes, contacts, identities, device/epoch and noncanonical bytes.
- `internal/pw/reply_v2_test.go:147`: Deny, deleted holding, missing own/peer
  Known, missing authorization, replaced ad and changed ad origin, before
  retry and during its probe; refusal survives reopening. Extended with
  missing ad record, corrupt signature and malformed local ad evidence via
  `invalidateBobV2` in `internal/pw/bob_atomic_v2_test.go:26`.
- `internal/pw/bob_compat_v2_test.go:133`: wrong listener, pinned identities,
  absent/foreign/unusable signer and invalid probe signatures.
- `internal/pw/reply_v2_test.go:195` and
  `internal/pw/reply_storage_v2_test.go:13`: wrong, corrupted or substituted
  saved acceptance, invitation and holding evidence, including version,
  digest, contact, signature and encoding conflicts.

Ads coverage extends `TestReplacementExpiryAndStateBoundary`
(`internal/ads/local_test.go:120`) to compare both unchanged fresh readers
with retained evidence at/beyond expiry. `TestReadRetainedLocalInTxAbsentAndInputs`
(`:203`) checks absence and invalid inputs. Existing tampering, signed-invalid
binding and malformed namespace cases now also exercise the retained reader
through `internal/ads/storage_test.go:139`. These use real encrypted Vaults;
no persistence coverage was replaced with memory-only tests.

## Validation

Existing settings were retained: `GOTOOLCHAIN=local`, empty `GOEXPERIMENT`,
`GOPROXY=off`, `GOSUMDB=off`, `GOFLAGS=-mod=readonly`. No timeout, dependency,
lint configuration or test-selection policy changed. Modified Go files were
formatted with `gofmt`; `git diff --check` passed. Tests ran with
`go1.27.1 linux/arm64`.

- Baseline `make lint`: PASS, `0 issues`.
- Focused Bob checks below: PASS, `internal/pw` 3.197s.
- `go test -count=1 -timeout=2m ./internal/ads`: corrected run PASS, 10.751s.
- `make test_fast TEST_ARGS=-count=1`: PASS, 16 families and 36 descendants,
  `internal/pw` 3.020s; existing runner retains its 10-minute timeout.
- Focused race command below: corrected run PASS, `internal/pw` 20.278s,
  `internal/ads` 1.495s, with no race report. It includes v1 Bob guards,
  unchanged Alice expiry guards and unchanged usable-contact expiry behavior.
- Final `make lint`: PASS, `0 issues`.
- Complete ordinary regression, `go test -count=1 -timeout=10m ./...`:
  corrected run PASS, exit 0; all packages completed, including
  `internal/pw` 106.849s, `internal/ads` 9.452s and `storage` 5.957s.

~~~sh
go test -count=1 -timeout=2m ./internal/pw \
  -run '^Test(BobReplyV2|BobAcceptV2|BobV2)'
go test -count=1 -timeout=10m ./...
go test -race -count=1 -timeout=5m ./internal/pw ./internal/ads \
  -run '^Test(Bob|PublishAndReopen|ReplacementExpiryAndStateBoundary|ReadRetainedLocalInTx|TamperingNeverReadsOrOverwritesInvalidCurrent|MalformedEncodingAndNamespaceShape|ValidSignatureCannotBypassBindingOrVersion|ClockBoundsAndLocation|ContactV2LocalEligibilityAndImmutableHistory|ReceiveAcceptanceV2CurrentGuards)'
~~~

Initial failures are retained here: the first ads run failed in
`TestMalformedEncodingAndNamespaceShape/{namespace_is_record,slot_is_namespace,extra_slot}`
(8.095s). The first ordinary and race runs, already started against that test
version, reported the same failure (ads 10.457s and 0.530s respectively).
Both commands exited 1; the first full run's PW package passed in 119.712s,
and the first focused race run's PW package passed in 20.914s.
The new test wrongly required a successful `Vault.View` after a storage error
had poisoned that transaction. It now returns the reader error from its named
error callback and requires the View error, while still asserting zero output,
no result and unchanged encrypted storage. Production code was unchanged by
this correction. No failure was hidden by timeout, skip or policy changes.

## Remaining limitations and workspace

Retained ad absence, replacement, corruption or changed listener/contact still
blocks Bob's reply. This increment does not define rotation, rediscovery or
removal of publication evidence. Owner mutation/signer serialization remains
the caller's responsibility, and a later Deny cannot recall returned bytes.

Alice still cannot complete delayed acceptance solely on the basis of this
change when her existing fresh-ad guard rejects it. Usable-contact projections
still apply their existing expiry checks. These remaining Round 6A items are
deliberately deferred; no end-to-end delayed-completion claim is made.

The Go checkout began clean at the accepted baseline. Its only changes are
the nine Go files described above and this report. No Git-writing commands,
commits, tags, nested Codex or exec-metrics were used. The specification's dirty
model remains unchanged; its before/after SHA-256 is
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`.

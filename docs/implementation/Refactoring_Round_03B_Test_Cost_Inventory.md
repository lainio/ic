# Refactoring round 03B: test cost inventory and fast-tier proposal

Measured 2026-11-17 with **err2 v1.4.2**. The complete ordinary suite passes
in **117.842967 s** command wall time; `internal/pw` reports **115.594 s**.
The proposed 16-family everyday selection passes in **1.375869 s** wall time
and **0.991 s** package time. These are different coverage scopes, not a
before/after optimization comparison. Only this report is added.

## 1. Workspace, instructions and provenance

Implementation: `/home/parallels/go/src/github.com/lainio/ic`.
Read-only `SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.

| Repository | Initial and final full HEAD | Initial and final branch | Initial dirty state | Final dirty state |
|---|---|---|---|---|
| Go | `bfc3e7aa10ff5a1d8ef5d77e7bf5df300bcc916d` | `tla-spec-based-refactoring-v1` | Clean; matches accepted baseline | Only this report, untracked |
| Spec | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | `break-demo` | Modified `models/active/IntroTreeV19.tla` | Same pre-existing modification |

Read the live root `AGENTS.md`, `storage/AGENTS.md`,
`internal/core/AGENTS.md`, the spec root instructions, implementation reality
document, all four requested prior reports, model index and all three required
contracts. No additional instructions exist under `internal/pw` or `docs`.
The spec's existing safe-restore mutation unions snapshot recovery grants into
authority; it contradicts the unchanged V19 contract and is preserved as user
state, not adopted as the semantic baseline. Reference hashes and its full
before/after diff are retained. No model command was run.

Evidence root **E = `/tmp/ic-round03b-20261117`**. The task message beginning
with `SPEC_REPO=` is saved as UTF-8 with a final newline at
`E/task-prompt.md`; SHA-256:

~~~text
d666daea85d8dfab3556d315318bda9c3fc4dd86d8ea7f2449f2bc5485e01d4a
~~~

This is the supplied task message, not the external launcher's complete input.
**External exec-metrics evidence path: not yet supplied; owner to append after
the external execution finishes.** No exec-metrics, nested Codex process,
sub-agent, Git write, dependency download or launcher change was performed.
Workspace-write, approval never, non-login shells and inherited offline settings
were preserved. Existing reports and all tracked implementation files are
unchanged; no overlapping user edits were observed.

The existing round-03A `capture.py` and `summarize.py` were copied unchanged
to E. Capture metadata `E/LABEL.json` contains exact argv, cwd, selected
inherited environment, finite outer limit, exit, timeout status, monotonic
wall time, aggregate child user/system CPU and completion timestamp.
`E/LABEL.stdout` and `.stderr` retain complete output. In particular,
`suite.stdout` is the complete, unfiltered ordinary JSON stream.

`analyze.py` is standard-library postprocessing only. It strictly parses every
JSON line, checks matching RUN/completion names, ranks families, and verifies
the candidate's exact names/outcomes against the full baseline. It introduces
no test runner or measurement framework. Its initial and final successful
captures are `analysis` and `analysis-final`; the latter clarifies that overlap
between CONT/PASS event intervals is not a concurrency measurement. Go releases
a parallel slot before emitting PASS (`/usr/local/go/src/testing/testing.go:2162`
and `:2176`). No tests were rerun for this analysis clarification.

Additional evidence:

- `inventory.json`: all 427 PW families, raw parent ranking, scheduling spans,
  all subtest completion timings, packages, failures and skips.
- `suite.summary.json`, `fast-candidate.summary.json`: existing summarizer output;
  `summaries.{json,stdout,stderr}` records that postprocessing command.
- `fast-selection.json`, `fast-verification.json`: proposed argv, expected and
  actual names, individual completions and exact comparison with the baseline.
- `tester-audit.json`: 799 PW/storage test-source `PushTester` locations;
  all use their returned function through `defer assert.PushTester(...)()`.
- `environment.json`, `environment-after.json`: effective Go/module settings,
  platform, CPU affinity and selected inherited settings.
- `git-before.json`, `git-after.json`, `spec-before.json`, `spec-after.json`,
  `tracked-input-hashes.json`, `reference-hashes.json`, `preservation.json`:
  repository identity and preservation evidence.
- `commands.json` and `evidence-sha256.json`: capture ledger and raw artifact
  fingerprints. Temporary evidence is outside the repository and is not durable
  archival storage.

## 2. err2 integration and tester lifecycle

`go list -m -json github.com/lainio/err2` resolves **v1.4.2**, without a
replacement, at `/home/parallels/go/pkg/mod/github.com/lainio/err2@v1.4.2`.
The installed module sum is
`h1:/Qz3lZ4jJQKw8jmwG7B/zxZEa9AGbZk9c6LvJxcFcOA=`.
The following references to `assert/assert.go` are relative to that directory.

| Check | Source inspection and result |
|---|---|
| Nested tester restoration | `assert/assert.go:179` captures the previous goroutine registration under `testers.Tx`; `:199` returns a closure that defers restoration before panic reporting. The outermost scope returns `PopTester`; `:225` removes that registration. The returned function must execute in LIFO order on the same goroutine. Legacy direct `PopTester` still does not restore nesting. |
| Atomic package default | The immutable asserter table is at `:117`; `current` loads the default with `atomic.LoadUint32` at `:1055`; `SetDefault` uses `atomic.SwapUint32` at `:1073`; flag/string access loads atomically at `:1142`. No new initialization gate is needed. |
| Removed workaround | `internal/pw/message_projection_history_v2_test.go:55` contains no `sync.Once`, `testerInit`, explicit default initialization or parent tester registration. The old report describes superseded source. |
| Parallel leaf ownership | The parent calls `t.Parallel()` at `:56`; each leaf calls it at `:75`, then registers its own tester at `:76`, then constructs its fixture at `:77`. Registrations are not inherited from the parent. |
| Nested fixture ownership | `fixtures_test.go:30`, `:47`, `:57`, `:105`, `:164`; `establishment_test.go:29`; `requester_test.go:29`; `first_use_v2_test.go:23`; `message_outgoing_v2_test.go:19`; `message_incoming_v2_test.go:20` and `:51`; `message_ack_v2_test.go:17` retain direct deferred restorers. Synchronous assertion/try work has the helper's context and restores the caller's context on return. |
| Error and worker boundaries | Named transaction callbacks retain their own `err2.Handle`; for example `requester_test.go:69` and `message_outgoing_v2_test.go:46`. Production `PushAsserter(assert.Plain)` scopes remain intact. Worker results return to the test goroutine, for example `invitation_test.go:231` and `message_receipt_v2_test.go:98`. The selected parallel history leaves do their protocol work synchronously. |

All paths in the last four rows are under `internal/pw` unless fully qualified.
The fixture's `t.Cleanup` still closes the captured Database handles, removes
temporary directories and clears its own secret; reopen captures its replacement
handle separately (`fixtures_test.go:38`, `:42`, `:63`). These lifetimes remain
owned by the allocating test. Nested restoration does **not** extend a deferred
tester registration into later `t.Cleanup` execution. The existing close callbacks
at `fixtures_test.go:42` and `:63` assert without registering there; their failure
attribution was not fault-injected in this round. Passing cleanup is verified,
not every hypothetical cleanup failure. No lifecycle change is proposed here.

A repository test-source search found no other err2 default-initialization
workaround or direct `assert.PopTester` use. The remaining PW `sync.Once` uses
are purposeful: channel release at `remote_concurrency_test.go:33` and `:176`,
and one-time input mutation at `remote_test.go:143`. They are not obsolete
tester initialization and must not be removed on that basis.

## 3. Environment, commands and complete baseline

Go `go1.27.1 linux/arm64`; module Go version `1.24.0`; Linux
`6.8.0-147-generic`, aarch64; five visible CPUs, affinity 0–4.
Inherited `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off`,
`GOSUMDB=off` remain effective. `CGO_ENABLED=1`, no workspace module, no
`GOMAXPROCS`, `GODEBUG` or `GORACE` override. Build cache is
`/home/parallels/.cache/go-build`; module cache is
`/home/parallels/go/pkg/mod`. No cache was cleared or relocated.

Every task-launched command ran sequentially. Go's normal package scheduling
and existing test parallelism remained enabled. `-count=1` prevents test-result
reuse, not build-cache use. Initial cache warmth, external load, CPU frequency
and disk-cache state were not controlled. This is one observation per requested
test command, not a statistical performance estimate.

Capture syntax, from the implementation root:

~~~sh
python3 /tmp/ic-round03b-20261117/capture.py LABEL OUTER_SECONDS COMMAND...
~~~

| Label | Exact child command or location | Outer limit s | Wall s | Exit | Result |
|---|---|---:|---:|---:|---|
| `lint-before` | `make lint` | 600 | 0.517755 | 0 | 0 issues |
| `suite` | `go test -count=1 -json -timeout=10m ./...` | 900 | 117.842967 | 0 | 23 packages pass; 11 have no test files |
| `pw-race` | Command below | 660 | 15.658792 | 0 | Focused history family passes; package 9.511 s |
| `storage-race` | `go test -race -count=1 -timeout=10m ./storage/...` | 900 | 10.932208 | 0 | All three packages pass |
| `fast-candidate` | Exact command in section 7 | 660 | 1.375869 | 0 | 16 families / 36 subtests pass; package 0.991 s |

The exact focused race command was:

~~~sh
go test -race -count=1 -timeout=10m -parallel=4 \
  ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'
~~~

No measured lint/test command timed out, failed, or reported a data race.
Baseline lint and all
four test captures have empty stderr. No relaxed-timeout retry occurred.
The race commands intentionally retain the requested nonverbose form: their
raw output provides package success and duration, not per-test event counts or
an observable skip inventory. No skip was reported, and the inspected PW/storage
test sources contain no `t.Skip` calls; exact race event counts are unavailable.
The ordinary JSON run supplies the complete named-event inventory.

The ordinary run contains **8,769 named completions**: 8,761 pass and eight
skip. PW has **5,859 passing named completions**, comprising **427 top-level
families and 5,432 descendants**, with no failures or skips. Parent completions
are included; these are not counts of independent assertions or leaf cases.
Tests executed inside diagnostic/reopen subprocesses are not independently
enumerated by the parent's JSON stream.

The eight existing named skips are:

~~~text
chain/TestNewVerifyBlock/nil_pincode
key/TestNewPublicCBOR/success
cmds/intro/TestExchangeDemoNATS
cmds/intro/TestHTTPDemoTCP
cmds/intro/TestOwnerStatusDemoTCP
internal/nodeidentity/TestProcessCreate
internal/nodeidentity/TestProcessOpen
internal/nodevault/TestStoreProcess
~~~

The last three are subprocess entry points used by their parent tests; their
top-level skips do not mean those parent process tests were omitted. No broker
or opt-in TCP demo flag was supplied. All no-test packages and skip events are
listed in `inventory.json` and `suite.summary.json`.

| Largest ordinary package durations | Go elapsed s |
|---|---:|
| `internal/pw` | 115.594 |
| `internal/ownerapi` | 14.159 |
| `internal/ads` | 9.886 |
| `cmds/node` | 6.626 |
| `storage` | 6.213 |
| `internal/nodevault` | 1.658 |

Storage race package times are 7.515 s (`storage`), 1.280 s
(`storage/internal/engine`) and 1.057 s (`storage/internal/record`). Package
spans overlap within a command and must not be added to derive command wall time.

| Command | Aggregate child user CPU s | Aggregate child system CPU s |
|---|---:|---:|
| Ordinary complete suite | 89.840215 | 18.971656 |
| Focused PW race | 33.978450 | 2.854749 |
| Storage race | 6.750417 | 0.856146 |
| Fast candidate | 1.075786 | 0.301978 |

These are command-wide CPU totals, including Go-driver/build/vet work and test
subprocesses, not per-family profiles. Wall time includes startup, build/link,
execution, waits and cleanup. The focused race command's 15.659 s wall versus
9.511 s package duration does not isolate a compiler cost. No new CPU profile
or compile-only experiment was collected. Historical fixture/stack-walk CPU
percentages from err2 v1.4.0 must not be reused as v1.4.2 attribution.

## 4. Twenty slowest PW families

All numeric times here are **measured (M)**. Work descriptions are **inferred
from inspected source (I)**. The present fixture/operation/crypto/I/O CPU and
wall-time split is **unknown (U)** without phase instrumentation or profiling.
No timing is inferred merely from the presence of a timeout expression.

Rank uses RUN-to-completion span for serial families and CONT-to-completion
span for the one parallel parent, excluding its wait behind unrelated serial
tests. The displayed serial duration is Go's rounded parent `Elapsed`; the
parallel row shows both measures. All table references are relative to
`internal/pw/`. Child counts are completed descendants in the JSON stream.

| Rank | Family | M: seconds | Children | Source | I: substantial work |
|---:|---|---:|---:|---|---|
| 1 | `TestRequestRemoteAcceptanceCancellationAndDeadline` | 5.07 | 3 | `remote_concurrency_test.go:223` | Two-Store HTTP fixture; one intentional five-second deadline |
| 2 | `TestMessageClientTimeout` | 5.00 | 0 | `message_client_test.go:329` | Peer withholds headers until client's five-second bound |
| 3 | `TestMessageACKExactHistoricalEvidence` | 4.52 | 88 | `message_ack_history_test.go:142` | Fresh ACK fixture per role/repeat/history mutation; foreign history adds another fixture |
| 4 | `TestMessageReceiptCurrentGuardsAndHistoricalVerification` | 3.66 | 64 | `message_receipt_test.go:117` | Receipt fixture; eight guard mutations at four callback phases, reopen and historical verification |
| 5 | `TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2` | 3.62 | 64 | `message_receipt_v2_test.go:16` | Same guard/phase dimensions over contact-bound v2 history |
| 6 | `TestMessageReceiptRetainedHistoryAndFinalInbox` | 3.53 | 64 | `message_receipt_history_test.go:17` | Receipt fixture for 16 history/inbox mutations, before/during callback, both roles |
| 7 | `TestIncomingCorruptLocalHistory` | 3.12 | 72 | `message_incoming_history_test.go:14` | Incoming fixture per two roles × two repeat states × six records × three corruption modes |
| 8 | `TestIncomingCurrentGuards` | 2.87 | 64 | `message_incoming_test.go:109` | Incoming fixture, guard/repeat/probe matrix, physical checks and reopen |
| 9 | `TestMessageProjectionRequiredHistoryV2` | 2.514828 tree; 0.00 parent | 112 | `message_projection_history_v2_test.go:55` | Parallel fresh ACK fixtures, optional reverse inbox, corruption, reopen, projection/commit refusal |
| 10 | `TestOutgoingCurrentGuardsIncludingRepeatAndProbeMutation` | 2.37 | 64 | `message_outgoing_test.go:200` | Fresh first-use-complete relationship per role/guard/repeat/callback case |
| 11 | `TestIncomingCurrentGuardsAndProbeRecheckV2` | 2.15 | 48 | `message_incoming_guards_v2_test.go:17` | Two roles, eight guards, three admission/retry phases |
| 12 | `TestMessageTransmitRejectsStoredEvidence` | 1.97 | 40 | `message_transmit_test.go:193` | Transmit fixtures and exact-history substitutions; no network send in this family |
| 13 | `TestMessageGuardInvalidationDuringCallbacksV2` | 1.87 | 42 | `message_atomic_v2_test.go:173` | Six create/envelope phases, seven guards, both nodes checked within each leaf |
| 14 | `TestMessageTransmitCurrentGuards` | 1.77 | 32 | `message_transmit_test.go:107` | Outgoing/envelope preparation, repeated transmission marker and guard checks |
| 15 | `TestRequestRemoteAcceptanceRejectsHTTPAndJSON` | 1.72 | 66 | `remote_http_test.go:20` | Fresh two-Store/listener fixture for 33 malformed replies at each of two stages |
| 16 | `TestMessageCurrentGuardsV2` | 1.70 | 40 | `message_outgoing_v2_test.go:306` | Ten guards, four create/prepare/retry phases; both nodes inside each case |
| 17 | `TestIncomingExactHistoryAndHistoricalSuccess` | 1.68 | 36 | `message_incoming_history_test.go:64` | Fresh incoming fixtures, nine history replacements, both roles/repeat states |
| 18 | `TestOutgoingRejectsCorruptHistory` | 1.65 | 48 | `message_outgoing_test.go:338` | Role/record/corruption combinations and physical no-write checks |
| 19 | `TestFirstUseCurrentLocalGuards` | 1.58 | 48 | `first_use_guards_test.go:21` | Three local phases, eight guards, before/during probes |
| 20 | `TestMessageEnvelopeCurrentGuards` | 1.53 | 32 | `message_envelope_test.go:175` | Eight guards, repeat and callback variants; both nodes inside each case |

For a ranking strictly by Go parent `Elapsed`, the parallel family drops out
and `TestFirstUseCurrentLocalGuardsV2` enters at 1.52 s / 48 descendants
(`first_use_guards_v2_test.go:21`). Both full rankings are retained in
`inventory.json`.

The parallel history parent's RUN-to-PASS span is **45.831199 s**, including
**43.316365 s PAUSE-to-CONT** while unrelated serial tests execute. Its
CONT-to-PASS span is **2.514828 s**; parent `Elapsed` is **0.00 s**, because
Go does not charge parallel-child waiting to the parent. There are 113
PAUSE/CONT pairs: parent plus 112 leaves. These facts establish parallel
execution, not zero work or 45.8 seconds of exclusive cost. Ordinary commands
retain Go's default `-parallel`; only the focused race command sets four.
No other PW family calls `t.Parallel()` in live source.

Significant child/group observations, using exact emitted names:

| Child or group | M: elapsed s | I: explanation and implementation |
|---|---:|---|
| `TestRequestRemoteAcceptanceCancellationAndDeadline/overall_deadline` | 5.02 | Real expiry; sibling `challenge_cancel` and `accept_cancel` are 0.02 each; `remote_concurrency_test.go:249`, `:262` |
| `TestMessageOutgoingCorruptionAndOrphanV2/true` and `/false` | 0.18 / 0.15 | Each runs a substantial inner corruption loop over both nodes; two named subtests are not just two operations; `message_envelope_v2_test.go:119` |
| `TestMessageEnvelopeRequiresExactSavedMessage/true` and `/false` | 0.12 / 0.10 | Repeated source mutations inside each selected group; `message_envelope_wire_test.go:140` |
| `TestMessageACKExactHistoricalEvidence/0/false/foreign_acceptance` | 0.09 | A second `newOutgoing` fixture at `message_ack_history_test.go:230`; other foreign-acceptance leaves 0.08, full family leaf range 0.05–0.09 |
| `TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2/0/signer/1` | 0.07 | Family leaves range 0.05–0.07; callback failure/refusal work at `message_receipt_v2_test.go:38` and `:53` |
| `TestMessageProjectionRequiredHistoryV2/1/accepted/request_ad/true` | 0.13 | Parallel family leaves range 0.09–0.13, including contention; setup and reverse-inbox branch at `message_projection_history_v2_test.go:77` |

Slash-delimited names do not necessarily introduce separately timed parents:
many are single `t.Run` calls with slashes embedded in their names. Only actual
events are counted. No overlapping parent and child durations are summed.
Large case count alone is not a cost classification: the 188-descendant
`TestMessageACKCorruptSlotsAndFinalRecheckV2` takes 0.87 s, because it builds
one ACK fixture per role outside the mutation subtests
(`message_ack_atomic_v2_test.go:126`, `:129`, `:168`) and restores records
between them. That shared mutable state also prevents blindly parallelizing it.

## 5. Fixture, waiting and persistence findings

### Repeated fixture work

The dominant matrix families in section 4 repeatedly enter the established
fixture chain. The v2 ACK chain is:

~~~text
ackTestV2 -> receiptTestV2 -> incomingTestV2 -> newOutgoingV2
  -> newFirstUseV2 -> newRequester -> newEstablishment -> ready
~~~

Precise entry points are in section 2. Legacy equivalents start at
`message_ack_test.go:22`, `message_receipt_test.go:21`,
`message_outgoing_test.go:22` and `first_use_test.go:19`.

**I:** `ready` creates three independently saved signers and one encrypted
bbolt Vault; `newRequester` creates the second Vault and its separate Known
evidence/device state. `newSigner` creates identity/unlock files and a fresh
secret; `newVault` owns its temporary path, random secret and atomic allowance
of 128 encryptions. Establishment, independent acceptance, fresh first use,
outgoing creation, admission and receipt issuance add authenticated protocol
operations as the chain deepens. `requester_test.go:54` deliberately seeds the
unit fixture's verified-ad snapshot; real online admission is exercised by
the separate HTTP fixtures, not proved by that seeding.

**M:** fresh-fixture matrices take the measured family/leaf durations above.
**U:** this run has no phase timers or new profile, so it cannot allocate those
durations among fixture preparation, test operations, signature verification,
assertion context, storage waits or cleanup. Fixture construction contains
real protocol verification; it is not synonymous with disposable key setup.
For example, the v2 receipt matrix also issues a prior receipt, mutates state
during signing, snapshots physical/logical state, reopens and verifies the
historical signature after refusal (`message_receipt_v2_test.go:26`, `:60`,
`:82`). Those operations are inside the measured family too.

### Real waits versus watchdogs

| Finding | M: family/child cost | I: actual wait or guard |
|---|---|---|
| Remote acceptance overall deadline | Family 5.07 s; deadline leaf 5.02 s | Handler awaits request cancellation at `remote_concurrency_test.go:250`; the test does not call cancel in the deadline case (`:262`). Production `remote.go:61` sets five seconds. |
| Message client deadline | 5.00 s | Handler parks at `message_client_test.go:337`; production `message_client.go:64` sets five seconds. Test's ten-second context (`:343`) bounds regressions; it is not the expected ten-second cost. |
| Short real cancellation deadline | `TestSendEstablishCancellation`, 0.05 s | Explicit 50 ms context at `establishment_client_test.go:181`, handler waits for cancellation. |
| Proving owner operation remains blocked | `TestMessageHTTPSerializesAdmitThroughFinalProbeWithOwnerDeny`, 0.36 s / four subtests | Passing branch deliberately waits 25 ms at `message_http_test.go:407` in each case; five-second branches at `:387`, `:413`, `:419` are failure watchdogs. |
| Channel coordination | `TestRequestRemoteAcceptanceConcurrentInvocations`, 0.03 s; `TestConcurrentChecksEachProbeOutsideVaultTransaction`, 0.01 s | Handshakes wait for other workers, but `awaitExchange`'s ten seconds (`remote_concurrency_test.go:161`) and `local_test.go:169`'s five seconds are failure limits, not normal sleeps. |
| Explicit cancellation after dispatch | `TestMessageClientCancellationAfterDispatch`, rounded 0.00 s | Test calls cancel after arrival; five-/one-second branches at `message_client_test.go:292` and `:299` only detect failure. Included in fast tier. |
| Abrupt process death | 0.04 s | Child parks until parent SIGKILL; fifteen-second context and five-second reap branch at `deny_crash_linux_test.go:135`, `:162` are watchdogs. Timeout kill is explicitly forbidden from counting as success. |
| Logical clock boundaries | Invitation issuance 0.02 s; strict first-use deadline v2 0.04 s | `invitation_test.go:85` checks expiry ±1 ns using supplied times; `first_use_v2_test.go:407` advances `f.now` by `FirstUseLifetime`. Neither waits 15 minutes or 60 seconds. |

Other watchdog-only sites include `acceptance_guards_test.go:267`,
`policy_test.go:338`, `owner_exchange_test.go:306` and `:318`,
`deny_exchange_test.go:345` and `delete_held_exchange_test.go:154`.
The owner exchange's already-expired context at `owner_exchange_test.go:218`
also does not wait for a future deadline. These observations classify source
behavior; they do not assign CPU time to blocked versus active execution.

### Subprocesses and restart

All values below are **M** whole-family durations, including parent setup,
child execution and assertions. Launch counts and purposes are **I** from
source, not separately measured startup costs. References are under `internal/pw`.

| Family | Seconds | Subprocess source and purpose |
|---|---:|---|
| `TestMessageProjectionProcessReopenV2` | 0.29 | `message_projection_v2_linux_test.go:93`, launch `:147`; four children, both roles × Deny/Delete; retained ACK/inbox with zero seals |
| `TestIncomingProcessReopen` | 0.10 | `message_incoming_linux_test.go:52`, launch `:100`; two children, exact admission replay after reopen |
| `TestIncomingProcessReopenV2` | 0.10 | `message_incoming_v2_linux_test.go:53`, launch `:107`; two v2 children |
| `TestMessageReceiptProcessReopen` | 0.12 | `message_receipt_linux_test.go:46`, launch `:110`; two children, receipt issuance from retained inbox |
| `TestMessageACKProcessReopen` | 0.11 | `message_ack_linux_test.go:76`, launch `:122`; two children, historical ACK replay |
| `TestBobDenySurvivesAbruptProcessDeath` | 0.04 | `deny_crash_linux_test.go:36`, launch `:142`, SIGKILL `:193`; committed Deny survives ungraceful death |
| `TestRequesterDiagnosticCodes` | 0.28 | `diagnostics_test.go:17`, launches `:32` / `:50`; ten diagnostic child selections |
| `TestFirstUseSignerDiagnostic` | 0.11 | `diagnostics_test.go:71`, launch `:81`; three diagnostic children |
| `TestOutgoingDiagnostics` | 0.04 | `message_outgoing_test.go:551`, launch `:553`; one sanitized-output child |
| `TestMessageEnvelopeDiagnostics` | 0.04 | `message_envelope_test.go:420`, launch `:422`; one child |
| `TestIncomingDiagnostics` | 0.05 | `message_incoming_test.go:281`, launch `:283`; one child |
| `TestMessageReceiptDiagnostics` | 0.08 | `message_receipt_test.go:298`, launch `:300`; one child |
| `TestMessageACKDiagnostics` | 0.06 | `message_ack_test.go:221`, launch `:223`; one child |
| `TestMessageTransmitDiagnostics` | 0.05 | `message_transmit_test.go:392`, launch `:394`; one child selecting two refusal tests |

These subprocess families are not the major ordinary-suite cost now. Their
current race cost is **U**: the focused race command does not select them.
Historical race-process overhead is not a current measured multiplier.

In-process close/reopen is distinct from a subprocess restart. Examples are
`TestOwnerV2LostResponseExactRetryAndReopen` (0.05 s,
`requester_exchange_v2_test.go:202`),
`TestFirstUseTwoNodeHTTPCommitOrderAndRestart` (0.05 s,
`first_use_exchange_test.go:295`, helper `:273`),
`TestDenyRetainsHoldingAndHistoryAcrossRestart` (0.37 s,
`deny_exchange_test.go:211`, reopen `:248`) and
`TestDeleteHeldTwoNodeHistoryRestartAndNoResurrection` (0.39 s,
`delete_held_exchange_test.go:223`, reopen `:261`). Their names do not imply
an `exec` launch. Neither kind establishes general power-loss consistency.

### Persistent databases and physical checks

**Keep** persistent coverage wherever the observation requires it:

- `fixtures_test.go:47` compares entire database bytes and encryption allowance;
  `:57` closes/reopens bbolt. The matrices in section 4 frequently invoke these
  through refusal helpers, for example `message_ack_v2_test.go:28` and
  `message_incoming_v2_test.go:34`. Replacing their shared fixture with memory
  would remove a measured assertion, not just an incidental setup cost.
- `TestMessageProjectionRequiredHistoryV2` reopens every mutated local history
  at `message_projection_history_v2_test.go:136` and verifies no state/spend/file
  changes on refusal. `TestMessageACKAndInboxEitherSenderV2`
  (`message_ack_v2_test.go:44`) and `TestRequesterV2ContactsAndExactReopen`
  (`requester_v2_test.go:30`, 0.09 s) also require exact retained evidence.
- The read-only/commit-failure checks use actual descriptors:
  `establishment_linux_test.go:32` scans `/proc/self/fd` and uses `Dup3` while
  preserving the original open description. Examples are
  `message_projection_v2_linux_test.go:17` (0.11 s) and `:50` (0.12 s), and
  `message_incoming_v2_linux_test.go:18` (0.09 s). These are Linux-specific
  file/commit tests, not portable memory-backend cases.
- `remote_fixture_test.go:113` builds independent production Stores and a
  listener; `:180` snapshots encrypted records, durable `usage.db` accounting
  and identities. This cost applies to the 66-case HTTP/JSON matrix as well
  as exchange/restart tests. It is broader than the small unit test lease.

**U:** physical I/O wall share, fsync latency and peak disk/descriptor demand
were not isolated. **Defer** any memory-backed fixture redesign; it is neither
needed for this fast command nor authorized by this inventory.

## 6. One additional parallelization candidate

Investigate only **`TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2`**
(`internal/pw/message_receipt_v2_test.go:16`): **3.62 s parent elapsed**, **3.623564 s
RUN-to-PASS**, **64 serial leaf subtests**, each 0.05–0.07 s in this sample.
It is a substantial current-v2 family using the already inspected fixture chain.

**I: likely independence.** Each leaf allocates its own `receiptTestV2` fixture,
two Vaults, three signers, secrets, lease counters, clock/runtime values,
receipt/envelope buffers and `probeSigner`. Its callback mutates that fixture
only; `mutateEnvelopeGuard` at `message_envelope_test.go:142` writes the selected
node's Vault. Each leaf retains physical/logical snapshots, local reopen and
historical signature checks. No listener, process, environment mutation or
descriptor replacement occurs in this path. The parent owns only the loops.

**Risks requiring a fresh audit before implementation:** overlap with the
existing parallel history family; shared err2 defaults/tracers, CBOR caches,
logging and random source; allocation, crypto and disk contention; cleanup
failure attribution; equal Vault IDs being safe only because files are distinct.
Other serial tests change proxy environment and tracers, for example
`remote_http_test.go:241` and `remote_test.go:187`. Preserve the scheduling
boundary that keeps those changes out of the parallel phase. Applicable lint
previously required both parent and leaf `t.Parallel`; each leaf must still
register its tester after resumption. Do not revive the obsolete Once gate.

**Expected benefit (I), still unmeasured:** there is up to 3.62 s of serial
family elapsed time to reduce, subject to contention and overlap. Dividing by
four gives only an idealized 0.91 s reference, not a forecast; no fourfold
speedup or full-suite saving is claimed. Current aggregate CPU demand and
co-scheduling with the 112 existing leaves could limit the gain. No new
parallelism, extraction, shared fixture, assertion change or race validation
of this candidate was performed. Classification: **Defer implementation**.

## 7. Fast everyday tier: explicit initial contract

Recommend **A: explicit, anchored `-run` selection** of these 16 complete
families. Exact command measured once:

~~~sh
go test -count=1 -json -timeout=10m ./internal/pw \
  -run '^(TestKnownBeforeAnySignerUse|TestAdHistoryNeverSubstitutesForIndependentKnown|TestAuthorizationDoesNotImplySignerUsability|TestInvitationIssuanceAndTimeBoundary|TestBobAcceptV2IndependentContactCommit|TestBobAcceptV2RejectsSignedBindings|TestBobAcceptV2RejectsUnauthenticatedBytes|TestReceiveAcceptanceV2IndependentContacts|TestReceiveAcceptanceV2DuplicateCannotRestoreDelete|TestFirstUseOrderedLocalObservationsV2|TestFirstUseReceiveStrictDeadlineAndCanonicalBytesV2|TestMessageACKAndInboxEitherSenderV2|TestMessageProjectionVersionIsolationV2|TestMessageSingleRecordRollbackV2|TestDenyAndDeleteAreDistinctLocalOperations|TestMessageClientCancellationAfterDispatch)$'
~~~

**M:** exit 0, 1.375869 s command wall, 0.991 s package, 52 named PASS events
(16 families + 36 subtests), no skips/failures/timeouts. The parser verifies
exactly the listed families and all their descendant names/outcomes match the
full baseline. No parallel family is selected. No assertion or case inside
a selected family was removed. This sample is a practical everyday cost;
there is no owner-approved time budget or repeated-run guarantee yet.

| Selected family | Candidate elapsed s | Coverage and exact source under `internal/pw` |
|---|---:|---|
| `TestKnownBeforeAnySignerUse` | 0.01 | Received/self/peer evidence cannot substitute for Known or cause signer calls; `local_test.go:88` |
| `TestAdHistoryNeverSubstitutesForIndependentKnown` | 0.01 | Even authentic historical ad storage supplies no introduction authority; `evidence_test.go:19` |
| `TestAuthorizationDoesNotImplySignerUsability` | 0.01 | Seven unavailable/foreign/invalid signer cases plus usable positive case; `local_test.go:110` |
| `TestInvitationIssuanceAndTimeBoundary` | 0.02 | Ad publication does not issue consent; directed/any invitations, IDs, exact expiry boundary; `invitation_test.go:23` |
| `TestBobAcceptV2IndependentContactCommit` | 0.05 | Atomic consumed binding/contact/holding and no Alice write; `bob_accept_v2_test.go:29` |
| `TestBobAcceptV2RejectsSignedBindings` | 0.02 | Thirteen signed identity/contact/binding conflicts, no consumption; `bob_accept_v2_test.go:88` |
| `TestBobAcceptV2RejectsUnauthenticatedBytes` | 0.02 | Tampering, canonical/size bounds, wrong signer/purpose and v1 bytes; `bob_accept_v2_test.go:133` |
| `TestReceiveAcceptanceV2IndependentContacts` | 0.06 | Alice's separate commit, no first-use state, exact read-only retry after reopen; `requester_accept_v2_test.go:29` |
| `TestReceiveAcceptanceV2DuplicateCannotRestoreDelete` | 0.06 | Historical acceptance cannot recreate holding, including reopen; `requester_accept_atomic_v2_test.go:257` |
| `TestFirstUseOrderedLocalObservationsV2` | 0.04 | Await, Bob useSeen and Alice Ready are separate; duplicate/refusal checks; `first_use_v2_test.go:58` |
| `TestFirstUseReceiveStrictDeadlineAndCanonicalBytesV2` | 0.04 | Invalid bytes and exact logical expiry refuse without state changes; `first_use_v2_test.go:394` |
| `TestMessageACKAndInboxEitherSenderV2` | 0.24 | Both senders, one-byte/maximum multibyte text, exact inbox/receipt/ACK and replay/persistence; `message_ack_v2_test.go:44` |
| `TestMessageProjectionVersionIsolationV2` | 0.21 | Cross-version history/inbox/ACK must fail closed; `message_projection_history_v2_test.go:189` |
| `TestMessageSingleRecordRollbackV2` | 0.16 | Put/encryption failures for outgoing/envelope, both nodes, unchanged disk and reopen; `message_atomic_v2_test.go:17` |
| `TestDenyAndDeleteAreDistinctLocalOperations` | 0.04 | Deny/Allow cannot restore deletion; Delete does not create Deny; `deny_exchange_test.go:456` |
| `TestMessageClientCancellationAfterDispatch` | 0.00 | Explicit cancellation bounds a dispatched request without a real five-second wait; `message_client_test.go:271` |

Keep this as **additional edit feedback**, with changed-area tests added when
appropriate. It omits the full history/current-guard/callback matrices,
competing-operation schedules, real five-second timeout checks, child-process
diagnostics and crash/restart checks, actual descriptor fault injection, broad
HTTP hostile-response matrices and most legacy v1 coverage. Its logical-clock
test does not replace real deadline tests. Its rollback test does not replace
actual bbolt commit-failure tests. It retains selected real bbolt/reopen checks
and a small HTTP exchange; fast does not imply mock-only or memory-only.

Unit fixtures seed verified-ad records; the selected Deny/Delete exchange also
exercises real two-Store HTTP preparation, but this tier is not full remote-ad
admission coverage. It does not cover complete V19 recovery/helper/snapshot,
device lifecycle, peer-view refresh or strong-use semantics. These are existing
implementation scope gaps, not coverage newly established by the selection.

The full regression command remains
`go test -count=1 -json -timeout=10m ./...`, with the separate requested race
checks retained. Run the full suite before a reviewable implementation change
is considered validated; use complete affected families for changes to their
guards, fixtures, wire formats, persistence or concurrency. This inventory
changes no Makefile/CI default or acceptance requirement.

| Approach | Benefit | Limit and recommendation |
|---|---|---|
| A. Explicit `-run` | Immediately reproducible, measured coverage; no test-source edits; exact whole-family selection is reviewable | Go can succeed when a requested name matches nothing. Future automation should check the expected top-level names, as this inventory did. Names must be reviewed on rename/new behavior. **Recommend A** as the bounded initial contract. |
| B. Opt-in `testing.Short()` gates | Broad default suite stays intact; explicitly expensive tests can skip only under `-short` | No PW `testing.Short()` classification exists now. Gating just two deadline tests leaves most fixture matrices running; classifying all expensive tests expands this increment into a maintenance policy. Broad skips can conceal useful negative cases. **Defer B** until evidence shows explicit selection is insufficient. |

No `-short` command or gating was introduced or run. Source selection, not
weakened assertions, accounts for the lower candidate cost.

## 8. Recommended Round 3C and semantic classification

Recommend one small Round 3C increment, **after owner approval of the fast-tier
contract**: expose the exact section-7 selection as an optional named everyday
test command (for example `make test-fast`), with a check that its expected
family names execute. Keep existing full-suite and race entry points unchanged.
Use the existing Go test/capture mechanisms; do not add a classification
framework. No such target, test change or acceptance automation is implemented
here. The single parallelization candidate in section 6 is a separately scoped
follow-up, not a second bundled Round 3C change.

| Inventory classification | Disposition |
|---|---|
| **Keep** | Full regression matrices, real deadline tests, subprocess checks, persistent byte assertions and current err2 lifecycle; their costs buy distinct observations. |
| **Adapt** | Everyday invocation scope only, subject to owner approval of the explicit selection. |
| **Defer** | New parallel family, `testing.Short()` gates, fixture/backend redesign and package extraction. |
| **Unknown** | Current per-phase CPU/I/O shares, candidate parallel speedup, complete PW race cost and all unexercised schedules. |
| **Split / Remove** | No code split or removal recommended by these measurements. |

V19 remains the general authority/lifecycle baseline. The accepted invitation
extension governs separate Bob/Alice commits and separate first use; historical
contacts, ACKs and receipts do not restore current permission. The code still
does not implement the whole V19 recovery/device/helper/strong-use system, and
its invitation-local Delete is not full V19 cache/trust/view cleanup. The spec
documents' older “PW-Contact-Go-01 unimplemented” status lags the inspected v2
Go tests. The messaging candidate remains separate; these tests do not establish
model composition, V19 refinement or cryptographic correctness. No missing
architecture or new semantic transition is proposed.

## 9. Final verification, limits and acceptance

Final `make lint` passes with exit 0, **0.517160 s**, 0 issues and empty stderr
(`E/lint-after.{json,stdout,stderr}`, outer limit 600 s).
The final tracked whitespace command is
`git --no-optional-locks diff --check`; the new untracked report is checked
separately by `E/check_whitespace.py`. Both checks use a 60 s outer limit;
their captures are `diff-check` and `report-whitespace`.
`E/check_final.py` verifies all original tracked-file hashes, reference hashes,
unchanged HEADs/branches, preserved spec diff/status, effective dependency and
environment, and that this report is the sole untracked Go-repository addition.
Only the generated temporary build-directory component of `GOGCCFLAGS` is
normalized for environment comparison; both raw snapshots remain available.
No Go source was touched, so no formatter was run.

| Automated final check | Result |
|---|---|
| `make lint` | Exit 0; 0 issues; 0.517160 s |
| `git --no-optional-locks diff --check` | Exit 0; no diagnostics; 0.016573 s |
| Separate untracked-report whitespace check | Exit 0; no tabs/trailing whitespace; one final newline; final capture `report-whitespace-final` |
| Preservation audit | Exit 0; all 548 original tracked files unchanged; reference hashes, spec diff/status, repository identities and environment unchanged |
| Report command/source cross-check | Measured fast argv matches the report exactly; all 20 ranked family names and implementation locations match parsed evidence |

The initial broad read-only `/tmp` search returned exit 2 for unrelated
service-private directories while locating the existing capture utilities.
No access workaround or retry was attempted; this was not a lint/test failure.

Final Go status:

~~~text
?? docs/implementation/Refactoring_Round_03B_Test_Cost_Inventory.md
~~~

No commit or tag was created. The spec retains only its original
` M models/active/IntroTreeV19.tla` modification.

The test baseline and candidate are single samples on one Linux/arm64 machine.
Map iteration order, external load, filesystem behavior and cache warmth can
change durations. Parallel leaves contend for CPU/storage; elapsed timing is
not CPU attribution. The nonverbose race outputs cannot supply a fresh per-test
event inventory. The complete PW race suite and broad race suite were not run;
the two requested race passes do not convert historical incomplete broad race
coverage into a pass.

No benchmarks, dependency tests, live broker/demo flags, controller/Flutter
checks, formal-model checks or manual two-window demonstration were run.
**Automated verification and owner acceptance are separate. Manual acceptance:
not performed; fast-tier contract approval remains pending.** No implementation
refinement proof, new TLC/SANY result or formal conformance claim is made.

One-sentence increment description: this report establishes the err2 v1.4.2
ordinary test baseline, classifies PW costs and proposes a measured 16-family
everyday selection without changing executable code or test behavior.

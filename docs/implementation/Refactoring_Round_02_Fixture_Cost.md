# Refactoring round 02: fixture-cost investigation

Measured 2026-11-13. **Investigation-only outcome:** no test optimization was
implemented. The three focused runs averaged **19.202 seconds**, and the
current profile confirms that repeated guarded protocol preparation dominates.
The dominant assertion-context cost is in production functions, not removable
test-helper setup. No small change with a demonstrated safety argument and
useful access to that cost was identified within this increment's constraints.
This uses the prompt's explicit investigation-only exit; it does not claim a
speedup or completion of the performance objective.

## 1. Workspace and provenance

Implementation workspace: `/home/parallels/go/src/github.com/lainio/ic`.
Read-only `SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.

| Repository | Branch | Initial and final HEAD | Initial status | Final status |
|---|---|---|---|---|
| Go | `tla-spec-based-refactoring-v1` | `3e1e3bbb7b1b62fc6d08bde9e97e9031e083d819` | Clean; matches accepted commit | Only this report is untracked |
| Spec | `break-demo` | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | Modified `models/active/IntroTreeV19.tla` | Same pre-existing modification |

Read the live root instructions, implementation reality document, round-one
report, model index and all three required semantic contracts. No nested
instructions were found under `internal/pw` or the report destination.
The spec reference documents are unchanged relative to committed HEAD.
The uncommitted V19 mutation was not used as semantic authority. Its diff
fingerprint is retained for preservation checks. V19 and the accepted
invitation extension retain their existing scope; the separate messaging
candidate gains no composition or refinement claim from these measurements.

No overlapping user edits were observed. No Go source, benchmark `init()` or
`b.Loop()` code, production code, dependency, Makefile, CI, controller, Flutter
or spec file was changed. No Git writes, dependency downloads, toolchain
changes, sandbox workarounds or nested Codex processes were used.

The task message is saved as UTF-8 text with a final newline at
`/tmp/ic-round02-20261113/task-prompt.md`; SHA-256:

~~~text
958efff1e6e8eef3f0dbff2a0851e623a22da8927c7d0871c09722a1e850d3c8
~~~

This is the task message beginning with `SPEC_REPO=`, not a reconstruction of
the external launcher's complete input. External exec-metrics evidence path:
**not yet supplied; user to append after the external run finishes**.

## 2. Environment, commands and raw evidence

Evidence root `E = /tmp/ic-round02-20261113`. The existing round-one
`capture.py` and `summarize.py` were copied unchanged to E; no measurement
framework was introduced. Each capture retains exact argv, cwd, selected
environment, monotonic command wall time, child user/system CPU, exit status
and timeout status in `E/LABEL.json`, with raw `.stdout` and `.stderr` files.
Go JSON completion events are retained in `.stdout`; `.summary.json` files
contain package/test completions, failures, skips and timeout observations.

Go is `go1.27.1 linux/arm64`, on Linux `6.8.0-147-generic`.
Inherited `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off` and
`GOSUMDB=off` were preserved. Effective `CGO_ENABLED=1`, build cache
`/home/parallels/.cache/go-build`, module cache `/home/parallels/go/pkg/mod`;
no `GOMAXPROCS` override. Every shell used `login=false`.

All measured test processes ran sequentially, without concurrent lint or
other test measurements. Baseline lint preceded them. `-count=1` prevents
test-result reuse; it does not clear the build cache. Initial cache warmth and
external host load were not controlled. Wall time includes the Go driver,
any build/link/vet work, test execution and cleanup. CPU samples are not
exclusive wall-time measurements.

Exact commands, from the implementation root:

~~~sh
python3 /tmp/ic-round02-20261113/capture.py lint-before 600 make lint
python3 /tmp/ic-round02-20261113/capture.py focused-before-1 180 go test -benchmem -count=1 -json -timeout=10m ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'
python3 /tmp/ic-round02-20261113/capture.py focused-before-2 180 go test -benchmem -count=1 -json -timeout=10m ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'
python3 /tmp/ic-round02-20261113/capture.py focused-before-3 180 go test -benchmem -count=1 -json -timeout=10m ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'
python3 /tmp/ic-round02-20261113/capture.py profile-current 180 go test -benchmem -count=1 -json -timeout=10m ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$' -cpuprofile=/tmp/ic-round02-20261113/pw.cpu -o /tmp/ic-round02-20261113/pw.test
python3 /tmp/ic-round02-20261113/capture.py pprof-all 60 go tool pprof -top -cum -nodecount=0 -nodefraction=0 /tmp/ic-round02-20261113/pw.test /tmp/ic-round02-20261113/pw.cpu
python3 /tmp/ic-round02-20261113/capture.py pprof-assert-callers 60 go tool pprof -peek 'github.com/lainio/err2/assert.PushAsserter$' /tmp/ic-round02-20261113/pw.test /tmp/ic-round02-20261113/pw.cpu
python3 /tmp/ic-round02-20261113/capture.py focused-race 180 go test -benchmem -count=1 -json -timeout=10m -race ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'
python3 /tmp/ic-round02-20261113/summarize.py focused-before-1 focused-before-2 focused-before-3 profile-current
python3 /tmp/ic-round02-20261113/summarize.py focused-race
python3 /tmp/ic-round02-20261113/capture.py lint-after 600 make lint
python3 /tmp/ic-round02-20261113/capture.py diff-check 60 git --no-optional-locks diff --check
python3 /tmp/ic-round02-20261113/capture.py report-check 60 git --no-optional-locks diff --no-index --check /dev/null docs/implementation/Refactoring_Round_02_Fixture_Cost.md
~~~

Additional evidence includes `git-before.json`, `git-after.json`,
`spec-before.json`, `spec-after.json`, `environment.json`, `input-hashes.json`,
`baseline-measurements.json`, `spec-dirty-diff.sha256`, `pw.cpu` and `pw.test`.
The input hashes cover the inspected fixture chain, reference documents,
installed err2 assertion implementation and both existing round-one benchmarks.
Raw evidence stays outside the repository at E.

## 3. Focused baseline

Each ordinary sample selects exactly the same parent and its 112 subtests:
two local roles, 28 history mutations, and two inbox-presence states.
There are **113 named pass events**, including the parent, not 113 independent
leaf tests. All three samples have identical completed names and outcomes,
zero failures, zero skips and exit 0. No timeouts occurred.

| Capture label | Command wall seconds | Parent test seconds | Package seconds | Child user / system CPU seconds | Subtests passed |
|---|---:|---:|---:|---:|---:|
| `focused-before-1` | 19.353 | 18.78 | 18.791 | 17.379 / 0.976 | 112 |
| `focused-before-2` | 19.155 | 18.78 | 18.783 | 17.283 / 0.894 | 112 |
| `focused-before-3` | 19.097 | 18.72 | 18.723 | 17.241 / 0.861 | 112 |

Mean command wall time: **19.202 s**; median: **19.155 s**;
range: **19.097–19.353 s**. These are three observations, not a controlled
statistical estimate. No per-fixture or per-phase wall timer was added.

Round one's complete ordinary suite measurements, **319.069 / 343.542 s**,
and PW package measurements, **316.054 / 340.349 s**, remain historical
context. Its focused parent timings, **19.54 / 21.66 s**, were collected in
the broad suite. Comparing those to today's isolated selection would not
establish a speedup. Round one's broad race attempt timed out in PW and
remains incomplete.

## 4. Fixture work and current CPU attribution

Every subtest calls this chain:

~~~text
ackTestV2
  receiptTestV2
    incomingTestV2
      newOutgoingV2
        newFirstUseV2
          newRequester
            newEstablishment
              ready
~~~

`profile-current` passed in **19.299 s** command wall time, **18.82 s** parent
time, with **17.71 s sampled CPU**. It is a separate diagnostic run, not a
fourth uninstrumented baseline or an after sample.

| Phase | Repeated work and evidence |
|---|---|
| Tester/assert context | Test and helper `PushTester`/`PopTester` setup; separately, production `PushAsserter(assert.Plain)` during guarded reads and decoding. Sampled cumulative CPU: `PushTester` 0.06 s (0.34%), `PopTester` 0.03 s (0.17%), versus `PushAsserter` 11.93 s (67.36%) and `runtime.Stack` 12.06 s (68.10%). |
| Cryptographic preparation | `ready` creates three independent saved signers, encrypted identity files and unlock material; paths, acceptances, ads, attempts, first-use requests/responses, envelopes and receipts are signed as preparation advances. `newSigner` totals 0.10 s (0.56%) including its filesystem work. Key generation has no separately reported sample in this profile; that does not mean zero cost. |
| Introductions and relationships | Each node saves introduction evidence, explicitly promotes it to Known and bootstraps a device. Bob issues an invitation and publishes an ad; the unit requester fixture seeds its verified-ad record as before. Fresh v2 attempt, Bob acceptance/reply, independent Alice acceptance, and fresh first use run through their guards. `newRequester` is 1.64 s, `newFirstUseV2` 5.81 s, `newOutgoingV2` 8.65 s, `receiptTestV2` 12.34 s and `ackTestV2` 14.43 s (81.48%), all cumulative. |
| Vault initialization | Two fresh encrypted bbolt Vaults per subtest, each with a separate random storage secret, file and finite 128-encryption lease. `newVault` is 0.14 s (0.79%) cumulative CPU. This does not measure all later storage activity or blocked I/O. |
| Actual test operations and verification | Prepare an incoming inbox in the 56 `present=true` cases; check inbox presence and successful ACK preflight; corrupt the selected history; reopen; require ACK and inbox refusal; require the final ACK commit to fail without the unchanged-success sentinel. Logical state, encryption allowance and physical bytes are checked by the existing refusal helpers. Across preparation and checks, `listKnownIntroductions` is 8.06 s (45.51%) and `ecdsa.VerifyASN1` 3.22 s (18.18%) cumulative CPU. |
| Cleanup and persistence | Each case reopens its modified local database and compares physical database bytes on refused operations. Registered cleanup closes databases, clears storage secrets and removes temporary directories. These remain inside measured execution; no isolated cleanup wall time is available. All bbolt `fdatasync` stacks total 0.12 s (0.68%) sampled CPU, which excludes time blocked waiting for storage. |

**Do not add these figures:** the fixture chain, production assertions,
introduction verification, cryptographic verification and Vault transactions
overlap. A function's cumulative CPU includes descendants. The 81.48% fixture
share does not mean 81.48% is avoidable or that key creation dominates.

The caller profile `pprof-assert-callers.stdout` identifies the sampled
`PushAsserter` callers as production functions. Large direct callers include
`record.(*Scope).Token` (1.97 s), `record.openRecord` (1.28 s),
`storage.(*readTx).recordName` (1.25 s), `wire.UnmarshalCanonical` (1.10 s)
and `record.(*Scope).Open` (1.06 s). No `PushAsserter` call occurs in the
PW test sources. Removing helper `PushTester` calls would not remove these
production contexts.

## 5. Optimization decision

**Selected optimization: none.** The following candidates were assessed;
none was implemented or experimentally substituted. The 20% target was not
treated as a safety exception or as a requirement to reject a smaller proven
benefit. The problem is the absence of a bounded, justified change to the
dominant cost under the present constraints.

| Candidate | Assessment |
|---|---|
| A: reusable immutable inputs | Keys and introduction bytes are possible future inputs, but their preparation is small relative to repeated guarded protocol execution. Reusing those bytes still requires each fresh Vault's received/known verification and every later policy/history check. Sharing the completed ACK fixture or cloning its committed state would bypass per-case fresh attempts and independently executed preparation. No such shortcut was taken. Input ownership and lifetime would need explicit plumbing through the shared fixture chain, plus auditing callers that mutate signers and evidence; a hidden shared cache is not justified here. |
| B: redundant test contexts | The current profile attributes only 0.09 s cumulative CPU in total to test push/pop operations. More importantly, installed err2 v1.4.0 `PushTester` stores one tester per goroutine and `PopTester` deletes that entry; it does not restore an outer tester. For example, `ready` calls `newVault` and then `newSigner`, whose nested cleanup deletes the tester registration. Merely finding an outer `defer assert.PushTester(t)()` does not establish the prompt's active-context precondition for every call. No context/recovery boundary was removed. Production `PushAsserter` and its error semantics remain outside authorized edits. |
| C: selective memory | The measured test reopens after every history mutation and requires physical byte equality for refusals. Replacing its Vaults with memory would weaken those assertions. Existing `NewMemory` is adequate for eligible tests, but swapping unrelated tests would not reduce this focused fixture cost. |

This is a bounded negative result, not proof that all future test-only
optimizations are impossible. No assertion, verification, negative case,
subtest, name, skip, policy guard, fresh session, independent Vault or
persistence check was removed. No parallel tests were introduced.

## 6. Changes and after measurements

Only `docs/implementation/Refactoring_Round_02_Fixture_Cost.md` was added:
it records the focused baseline, current profile, rejected optimization
candidates, validation and next-step recommendation.

**After measurements: not applicable.** No test change exists to compare.
There are no measured after improvements or regressions, and no claimed
focused or overall suite speedup. The performance objective and 20% target
remain unmet. Three additional unchanged ordinary samples were not relabeled
as an after comparison.

## 7. Automated validation and unrun checks

| Check | Result |
|---|---|
| Baseline `make lint` | Exit 0, 0 issues; 0.620 s |
| Three ordinary focused runs | All pass: 112 subtests plus parent, no failures/skips/timeouts |
| Current profile run | Pass: same 113 named pass events, no failures/skips/timeouts |
| Focused `-race` | Exit 0; 36.584 s command wall, 35.10 s parent, 36.125 s package; same 112 subtests plus parent pass, no skips or reported race |
| Final `make lint` | Exit 0, 0 issues; 0.468 s |
| `git --no-optional-locks diff --check` | Exit 0; no tracked-file whitespace errors |
| Untracked report `diff --no-index --check` | Exit 1 because the new file differs from `/dev/null`; no whitespace diagnostics |

All lint, test and profiling commands passed. Read-only discovery also probed a few nonexistent
conventional filenames; those inspection misses are not test failures or
sandbox rejections. No Go files were touched, so no formatter was run.
The untracked report was also checked separately with `diff --no-index
--check`; ordinary `diff --check` does not inspect untracked files.

The complete ordinary PW package run was **not run**: the prompt requires it
if a test-only improvement is implemented, which did not occur. The complete
broad race suite, full ordinary suite, unrelated packages, benchmarks, live
demo/controller/Flutter checks and external broker checks were not run.
Today's focused race pass does not repair round one's incomplete broad race
result or change its timeout policy.

Manual acceptance is separate: **not performed**. No two-window acceptance,
new formal-model validation, conformance proof or owner acceptance is claimed.

## 8. Selective memory-backed test assessment

Both backends already exist in `storage/internal/engine/{memory,bbolt}.go`,
and `storage/db.go` exposes `NewMemory` and `OpenBolt` through the same
encrypted Vault facade. There is no need for another backend.

Potentially suitable semantic-only candidates are
`TestFirstUseRandomSessionAndRetainedBinding` and its `V2` counterpart.
They construct two fresh relationships, verify timing/held binding and fresh
session IDs, and complete first use. Their own bodies and setup chain do not
assert persistent reopen, file locks or physical byte equality. A future
explicit memory fixture could retain separate encrypted Vaults, finite leases,
fresh attempts and all current guards. They still use bbolt today; this is
source-based suitability assessment, not a validated backend conversion.

Tests that must retain persistent coverage include the measured
`TestMessageProjectionRequiredHistoryV2`, `TestMessageACKAndInboxEitherSenderV2`,
`TestRequesterV2ContactsAndExactReopen`, the v2 projection process-reopen,
read-only-backend and commit-failure tests in
`message_projection_v2_linux_test.go`, and every case relying on
`vaultFixture.unchanged`, `reopen`, raw database bytes or descriptor faults.
The existing shared `newVault` must therefore remain persistent by default.

The `internal/nodevault.Store` additionally owns a persistent `usage.db`,
exclusive lock and committed encryption reservations in `provider.reserve`.
Its production-bound, process/restart and accounting tests are not candidates
for bypassing that accounting with an ephemeral Vault. PW's small test lease
does not replace the Store's persistent accounting guarantees.

A separately scoped memory comparison of the two semantic-only session tests
is defensible, but **not justified as the next attempt to solve this measured
hotspot**. Their preparation still performs the dominant verification work,
and this focused test's durability requirements rule out conversion. The low
sampled storage CPU alone cannot predict memory's wall-time benefit.

## 9. Remaining costs and next increment

The dominant costs remain production assertion-context stack walks and repeated
authenticated introduction/history checks during fresh protocol preparation.
They occur inside the encrypted Vault's guarded reads as well as at protocol
boundaries. Caching current authority, skipping verification, restoring a
prepared success or disabling durability is not an accepted optimization.

For the next round-two decision, review whether to authorize one narrow
investigation of production assertion-context overhead, using the retained
caller profile. Any eventual change must establish entry/worker context
ownership and preserve exact sentinels, error recovery and all verification;
the present evidence is not permission to remove nested `assert.Plain` calls
or change err2. If the next increment must remain test-only, first agree on
explicit immutable input ownership through the fixture chain and expect a
modest benefit rather than attributing the full fixture CPU to preparation
that can be reused.

No such implementation was started, and round three was not begun.

# Refactoring round 03A: parallel history subtests

Measured 2026-11-14. Running the 112 independent history subtests with
`-parallel=4` reduced median focused command wall time from **6.449956 s to
2.929852 s (54.58%)**. Median package time fell **57.09%**. Recommendation:
**keep this bounded change**. The final focused ordinary and race runs preserve
all original subtest names and outcomes. Complete validation is recorded below.

## 1. Workspace and provenance

Writable workspace: `/home/parallels/go/src/github.com/lainio/ic`.
Read-only `SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.

| Repository | Initial and final HEAD | Initial and final branch | Initial dirty state |
|---|---|---|---|
| Go | `713ffc902b8f486be3e65636720cbaeb20ae882b` | `tla-spec-based-refactoring-v1` | Clean; exactly the accepted baseline |
| Spec | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | `break-demo` | Modified `models/active/IntroTreeV19.tla` |

Final Go dirty state:

~~~text
 M internal/pw/message_projection_history_v2_test.go
?? docs/implementation/Refactoring_Round_03_Parallel_Subtests.md
~~~

The spec's initial/final status and complete diff are identical. Its existing
V19 safe-restore mutation was preserved, not treated as the semantic baseline.
The model index and all three required contracts were read, along with the
implementation reality document and all three previous refactoring reports.
Live root instructions apply; no additional `AGENTS.md` exists under
`internal/pw` or `docs`. The read-only storage/core and spec instructions were
also inspected. No previous report, production file, dependency, benchmark,
Makefile, CI, controller, Flutter file or protocol contract changed.

Evidence root **E = `/tmp/ic-round03a-20261114`**. The supplied task message
beginning `SPEC_REPO=` is retained as UTF-8 with a final newline at
`E/task-prompt.md`; SHA-256:

~~~text
5cdef86338538ca7cd5af16a3199102f69947d4adc6062dbfc71635d35740277
~~~

This records the task message, not the external launcher's complete input.
The external exec-metrics path was not supplied; the owner can append it after
the external run finishes. No exec-metrics or nested Codex process was invoked.
No Git-writing command, download, toolchain change or sandbox workaround was
used. No commit or tag was created.

`E/message_projection_history_v2_test.go.original` is the verified pre-edit
snapshot, with SHA-256:

~~~text
e0d412541d3698b37e1404d4b3b5743f5983e8636e44a854d3cd15b1d4b1e234
~~~

The snapshot matched live source immediately before editing. No correctness
failure or race required restoration. Two intermediate source snapshots are
also retained as `.initial-parallel` and `.once-serial-parent`; their lint
findings and superseded measurements are described below.

## 2. Isolation audit

Every leaf follows the complete existing chain:

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

| Boundary | Inspected ownership and preserved behavior |
|---|---|
| Vaults and paths | `ready` creates Bob's Vault; `newRequester` creates Alice's. Each `newVault` uses its leaf's `t.TempDir()/vault.db`, a fresh Database and encrypted bbolt storage. Reused numeric Vault/Key IDs are scoped to separate files. No database or fixture crosses subtests. |
| Signing identities and secrets | `ready` invokes `newSigner` three times for root, Bob and Alice. Each has separate temporary identity/unlock files and random 32-byte wrapping material. `nodeidentity.Create/Open` constructs an independent enclave backend; it does not use `key.Enclave` or the enclave package's default Store. Key handles and probe counters belong to that fixture. |
| Encryption allowances | Each Vault has its own `testLease`, fresh random secret and atomic allowance initialized to 128. Reopen reuses only that Vault's own lease. No shared allowance or secret cache is introduced. |
| Establishment and evidence | Introductions, explicit Known promotion, device bootstrap, invitation, ad and signed request are prepared per fixture. `responseV2` saves a fresh random v2 attempt and commits Bob acceptance before returning the saved reply; `receiveV2` independently commits Alice. The existing unit-fixture verified-ad seeding remains unchanged. |
| First use and messages | `newOutgoingV2` completes a fresh random session through separate requester/acceptor observations. `incomingTestV2` prepares a sender's outgoing bytes; `receiptTestV2` admits them at the receiver; `ackTestV2` issues a receipt. All evidence and mutation buffers are local or owned bytes read from that fixture. The older deterministic preparatory v1 attempt bytes are separately allocated and are not the saved v2 attempt. |
| Time and configuration | `invitationNow` is initialized once and only read; each fixture stores its own value in `f.now`. Its clock closures capture that fixture. Service origins and record names are constant strings. Go module version 1.24 supplies per-iteration bindings for the existing `local`, `mode` and `present` range variables. |
| Physical persistence | Each leaf still mutates its own history and calls `n.own.reopen(t)`. Refusal helpers retain logical-state, allowance and `os.ReadFile` whole-database byte comparisons for both nodes. No other leaf writes either observed file. Commit-time revalidation and exact error-sentinel checks remain in place. |
| Cleanup | `t.Cleanup` belongs to the leaf that allocated each resource. Reopen registers closure of the new Database; original closure remains idempotent. Database closure precedes corresponding secret clearing and directory removal. All protocol work is synchronous within the leaf; cleanup cannot clear a sibling's secret or close its file. |
| Transactions and synchronization | Vault View/Update callbacks execute on the calling goroutine. Database/Vault admission and lifecycle synchronization, bbolt transaction ordering and atomic lease counters remain unchanged. Only the test-owned `sync.Once` initialization gate is added. |

The selected path performs no environment or working-directory changes,
subprocess launches, HTTP calls or listener creation. Its loopback URLs are
signed configuration data. No fixture worker goroutines carry assertions or
outlive their leaf. Shared `crypto/rand.Reader` supports concurrent use;
CBOR v2.9.0 modes have immutable options and synchronized type caches. The
wire modes are initialized before tests and not reassigned here. Error
sentinels are read-only. glog uses synchronized configuration/output; selected
tests do not change logging flags or replace writers. err2 tracer references
use atomic storage; the selected path does not alter them. Diagnostic text
can interleave on a failure, but no assertion depends on its ordering.

Other PW tests temporarily change environment and tracers, restoring them
through their existing cleanup/defer paths. The original package has no
`t.Parallel()` call and no TestMain/init test hook. The final change makes
only this family parallel: Go completes the ordinary serial tests and their
cleanup before releasing this parent. Thus those configuration mutations do
not overlap these children. This isolation claim must be revisited if another
top-level family is parallelized later.

### Assertion lifecycle and required scheduling

Installed **err2 v1.4.1** stores tester registrations in an RWMutex-protected
map keyed by goroutine ID. `PushTester` sets one entry; `PopTester` deletes it.
Nested pushes **do not restore an outer tester**. The fixture chain already
contains nested pushes: after a helper returns, an outer deferred pop is not
evidence that its tester remains registered. Unregistered assertions retain
err2's existing panic fallback; this round does not claim to repair nested
failure attribution or cleanup diagnostics. Every existing assertion,
deferred recovery boundary and cleanup callback is unchanged. A sibling's
different goroutine key cannot supply or erase this leaf's registration.

`PushAsserter(assert.Plain)` separately saves/restores goroutine-local modes;
those production scopes and error identities are untouched. No helper
`PushTester` in this chain executes inside one of those production scopes.

There is also a process-wide initialization hazard: the first `PushTester`
may call `SetDefault(TestFull)`. Its default index is read without the setter's
mutex, so independently racing first pushes are not justified by the tester
map lock. A **local `sync.Once`** gates this initialization. After each leaf's
`t.Parallel()` returns, all leaves call `testerInit.Do`; the winning callback
uses the normal `defer assert.PushTester(t)()` lifecycle and immediately
returns. `sync.Once` publishes completion before any leaf makes its ordinary
deferred push or builds fixtures. That ordinary push follows the callback's
pop, so no nested restoration is assumed. The gate caches no fixture, key,
Vault, evidence or assertion result.

The parent also calls `t.Parallel()` because live `tparallel` lint explicitly
requires it when the children are parallel. This is a repository-policy
requirement, not an additional performance experiment. An initial serial
parent with a deferred tester context failed lint's cleanup rule; replacing
that context with the Once gate exposed its parent-parallel rule. Both
diagnostics were honored without suppression or lint/configuration changes.
The final parent holds no fixture resources or tester registration; each leaf
owns its own setup, assertions and cleanup after resumption.

## 3. Environment and measurement method

Go `go1.27.1 linux/arm64`; module Go version `1.24.0`; err2 `v1.4.1`, with
no replacement. Five visible CPUs, affinity 0–4. Inherited `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=readonly`, `GOPROXY=off` and `GOSUMDB=off` were preserved.
Effective `CGO_ENABLED=1`; no `GOMAXPROCS` override. Existing build/module
caches were used without clearing or relocating them. All measurement shells
used `login=false`; no permission or network setting changed.

The previous round's `capture.py` and `summarize.py` were copied unchanged.
Every measured/test/lint command ran sequentially as a separate invocation;
the next started only after the prior process completed. Capture syntax is:

~~~sh
python3 /tmp/ic-round03a-20261114/capture.py LABEL OUTER_SECONDS COMMAND...
~~~

Each `E/LABEL.json` records exact argv, cwd, inherited settings, monotonic wall
time, child user/system CPU time, exit and timeout status. `.stdout` and
`.stderr` preserve raw results. `.summary.json` retains JSON completions,
failures and skips. `analyze.py` generates `measurements.json`, verifies equal
focused test names/outcomes, and computes the comparison without table rounding.

Exact child commands and evidence labels:

~~~sh
# focused-before-1/-2/-3; focused-final-1/-2/-3; outer 660 s each
# Superseded focused-after-1/-2/-3 used this identical command too.
go test -count=1 -json -timeout=10m -parallel=4 \
  ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'

# focused-race-final; superseded focused-race; outer 660 s each
go test -race -count=1 -json -timeout=10m -parallel=4 \
  ./internal/pw -run '^TestMessageProjectionRequiredHistoryV2$'

# pw-before; pw-after-final; superseded pw-after; outer 900 s each
go test -count=1 -timeout=10m ./internal/pw

# lint-before, lint-after, lint-corrected, lint-parallel-parent,
# lint-final; outer 600 s each
make lint

# diff-check; outer 60 s
git --no-optional-locks diff --check

# final-audit; outer 60 s
python3 /tmp/ic-round03a-20261114/check_final.py
~~~

The ordinary package command intentionally retains its default parallel limit;
the six focused comparison runs use exactly `-parallel=4`. No ordinary command
uses `-bench` or `-benchmem`. `-count=1` prevents result-cache reuse, not build
caching. No samples were dropped for being slow. External machine load and
cache warmth were not controlled; these are three observations per side,
not a confidence interval or a claim for other hardware.

## 4. Final before/after comparison

Every comparison run passed the original **112 leaf subtests**: two local
roles × 28 corruption modes × two inbox-presence cases. Each has 113 named
pass events including the parent, zero failures and zero skips. Raw events
retain each leaf duration. Final samples contain all 112 child PAUSE/CONT
pairs. No Go or external timeout occurred.

| Label | Command wall s | Package s | Parent-reported s | Full focused tree span s |
|---|---:|---:|---:|---:|
| `focused-before-1` | 6.501142 | 6.090 | 6.08 | 6.084077 |
| `focused-before-2` | 6.449956 | 6.093 | 6.09 | 6.087402 |
| `focused-before-3` | 6.342956 | 5.981 | 5.98 | 5.976069 |
| `focused-final-1` | 3.082077 | 2.614 | 0.00 | 2.608826 |
| `focused-final-2` | 2.926311 | 2.597 | 0.00 | 2.591152 |
| `focused-final-3` | 2.929852 | 2.613 | 0.00 | 2.608268 |

| Measure | Before median | Before min–max | After median | After min–max | Median change |
|---|---:|---:|---:|---:|---:|
| Command wall s | 6.449956 | 6.342956–6.501142 | 2.929852 | 2.926311–3.082077 | −54.58% |
| Package s | 6.090 | 5.981–6.093 | 2.613 | 2.597–2.614 | −57.09% |
| Focused tree span s | 6.084077 | 5.976069–6.087402 | 2.608268 | 2.591152–2.608826 | −57.13% |

Change is `100 * (after median / before median - 1)`. Go's parent `Elapsed`
excludes time waiting for parallel children: its change to 0.00 is **not a
100% speedup**. The tree span is derived from the parent's JSON RUN and PASS
timestamps, including child completion, and rounded to microseconds. Command
wall and package duration are the primary comparison. Child durations are
never summed to infer wall time.

Command CPU times remain in the raw metadata. The final median child user
CPU is 6.086103 s versus baseline 4.885658 s; median system CPU is 1.365277 s
versus 0.759712 s. Lower wall time does not imply less aggregate CPU work.
These command totals include driver/build work and do not establish where
the additional CPU was spent. No second optimization or new profile was run.

## 5. Automated validation and retained intermediate results

| Check / label | Command wall s | Result |
|---|---:|---|
| Baseline lint / `lint-before` | 0.420280 | Exit 0, 0 issues |
| Three before and three final focused runs | See comparison | Identical 112 leaves + parent pass; zero failures/skips |
| Final focused race / `focused-race-final` | 14.471806 | Exit 0; identical names/outcomes; no reported race |
| Complete ordinary baseline / `pw-before` | 121.291937 | Exit 0; package 120.940 s |
| Complete ordinary final / `pw-after-final` | 109.692145 | Exit 0; package 109.372 s |
| Final lint / `lint-final` | 13.375167 | Exit 0, 0 issues; 32 cache-persistence warnings |
| Whitespace / `diff-check` | 0.015990 | Exit 0; no diagnostics |
| Source/report preservation / `final-audit` | See capture metadata | Exact permitted source delta, unchanged other inputs, gofmt and report whitespace verified |

The final race run passes the same 112 leaves and parent, with no skips,
failures, reported data race or timeout; package duration is 9.332 s. Its
parent-reported duration is 0.01 s under the same parallel accounting rule.
All required Go test commands passed. Complete ordinary package output is
nonverbose by explicit command: it reports package success/duration, but
does not emit individual test counts or skips. Those values are **not
inferred** from source or historical reports. Focused JSON supplies the exact
counts above. The full package race suite and unrelated packages were not run.

Two intermediate lint failures are retained, not presented as passes:

| Label | Wall s | Exit | Finding |
|---|---:|---:|---|
| `lint-after` | 13.486559 | 2 | Serial parent with deferred tester: `should use t.Cleanup instead of defer` |
| `lint-corrected` | 15.211914 | 2 | Serial parent with Once gate: `should call t.Parallel on the top level as well as its subtests` |
| `lint-parallel-parent` | 15.088392 | 0 | Final parent/child scheduling and Once gate: 0 issues |

Before those lint findings, the initial parallel variant passed these checks:

| Superseded label | Wall s | Package s | Result |
|---|---:|---:|---|
| `focused-after-1` | 5.294802 | 2.595 | 112 leaves + parent pass; no skips |
| `focused-after-2` | 3.079878 | 2.696 | Same |
| `focused-after-3` | 2.978506 | 2.600 | Same |
| `focused-race` | 14.795435 | 9.596 | Same; no race reported |
| `pw-after` | 109.202278 | 108.841 | Complete package pass |

These captures describe superseded source and are excluded from the final
comparison for that reason, not because of their timings. The first initial
after command has a larger build/startup component; it remains recorded.
The Once/serial-parent intermediate was linted only. Final source received
three fresh focused runs, a fresh focused race run and a fresh full-package
run; no result was reused as validation of changed source.

Lint emitted warnings when attempting to persist facts to the existing
read-only `/home/parallels/.cache/golangci-lint` cache. Each intermediate lint
above had 32 such warnings. The two failures were the actual `tparallel`
diagnostics, not cache warnings. No cache relocation, permission workaround,
rule suppression or timeout increase was used.

`git diff --check` covers the tracked source. `check_final.py` separately
checks untracked report whitespace and gofmt, proves the source is exactly
the original plus parallel scheduling/Once initialization, and verifies all
other tracked file hashes, inspected reference hashes, initial spec diff,
branches/SHAs, err2 dependency and Go settings. Only Go's generated temporary
build-directory component of `GOGCCFLAGS` is normalized for environment
comparison. The original raw environments remain available.

Additional evidence: `git-before.json`, `git-after.json`, `spec-before.json`,
`spec-after.json`, `environment.json`, `environment-after.json`,
`tracked-input-hashes.json`, `reference-hashes.json`, `preservation.json`,
`measurements.json`, `validation.json` and `commands.json`. Raw artifacts stay
under E; the previous reports are unchanged.

## 6. Acceptance, remaining risks and round 3B

**Automated result:** the final source has improved focused wall time with
unchanged assertions and persistence coverage; required final checks are
recorded above. The once-only assertion-default gate and the lint-required
parallel parent are part of this experiment, not fixture changes.

**Manual acceptance: not performed.** No formal-model validation, new
refinement/conformance proof, cryptographic proof or two-window demonstration
is claimed. V19 remains the lifecycle/authority baseline, with the accepted
invitation extension governing independent local establishment commits.
Scheduling these tests changes no modeled action and resolves none of the
broader implementation gaps documented in the reality and earlier reports.

Keep this change, subject to owner review of its necessary parent scheduling.
The before/after ranges are separated for command, package and tree span.
Full-package samples are validation observations, not a robust suite-speedup
estimate: there is only one baseline and one final sample, and the family now
runs after the serial tests. Initial cache warmth and external load remain
uncontrolled. Parallel execution also increases instantaneous resource use
and can expose contention on smaller machines. One focused race pass is
evidence for the exercised interleavings, not proof of every possible schedule.

For round 3B, audit and measure one additional slow test family only after
owner acceptance of 3A. Recheck shared defaults, tracer/environment lifetime,
goroutine tester ownership and persistent-file isolation, especially overlap
with this now-parallel parent. Keep the same finite timeout policy and raw
evidence. The nested `PushTester` non-restoration behavior remains an explicit
constraint; neither an outer defer nor a passing race run proves continuous
tester registration. No second family was optimized in this round.

One-sentence change summary: `TestMessageProjectionRequiredHistoryV2` runs its
112 existing persistent-history subtests in parallel, with synchronized err2
default initialization and the parent scheduling required by live lint policy.

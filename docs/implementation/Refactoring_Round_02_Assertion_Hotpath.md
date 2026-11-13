# Refactoring round 02B: assertion hot-path experiment

Measured 2026-11-13. Replacing the cleared-state assertions in `Scope.Token`
and `Scope.Open` with direct sentinel returns reduced the median focused PW
command time by **10.91%**, the parent test time by **15.49%**, and Vault read
time per operation by **26.80%** across three samples before and after.
The production diff is confined to those two functions. **Recommendation:
keep.** All required Go tests and baseline/final lint passed.

## 1. Workspace and provenance

Implementation workspace: `/home/parallels/go/src/github.com/lainio/ic`.
Read-only `SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.

| Repository | Initial and final full HEAD | Initial and final branch | Initial dirty state |
|---|---|---|---|
| Go | `9c2f38c8cbe65e0085da5799e91efbdf67a1dd18` | `tla-spec-based-refactoring-v1` | Clean; matches accepted `9c2f38c` |
| Spec | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | `break-demo` | Modified `models/active/IntroTreeV19.tla` |

Both full SHAs and branches are unchanged. Final Go dirty state contains
only this experiment:

~~~text
 M storage/internal/record/scope.go
?? docs/implementation/Refactoring_Round_02_Assertion_Hotpath.md
~~~

The spec's final dirty state remains exactly the original
` M models/active/IntroTreeV19.tla`; its before/after diff SHA-256 is
`4672147e476423054de188c672700ace6896c064ba198b8b9553a4718ef9064e`.
No existing user change was overwritten. No commit or tag was created.

Read the live root `AGENTS.md`, `storage/AGENTS.md`, implementation reality
document, both prior refactoring reports, and the spec model index and three
required contracts. No additional nested instructions were found under
`storage`, `internal/pw`, or `docs`. The spec root instructions were also read.
The existing dirty V19 model was preserved; the unchanged reference contracts
supply semantic context, not that local model mutation. No TLA+ files were
modified or executed.

Evidence root `E = /tmp/ic-round02b-20261113`. The task message beginning with
`SPEC_REPO=` is saved as UTF-8 with a final newline at
`E/task-prompt.md`; SHA-256:

~~~text
7aae0c9e4ab0973c15bd594bcd76370a795ed98b90a8fa6b5a9d9549fdcbe79c
~~~

This is the task message, not the external launcher's complete input.
External exec-metrics path: **not supplied; user to append after launcher
completion**. No exec-metrics, nested Codex process, Git-writing command,
download, dependency change, or sandbox workaround was used.

The existing round-two `capture.py` and `summarize.py` were copied unchanged
to E. Each `E/LABEL.json` retains exact expanded argv, cwd, selected environment,
exit status, timeout status, monotonic command wall time, child CPU times and
completion timestamp. `E/LABEL.stdout` and `.stderr` retain raw output;
`.summary.json` files retain Go completion events, failures and skips.
`analyze.py` reproduces `measurements.json`, which retains the numeric
comparison without table rounding. `validation.json` summarizes completed
captures; `commands.json` retains the command/timeout ledger.
`measurement-plan.json` identifies the excluded initial captures.
`input-hashes.json`, `err2-input-hashes.json`, and `environment.json` identify
the inspected source, references, installed dependency and environment.
`git-before.json`, `git-after.json`, `spec-before.json`, and `spec-after.json`
retain repository state; `environment-after.json` records final settings.

Exact pre-edit snapshots are `E/scope.go.original` and
`E/scope_test.go.original`. The latter test file remains unchanged. The source
snapshot is the required restoration source if a correctness check fails;
restoration must not use Git or overwrite unrelated edits.

## 2. Environment and measurement method

Go `go1.27.1 linux/arm64`; Linux `6.8.0-147-generic`; five visible CPUs with
affinity 0–4. Installed err2 is `v1.4.0`, with no replacement. Inherited
`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off`, and `GOSUMDB=off`
were preserved. Effective `CGO_ENABLED=1`, build cache
`/home/parallels/.cache/go-build`, module cache `/home/parallels/go/pkg/mod`;
no `GOMAXPROCS` override. All measured shells used `login=false`.
No affinity, toolchain, cache, concurrency, tracer, or test settings changed.

The six comparison test runs and two benchmark commands ran sequentially,
without overlapping test, benchmark, or lint processes started by this task.
External host load, frequency and initial cache warmth were not controlled.
`-count=1` prevents test-result caching; it does not clear the build cache.
Command wall time includes the Go driver and any build/link/vet work.
Parent/package durations come directly from Go JSON, without summing nested
subtests. The first after command includes a larger non-test portion
(18.315462 s command versus 15.719 s package); it is retained in the comparison.

Benchmark source is the committed `storage/vault_benchmark_test.go`, including
the user's `b.Loop()` and `err2.SetTracers(nil)` initialization. Each measured
operation still opens a read transaction, finds the child namespace,
authenticates/decrypts a 1 KiB record and checks its contents. Setup, warm-up
read and cleanup remain outside its timer. Both sides use `-benchtime=1s`
and `-count=3`, without changing the benchmark.

Capture invocation is `python3 /tmp/ic-round02b-20261113/capture.py LABEL
OUTER_SECONDS COMMAND...`, from the implementation root. The labels and outer
limits below, together with these exact child arguments, define every run:

~~~sh
# focused-before-1 through focused-before-5; focused-after-1 through -3
# Outer limit: 180 seconds each. Only before-3/-4/-5 enter the comparison.
go test -benchmem -count=1 -json -timeout=10m ./internal/pw \
  -run '^TestMessageProjectionRequiredHistoryV2$'

# bench-before, bench-after; outer limit: 120 seconds each
go test -run '^$' -bench '^BenchmarkVaultRead1KiB$' -benchmem \
  -benchtime=1s -count=3 -timeout=10m ./storage

# record-after; outer limit: 180 seconds
go test -benchmem -count=1 -json -timeout=10m ./storage/internal/record
# storage-after; outer limit: 180 seconds
go test -benchmem -count=1 -json -timeout=10m ./storage/...
# storage-race; outer limit: 180 seconds
go test -benchmem -count=1 -json -timeout=10m -race ./storage/...
# focused-race; outer limit: 180 seconds
go test -benchmem -count=1 -json -timeout=10m -race ./internal/pw \
  -run '^TestMessageProjectionRequiredHistoryV2$'
# pw-full; outer limit: 900 seconds
go test -benchmem -count=1 -json -timeout=10m ./internal/pw

# lint-before, lint-after; outer limit: 600 seconds each
make lint
# diff-check; outer limit: 60 seconds
git --no-optional-locks diff --check
# gofmt-check; outer limit: 60 seconds
gofmt -l storage/internal/record/scope.go
# final-audit (initial audit), final-audit-2 (corrected audit); 60 seconds each
python3 /tmp/ic-round02b-20261113/check_final.py
~~~

## 3. Before and after measurements

All six comparison runs passed the same parent and 112 subtests: two local
roles, 28 history mutations, and two inbox-presence states. Each has 113 named
pass events including the parent, zero failures, zero skips, and exit 0.
These are event counts, not 113 independent leaf tests. No run timed out.

| Capture label | Command wall s | Parent test s | Package s | Child user s | Child system s |
|---|---:|---:|---:|---:|---:|
| `focused-before-3` | 19.588524 | 19.24 | 19.241 | 17.571500 | 0.923488 |
| `focused-before-4` | 18.954741 | 18.59 | 18.593 | 17.144781 | 0.859721 |
| `focused-before-5` | 18.928586 | 18.55 | 18.555 | 17.151315 | 0.829572 |
| `focused-after-1` | 18.315462 | 15.71 | 15.719 | 20.781343 | 1.399034 |
| `focused-after-2` | 16.886742 | 16.53 | 16.534 | 14.769946 | 0.952353 |
| `focused-after-3` | 16.063181 | 15.67 | 15.677 | 14.347417 | 0.793213 |

| Measure | Before median | Before min–max | After median | After min–max | Median change |
|---|---:|---:|---:|---:|---:|
| Command wall s | 18.954741 | 18.928586–19.588524 | 16.886742 | 16.063181–18.315462 | −10.91% |
| Parent test s | 18.59 | 18.55–19.24 | 15.71 | 15.67–16.53 | −15.49% |
| Package s | 18.593 | 18.555–19.241 | 15.719 | 15.677–16.534 | −15.46% |

Percentage change is `100 * (after median / before median - 1)`; negative
means less time or allocation. Every after observation is below the before
range for both command and parent duration. This is reproducible improvement
within these samples, not a confidence interval or an overall suite speedup.

Two initial runs briefly overlapped because the second was launched before
the first completion was confirmed. Both are retained but excluded from all
before/after statistics; three fresh sequential before runs replaced them.
They passed all 113 named events with no skips or timeouts:

| Excluded label | Command wall s | Parent s | Package s | Reason |
|---|---:|---:|---:|---|
| `focused-before-1` | 19.366464 | 18.91 | 18.916 | Brief overlap with before-2 |
| `focused-before-2` | 19.235082 | 18.83 | 18.840 | Brief overlap with before-1 |

Benchmark output uses suffix `-5` on both sides. All six samples passed:

| Phase/sample | Iterations | ns/op | B/op | allocs/op |
|---|---:|---:|---:|---:|
| Before 1 | 9,022 | 131,295 | 12,432 | 196 |
| Before 2 | 9,291 | 131,377 | 12,432 | 196 |
| Before 3 | 9,136 | 131,190 | 12,432 | 196 |
| After 1 | 12,488 | 96,038 | 12,128 | 187 |
| After 2 | 12,475 | 96,102 | 12,128 | 187 |
| After 3 | 12,314 | 98,020 | 12,128 | 187 |

| Measure | Before median | Before min–max | After median | After min–max | Median change |
|---|---:|---:|---:|---:|---:|
| ns/op | 131,295 | 131,190–131,377 | 96,102 | 96,038–98,020 | −26.80% |
| B/op | 12,432 | 12,432–12,432 | 12,128 | 12,128–12,128 | −2.45% |
| allocs/op | 196 | 196–196 | 187 | 187–187 | −4.59% |

Whole benchmark command wall times were 3.947422 s before and 5.229395 s
after; package times were 3.624 s and 3.628 s. Fixed-duration calibration and
build/startup costs mean command duration is not the per-operation metric.
The longer after command does not reverse the measured ns/op improvement.

No new CPU profile was needed or collected. The previous 1.97 s / 1.06 s
caller figures were motivation, not predicted wall-time savings. Source
inspection confirms the two direct `PushAsserter` calls are gone; remaining
assertion contexts and their `runtime.Stack` cost were not optimized.

## 4. Production change and semantic-equivalence argument

Only `storage/internal/record/scope.go` changes. In `Token`, the first check
returns the zero named token and the exact `ErrCleared` object. In `Open`,
it returns `nil, nil, ErrCleared`. Each function retains
`defer err2.Handle(&err, nil)` and its existing downstream calls.
`Derive`, `ValidatePath`, `Seal`, `Clear`, and every other assertion/context
remain unchanged. No test source was changed or added.

The complete package-local call chains were inspected before editing:

~~~text
Scope.Token
  encodeContext
  lookupToken
    checkContext -> fieldEnd
    HMAC-SHA256

Scope.Open
  encodeContext
  openRecord [owns assert.Plain]
    openEnvelope
      newEnvelopeAEAD -> AES / GCM
      parseEnvelope -> checkHeader
      encodeAAD -> checkHeader, checkContext -> fieldEnd
      AEAD.Open [existing errAuthentication translation]
    decodePlaintext -> fieldEnd
    lookupToken -> checkContext -> fieldEnd, HMAC-SHA256
    token comparison; optional requested-key comparison
~~~

`encodeContext`, `lookupToken`, and their validation helpers use ordinary
error returns or `try.To*`; none uses `assert`. Installed err2 `try.To*`
panics with the original error object, and `Handle(&err, nil)` propagates
without annotation. The removed `Plain` context therefore cannot affect
their validation failures or exact error identity.

`openRecord` installs its own `Plain` context before every assertion. This
covers index-key length, requested-key bounds, recomputed HMAC token equality,
and requested logical-key equality. Its context is restored before its own
non-annotating err2 handler runs. `PushAsserter` saves/restores any prior
goroutine context, or removes its entry if none existed. Removing the outer
context changes that bookkeeping but leaves the same caller context after
the call. No assertion lies between the removed context and `openRecord`'s
own context, or after it returns. Standard-library crypto has no err2
assertion dependency; these reads invoke no provider/spend callback.

The cleared check still precedes path, key, envelope and authentication
validation. The old `assert.That(..., ErrCleared)` under `Plain` panicked
with that sentinel; non-annotating recovery returned it. Direct return
supplies the identical sentinel and zero/nil results through the retained
handler. Diagnostic stack shape for a cleared error can differ because it
now takes the ordinary return path; byte-identical tracing is not claimed.
Runtime and unexpected panics retain the existing err2 propagation policy.

For live scopes, path and key bounds, expected identity, AEAD authentication,
plaintext decoding, HMAC token verification and requested-key comparison
are unchanged and occur in the same order. `openRecord` still returns owned
bytes only after all checks; failures expose no partial key or value.
No secret derivation, copying, clearing, spend accounting, scope field,
transaction, rollback or protocol guard changed.

The scope remains immutable during live concurrent calls. Owners must drain
work before `Clear`; concurrent clear/use and reentrancy remain outside the
contract. Removing goroutine-local assertion bookkeeping supplies no new
synchronization promise and removes none of the supported scope lifecycle
rules. Vault admission still pins the scope through transaction completion.

V19 remains the general lifecycle/authority baseline, with the accepted
invitation extension governing independent establishment commits. This edit
changes no modeled state transition, received/verified boundary, current
authorization check, durable evidence, contact projection or message rule.
The existing broader implementation gaps described by the reality and prior
reports remain outside this experiment.

## 5. Automated validation

| Check / capture label | Command wall s | Result |
|---|---:|---|
| Baseline `make lint` / `lint-before` | 0.568075 | Exit 0, 0 issues |
| Focused ordinary PW before/after | See above | All six comparison runs pass |
| Record tests / `record-after` | 0.317668 | 300 named pass events; no skips |
| Complete storage / `storage-after` | 6.455112 | All three packages pass; 840 named pass events; no skips |
| Storage race / `storage-race` | 11.221358 | Same three packages and 840 named pass events; no skips or reported race |
| Focused PW race / `focused-race` | 38.463856 | 113 named pass events; parent 31.89 s, package 32.907 s; no skips or reported race |
| Full ordinary PW / `pw-full` | 259.646016 | Exit 0; package 259.312 s; 5,859 named pass events; no skips |
| Final `make lint` / `lint-after` | 24.647989 | Exit 0, 0 issues; cache-persistence warnings below |
| `gofmt` on touched Go source | — | Applied to `scope.go` only; `gofmt-check` output empty |
| `diff-check` | 0.016614 | Exit 0; no tracked whitespace errors |
| Supplemental provenance / `final-audit` | 0.166694 | Exit 1: audit compared Go-generated temporary directory names literally; see below |
| Untracked report and preservation / `final-audit-2` | — | Corrected audit verifies report whitespace, snapshots, unchanged inputs, stable environment and Git state |

Existing coverage is sufficient for this two-guard change; no additional
regression test was necessary:

| Required property | Existing exercised coverage |
|---|---|
| Cleared precedence, exact `ErrCleared`, zero/nil results | `TestScopeOwnershipAndClear`, both valid and invalid inputs |
| Invalid paths and keys | `TestScopeSpending`, `TestScopeValidatePath`, `TestTokenBounds`, `TestRecordFailures`, Vault invalid-key/path cases |
| Malformed authenticated payload, wrong token, wrong requested key | `TestScopeValidation`, `TestRecordBeyondAEAD`, `TestRecordRequestedKey` |
| Unauthenticated/tampered records, wrong identity/context | `TestEnvelopeIntegrity`, `TestRecordFailures`, Vault tampered/relocated record cases |
| Ownership, exhaustion, lifecycle and concurrency | `TestScopeComposition`, `TestScopeOwnershipAndClear`, `TestScopeSpending`, `TestScopeConcurrentAllowance`, Vault lifecycle/key-usage tests |
| Rollback, ignored errors, exact callback sentinel and panic propagation | `TestVaultRecords` atomic cases for memory and bbolt, namespace rollback cases, engine tests |
| Unchanged logical/physical state on refused protocol work | All 112 focused history subtests retain reopen, failure, allowance and database-byte checks |

The record tests exercise exact identities with `assert.Equal`, including
under `PushTester`'s non-Plain testing default. Vault callbacks still own
their errors and preserve recovery/finish/backend rollback order. No test
case, assertion, fixture, timeout or skip was changed.

All required test commands completed successfully, with no test failures,
skips, timeouts or incomplete test runs. No restoration was needed. Event
counts include parent tests and subtests. The full PW package was run once;
its duration is validation evidence, not a matched full-package speedup
comparison against the earlier reports.

Final lint reported 312 warnings about persisting analysis facts to the
existing read-only `/home/parallels/.cache/golangci-lint` cache. It still
completed with exit 0 and 0 issues. Raw diagnostics are retained in
`E/lint-after.stderr`; no cache relocation, retry or permission workaround
was attempted.

`git diff --check` covers the tracked production diff; `check_final.py`
separately checks the untracked report's whitespace. The initial supplemental
audit failed when it compared full `go env` output literally: the only
difference was the generated `/tmp/go-build` directory number in
`GOGCCFLAGS`'s `-ffile-prefix-map`. No setting had changed. The original audit
is retained as `E/check_final.initial.py`, with its failed capture; its
follow-on all-captures-green summary also correctly refused success.
The corrected audit normalizes only that generated directory number,
retains both raw environment snapshots and checks every other flag verbatim.
This was an audit-script error, not a production correctness-test failure;
no Go source/test/assertion or environment was changed to resolve it.

The successful corrected capture and `preservation.json` record unchanged
tests, benchmark, reference hashes, capture scripts, stable Go settings and
CPU affinity. The exact pre-edit source snapshot matches the accepted
committed source. All inspected inputs except the authorized production
file retain their initial hashes.

## 6. Limits, acceptance and recommendation

**Keep** the two-function change: it is small, the call-chain argument
preserves the required behavior, all required automated checks pass, and
both workloads show improvement in each after sample. The focused command
gain is below 20%, which the experiment explicitly permits.
The three-sample improvements are consistently separated from the before
ranges on this machine. They do not establish a population confidence
interval, a full-suite speedup, or performance under other hardware/load.
Build-cache warmth and external load remain measurement uncertainty.
Nested assertion setup and repeated authenticated Vault operations remain
costs; no further optimization was attempted.

The entire repository, broad race suite and complete PW race package were
not rerun. No extra CPU profile, live demo, external-broker check, controller
test, Flutter test, TLC/SANY run or formal-model check was performed.
The historical incomplete broad race result remains historical and is not
converted into a pass by this experiment.

Manual acceptance: **not performed**. Automated Go validation is separate
from owner acceptance. This report claims no formal refinement, new TLC
result, cryptographic proof or real demo acceptance.

One-sentence change summary: `Scope.Token` and `Scope.Open` now return the
exact cleared-scope sentinel directly, avoiding their per-call assertion
context setup while retaining recovery and authenticated record validation.

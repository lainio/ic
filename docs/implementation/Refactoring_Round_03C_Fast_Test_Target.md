# Refactoring round 03C: optional fast test target

`make test_fast` implements the reviewed Round 03B section-7 selection.
The final fresh run passes **16 families and 36 descendants in 1.423327 s**
command wall time, with **1.035 s** reported by Go. Ordinary successful-result
caching works: the final two ordinary runs take **0.165716 s** and
**0.165181 s**, both reporting `(cached)`.

This target provides additional development feedback. It does not replace
complete regression, relevant race tests or integration acceptance.

## 1. Workspace and provenance

| Repository | Initial and final full HEAD | Initial and final branch | Initial dirty state | Final dirty state |
|---|---|---|---|---|
| Go | `b51b66b7bc5d3cf4f079622dc0c281c66b3ca4bc` | `tla-spec-based-refactoring-v1` | Clean; matches accepted baseline | Modified `Makefile`; new helper and this report, both untracked |
| Read-only spec | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | `break-demo` | Modified `models/active/IntroTreeV19.tla` | Same pre-existing modification, byte-for-byte |

Go workspace: `/home/parallels/go/src/github.com/lainio/ic`.
`SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.
Read the applicable root `AGENTS.md`, the spec root instructions, implementation
reality document, Round 03B inventory, model index and all three required
contracts. There are no additional `AGENTS.md` files under `scripts` or `docs`.
Reviewed the Makefile and existing Python scripts/documentation conventions.

The spec's existing safe-restore mutation restores snapshot recovery grants;
it contradicts the unchanged V19 contract. It remains preserved user state,
not a new semantic baseline. No TLA+ command or edit was performed.

Evidence root **E = `/tmp/ic-round03c-20261117`**. The supplied task message
beginning with `SPEC_REPO=` is saved as UTF-8 with a final newline at
`E/task-prompt.md`. SHA-256:

~~~text
ea34fd4f72afddf74f86109b26a1587815933282a90bf51c6848aee9c2a75f2d
~~~

This is the task message, not the external launcher's complete input.
**External exec-metrics path: not supplied; the externally launched run's
artifacts remain outside this report's evidence set.** No exec-metrics,
nested Codex process, sub-agent, Git write, dependency download, sandbox
workaround or launcher-setting change was used. Shells were non-login;
workspace-write, approval never and inherited offline settings were preserved.

`E/capture.py` is an unchanged copy of the Round 03B capture utility. For each
label, `E/LABEL.json` records exact argv and shell rendering, cwd, exit status,
monotonic wall time, aggregate child CPU, outer timeout, completion timestamp,
selected inherited environment and output paths. `E/LABEL.stdout` and
`E/LABEL.stderr` retain the raw command output. The helper renders Go JSON
`Output` fields into readable Go test output; `E/fast-json.stdout` additionally
retains the complete current cached JSON event stream used for negative replay.

Other evidence:

- `git-before.json`, `git-after.json`, `spec-before.json`, `spec-after.json`:
  repository identities, dirty states and full diffs.
- `git-before-hashes.json`, `spec-before-hashes.json`, `preservation.json`:
  tracked-file fingerprints and final preservation checks, including references.
- `environment.json`, `environment-after.json`: effective Go/module settings,
  tool versions, platform, CPU affinity and inherited settings.
- `selection-verification.json`: exact expected names, anchored expression,
  all 52 RUN/PASS names, equality with Round 03B and each measured run's results.
- `verify_target.py`, `replay-go.py`, `failure_fixture_test.go`,
  `negative-verification.json`, individual `LABEL.jsonl` files and captures:
  controlled negative inputs and results; all outside the checkout.
- `check_final.py`, `final-audit.{json,stdout,stderr}`: syntax, whitespace,
  result and preservation checks. `commands.json` and `evidence-sha256.json`
  retain the capture ledger and evidence fingerprints.

Temporary `/tmp` evidence is not durable archival storage.

## 2. Changed files and invocation

| File | Change |
|---|---|
| `Makefile` | Add one optional phony `test_fast` target and its fresh-run comment. |
| `scripts/test_fast.py` | Run the explicit selection and verify Go's JSON test events using only Python's standard library. |
| `docs/implementation/Refactoring_Round_03C_Fast_Test_Target.md` | Record scope, measurements, controlled failures and limitations. |

One-sentence change summary: add an optional, cache-compatible everyday target
that verifies every reviewed family and every emitted descendant passes.

~~~sh
make test_fast
make test_fast TEST_ARGS=-count=1
~~~

The recipe is `python3 scripts/test_fast.py $(GO) $(TEST_ARGS)`.
The helper accepts empty `TEST_ARGS` or exactly `-count=1`; other arguments
fail before Go launches. This deliberately prevents selection filters,
repetitions, short mode or scheduling overrides from changing the fast contract.
The existing `TEST_ARGS` default and other targets remain unchanged.

The child command is exactly:

~~~text
go test [optional -count=1] -json -timeout=10m ./internal/pw -run PATTERN
~~~

`PATTERN` is `"^(" + "|".join(TESTS) + ")$"`, where `TESTS` below is the
single authoritative executable list in the helper. There is no slash component
in this expression, so Go selects exact top-level names and leaves every
descendant eligible. The Makefile has no second list. No benchmark, race,
short-mode or forced-uncached flag is added to the everyday command.

## 3. Exact selection and verification

The list matches Round 03B section 7 exactly, including order:

~~~text
TestKnownBeforeAnySignerUse
TestAdHistoryNeverSubstitutesForIndependentKnown
TestAuthorizationDoesNotImplySignerUsability
TestInvitationIssuanceAndTimeBoundary
TestBobAcceptV2IndependentContactCommit
TestBobAcceptV2RejectsSignedBindings
TestBobAcceptV2RejectsUnauthenticatedBytes
TestReceiveAcceptanceV2IndependentContacts
TestReceiveAcceptanceV2DuplicateCannotRestoreDelete
TestFirstUseOrderedLocalObservationsV2
TestFirstUseReceiveStrictDeadlineAndCanonicalBytesV2
TestMessageACKAndInboxEitherSenderV2
TestMessageProjectionVersionIsolationV2
TestMessageSingleRecordRollbackV2
TestDenyAndDeleteAreDistinctLocalOperations
TestMessageClientCancellationAfterDispatch
~~~

The verifier requires the expected package start and successful completion,
RUN/PASS for all 16 expected families, and a complete passing lifecycle for
every emitted descendant. It rejects unexpected families/packages, any failed
or skipped test, missing completion, duplicate or invalid transitions, invalid
JSON/UTF-8, duplicate JSON fields, nonstandard numeric constants and an
unterminated final JSON line. It understands PAUSE/CONT without introducing
parallelism. No descendant-name list is frozen into the runner.

Go's stderr is inherited, and all JSON `Output` text is printed even when
verification fails. A nonzero Go status takes precedence over verification
errors; signal termination uses the usual shell `128 + signal` convention.
With Go status zero, verification failure returns 1. GNU Make reports the
recipe's status in `Error N`, then returns its own standard failure status 2.
The positive helper summary is printed only after both checks succeed.

Fresh and cached observations contain exactly **52 matching RUN/PASS names**:
16 families plus 36 descendants, with no extra families, failures or skips.
These names also match the accepted Round 03B candidate's complete descendant
set. Cached RUN/PASS events describe the cached successful execution; the
`-count=1` run establishes fresh execution.

## 4. Measurements

Machine: Linux `6.8.0-147-generic`, aarch64, CPU affinity 0–4;
Go `go1.27.1 linux/arm64`, Python `3.12.3`.
Inherited/effective settings remain `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GOSUMDB=off`,
`CGO_ENABLED=1`, build cache `/home/parallels/.cache/go-build`.
No cache was cleared or relocated and no test scheduling was changed.

From the Go root, capture syntax is:

~~~sh
python3 /tmp/ic-round03c-20261117/capture.py LABEL OUTER_SECONDS COMMAND...
~~~

| Label | Exact command | Wall s | Exit | Observation |
|---|---|---:|---:|---|
| `lint-before` | `make lint` | 0.618393 | 0 | 0 issues; before repository edits |
| `fast-uncached` | `make test_fast TEST_ARGS=-count=1` | 1.574754 | 0 | 16 + 36 pass; package 1.007 s |
| `fast-ordinary-1` | `make test_fast` | 1.523775 | 0 | 16 + 36 pass; cache populated |
| `fast-ordinary-2` | `make test_fast` | 0.164450 | 0 | 16 + 36 pass; `(cached)` |
| `fast-json` | Expanded child command from section 2, without `-count=1` | 0.165291 | 0 | Cached raw JSON for replay fixtures; exact argv in metadata |
| `verification` | `python3 -B /tmp/ic-round03c-20261117/verify_target.py` | 2.642901 | 0 | All selection checks and 24 controlled replays pass |
| `fast-uncached-final` | `make test_fast TEST_ARGS=-count=1` | 1.423327 | 0 | Final helper; 16 + 36 pass; package 1.035 s |
| `fast-ordinary-final-1` | `make test_fast` | 0.165716 | 0 | Final helper; `(cached)` |
| `fast-ordinary-final-2` | `make test_fast` | 0.165181 | 0 | Final helper; `(cached)` |
| `lint-after` | `make lint` | 0.415987 | 0 | 0 issues |

Lint captures have a 600 s outer limit; test and controlled-verification
captures have 660 s. All completed without outer timeout. The three final
target runs follow the small change making UTF-8 decoding strict. All six
positive target captures have empty stderr. Wall time includes the helper,
Go startup/build-cache work, test execution, output and capture polling; it
is not CPU time or an isolated protocol-operation measurement. Cache warmth,
external load and filesystem state were not controlled. These observations
meet the requested approximate everyday duration, not a performance guarantee.

## 5. Controlled failure evidence

`verify_target.py` creates temporary JSON replays and executes the unchanged
helper, including Makefile-level cases through a temporary `GO` executable.
The replay returns the stipulated Go status and a stderr diagnostic; those
values and exact commands are retained in each capture. It changes no Go
source, production test, committed file or launcher setting.

| Case / evidence label | Go status | Helper status | Command status | Result |
|---|---:|---:|---:|---|
| `missing-family` | 0 | 1 | Make 2 | Remove one family's events; reports its exact missing name. |
| `renamed-family` | 0 | 1 | 1 | Rename one family in the replay; unexpected and missing names detected. |
| `failed-family` | 1 | 1 | 1 | Selected-family failure remains failure. |
| `failed-child-zero-exit` | 0 | 1 | Make 2 | Failed descendant cannot be hidden by successful parent/package or process status. |
| `skipped-family`, `skipped-child` | 0 | 1 | 1 each | Every selected skip fails verification. |
| `exit-status-seven` | 7 | 7 | 7 | Even an otherwise passing stream cannot mask the child's status. |
| `make-exit-status-seven` | 7 | 7 | Make 2 | Make prints `Error 7`. |
| `unexpected-family` | 0 | 1 | 1 | A name with an expected-name prefix and extra suffix is rejected. |
| `malformed-json`, `invalid-utf8`, `non-object-json`, `duplicate-json-field`, `invalid-json-constant` | 0 | 1 | 1 each | Malformed streams rejected. |
| `truncated-final-line`, `missing-package-completion`, `empty-stream`, `unfinished-child`, `missing-child-run`, `duplicate-run` | 0 | 1 | 1 each | Incomplete or invalid lifecycles rejected. |
| `replay-positive`, `parallel-deep-descendant` | 0 | 0 | 0 each | Passing controls accepted, including PAUSE/CONT and an added deep slash-named descendant. |
| `real-no-match` | 0 | 1 | Make 2 | Real Go no-match output cannot produce target success. |
| `real-failed-test` | 1 | 1 | Make 2 | Real Go failure output and diagnostic preserved. |

The two real Go inputs were generated with:

~~~sh
go test -count=1 -json -timeout=10m ./internal/pw \
  -run '^TestRound03CMissingFamily$'
go test -count=1 -json \
  /tmp/ic-round03c-20261117/failure_fixture_test.go
~~~

`go-no-match` exits **0** in **0.365757 s**, with no test names executed.
`go-controlled-failure` exits **1** in **0.165467 s** from a temporary test's
`t.Fatal("controlled Go test failure diagnostic")`. Its standalone package
is also outside the expected package; the matching-package failure replays
separately exercise selected-test and descendant failure handling.

For example, the missing-family target command is exactly:

~~~sh
env IC_FAST_REPLAY=/tmp/ic-round03c-20261117/missing-family.jsonl \
  IC_FAST_STATUS=0 \
  make test_fast GO=/tmp/ic-round03c-20261117/replay-go.py
~~~

It exits 2 in **0.065183 s**, reporting
`missing families: TestKnownBeforeAnySignerUse` and Make `Error 1`.
The failed-descendant Make case exits 2 in **0.064349 s**.
Every replay's exact argv, timing and stdout/stderr are retained in its capture
and indexed by `negative-verification.json` / `commands.json`.
No negative case prints the helper's positive completion summary.

`make test_fast 'TEST_ARGS=-skip=.*'` also exits **2** in **0.032349 s**
before Go runs, with the allowed-arguments diagnostic
(`selection-override-refused`).

## 6. Final checks and limits

Final `make lint` passes with 0 issues. `git --no-optional-locks diff --check`
passes with no diagnostics (`diff-check` capture). The separate final audit
checks Python syntax without writing bytecode, whitespace in the untracked
helper/report, exact selected-name evidence, both repository identities,
unchanged offline settings, all original tracked-file hashes and the spec's
original diff. Only `Makefile` differs among previously tracked Go files;
the two additions are exactly the helper and this report. Existing Makefile
content, including full-regression and race targets, is preserved verbatim.

Final Go status:

~~~text
 M Makefile
?? docs/implementation/Refactoring_Round_03C_Fast_Test_Target.md
?? scripts/test_fast.py
~~~

No production Go code, tests, benchmarks, dependencies/module files, Flutter,
controller scripts, previous reports or TLA+ files were changed. No overlapping
user changes were observed. No commit or tag was created.

The complete suite was deliberately not rerun for this optional tooling change.
The accepted Round 03B **117.842967 s** full-suite result remains historical
baseline evidence, not validation of new production changes. Relevant race
suites, benchmarks, controller/Flutter checks, live integration acceptance,
manual UI checks and TLA+/SANY/TLC checks were not run in this round. No new
model result, implementation-refinement or formal-conformance claim is made.

Maintenance obligations and limitations:

- Python 3 is now required only for the optional target; no third-party package
  is needed. The helper buffers this bounded selection's stdout until Go exits;
  stderr remains live. Unexpected future Go JSON event forms fail closed and
  require review rather than being silently accepted.
- Renames or selection changes require review of the one helper list against
  the accepted coverage contract. New descendants remain eligible without
  editing that list; the verifier checks emitted descendants, not an independent
  permanent inventory of every possible dynamically generated child.
- Successful-result caching intentionally reuses prior successful events.
  Use `TEST_ARGS=-count=1` when fresh execution is required. The inherited
  environment remains Go's responsibility; measured settings are recorded above.
- Keep changed-area tests, complete regression, relevant race tests and
  integration acceptance. This tier omits the wider history/guard matrices,
  competing-operation schedules, real long deadlines, subprocess diagnostics,
  crash checks and broad HTTP/legacy coverage described in Round 03B. Existing
  V19 recovery/helper/device/strong-use scope gaps remain unchanged.

Round 03C stops at this optional target. Round 03D was not started.

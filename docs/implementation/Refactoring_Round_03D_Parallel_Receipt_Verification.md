# Refactoring round 03D: parallel v2 receipt verification tests

Measured 2026-11-17 with err2 **v1.4.2**. Parallel scheduling of
`TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2` reduced median
focused command wall time from **3.889236 s to 1.872412 s (51.86%)**.
Median package time fell from **3.538 s to 1.506 s (57.43%)**.
All 64 original leaves pass with identical names and outcomes. The isolation
audit found no blocker. Recommendation: **keep this bounded change**.

## Workspace and scope

Writable Go workspace: `/home/parallels/go/src/github.com/lainio/ic`.
Read-only `SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.

| Repository | Initial and final HEAD | Branch | Initial dirty state |
|---|---|---|---|
| Go | `79a7e1e18ef194a199755ffb2840c461d867d386` | `tla-spec-based-refactoring-v1` | Clean; matches the accepted baseline |
| Spec | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | `break-demo` | Modified `models/active/IntroTreeV19.tla` |

Read the live root `AGENTS.md`, implementation reality document, Round 03A,
03B and 03C reports, model index and all three required semantic contracts.
No additional instructions exist under `internal/pw` or `docs`. Storage/core
instructions and the spec root instructions were also inspected while tracing
the fixtures. The spec's existing safe-restore mutation restores snapshot
recovery grants, contrary to the unchanged V19 contract. It remains preserved
owner state, not the semantic baseline for this task.

The only source change is in `internal/pw/message_receipt_v2_test.go`:
one parent `t.Parallel()` and one leaf-callback `t.Parallel()` that applies to
each of the 64 leaves. The latter immediately precedes the original
`defer assert.PushTester(t)()`. There is no parent tester registration,
initialization gate, fixture sharing or assertion change. `gofmt` was applied
only to that file. This report is the only other repository change.

All prior reports, production code, dependencies, Makefile, scripts, benchmarks,
CI, controllers, Flutter and spec files are preserved. No overlapping owner
edit was observed. No commit, tag, destructive Git operation, exec-metrics,
nested Codex invocation or agent delegation was performed. Workspace-write,
approval never and non-login shells remained in effect.

## Isolation audit

The complete fixture chain is:

~~~text
receiptTestV2 -> incomingTestV2 -> newOutgoingV2 -> newFirstUseV2
  -> newRequester -> newEstablishment -> ready
~~~

Source locations below are relative to `internal/pw` unless qualified.

| Boundary | Inspected ownership and preserved checks |
|---|---|
| Matrix and captures | The parent owns only loops. Receivers 0/Bob and 1/Alice each exercise eight guards at four points: before the call, first usability probe, receipt signing, final usability probe. Guards remain `deny`, `delete`, `own Known`, `peer Known`, `authorization`, `history`, `first use`, `signer`. Go module language version 1.24 gives each range iteration its own variables. Names and dimensions are unchanged. |
| Vaults and database paths | `fixtures_test.go:30` allocates a fresh Database and encrypted bbolt Vault at the leaf's `t.TempDir()/vault.db`. `ready` creates Bob's and `newRequester` creates Alice's. Equal numeric Vault/Key IDs are confined to different files. No sibling can write either file observed by a leaf. |
| Signing identities | `fixtures_test.go:105` creates three separate identity/unlock file pairs with fresh random wrapping secrets. `internal/nodeidentity/identity.go:35` and `:60` construct independent enclave backends. Neither `key.Enclave` nor the enclave package's default `Store` supplies these handles. The installed enclave implementation signs synchronously using its handle's private key. |
| Probe callbacks and counters | Each leaf creates its own `probeSigner`. `fixtures_test.go:139` increments its atomic counter and invokes `s.sign(data)` directly. The closure's `signErr`, snapshots and selected guard belong only to that leaf. No worker is launched and no callback is retained for later execution. Non-atomic callback fields need no cross-leaf synchronization because they are never shared. |
| Encryption and mutable state | Every Vault owns a random secret and a separate atomic allowance initialized to 128. Reopen retains only that Vault's lease. Protocol state, identities, runtime values, signed buffers and mutation snapshots are allocated within the leaf. The package's fixed `invitationNow` is only read; clocks capture the individual fixture. Service origins are signed data, not listeners. |
| Protocol construction | Each fixture creates introduction evidence, explicitly verifies Known and bootstraps local devices. The existing unit-fixture verified-ad seeding in `requester_test.go:54` is unchanged. `responseV2` saves a fresh attempt and commits Bob before returning his reply; `receiveV2` separately commits Alice. `newOutgoingV2` performs the fresh first-use exchange before sender creation and receiver admission. No cross-fixture or cross-Vault transaction is introduced. |
| Callback ordering | `IssueMessageReceiptV2` calls `device.InspectLocal`, receipt signing and the final probe synchronously, outside its Vault View transactions. `localSigner.Sign` directly forwards to the leaf's handle. `mutateEnvelopeGuard` changes only `n.own.vault`; successful callback updates retain the existing check that signing is outside transactions. `storage/tx.go:25` and `:42`, the bbolt adapter and bbolt's View/Update execute callbacks on the caller's goroutine. |
| Physical and logical refusal checks | `refuseMessageReceiptV2` retains the exact `errMessageReceipt` and nil-result assertions, both nodes' file/allowance checks, and the receiver's logical-state comparison. During-signing cases snapshot after the deliberate mutation and reject any further receiver write; the other Vault remains byte-for-byte unchanged. `outgoingTestState` and `heldTestState` still inspect root records and their existing namespaces. |
| Historical verification | Every leaf first issues a valid receipt and saves its inbox history. After guard invalidation it checks refusal and unchanged inbox, closes/reopens its own database, checks refusal again, mathematically verifies the old receipt against the original envelope and independent sender binding, then checks refusal once more. Successful historical verification still cannot restore permission. |
| Cleanup | Resources are registered on the allocating leaf's `t.Cleanup`. Reopen captures its replacement Database separately; repeated original closure is idempotent. Database closure precedes the relevant secret clearing and temporary-directory removal. All fixture work completes synchronously before leaf cleanup; no sibling shares its secret, handle or database path. |

Shared infrastructure was inspected separately. CBOR v2.9.0 encoding/decoding
modes use immutable options and synchronized type caches; the wire modes are
initialized before tests and not reassigned by either parallel family.
`crypto/rand.Reader` supports concurrent use. Logging configuration is not
changed by these paths, and no assertion depends on diagnostic ordering.
Error sentinels are read-only. The selected path performs no environment or
working-directory changes, descriptor replacement, listener creation or
subprocess launch.

err2 v1.4.2's `assert/assert.go:179` registers testers by goroutine in a
synchronized map and its returned function restores the previous registration
in LIFO order. The default asserter uses atomic loads/swaps (`:1055`, `:1073`).
Every leaf registers after `t.Parallel()` resumes. Nested fixture helpers keep
their existing deferred restorers; named error-returning callbacks keep their
own `err2.Handle`, and scoped production `assert.Plain` remains intact.
No tester registration is inherited from the parent or a sibling. Round 03A's
v1.4.1 initialization workaround is obsolete; current history-family source
contains no such gate, and none was added here.

Existing fixture cleanup assertions run after deferred tester restoration.
That pre-existing lifecycle is unchanged; cleanup failures were not
fault-injected. The correction in err2 does not extend a function's tester
registration into later cleanup. It does prevent synchronous nested helper
returns from dropping the leaf's active registration.

Go's installed `testing.T.Parallel` implementation explicitly pauses until
non-parallel tests finish (`/usr/local/go/src/testing/testing.go:1912`). Its
parent barrier is released after serial test completion, including cleanup.
The selected parent pauses before creating fixtures or children. Therefore
serial proxy-environment tests using `t.Setenv` complete and restore their
environment before this family runs. The serial diagnostic tests in
`guards_test.go`, `invitation_storage_test.go`, `acceptance_guards_test.go`
and `remote_test.go` likewise restore their tracer writers before release.
Atomic tracer references alone would not make their temporary `bytes.Buffer`
writers safe; the scheduling boundary is necessary and preserved.

The only other parallel family is `TestMessageProjectionRequiredHistoryV2`.
Its 112 leaves independently enter the same fixture chain through `ackTestV2`
and share none of the mutable fixtures above. Both families can contend for
CPU, random generation, filesystem resources and synchronized caches; their
correctness observations do not share mutable protocol state. The combined
race run exercised both families in one process. Its first history leaf
continued at 13:33:41.223548928 +02:00, before the final receipt leaf's PASS at
13:33:41.337487761 +02:00. These overlapping event intervals show scheduling
overlap, not an exact count of concurrently executing goroutines.

## Measurements and raw evidence

Evidence root **E = `/tmp/ic-round03d-20261117`**. Existing `capture.py` from
Round 03C and `summarize.py` from Round 03B were copied unchanged. Capture
metadata `E/LABEL.json` records exact argv, shell rendering, cwd, inherited
settings, monotonic command wall time, aggregate child user/system CPU,
exit status and timeout status. `E/LABEL.stdout` and `.stderr` retain raw
output. JSON test streams are complete and unfiltered.

`analyze.py` strictly parses those streams, checks unique matching RUN and
completion events, verifies the exact 64 receipt names from the original
matrix and checks PAUSE/CONT pairs. `measurements.json` retains every named
completion, timing, failure/skip list and the unrounded comparison. The
nonverbose full-package commands do not enumerate subtests or skips; their
counts are recorded as unavailable, not inferred from earlier inventories.

Machine: Go `go1.27.1 linux/arm64`, Linux `6.8.0-147-generic`, CPU affinity
0–4. Module Go version 1.24.0; err2 v1.4.2 without replacement. Inherited
`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GOSUMDB=off`
were preserved, with `CGO_ENABLED=1` and no `GOMAXPROCS`, `GODEBUG` or `GORACE`
override. Existing build/module caches were neither cleared nor relocated.
Every test/lint command ran sequentially, without overlap with another
test/lint command. No benchmark or cached test result enters the comparison.

Capture syntax from the Go root:

~~~sh
python3 /tmp/ic-round03d-20261117/capture.py LABEL OUTER_SECONDS COMMAND...
~~~

Exact commands and labels:

~~~sh
# lint-before and lint-after; outer limit 600 s
make lint

# focused-before-1/-2/-3 and focused-after-1/-2/-3; outer limit 660 s
go test -count=1 -json -timeout=10m -parallel=4 \
  ./internal/pw \
  -run '^TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2$'

# pw-before and pw-after; outer limit 900 s
go test -count=1 -timeout=10m ./internal/pw

# focused-race; outer limit 660 s
go test -race -count=1 -json -timeout=10m -parallel=4 \
  ./internal/pw \
  -run '^TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2$'

# combined-race; outer limit 660 s
go test -race -count=1 -json -timeout=10m -parallel=4 \
  ./internal/pw \
  -run '^(TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2|TestMessageProjectionRequiredHistoryV2)$'
~~~

The same ten-minute Go timeout and command-specific outer limits applied
before and after. Full-package commands retain the default parallel limit;
focused and combined commands use four. No machine settings changed.

| Focused sample | Command wall s | Package s | Parent elapsed s | Receipt tree span s |
|---|---:|---:|---:|---:|
| `focused-before-1` | 4.140773 | 3.560 | 3.55 | 3.553891 |
| `focused-before-2` | 3.889236 | 3.537 | 3.53 | 3.531603 |
| `focused-before-3` | 3.882423 | 3.538 | 3.53 | 3.532890 |
| `focused-after-1` | 4.293919 | 1.506 | 0.00 | 1.500005 |
| `focused-after-2` | 1.872412 | 1.517 | 0.00 | 1.511668 |
| `focused-after-3` | 1.871711 | 1.497 | 0.00 | 1.491017 |

| Measure | Before median | Before min–max | After median | After min–max | Median reduction |
|---|---:|---:|---:|---:|---:|
| Command wall s | 3.889236 | 3.882423–4.140773 | 1.872412 | 1.871711–4.293919 | 51.86% |
| Package s | 3.538 | 3.537–3.560 | 1.506 | 1.497–1.517 | 57.43% |
| Receipt tree span s | 3.532890 | 3.531603–3.553891 | 1.500005 | 1.491017–1.511668 | 57.54% |

Every focused sample passes 64 leaves plus the parent, with zero failures,
skips or timeouts. All after samples contain 65 PAUSE/CONT pairs. Parent
elapsed time excludes waiting for parallel children, so 0.00 s is not the
family's execution cost. Tree span uses parent RUN-to-PASS before and
CONT-to-PASS after, including all children; timestamps are rounded to
microseconds. Child durations are never summed to estimate wall time.

The first after command is slower overall than every baseline command and
is retained in all statistics. Its wall-minus-package gap is 2.787919 s;
the source edit requires rebuilding the test binary, but this capture does
not isolate compilation from other driver/startup work. The package-time
ranges are separated; command-wall ranges overlap. No warmup was discarded
and no additional timing samples were selected to improve the result.

Median aggregate child user CPU increased from 3.022659 s to 3.729735 s;
system CPU increased from 0.527026 s to 0.916095 s. These include Go-driver
work and do not identify individual fixture, assertion, crypto or I/O costs.
Lower wall time does not imply lower CPU usage.

## Validation and preservation

| Check / evidence label | Command wall s | Package s | Result |
|---|---:|---:|---|
| `lint-before` | 0.516852 | — | Exit 0; 0 issues |
| `pw-before` | 112.223310 | 111.861 | Complete uncached PW pass |
| Six focused ordinary samples | Above | Above | Exact original 64 leaves + parent pass |
| `focused-race` | 11.417067 | 5.933 | 64 leaves + parent pass; no race reported |
| `combined-race` | 15.224305 | 14.830 | 176 leaves + two parents pass; no race reported |
| `lint-after` | 14.568770 | — | Exit 0; 0 issues |
| `pw-after` | 110.332167 | 109.969 | Complete uncached PW pass |

All test commands exit 0 without Go or outer timeout. JSON runs have zero
failures and skips; the combined run has 64 receipt and 112 history leaves
with 178 PAUSE/CONT pairs. Full-package nonverbose output reports success
and duration without a fresh per-test/skip inventory. Test stderr is empty.
After lint emits 32 warnings about persisting facts to the existing read-only
golangci-lint cache; it still reports 0 issues. No cache workaround, lint
suppression or permission change was used.

The final preservation audit passed: 551 original Go tracked files and 313
spec tracked files were checked. Only the permitted Go test differs; every
spec file and every other original Go file matches its initial fingerprint.

`check_final.py` verifies the source equals the original snapshot plus exactly
the two scheduling additions, including every original assertion, err2 idiom,
subtest name and other test in the file. It also checks gofmt, tracked diff
whitespace, new-report whitespace, original tracked-file hashes in both
repositories, unchanged Git identities/staged state, the spec's exact original
diff/status, dependency resolution and environment settings. Raw snapshots,
hashes and results are retained in `git-{before,after}.json`,
`spec-{before,after}.json`, `*-before-hashes.json`, `environment*.json`,
`message_receipt_v2_test.go.original` and `preservation.json`.
`commands.json` indexes captured commands and `evidence-sha256.json` records
artifact fingerprints. Temporary evidence is not durable archival storage.
The external exec-metrics evidence path was not supplied; the owner runs that
tool separately.

Final Go dirty state:

~~~text
 M internal/pw/message_receipt_v2_test.go
?? docs/implementation/Refactoring_Round_03D_Parallel_Receipt_Verification.md
~~~

The spec retains only its pre-existing V19 modification, byte-for-byte.

## Decision and limits

Keep the scheduling change: isolated fixture ownership, unchanged checks,
identical focused outcomes, standalone/combined race passes and lower median
focused wall/package times support it. The complete-package observations are
single samples on each side, not a reliable estimate of suite-wide savings.
External load, cache warmth and filesystem state were uncontrolled. Parallel
execution raises instantaneous resource demand, and race checks cover only
the exercised schedules.

V19 remains the general state-semantics baseline, with the accepted invitation
extension governing independent local establishment and separate first use.
Historical receipts still grant no current authority. Scheduling changes no
modeled transition and resolves none of the existing full-V19 recovery,
device/helper, peer-view/strong-use or full Delete cleanup gaps. The semantic
documents' older unimplemented contact status lags the current Go v2 code;
this experiment makes no composition, refinement or cryptographic proof claim.

The complete PW package was validated. The complete repository suite, complete
PW race suite, benchmarks, live integration/manual acceptance and TLA+ tools
were not run. No broader parallelism or fixture redesign is proposed in this
round. The final test-performance experiment ends here; package-architecture
review is the next planned work.

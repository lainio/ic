# Refactoring round 01: baseline and inventory

Measured 2026-11-12 on the current checkout. This round adds three
microbenchmarks and records test costs and production responsibilities;
it changes no production behavior.

## Baseline and provenance

Implementation workspace: `/home/parallels/go/src/github.com/lainio/ic`.
Read-only `SPEC_REPO`: `/home/parallels/go/src/github.com/optechlab/intro-tree`.
Both live root `AGENTS.md` files, `storage/AGENTS.md`,
`internal/core/AGENTS.md`, `Current_Go_Implementation_Reality.md`, the model
index, all three required contracts and `IntroTreePWInvitationV1.md` were read.
No further nested instructions were found in the inspected trees.

| Repository | Branch | Initial HEAD | Initial dirty state |
|---|---|---|---|
| Go | `tla-spec-based-refactoring-v1` | `4f6ba93835bb2711a6185712282f43aaa55d0c04` | Clean |
| Spec | `break-demo` | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` | Modified `models/active/IntroTreeV19.tla` |

Recorded Go `4922c22` resolves to
`4922c2252646d5489d62c83bfd8a1b5485040c13`. The subsequent reachable commits
are `78086dd61c08cec7af821cf707592ff2c9774881` (`codex refactoring`, a sibling
branch's `internal/pw/invitation.go` edits) and the current merge
`4f6ba93835bb2711a6185712282f43aaa55d0c04`. The merge tree is **identical** to
the recorded Go tree: `git --no-optional-locks diff --stat 4922c22..HEAD`
and its full-SHA `--numstat` equivalent are empty. No checkout was needed.

Spec history after recorded
`3bd9738ef8fd4885c42e1402467a878943e2bd50` adds only
`scripts/my-break.sh` (16 lines). Between reviewed invitation/contact commit
`1ac5e9998f28e5846c20d154b1195146f7fdbc3f` and that recorded HEAD are
`3dafdf0d951fb1188b733422ab25c52007fef32e` (prompt) and
`3bd9738ef8fd4885c42e1402467a878943e2bd50` (contract alignment).
The invitation and message model files have no diff from the reviewed commit
to current HEAD. The uncommitted V19 edit changes
`RestoreSafeRecoverySnapshot` to union `SnapshotRecoveryGrant[x]` back into
`RecoveryGrant[x]`, contrary to the safe-restore contract. It was preserved;
this inventory references the committed V19 contract, not that local mutation.

The older reality document and spec's “PW-Contact-Go-01 unimplemented” status
lag live code. V2 signed contacts, owner/peer HTTP adapters, separate local
acceptance, first use, message admission, receipts and ACK observation exist.
For example, `internal/ownerapi/establishment.go:93` calls `BobAcceptV2`,
and `internal/pw/message_ack_v2.go:31` records historical ACKs without restoring
current permission. V19 remains the lifecycle/trust reference; invitation
establishment follows `IntroTreePWInvitationV1`. The separate message candidate
supplies no composed refinement or implementation proof.

The task prompt is saved verbatim as UTF-8 text with a final newline at
`/tmp/ic-round01-20261112/task-prompt.md`; SHA-256:
`59f424fd7c74fa8dc0cef82ffe374b9096a3cbc0c7d95a3f5ef4f54895bc6801`.
External exec-metrics run path: **user to append after launcher exits**.

## Environment and test scope

Go `go1.27.1 linux/arm64`; module requires Go `1.24.0`, no `toolchain`
directive. Effective `github.com/lainio/err2` is `v1.4.0`, with no replacement
(`go list -m -json github.com/lainio/err2`). Linux
`6.8.0-147-generic`, aarch64, five visible CPUs with affinity 0–4.
Inherited settings were preserved: `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GOSUMDB=off`;
`CGO_ENABLED=1`, no workspace module, no custom tags or `GOMAXPROCS` override.
Effective build cache: `/home/parallels/.cache/go-build`; module cache:
`/home/parallels/go/pkg/mod`. No cache clearing, fresh cache, dependency
downloads, toolchain changes or Git writes were performed. Shells used
`login=false`. Final lint's cache writes were denied by the read-only
`/home/parallels/.cache/golangci-lint` mount; lint itself completed successfully.
No workaround, cache relocation or retry was attempted.

`make test`/`testj` use `-benchmem` and the package union `chain`, `node`,
`identity`, `hop`, `key`, `internal/core/...`, `storage/...`, `internal/...`.
`make testr` adds `-mod=readonly -race -count 1`; focused race targets are
`test6r`, `test7r`, `test8r`. `make check` is lint + test + CLI build;
`make lint` invokes `golangci-lint run`. No tracked CI workflow or separate
CI Go test command was found (`.github` and `.gitlab-ci.yml` are absent).

The complete default Go scope selected here is `./...`: a superset of the
Makefile union that includes the accepted demo's `cmds/node`, `cmds/intro`,
`cmd/vault-playground`, and legacy `digest`, `enclave`, `pw`. No test ordering,
package concurrency, assertions, skips or parallelism were changed.
`-count=1` disables result reuse, not the build cache. Explicit `-timeout=10m`
preserves Go's default package timeout; outer capture limits are also recorded.
The first sample used the existing cache of unknown prior warmth, touched by
baseline lint; the second is a warm repeat. Neither is a cold-machine measure.

Separate opt-ins: `cmds/intro` has `-intro-demo-http-tcp` for
`TestHTTPDemoTCP` and `TestOwnerStatusDemoTCP`, and
`-intro-demo-nats-url=<existing-loopback-broker>` for `TestExchangeDemoNATS`.
No broker address was supplied, so the NATS check is unavailable here.
`scripts/README.md:330` documents Python socket-free controller tests and
`:338`/`:348` the `PW_DEMO_LIVE=1` and `PW_DEMO_CHAT_LIVE=1` smoke checks;
those are outside this Go measurement scope and were not run. Flutter and
manual two-window acceptance were not run.

## Measurements

Evidence root `E = /tmp/ic-round01-20261112`. Every measured command ran
sequentially from the implementation root using
`python3 /tmp/ic-round01-20261112/capture.py LABEL OUTER_SECONDS COMMAND...`.
`E/LABEL.json` retains exact argv, cwd, environment, exit, timeout, monotonic
wall duration and aggregate child CPU time; `E/LABEL.stdout` and `.stderr`
retain raw output. Test stdout is JSON where `-json` is present.
`E/summarize.py` preserves pass/fail/skip events and writes `.summary.json`;
parent/subtest elapsed values are never summed for wall attribution.
The temporary scripts use only Python's standard library and propagate failures.

Both ordinary samples pass 23 packages; 11 packages report no test files.
Each has 8,769 named completion events including parent tests and subtests;
these are not independent test counts. The eight existing named skips are
`chain/TestNewVerifyBlock/nil_pincode`,
`key/TestNewPublicCBOR/success`,
`cmds/intro/{TestExchangeDemoNATS,TestHTTPDemoTCP,TestOwnerStatusDemoTCP}`,
`internal/nodeidentity/{TestProcessCreate,TestProcessOpen}` and
`internal/nodevault/TestStoreProcess`. The latter three are subprocess entry
points; their parent tests execute the child paths with fixture environment.
No skips were added. Missing conventional CI paths were inspection results,
not sandbox rejections or failed test measurements.

| Label / raw evidence prefix under E | Wall seconds | Exit | Outer limit seconds | Result |
|---|---:|---:|---:|---|
| `lint-before` | 0.467 | 0 | 600 | 0 issues, before edits |
| `suite-1` | 319.069 | 0 | 900 | Complete ordinary scope |
| `suite-2` | 343.542 | 0 | 900 | Complete warm repeat |
| `suite-race` | 617.749 | 1 | 1200 | PW package timeout; incomplete race coverage |
| `compile-pw` | 0.722 | 0 | 180 | Warm compile/link only, no execution |
| `compile-pw-race` | 0.724 | 0 | 180 | Warm race compile/link only, no execution |
| `startup-pw` | 0.008 | 0 | 30 | Existing binary, no selected tests |
| `startup-pw-race` | 1.033 | 0 | 30 | Existing race binary, no selected tests |
| `profile-pw` | 20.671 | 0 | 180 | One selected test, CPU profiling enabled |
| `focused-owner` | 15.469 | 0 | 90 | Three deadline/cancellation samples |
| `affected-focused` | 0.724 | 0 | 180 | Focused fixture/evidence tests after additions |
| `affected-tests` | 6.484 | 0 | 180 | Full affected core/storage packages |
| `benchmarks` | 3.090 | 0 | 120 | Three 250 ms samples per benchmark |
| `tcp-1` / `tcp-2` | 0.570 / 0.416 | 0 / 0 | 60 each | Supplemental opt-in TCP, two ordinary samples |
| `tcp-race` | 1.589 | 0 | 60 | Same TCP scope with race |
| `lint-after` | 2.428 | 0 | 600 | 0 issues; cache-persistence warnings |

Commands below are the exact child commands passed to the capture script.
The table supplies their labels and outer timeouts; metadata retains the full
expanded argv without abbreviations. The three TCP samples were collected
after the default-scope baseline, separately from its wall times. They do not
include an external broker or the Python/controller/Flutter checks.

~~~sh
# lint-before, lint-after
make lint
# suite-1, suite-2
go test -benchmem -count=1 -json -timeout=10m ./...
# suite-race
go test -benchmem -count=1 -json -timeout=10m -race ./...
# compile-pw
go test -c -x -o /tmp/ic-round01-20261112/pw.test ./internal/pw
# compile-pw-race
go test -c -race -x -o /tmp/ic-round01-20261112/pw-race.test ./internal/pw
# startup-pw
/tmp/ic-round01-20261112/pw.test -test.run '^$' -test.timeout=10m
# startup-pw-race
/tmp/ic-round01-20261112/pw-race.test -test.run '^$' -test.timeout=10m
# profile-pw
go tool test2json -t -p github.com/lainio/ic/internal/pw /tmp/ic-round01-20261112/pw.test -test.v -test.count=1 -test.timeout=10m -test.run '^TestMessageProjectionRequiredHistoryV2$' -test.cpuprofile=/tmp/ic-round01-20261112/pw.cpu
# focused-owner
go test -benchmem -count=3 -json -timeout=10m ./internal/ownerapi -run '^TestAdFetchCancellationAndFiveSecondDeadline$'
# affected-focused
go test -benchmem -count=1 -json -timeout=10m ./internal/core/intro ./storage -run '^(TestSignedRepresentationRoundTrip|TestSignedBodyCoverage|TestVaultConsumer)$'
# affected-tests
go test -benchmem -count=1 -json -timeout=10m ./internal/core/intro ./storage/...
# benchmarks
go test -run '^$' -bench '^(BenchmarkEdgeCanonicalEncoding|BenchmarkEdgeVerifySignature|BenchmarkVaultRead1KiB)$' -benchmem -benchtime=250ms -count=3 -timeout=10m ./internal/core/intro ./storage
# tcp-1, tcp-2
go test -benchmem -count=1 -json -timeout=10m ./cmds/intro -run '^(TestHTTPDemoTCP|TestOwnerStatusDemoTCP)$' -args -intro-demo-http-tcp
# tcp-race
go test -benchmem -count=1 -json -timeout=10m -race ./cmds/intro -run '^(TestHTTPDemoTCP|TestOwnerStatusDemoTCP)$' -args -intro-demo-http-tcp
~~~

CPU postprocessing commands are retained as `pprof-cumulative`, `pprof-flat`
and `pprof-all` (60 s outer limit each; exit 0; 2.496 / 0.166 / 0.115 s):

~~~sh
go tool pprof -top -cum -nodecount=35 /tmp/ic-round01-20261112/pw.test /tmp/ic-round01-20261112/pw.cpu
go tool pprof -top -nodecount=20 /tmp/ic-round01-20261112/pw.test /tmp/ic-round01-20261112/pw.cpu
go tool pprof -top -cum -nodecount=0 -nodefraction=0 /tmp/ic-round01-20261112/pw.test /tmp/ic-round01-20261112/pw.cpu
~~~

Slowest packages, elapsed seconds from Go JSON (concurrent package spans):

| Package | Ordinary 1 | Ordinary 2 | Race |
|---|---:|---:|---:|
| `internal/pw` | 316.054 | 340.349 | 600.023, timeout |
| `internal/ownerapi` | 22.463 | 23.124 | 68.947 |
| `cmds/node` | 12.489 | 12.374 | 30.813 |
| `internal/ads` | 11.983 | 12.080 | 17.134 |
| `storage` | 6.762 | 6.655 | 8.952 |
| `internal/nodevault` | 1.850 | 1.860 | 6.209 |

Slowest ordinary parent tests, plus a diagnostic race outlier. Names without
a package prefix are in `internal/pw`. Each includes its nested subtests;
do not add these numbers to package durations or to their child durations.

| Test | Ordinary 1 | Ordinary 2 | Race |
|---|---:|---:|---:|
| `TestMessageProjectionRequiredHistoryV2` | 19.54 | 21.66 | 37.80 |
| `TestMessageACKExactHistoricalEvidence` | 13.17 | 13.79 | 28.52 |
| `TestMessageReceiptCurrentGuardsAndHistoricalVerification` | 11.64 | 12.69 | 22.14 |
| `TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2` | 11.25 | 12.45 | 21.52 |
| `TestMessageReceiptRetainedHistoryAndFinalInbox` | 10.80 | 11.76 | 20.38 |
| `TestIncomingCorruptLocalHistory` | 8.96 | 10.57 | 18.27 |
| `internal/ownerapi/TestPWDiagnosticStages` | 3.20 | 3.36 | 34.91 |

The race command passed the other 22 tested packages and reported the same
eight named skips, then hit the **package-wide** ten-minute limit while
`TestRequesterV2RejectsOwnConfiguration/http://[::1%lo]:4040` was active.
That active subtest is not evidence of a ten-minute individual hang.
The retained output has no `WARNING: DATA RACE`, but this is **not a complete
race pass**. The outer wrapper did not time out (`timed_out=false`); Go's own
package timeout caused exit 1. The failing scope was not rerun or extended.

Supported cost attribution and limits:

- **Build/link/vet:** full commands include the Go driver, default vet and
  any necessary build/link work. The later `-c -x` logs show cached dependencies,
  generated test-main compilation and linking (race-instrumented in the second
  binary), with no test execution or vet subprocess in those compile-only
  logs. Their roughly 0.72 s is warm artifact preparation, not a cold-build or
  isolated compiler benchmark. Full-suite initial race compilation and vet
  were not separately timed. No compilation estimate subtracts overlapping
  package/test elapsed values from wall time.
- **Initialization/TestMain:** direct no-test binaries measured process startup,
  package initialization and exit, 0.008 s ordinary versus 1.033 s race.
  `internal/pw` has no TestMain. Other packages do: `chain`, `node`, `enclave`
  and `internal/core/intro`; the latter generates fixture keys before `m.Run`.
  Benchmark `-run '^$'` still runs that initialization/TestMain, outside reported
  per-operation timers. No no-test command is labeled pure compilation.
- **Fixture and execution CPU:** the one profiled PW test took 20.31 s by
  test output, with 19.00 s sampled CPU. Its 112 subtests each call `ackTestV2`
  (`message_projection_history_v2_test.go:74`). That fixture chain accounts for
  15.29 s / 80.47% cumulative CPU; `newRequester` 1.88 s, `newVault` 0.21 s,
  `newSigner` 0.18 s and key generation 0.01 s. Thus repeated full protocol
  setup is supported as a hotspot; raw key creation alone is not supported as
  its dominant cause. These are nested CPU samples, not disjoint wall phases.
  Fixture cleanup is included in test wall time but has no isolated wall timer.
- **Repeated validation:** `assert.PushAsserter` accounts for 12.23 s
  cumulative CPU, with `assert.goid`/`runtime.Stack` on that path; ECDSA
  `VerifyASN1` accounts for 3.32 s, `listKnownIntroductions` 8.52 s, and
  bbolt `fdatasync` 0.24 s. These overlap the fixture and transaction stacks;
  they cannot be summed. This records accepted err2 v1.4.0 usage, not a proposal
  to rewrite the style or remove assertions. It motivates understanding how
  often complete guarded setup is repeated. CPU profiles do not measure time
  blocked on storage, nor justify production caching of authority checks.
- **Deliberate waits:** the focused owner test passed three times at 5.02 s
  each (deadline child 5.01 s, cancellation child 0.01 s). Command child CPU
  was only 0.637 s across 15.469 s wall. Source
  `internal/ownerapi/ad_fetch_http_test.go:218` intentionally leaves the HTTP
  response open until cancellation/deadline, and checks at least four seconds.
  Similar five-second parent tests appear in ads, storage and PW baseline
  output. They cover different layer boundaries; their removal as “duplicates”
  is not justified by similar duration. No sleep/deadline was shortened.
- **Subprocess/race effects:** diagnostics and reopen tests launch existing
  test binaries; `cmds/node/diagnostics_test.go:25` additionally runs a real
  `go build` inside its test. These costs are inside test elapsed time.
  `internal/ownerapi/diagnostics_test.go` runs multiple diagnostic subprocesses;
  its 3.20/3.36 s ordinary versus 34.91 s race is consistent with repeated
  instrumented process costs, but was not isolated further. No race settings
  were changed. Full PW race duration remains censored by timeout; no full
  suite race multiplier or completed total is inferred.

The ordinary wall samples differ by 7.7%; retain both, without a statistical
claim from two observations. External machine load and cold filesystem effects
were not controlled. Focused investigation was limited to PW and ownerapi;
no source timing instrumentation or additional full-suite rerun was added.

## Benchmark definitions

Existing `key/crypto_test.go:49` benchmarks public-key text decoding together
with key creation and public-key extraction. It does not isolate the three
operations added here. Each new benchmark checks its fixture before timing
and checks the result of every iteration. Setup and cleanup are excluded;
the timer includes lightweight result checks and the production operation.

| Benchmark / source | One timed operation | Excluded setup and validity |
|---|---|---|
| `BenchmarkEdgeCanonicalEncoding`, `internal/core/intro/evidence_benchmark_test.go:17` | Encode one signed edge to deterministic CBOR and compare all result bytes. | Two keys, introduction/signing, rooted proof and canonical round trip. |
| `BenchmarkEdgeVerifySignature`, same file `:42` | `Edge.VerifySignature`: unsigned-edge encoding, public-key decoding, hashing and P-256 verification; require true each time. | Two keys and signing; positive rooted proof and tampered-body negative check. No Known promotion. |
| `BenchmarkVaultRead1KiB`, `storage/vault_benchmark_test.go:19` | A new View transaction, child lookup, Get authentication/decryption of 1,024 bytes and complete content check. | Fresh bbolt file, random secret, existing `consumerProvider`, manifest/Vault and one initial write; close/clear after timer stops. Check no encryption-budget spending. |

Three bounded samples (`-benchtime=250ms -count=3`, ordinary build):

| Benchmark | ns/op, samples 1 / 2 / 3 | B/op, all samples | allocs/op, all samples |
|---|---|---:|---:|
| Edge canonical encoding | 584.6 / 583.3 / 607.6 | 448 | 2 |
| Edge signature verification | 61,969 / 61,810 / 62,762 | 1,408 | 20 |
| Vault read 1 KiB | 133,637 / 130,266 / 130,895 | 12,432 | 196 |

Iteration counts are retained in `E/benchmarks.stdout`; package command
durations there are 1.793 s core and 0.977 s storage. These microbenchmarks
cover representative primitives underlying measured fixture/validation paths,
not full v2 establishment or network latency. Vault reads use a warm open
file/page cache but perform a new transaction and decryption each iteration;
they never turn into a mutation's exact-retry or cached application result.
Encoding and verification likewise invoke the production API every iteration.
Setup is once per calibrated benchmark invocation, so no fixed iteration
budget was needed. The suite's general TestMain cost is not an ns/op cost.

## Production inventory

Paths below are relative to this repository. Dependencies list direct imports
within this module, not transitive dependencies; `internal/` is abbreviated
`i/`, and `storage/internal/` is `s/i/`. Counts and complete import lists are
retained in `E/inventory.json` (production Go files only). Recommendations are
scoped to the accepted demonstration, not approval to change packages.

| Package / evidence | Responsibility and direct internal dependencies | State owner / model trace | Recommendation and uncertainty |
|---|---|---|---|
| `cmd/tdc/tdc.go`, `cmds` | Entry point and common flags. Entry imports `cmds` plus `cmds/{domain,id,intro,node,pw}`; `cmds` imports `key,utils`. | Process lifecycle; no modeled durable action. | **Keep** demo wiring; **Defer** legacy command retirement. One binary includes both generations. |
| `cmds/node/{node,state,serve}.go` | Identity/state CLI, listener setup and shutdown. `cmds,i/{localhttp,nodeidentity,nodevault,ownerapi,peerapi},key`. | Opens one node's signer/Store, joins servers before close; service composition, not cross-node transaction. | **Keep** ownership; **Split** is a later review option for configuration versus serving, not a length-based defect. |
| `i/ownerapi` (24 files) | Owner auth/routes, capabilities, signer/configuration coordination. `i/{ads,core/intro,core/wire,device,localhttp,onboarding,policy,pw},key,storage`. | `device.go:19` service mutation mutex serializes local preflight/sign/commit; delegates modeled actions. | **Split** candidate at HTTP/capability composition boundary; retain shared mutation ordering. |
| `i/peerapi` (11 files) | Bounded peer HTTP decoding, challenge ledgers, proof/establish/use/message adapters. `i/{ads,core/wire,onboarding,policy,pw},key,storage`. | Ephemeral challenges; narrow owner capabilities perform durable writes. Receive bytes is not admission. | **Keep** peer/owner separation; **Defer** v1 challenge retirement. |
| `i/pw` (44 files, 6,468 lines) | V1/v2 canonical evidence, invitation, independent establishment, contacts, first use, messages, HTTP clients. `i/{ads,core/wire,device,localhttp,onboarding,policy},key,storage`. | TX-B consumes invitation + acceptance + holding; TX-A saves requester acceptance + holding; independent first-use observations; receiver-local inbox; sender-local ACK. | **Split** review candidate for pure evidence versus local transitions versus transport. No extraction selected; model and version boundaries are substantive. |
| `i/onboarding/{received,known,acceptance,choice_read,export,check}.go` | Choice, acceptance, Received/Known and minimal exports. `i/core/intro,key,storage`. | Caller Vault transactions; `known.go:35` explicitly verifies/promotes Received. `ReceiveEdge`, `VerifyReceived`, `PresentSelf`. | **Keep** explicit promotion; **Adapt** only for later full device-mediated `Introduce` scope. No global graph authority. |
| `i/core/intro` | Path/edge parsing, rooted proof, signatures, inbox, acceptance choice. `hop,i/core/wire,key`. | Pure evidence and in-memory inbox/choice; no Vault or trust owner. | **Keep** rooted verification; **Adapt** legacy options/rotation and generic multi-root path utilities if used as V19 policy. Capability alone is not proof of a semantic defect. |
| `i/core/wire/wire.go` | Deterministic CBOR encoding, bounded decoding and canonical equality. None. | No authority creation; concrete byte obligation omitted by symbolic model. | **Keep** canonical boundary; raw `Unmarshal` is intentionally distinct from verification. |
| `i/ads` | Publication, received/verified ads and online proof client. `i/{core/wire,device,localhttp,onboarding},key,storage`. | Local publication and separate received/verified records; `PublishAd`, `ReceiveAdClaim`, `VerifyAd`. | **Adapt** for full V19 slots/epochs later: `local.go:43` explicitly limits slot 1, epoch 0, Device == Node. Preserve current slice. |
| `i/device/local.go` | One local software signer's authorization and live probe. `i/onboarding,key,storage`. | Vault authorization record versus per-call usability; bounded `BootstrapDevice`. | **Adapt** for broader device lifecycle later; no complete revoke/loss/recovery implementation inferred. |
| `i/policy/denied.go` | Root/local-bound deny set and allow. `i/core/wire,key,storage`. | One encrypted local record; `DenyPeer`/`AllowPeer` eligibility component. | **Keep** local policy; broader live pipe/trust semantics remain separate. |
| `i/nodeidentity/{identity,files}.go` | Private software signer persistence and key/path validation. `key`. | Identity file and wrapping key, not introduction or device authority. | **Keep** independent signer; **Defer** hardware/recovery ceremonies. |
| `i/nodevault/{vault,provider,local}.go` | Store lifecycle, identity binding, exclusive usage DB and finite encryption reservations. `i/nodeidentity,key,storage`. | Owns Database/Vault/provider/usage lock; no modeled introduction action. | **Keep** local ownership. `vault.go:31` explicitly disclaims rollback-resistant accounting and broad power-loss recovery. |
| `storage/{db,vault,tx,namespace,manifest,keyprovider,errors}.go` | Scoped encrypted transactions, namespaces, leases and handle lifetime. `s/i/{engine,record}`. | One Vault per callback; Update commits only on success; no peer authority. | **Keep** abstraction and explicit unwind order. Atomic storage supports actions but is not a refinement proof. |
| `s/i/engine` | Memory and bbolt transaction backends. None. | Backend commit/rollback and namespace ownership. | **Keep** separate from crypto and semantic guards. |
| `s/i/record` | Key derivation, tokens, authenticated record encoding/seal/open. None. | Cryptographic record scope and key clearing, no lifecycle authority. | **Keep**; symbolic models do not prove these cryptographic properties. |
| `key/crypto.go` | Key handles, public-key/signature primitives, hashes and legacy global enclave factory. None. | No modeled authority; newer nodeidentity owns independent backends. | **Adapt** potential boundary between reusable verification and legacy global factory; no style/API change now. |
| `i/localhttp/localhttp.go` | Loopback address/URL validation and bounded HTTP transport. None. | Transport constraint, no durable owner. | **Keep** current demo constraint; broader transports deferred. |
| `cmds/intro` (13 files) | Onboarding/HTTP/NATS demonstrations. `cmds,i/{core/intro,core/wire,localhttp,nodeidentity,nodevault,onboarding,ownerapi},key,storage`. | Demo-owned fixtures and stores; composes existing actions. | **Defer** consolidation; useful regression surfaces with separate opt-ins. |

Other substantial/legacy surfaces: `enclave` (797 production lines) imports
`chain,digest,identity,key,pw`; `i/protocol` (690) imports
`chain,cmds,digest,enclave,i/nconn,key,pw`; `node` (512) imports
`chain,digest,hop,key`; `chain` imports `hop,key`; `identity` imports
`chain,key,node`; `digest` imports `hop,key`; top-level `pw` imports `key`;
`hop` and `i/nconn` have no internal imports. Legacy `cmds/id` imports
`chain,cmds,enclave,hop,identity,i/protocol,key`, `cmds/domain` imports
`cmds,identity`, and `cmds/pw` imports `cmds,enclave,hop,i/protocol`.
These are **Defer/Unknown** for compatibility and retirement: NATS playground,
multi-domain/global-enclave and older trust/distance semantics must not be
mistaken for the accepted independent-node path. `cmd/vault-playground`
imports only `storage` and is **Defer** as an example surface. No **Remove**
recommendation is justified by this round; v1 retirement remains undecided.

Known V19 scope gaps are not regressions: the modern path has no full
multi-device lifecycle/recovery/snapshot/helper service, peer-view refresh or
strong-use mapping. `internal/pw/delete_held.go:18` explicitly implements
invitation `ChangeBob/ChangeRequester("Delete")`, not V19's full ad-cache,
trust and peer-view cleanup. Atomic cross-host V19 `CreatePW` is intentionally
replaced for establishment by independent commits under the accepted extension.
Historical acceptance/contacts/ACKs remain evidence, not restored authority.

Concrete `internal/pw` traceability: `invitation.go` implements
`IssueInvitation`/`RevokeInvitation`; `requester.go:334` implements
`SaveAttempt`; `bob_accept_v2.go` implements `BobAccept`;
`requester_accept_v2.go` implements `ReceiveAcceptance`; `reply_v2.go`
implements `BobReply`; `first_use_v2.go` implements the separate
`SendFirstUse`/`BobFirstUse`/`ReceiveFirstUse` observations. In the separate
message candidate, `CreateOutgoing`, `Transmit`/`RetryExact`, `AcceptIncoming`,
`ReturnReceipt` and `ObserveReceipt` correspond in responsibility to
`message_outgoing_v2.go`, `message_transmit_v2.go`, `message_incoming_v2.go`,
`message_receipt_v2.go` and `message_ack_v2.go`. These are responsibility
mappings, not verified refinements. Current tests such as
`TestMessageProjectionRequiredHistoryV2`,
`TestContactV2LocalEligibilityAndImmutableHistory` and
`TestMessageACKAndInboxEitherSenderV2` exercise exact-history and local-ownership
boundaries with real encrypted storage.

Five concrete cohesion/naming review examples:

1. `internal/ownerapi/device.go:19` names a handler that owns the common
   mutation lock used beyond device bootstrap; `establishment.go:71` uses it
   for pairing. A future owner-service boundary must retain that shared lock.
2. `internal/pw/bob_accept_v2.go:18` says “unwired to HTTP”, while
   `internal/ownerapi/establishment.go:93` invokes it from the peer capability.
   This is a stale status comment, not an absent feature.
3. `internal/pw/contact_v2.go:45` uses an `alice bool` for the local
   establishment role. `message_ack_v2.go:31` instead concerns the sender.
   Bob/Alice are meaningful model roles; sender/receiver may reverse and are
   not interchangeable renamings.
4. `cmds/node/serve.go:261` combines flag/path validation, signer/Store
   acquisition, credentials and capability wiring. A configuration/assembly
   boundary is discussable; its visible cleanup and server lifecycle matter.
5. `key/crypto.go:138` aliases signer handles, while `:174` constructs through
   a global enclave and `:200` verifies public signatures. Those responsibilities
   cross old playground and independent-node usage; extraction needs caller
   review, not a blanket rename.

Accepted `err2 v1.4.0` usage remains intact. For example `storage/tx.go:42`
defers `tx.finish` before `err2.Handle`, so recovery runs before the commit
decision; callbacks own named errors. `bob_accept_v2.go:35` scopes
`assert.Plain`, translates public errors, signs outside Update and rechecks
durable guards inside it. `cmds/node/serve.go:261` keeps compensation visible.
Tests use `defer assert.PushTester(t)()` and workers report errors to the test
goroutine. These are established conventions, not refactoring targets here.

## Round 2 candidates and acceptance limits

At most three candidates for owner selection; none started in this round:

1. **PW test-fixture construction review.** The dominant package takes
   316–340 s and its largest test spends 80% of sampled CPU in `ackTestV2`.
   Examine opportunities to reuse immutable fixture inputs while preserving
   fresh independent Vaults, exact signed history, negative guards and failure
   coverage. Keep err2 conventions and current authorization checks intact.
   No speedup is promised and no shared mutable fixture is authorized here.
2. **Clarify owner-service and PW responsibility boundaries.** The inventory
   identifies the shared mutation lock, HTTP capability composition and pure
   evidence/local-transition/transport responsibilities. Review the five exact
   examples above and agree on ownership before choosing any package extraction.
   Protect independent commits and network I/O outside transactions.
3. **Define a sustainable complete race check.** The existing default package
   limit prevented completing `internal/pw`, while completed diagnostics show
   substantial subprocess overhead. Review the timeout and coverage policy
   with fixture-cost evidence before changing any Makefile/CI setting; this
   round neither changes that policy nor treats the partial race run as green.

Automated validation: both ordinary full-scope samples pass; affected focused
tests and full core/storage tests pass after additions; all nine benchmark
samples and all supplemental TCP samples pass. Baseline/final lint both report
0 issues. Final lint emits 16 cache-persistence warnings for a read-only cache
mount (raw `lint-after.stderr`); no settings or sandbox workaround was used.
The one broad race run is incomplete due to its package timeout, as detailed
above. The previously completed race results for core/storage remain evidence
for unchanged production/test behavior; the new benchmark functions were run
normally. No broader rerun was warranted by benchmark-only additions.

Final `git --no-optional-locks diff --check` passes (exit 0; outer limit
30 s), with metadata and raw output at `E/diff-check.{json,stdout,stderr}`.
Since new files are untracked, a separate standard-library whitespace check of
the three files also passes (exit 0; 30 s limit;
`E/whitespace.{json,stdout,stderr}`). Its exact source is
`E/check_whitespace.py`; ordinary `git diff --check` alone does not inspect
untracked files. Only the two new Go files were formatted with `gofmt -w`;
`gofmt -l` on those files is empty. Effective Go environment is also retained
in `E/environment.stdout` with its exact capture metadata.

Manual acceptance: **not performed**. No fresh two-window demo acceptance,
Flutter rehearsal, TLC/SANY run, model composition evidence, cryptographic
proof or Go refinement proof is established. The historical 101-second run
is not comparable; this report claims no speedup, causal productivity gain
or defect elimination.

Final HEADs and branches equal the initial values above. Final Go dirty state
consists only of three new untracked files:

~~~text
?? docs/implementation/Refactoring_Round_01_Baseline.md
?? internal/core/intro/evidence_benchmark_test.go
?? storage/vault_benchmark_test.go
~~~

The spec remains on `break-demo` at
`c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` with only the original V19
safe-restore mutation; its final diff matches the inspected initial diff.
No existing tracked implementation file changed. Evidence and temporary
binaries remain under `E` for inspection; no commits or tags were created.

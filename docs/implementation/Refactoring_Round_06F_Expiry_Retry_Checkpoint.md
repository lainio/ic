# Round 6F: Lost response after advertisement expiry

Status: test-only checkpoint, 2026-11-19.
Accepted Go baseline: `b5cd95140bd432ffe41d00c04ff44d3e1cc68f08`.
`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree` remained
read-only at `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665`.

## Scenario and evidence

Extended `TestOwnerV2LostResponseExactRetryAndReopen` in
`internal/pw/requester_exchange_v2_test.go`; no fixture or production changes.
The existing independently bound encrypted stores, restored signers, real peer
listeners, HTTP handlers, response-drop mechanism and reopen logic are reused.

Before Alice saves an attempt, `ads.PublishLocal` replaces the fixture ad with
an authentic publication using `time.Now().Add(-ads.TTL + 5*time.Second)`.
Alice receives and verifies it through the real remote current-ad proof API.
Its signed deadline precedes the invitation deadline. All subsequent HTTP
guards retain their production wall clock; no signed evidence is edited.

1. Alice's owner redemption saves her v2 request before the first
   `POST /peer/pw/establish`. Bob consumes the invitation and saves his
   acceptance and holding. The fixture captures his response and closes the
   connection without delivering it. Alice receives HTTP 502 and retains only
   her request; there is no automatic retry.
2. A timer waits until the signed ad deadline. Bob's authenticated fresh lookup
   returns zero/false; Alice's fresh establishment-ad reader reports
   `ads.ErrInvalidRecord`. Both stores' file snapshots remain unchanged.
3. Both persistent stores close and reopen independently, retaining the same
   listener ports and exact relationship records. Owner capabilities are rebound.
   Alice's second redemption retrieves and sends her original request bytes.
   The second peer response equals the lost response and Bob's saved acceptance.
   Before delivery, the observer still sees Alice's unchanged pending records.
4. Alice independently commits exactly the accepted/held records, preserving
   her request and other inspected state. Bob's invitation, accepted/held
   records and encrypted files remain unchanged, as do both durable usage files.
   Both usable-contact projections equal the contacts in the original signed
   request/acceptance and leave both file snapshots unchanged.
5. A subsequent exact owner retry is read-only. After Alice deletes her holding,
   another owner retry reports `local_held:false`, preserves acceptance history
   and creates no holding. Neither retry adds peer traffic.

Observed establishment traffic is exactly two peer POSTs and zero Alice
callbacks or third ACKs. Four owner-handler invocations cover response loss,
successful retry, duplicate and post-delete retry; these owner invocations use
the existing in-process HTTP recorder. There is one establishment-request
signature and one acceptance signature. Additional signing is limited to the
expected discarded usability probes: two Alice/one Bob on successful retry,
one per usable projection, and one Alice probe per later owner retry.
Existing missing/changed-ad refusal tests are untouched.

## Validation and timing

Used `go1.27.1 linux/arm64`, `GOTOOLCHAIN=local`, empty `GOEXPERIMENT`,
`GOPROXY=off`, `GOSUMDB=off`, and `GOFLAGS=-mod=readonly`.
Existing timeouts and lint settings were preserved; only the touched Go file
was formatted with `gofmt`.

| Check | Result |
|---|---|
| Baseline `make lint` | PASS, 0 issues; 0.59s wall |
| Focused uncached integration, command below | PASS, test 5.07s, package 5.072s; 6.25s wall |
| Focused race, command below | PASS, test 5.19s, package 6.204s; 8.24s wall; no race report |
| `make test_fast TEST_ARGS=-count=1` | PASS, 16 families / 36 descendants; package 1.137s, 1.50s wall |
| Final `make lint` | PASS, 0 issues; 3.05s wall |
| `go test -count=1 -timeout=10m ./...` | PASS, all packages; PW 138.839s, ads 10.160s, storage 6.221s; 141.31s wall |
| `git --no-optional-locks diff --check` | PASS |

~~~sh
go test -count=1 -timeout=2m ./internal/pw \
  -run '^TestOwnerV2LostResponseExactRetryAndReopen$' -v
go test -race -count=1 -timeout=5m ./internal/pw \
  -run '^TestOwnerV2LostResponseExactRetryAndReopen$' -v
~~~

Bob's post-commit observation left 4.986s before expiry in the ordinary run
and 4.934s in the race run. The five-second window starts after fixture setup;
remote verification and initial commit must finish within it. Heavy scheduling
delays or wall-clock changes can still fail this real-time scenario. No timeout
was increased or assertion weakened. All requested checks exited 0; no test
failed. Final lint only warned that its analysis cache could not be persisted
in the read-only cache directory.

## Semantic limits and workspace

Read Round 6A–6E, implementation reality, repository guidance and the four
required semantic references. This exercises the invitation extension's
independent commits, immutable retry and contact obligations in the state
contract, action map §3.1 and conformance map §9. Ad expiry is a concrete Go
policy within the model's abstract freshness/current-binding prerequisites.

This is automated HTTP integration evidence, not manual demonstration
acceptance or formal refinement. Reopen uses retained listeners and signers,
not a process-kill/crash-consistency experiment. Local usable contacts imply
neither remote permission nor reachability, first use, `PWOpen` or Trust.
First use and messaging are not exercised by this scenario. Retained evidence
removal, replacement or corruption still refuses; rotation/rebinding and broader
V19 refinement remain outside this increment. No TLC checks were run.

The Go checkout began clean and only the existing test file and this report
are changed. No Git-writing commands, commits, tags, nested Codex or
exec-metrics were used. The existing dirty spec model is preserved with SHA-256
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`.

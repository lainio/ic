# Round 05C: typed message HTTP JSON decoder

Date: 2026-11-18.

**Recommendation: Keep the scoped parser replacement.** Focused, fast, full
and race tests pass. Final lint fails on three deprecated ECDSA field uses in
unchanged files after the Go minimum increase; this is not a clean-lint
checkpoint. The diagnostics and the initial test-fixture failure are recorded
below without suppression.

The response decoder now uses a private typed `encoding/json/v2` destination.
The declared Go minimum is **1.27.0**, raised from 1.24.0. The only authorized
input-policy change is accepting escaped JSON member names whose decoded
values are exactly `version` or `receipt`. Both wire versions remain supported.

## Repository identity and evidence

| Repository | HEAD / branch | Initial state |
|---|---|---|
| `/home/parallels/go/src/github.com/lainio/ic` | `67bda335d784f1f5febb109c5b10a0fa8612c55e` / `tla-spec-based-refactoring-v1` | Clean; accepted baseline |
| `/home/parallels/go/src/github.com/optechlab/intro-tree` | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` / `break-demo` | Existing modification to `models/active/IntroTreeV19.tla` |

The second repository is `SPEC_REPO` and remains read-only. Initial V19 file
SHA-256:
`fa382e180fb5bde7a19c975583b22108a8b65aef38074f3d653752efba5c878d`.

Evidence directory: `/tmp/ic-round05c-qwm9f80u/`.
`go-before.json` and `spec-before.json` contain roots, HEADs, branches, status
and raw diffs; `go-sha256-before.json` and `spec-sha256-before.json` identify
the reviewed inputs. `environment.txt` records the installed toolchain and
existing settings. These temporary files are local evidence, not committed
artifacts.

`prompt.txt` preserves the Round 5C task message as UTF-8 with LF endings and
one final newline, excluding the separate AGENTS/environment message.
Its SHA-256, also stored in `prompt.sha256`, is:
`5d9aa71c403b4fcf4d7323649b7c07c5b7e899327369c4424c617e49ad5ab2d7`.

Read the live root `AGENTS.md`,
`Current_Go_Implementation_Reality.md`, the
[Round 05B report](Refactoring_Round_05B_JSON_Parser_Review.md), the leaf
decoder/tests, and the existing PW client/tests. Required semantic references
were read from `SPEC_REPO`:

- `docs/IntroTree_Model_Index.md`;
- `docs/contracts/IntroTree_StateSemantics_Contract.md`;
- `docs/contracts/IntroTree_Implementation_Action_Map.md`;
- `docs/contracts/IntroTree_Conformance_Test_Map.md`.

The state contract's received/verified distinction still applies: HTTP success
returns untrusted receipt bytes, never authority. The action map leaves network
serialization outside its modeled responsibilities. The invitation extension
and conformance map keep the messaging candidate separate and claim no
composition proof. This transport representation change introduces no state
transition or new V19 mismatch; these tests do not establish V19 conformance.
No TLC execution or specification change is part of this round.

## Changed files and Go-version decision

Only four Go-repository files are changed:

| File | Change |
|---|---|
| `go.mod` | Only `go 1.24.0` becomes `go 1.27.0` |
| `internal/pw/internal/messagehttp/message_client.go` | Private response struct and typed JSON v2 response decoding |
| `internal/pw/internal/messagehttp/message_client_test.go` | Authorized escaped-name accepts and preserved/expanded rejection and boundary coverage |
| `docs/implementation/Refactoring_Round_05C_Typed_JSON_Decoder.md` | This report |

Go 1.27.0 is the expressly requested minimum for the ordinary JSON v2 import.
The installed `/usr/local/go/api/go1.27.txt` lists `encoding/json/v2`, including
`Unmarshal` and `RejectUnknownMembers`. Execution used **go1.27.1 linux/arm64**
and golangci-lint 2.13.2 built with go1.27.1. No separate 1.27.0 toolchain was
available or downloaded, so patch-level 1.27.0 execution is not claimed.

Existing settings were retained: `GOTOOLCHAIN=local`, empty `GOEXPERIMENT`,
`GOPROXY=off`, `GOSUMDB=off`, and `GOFLAGS=-mod=readonly`. No dependency,
`go.sum`, toolchain directive, machine setting or lint configuration changed.
The outbound request still uses the existing `encoding/json` marshaler.

## Before/after parser comparison

Before: `json.Decoder` token traversal, `UseNumber`, a seen-name map, raw-name
backslash inspection, a member switch, closing-delimiter checks and a final
EOF token check, plus explicit UTF-8 validation.

After: a fresh private `messageResponse` with `Version int` and `Receipt string`,
explicit lowercase JSON tags, and one whole-buffer
`jsonv2.Unmarshal(..., jsonv2.RejectUnknownMembers(true))`. JSON v2 supplies
duplicate detection, case-sensitive name matching, strict UTF-8 validation
and single-value framing. There is no tokenizer, custom unmarshal hook,
second traversal, exported API or shared decoding framework.

| Input or validation | Before | After |
|---|---|---|
| Lowercase names, either order, JSON whitespace | Accept | Accept |
| Single escaped name decoding exactly to `version` or `receipt` | Reject | **Accept: authorized change** |
| Escaped aliases duplicating either member, in either order | Reject | Reject |
| Repeated fields, conflicting values, duplicate nulls | Reject | Reject |
| Capitalization aliases, including Unicode case folding | Reject | Reject |
| Unknown names, including escaped unknown names | Reject | Reject |
| Selected numeric token `1` or `2` | Accept | Accept |
| Wrong number, fraction, exponent, overflow, quoted number or other type | Reject | Reject |
| Missing/null members, top-level null, empty receipt | Reject | Reject |
| Malformed syntax, BOM, non-JSON whitespace, invalid UTF-8, trailing data | Reject | Reject |
| Canonical standard base64 with required padding and zero pad bits | Accept | Accept |
| Noncanonical pad bits, URL alphabet, CR/LF, whitespace or bad padding | Reject | Reject |
| JSON escapes inside an otherwise canonical base64 receipt | Accept | Accept |
| Body at 2048 bytes / 2049 bytes | Accept / reject | Accept / reject |
| Positive decoded receipt at caller's limit / over limit | Accept / reject | Accept / reject |

For example, `"\u0076ersion"` and `"rece\u0069pt"` now name the two permitted
fields. `"\u0056ersion"` still fails because it decodes to `Version`.
A literal `receipt` followed by `rece\u0069pt` still fails as a duplicate.
Receipt-value spellings such as `"\u0041A\u003d="` and `"\/w=="` remain valid.
This policy permits equivalent string escapes; it does not make JSON canonical.

Explicit checks still enforce the 2048-byte raw body bound, selected version
1 or 2, encoded receipt bound, nonempty decoded receipt, caller-supplied decoded
receipt limit and re-encoding equality. A fresh struct gives missing/null
members invalid zero values; presence pointers are unnecessary. Typed integer
decoding rejects fractions and exponents even when mathematically integral.

The receipt remains a string decoded through
`base64.StdEncoding.Strict().DecodeString`, followed by
`base64.StdEncoding.EncodeToString(receipt) == response.Receipt`.
This rejects nonzero unused pad bits and CR/LF that strict decoding alone
would otherwise ignore. Automatic `[]byte` JSON decoding is not used.
Both PW callers still supply their version-specific limits, currently 640
bytes each. Tests also use limits 1, 2 and 3 and exercise 639 through 643 bytes;
641 and 642 require the decoded-length check despite fitting the encoded bound.

Every failure returns exactly `(nil, ErrOutcomeUnknown)`, including partial
JSON or base64 decoding. Raw errors never pass through `try.To`, `err2.Handle`,
wrapping or tracing. Tests compare the sentinel directly and require nil bytes.
HTTP status/header/trailer checks, bounded reads, close/cancellation handling,
five-second timeout, request construction, one POST without redirects/retries,
URL policy and pre-/post-dispatch error classification are unchanged.
Other protocol parsers, signed bytes, CBOR, storage, authorization and
transactions are untouched.

## Round 05B acceptance replay

The original prototype sources and output were available at
`/tmp/ic-round05b-json-Hazy4D/` and copied to the new evidence directory as
`round05b-{main.go,current.go,existing.go,results.txt}`. The old decoder function
was checked byte-for-byte against the accepted baseline. `production.go`
copies the new private struct and decoder, renaming only the function for the
standalone comparison. `comparison.go`, `current.go` and `existing.go` replay
the unchanged 57 original plus 59 additional Round 05B cases per wire version.

| Wire version | Before accepted / rejected | After accepted / rejected | Differences |
|---|---|---|---|
| 1 | 15 / 101 | 18 / 98 | Exactly the three escaped-name cases |
| 2 | 15 / 101 | 18 / 98 | Exactly the three escaped-name cases |

All 464 decoder outcomes matched the expected before/after classifications.
All common successes returned identical bytes; the newly accepted cases
returned the expected bytes. All failures returned the exact sentinel and nil.
This finite corpus is the requested acceptance evidence, not an exhaustive
proof over every possible JSON byte sequence.

The repository test changes retain all original rejection cases except the
two explicitly authorized escaped-name cases, which move to acceptance.
Additional coverage includes both escaped names together; every order of
literal/two escaped aliases and null duplicate values; case and Unicode
aliases; malformed names/values; numeric spellings and overflow; receipt
escapes; canonical base64; and raw-body/decoded-receipt boundaries.

## Commands, raw results and finite timeouts

Every command below ran from the Go root through the evidence directory's
`run.py`. It saves combined raw stdout/stderr in `<label>.log`, and exact argv,
working directory, UTC start, elapsed seconds, exit status and outer-timeout
outcome in `<label>.json`. It returns the command's status without suppression.
The actual command prefix is
`timeout --signal=TERM --kill-after=10s <outer-bound>`.

| Label | Exact command after timeout prefix | Outer bound | Outcome |
|---|---|---|---|
| `baseline-lint` | `make lint` | 5m | PASS, exit 0, `0 issues.`; 0.442s |
| `focused-messagehttp` | `go test -count=1 -timeout=2m -v ./internal/pw/internal/messagehttp` | 3m | FAIL, exit 1; new fixture expectation error described below; 0.348s |
| `focused-messagehttp-corrected` | `go test -count=1 -timeout=2m -v ./internal/pw/internal/messagehttp` | 3m | PASS, exit 0, five test families; 0.248s |
| `pw-message-client` | `go test -count=1 -timeout=2m -v ./internal/pw -run '^TestMessageClient'` | 3m | PASS, exit 0; PW 5.018s, wall 7.669s |
| `behavioral-comparison` | `go run /tmp/ic-round05c-qwm9f80u/comparison.go /tmp/ic-round05c-qwm9f80u/current.go /tmp/ic-round05c-qwm9f80u/production.go /tmp/ic-round05c-qwm9f80u/existing.go` | 3m | PASS, exit 0; 0.109s |
| `test-fast` | `make test_fast TEST_ARGS=-count=1` | 11m | PASS, exit 0; 16 families and 36 descendants, PW 0.951s, wall 1.278s |
| `full-suite` | `go test -count=1 -timeout=10m ./...` | 12m | PASS, exit 0; full PW 107.239s, wall 112.101s |
| `focused-race` | `go test -race -count=1 -timeout=5m ./internal/pw/internal/messagehttp ./internal/pw -run '^TestMessageClient'` | 6m | PASS, exit 0; leaf 1.017s, PW 6.038s, wall 11.521s |
| `final-lint` | `make lint` | 5m | FAIL, make exit 2 / lint exit 1; three SA1019 issues; 29.252s |
| `diff-check` | `git --no-optional-locks diff --check` | 1m | PASS, exit 0, no output; 0.009s |

No Go test timeout or outer timeout fired. The full suite was neither narrowed
nor skipped. The race selection includes all five leaf decoder test families
and the existing PW message-client HTTP/classification tests, including the
five-second client timeout. Final report whitespace is also checked separately
because Git's ordinary diff does not include an untracked report.

The initial focused failure was in the newly added expanded-receipt fixture,
not the implementation: 300 decoded zero bytes become 400 base64 `A` characters,
or 2400 characters after replacing each with `\u0041`, before object overhead.
It therefore correctly exceeded the 2048-byte body bound. The fixture was
corrected to 240 bytes for acceptance and 300 for rejection (1946/2426 body
bytes). No production behavior or existing rejection expectation was weakened.
The failed log and corrected rerun are both retained.

Final lint reports these three findings, all outside the modified files:

- `internal/nodeidentity/identity.go:153:5`: SA1019 on
  `crypto/ecdsa.PrivateKey.D`.
- `key/crypto.go:209:3`: SA1019 on `crypto/ecdsa.PublicKey.X`.
- `key/crypto.go:210:3`: SA1019 on `crypto/ecdsa.PublicKey.Y`.

The diagnostics state that the fields were deprecated in Go 1.26, with
alternatives available since Go 1.25. Baseline lint passed with the old
`go 1.24.0` declaration; the raised target exposes these existing uses.
They were not changed because this round expressly excludes cryptographic
and unrelated cleanup. No lint exclusions or weaker configuration were added.
The full raw `final-lint.log` also retains 3064 read-only-cache warnings for
`/home/parallels/.cache/golangci-lint/`; neither cache location nor machine
settings were changed. These warnings do not erase the three code findings.

## Compatibility limitations and recommendation

Go 1.24–1.26 builds are no longer supported by the declared module minimum.
Validation is on installed Go 1.27.1 linux/arm64; other toolchains and platforms
were not executed. The escaped-name relaxation is specific to this message
response decoder; other protocol parsers retain their own representation rules.
Both message wire versions remain active. Returned receipts still require
separate protocol authentication; JSON validity and HTTP 200 do not establish
receipt authenticity, receiver commitment or V19 conformance.

Final repository status contains exactly the four authorized files above:
three tracked modifications and this untracked report. HEADs and branches are
unchanged. `spec-after.json` equals `spec-before.json`, including the existing
dirty V19 diff; `spec-sha256-after.json` equals the initial hashes. The V19
modification was preserved byte-for-byte. `scope-check.json` records that
HTTP dispatch, URL validation, response reading and sentinels match the baseline
byte-for-byte, and that the temporary comparison used the current production
decoder. No commit, tag, Git-writing command, network download, nested Codex,
exec-metrics, unrelated cleanup or other parser replacement was performed.

Keep this implementation because it matches the authorized Round 05B policy
and passes the behavioral comparison, full tests and relevant race checks.
The three lint findings remain outstanding compatibility work for the Go
minimum increase, outside this parser-only increment. Do not describe this
checkpoint as all checks green. No further parser or cryptographic changes
were attempted.

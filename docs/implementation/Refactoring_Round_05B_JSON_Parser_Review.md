# Round 05B: message HTTP JSON parser review

Review date: 2026-11-18. Analysis and temporary experiment only.

**Neither typed decoder is an exact replacement.** The current token decoder
is the simplest of these choices if both the accepted input language and the
Go 1.24 minimum must remain fixed.

**One recommended change for a subsequent implementation round:** adopt a
private typed `encoding/json/v2` decoder with `Version int`, `Receipt string`
and `RejectUnknownMembers(true)`, retaining explicit version, body and
canonical-base64/receipt-length checks. Explicitly change the policy to allow
JSON escapes in member names that decode to exactly `version` or `receipt`.
This removes manual object traversal, duplicate tracking and raw-name checks;
it requires raising the declared minimum to **Go 1.27.0**. This is a proposal
for both a format-policy change and a minimum-version change, not an equivalent
refactor. If either is unacceptable, **Keep** the current decoder.

## Baseline and scope

| Repository | HEAD / branch | Initial state |
|---|---|---|
| Go workspace | `2ed751c58b65f3602b74a6a9d0391d93c6c4c9ea` / `tla-spec-based-refactoring-v1` | Clean; matches accepted baseline |
| Read-only `SPEC_REPO` | `c47e2b9c80c68bf22aec0d1466f4ab471c8fb665` / `break-demo` | Existing modification to `models/active/IntroTreeV19.tla` |

`SPEC_REPO=/home/parallels/go/src/github.com/optechlab/intro-tree`.
Read live root instructions, `Current_Go_Implementation_Reality.md`, the four
required semantic references, both requested test files and Round 04.
The [Round 04 extraction contract](Refactoring_Round_04_Package_Architecture.md#L491)
explicitly preserved strict JSON; its line 508 is not authorization to relax it.
This review follows only message dispatch and its receipt-verification
dependency. No other protocol JSON parser was inspected.

The semantic references are `docs/IntroTree_Model_Index.md:447`,
`docs/contracts/IntroTree_StateSemantics_Contract.md:16`,
`docs/contracts/IntroTree_Implementation_Action_Map.md:430` and
`docs/contracts/IntroTree_Conformance_Test_Map.md:583`, relative to `SPEC_REPO`.
They distinguish received material from authority, leave concrete network
serialization outside the V19 contract, and keep the messaging candidate
separate. No JSON spelling rule below is a V19 state invariant. No new V19
mismatch is established by this review, nor is Go conformance proved. The
existing dirty model is not treated as an accepted baseline change.

## Exact current input language

Sources: [leaf decoder:138](../../internal/pw/internal/messagehttp/message_client.go#L138),
[JSON cases:13](../../internal/pw/internal/messagehttp/message_client_test.go#L13),
[limit cases:71](../../internal/pw/internal/messagehttp/message_client_test.go#L71).
For trusted caller inputs selecting wire version 1 or 2 and a positive limit:

- The entire body is at most 2048 bytes and valid UTF-8. It contains exactly
  one JSON object, with exactly two members: raw, unescaped, lowercase
  `"version"` and `"receipt"`, each once. Either order and ordinary JSON
  whitespace are accepted. Unknown names, aliases, duplicates, malformed
  syntax, a BOM, non-JSON whitespace and trailing non-whitespace are rejected.
- `version` is the exact numeric token `1` or `2` matching the selected
  version. Wrong versions, `1.0`/`2.0`, exponents, quoted numbers, booleans,
  objects, arrays, missing values and `null` are rejected.
- `receipt` is a JSON string whose **unescaped value** is canonical standard
  base64: standard alphabet, padding when required, zero unused pad bits,
  no whitespace or CR/LF. It decodes to 1 through `receiptLimit` bytes.
  Missing, null, empty or other JSON types are rejected. Arbitrary decoded
  bytes are accepted; this function does not authenticate or parse CBOR.
- The unescaped base64 string is at most `EncodedLen(receiptLimit)` bytes
  before decoding; the decoded limit is checked separately. Both real wire
  versions currently use 640 bytes, so the encoded bound is 856. Receipts of
  641 and 642 bytes also encode to 856 bytes and require the decoded check;
  643 bytes encode to 860 and fail the encoded check.

The body is **not canonical JSON**. For example, a receipt value written as
`"\u0041A\u003d="` is accepted as `"AA=="`; `"\/w=="` is accepted as `"/w=="`.
Escapes in names are rejected even when they decode to an allowed name.
Thus neither banning every backslash nor comparing re-marshaled JSON to the
original body preserves the language. Raw body bytes, including escapes and
whitespace, still count toward 2048.

Every rejection returns exactly `(nil, ErrOutcomeUnknown)`, without wrapping
or tracing the input-bearing JSON/base64 error. See the
[sentinels:30](../../internal/pw/internal/messagehttp/message_client.go#L30),
[PW aliases:9](../../internal/pw/message_client.go#L9) and
[identity tests:218](../../internal/pw/message_client_test.go#L218).
The HTTP reader additionally enforces status, headers, trailers, bounded reads,
context and close errors ([reader:106](../../internal/pw/internal/messagehttp/message_client.go#L106));
a JSON replacement does not replace those checks.

## What the restrictions protect

| Responsibility | Assessment |
|---|---|
| Received bytes never become authenticated evidence through HTTP success | Actual authority boundary. [PW client:20](../../internal/pw/message_client.go#L20) returns untrusted bytes. Separate ACK observation authenticates exact saved history; [v1 receipt:123](../../internal/pw/message_receipt.go#L123) and [v2 receipt:114](../../internal/pw/message_receipt_v2.go#L114) check canonical CBOR, inner version, payload binding and receiver signature. |
| Selected outer version, required nonempty receipt, faithful byte decoding | Actual transport/schema contract; avoids missing data and version confusion. Outer version is not a substitute for inner evidence authentication. |
| Body and decoded receipt limits | Concrete resource/domain bounds; retain them. The encoded-length precheck bounds decoding work but does not replace either limit. V19 does not specify these numeric caps. |
| No duplicates | Input policy with a useful ambiguity defense: avoids overwrite/order-dependent interpretations. Retain it, including duplicates expressed through escaped aliases. |
| Unknown-name rejection, exact capitalization, unescaped names, integer spelling, UTF-8 and canonical base64 | Additional representation/interoperability policy, not cryptographic authority. Some rules reduce ambiguity; none proves receipt authenticity. The recommended relaxation concerns only escapes in otherwise exact names. |
| One object and no trailing data | Explicit framing/schema policy. Retain it so success cannot silently ignore another response value or garbage. |

The deliberately unauthenticated `/w==` response succeeds in the
[existing HTTP test:21](../../internal/pw/message_client_test.go#L21).
Both selected versions and their real receipt bounds are exercised at
[line 139](../../internal/pw/message_client_test.go#L139).

## Behavioral comparison

The typed candidates use a fresh struct on each call. The legacy candidate
uses `encoding/json.Decoder`, `DisallowUnknownFields()`, explicit UTF-8
validation and a second `Decode` requiring `io.EOF`. The v2 candidate uses
whole-buffer `Unmarshal(..., RejectUnknownMembers(true))`; UTF-8, duplicates,
case-sensitive matching and trailing-data rejection come from v2. Both use
the same explicit body/version/strict-base64/decoded-length checks as current.
`Receipt` is a **string**, not `[]byte`.

Results apply identically to selected wire versions 1 and 2. A = accept;
R = reject. These columns describe the complete candidates, not bare library
defaults (both libraries ignore unknown members unless configured otherwise).

| Input category | Current tokens | Typed legacy | Typed v2 |
|---|---|---|---|
| Valid object, either order, JSON whitespace | A | A | A |
| Duplicate version/receipt, including escaped duplicate names | R | A when resulting values pass; overwrite/no-op semantics | R |
| Unknown member | R | R | R |
| Single escaped `version` or `receipt` name | R | A | A |
| Capitalization aliases, including `verſion` Unicode case fold | R | A | R |
| Selected integer token | A | A | A |
| Wrong version, fraction, exponent, string, boolean, object or array version | R | R | R |
| Malformed JSON, trailing object/scalar/garbage, BOM | R | R | R |
| Invalid UTF-8 in name/value/outside object | R | R via explicit check | R by default |
| Missing fields, top-level null, single null member, empty receipt | R | R via postchecks | R via postchecks |
| Valid value followed by duplicate null member | R | A: null leaves scalar unchanged | R: duplicate |
| Noncanonical base64: `AB==`, `AAB=`, CR/LF, URL alphabet, bad/missing padding | R | R | R |
| JSON escapes in a canonical receipt string | A | A | A |
| Exactly 2048 body bytes / 2049 bytes | A / R | A / R | A / R |
| Receipt exactly at positive limit / one byte over | A / R | A / R | A / R |

Neither `int` decoder accepts a fractional or exponent spelling, even when
mathematically integral. Presence pointers are unnecessary here: with a fresh
struct, missing/null fields become invalid zero values under the postchecks.
The legacy duplicate/null exception above shows why those checks alone do not
replace duplicate detection.

Direct `[]byte` decoding is not equivalent: **both libraries accept `AB==`**
(nonzero unused pad bits). Legacy decoding also accepts CR/LF inside the
base64 string and a JSON byte array such as `[0]`; v2 rejects those. Keep the
string and `StdEncoding.Strict().DecodeString` plus re-encoding equality.
`Strict()` alone still ignores CR/LF. These findings agree with installed
Go source `/usr/local/go/src/encoding/json/v2/arshal_default.go:425`.

Legacy typed decoding needs custom duplicate, exact-case and raw-name
validation to retain the language. V2 still needs raw-name validation if the
escape ban remains. Adding a second token walk or custom unmarshaling solely
for these rules is not a meaningful simplification of this two-field parser.

## Prototype evidence and Go version

Temporary, standard-library-only prototype:
`/tmp/ic-round05b-json-Hazy4D/{main.go,current.go,existing.go,results.txt}`.
The current decoder function was copied byte-for-byte and checked against the
workspace. Existing literal cases were copied from the leaf tests; the harness
also reproduces their small-limit loops. No repository tests were edited.
`main.go:25` is the legacy candidate; `:42` is v2; `:53` contains their common
postchecks. Sharing that code is only an experimental convenience; the
recommended production change remains one private protocol-specific function.

~~~console
go run /tmp/ic-round05b-json-Hazy4D/main.go \
  /tmp/ic-round05b-json-Hazy4D/current.go \
  /tmp/ic-round05b-json-Hazy4D/existing.go
~~~

Each wire version ran **57 existing + 59 additional = 116 cases**, with all
three implementations (696 compared outcomes). Additional cases include
duplicate conflicts/nulls, Unicode case folding, escaped receipt values,
invalid UTF-8 inside strings, unpaired surrogates, malformed syntax, numeric
overflow, CR/LF/pad bits, exact body boundaries and receipt sizes 639–643.

| Per wire version | Accepted / rejected | Differences from baseline |
|---|---|---|
| Current | 15 / 101 | 0 |
| Typed legacy | 31 / 85 | 16 additional accepts: 6 existing cases, 10 added cases |
| Typed v2 | 18 / 98 | 3 additional accepts: the two existing escaped-name cases and an added case escaping both names |

No baseline-accepted case was rejected by either candidate; returned bytes
matched on all common successes. Every failure returned the prototype's exact
sentinel and nil bytes. Another 18 inputs across both wire versions probed
both direct-byte decoders. Exit status was 0; differences are recorded results,
not a claim that either candidate passes the unchanged strict-JSON tests.
The actual package tests separately verify production sentinel identity.

Execution used installed `go1.27.1 linux/arm64`, `GOTOOLCHAIN=local` and an
empty `GOEXPERIMENT`. V2 was available without changing settings. The
[Go 1.27 release notes](https://go.dev/doc/go1.27)
describe the now-available packages and preserved legacy API behavior.
[V2 documentation](https://pkg.go.dev/encoding/json/v2@go1.27.1)
documents case-sensitive matching and unknown-member rejection options.

The legacy candidate uses APIs available at the current
[`go 1.24.0` minimum](../../go.mod#L3); it was executed on 1.27.1, **not** on a
1.24 runtime. The recommended v2 import requires changing that minimum to
1.27.0 for ordinary supported builds without experimental settings. A newer
local compiler does not make the import available to Go 1.24 users. No
dependency, toolchain download, compatibility framework or experimental flag
is proposed.

For a future implementation, change only the escaped-name acceptance cases
for both versions; keep escaped duplicates, capitalization and every other
rejection above. Keep direct sanitized sentinel returns: do not route raw
decoder errors through `try.To`/`err2` tracing. The existing handwritten error
handling here is deliberate, while assertion-based tests retain
`defer assert.PushTester(t)()`.

## Validation and final state

- Baseline `make lint`: PASS, `0 issues.`
- `go test -mod=readonly -count=1 ./internal/pw/internal/messagehttp
  ./internal/pw -run '^TestMessageClient'`: PASS; leaf 0.004s, PW 5.022s.
- Temporary comparison: PASS as an experiment; differences documented above.
- Final `make lint`: PASS, `0 issues.`
- Local report links/line references and whitespace checks: PASS.
- Final Go HEAD and branch match the baseline table. Dirty state consists only
  of this new, untracked report; tracked-file diff is empty. The read-only
  specification checkout retains its pre-existing model modification.

No full-suite run was needed for this documentation-only review. No production,
test, module, Makefile, repository script or specification file was changed;
no parser replacement, commit, tag, nested Codex or agent was run.

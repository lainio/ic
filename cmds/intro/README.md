# Introduction path and acceptance demos

## Two-terminal Root -> Alice exchange

This disposable developer demo uses two CLI processes with separate fresh
signing handles and an external local Core NATS broker.
The broker is a third process/service, not a third IntroTree participant.
If already installed, the owner can start it in another pane:

~~~sh
nats-server -a 127.0.0.1 -p 4222
~~~

In Root's terminal:

~~~sh
go run ./cmd/tdc intro exchange-demo root --session demo1
~~~

Root subscribes to both subjects and flushes them before printing its actual
full CBOR public-key bytes as hex and `ready for Alice`.
Copy that entire public hex value into Alice's command, replacing
`ROOT_PUBLIC_KEY_HEX`:

~~~sh
go run ./cmd/tdc intro exchange-demo accept --session demo1 --root ROOT_PUBLIC_KEY_HEX
~~~

With a built executable, the same commands are
`tdc intro exchange-demo root --session demo1` and
`tdc intro exchange-demo accept --session demo1 --root ROOT_PUBLIC_KEY_HEX`.
This manual public-value copy independently selects Alice's expected root
and parent; it is not production provisioning or discovery.
The `accept` invocation authorizes this one direct-root offer, with no
interactive human consent ceremony.

Alice requests an offer with canonical CBOR `key.Info` containing only her
public key. Storage IDs are not authority and are omitted: the pinned demo
backend's `ID()` wraps private-key material, so neither role sends it.
Root signs and retains one exact `R -> Alice` proposal.
Alice parses it, checks the direct shape, and uses
`onboarding.SignAfterStoredChoice` to check the pinned root/parent/child,
commit choice, sign, verify, and save the detached acceptance.
She verifies locally, then sends only that signature back.
Root runs `VerifyAcceptance` against its retained proposal and replies with
`acceptance-verified` only after that check succeeds.

Successful stdout summaries (not complete terminal transcripts):

~~~text
root public key (hex): <actual full public-key hex, different each run>
ready for Alice
proposal sent: R -> Alice
Alice's acceptance verifies: true
~~~

~~~text
proposal received: R -> Alice
choice and acceptance saved: true
local acceptance verifies: true
issuer reported acceptance verified: true
~~~

Both roles require `--session`: 1..64 ASCII letters, digits, `_` or `-`.
It scopes exactly `ic.intro-demo.<session>.offer` and
`ic.intro-demo.<session>.acceptance`; it is no identity, authorization,
shared secret, or enrollment record. Use a fresh session for each run.
Both accept `--nats-url` (default `nats://127.0.0.1:4222`) and positive
`--timeout` (default `2m`, total invocation deadline).
Only one plain loopback endpoint is allowed; `localhost` resolves here to
`127.0.0.1`, and literal IPv4/IPv6 loopback addresses are supported.
No credentials, public server, reconnect, resend, or concurrent clients.
The private payload limit is 64 KiB, also bounding error diagnostics.
Application rejections use an empty body and one private error header;
diagnostic text does not preserve Go error identity across processes.
Rejections, missing responders, timeouts, and output errors exit nonzero;
the root CLI prints diagnostics on stderr (`go run` may add its exit status).

Alice owns and removes a private temporary bbolt Vault/database, clears the
existing provider's secret, and keeps her key handle only for this invocation.
Choice and acceptance are auxiliary saved evidence, not membership.
NATS is only byte transport: no end-to-end confidentiality, anti-replay
protocol, production admission, restart recovery, global one-parent
enforcement, rotation, or ancestor policy is claimed.
The acknowledgement is an unsigned peer report, not independent authority,
a signed certificate, or an authenticated acknowledgement protocol.
The meaningful observation is Root's actual signature check; flushing a
message is no proof that its peer verified it.
The authority bridge to V19 `Edges`/`Known` remains unresolved.
This adds no V19 transition, enrollment, trust, or pairwise connection.

Ordinary tests are broker-free. Explicit integration validation, with an
owner-provided permitted local broker already running:

~~~sh
go test -mod=readonly -count=1 -run '^TestExchangeDemoNATS$' -v ./cmds/intro -args -intro-demo-nats-url nats://127.0.0.1:4222
~~~

Without the flag that test explicitly skips; with it, broker absence or
timeout fails. It runs independent NATS clients in one test process, including
wrong-root and invalid-acceptance rejection. This is integration evidence,
not evidence that the two manual CLI processes above have been executed.
Read the Root runner, Alice runner, and tests after this walkthrough.

## Generated path fixtures

Run a generated fixture through the existing `tdc` executable:

~~~sh
go run ./cmd/tdc intro demo valid
go run ./cmd/tdc intro demo bad-link
~~~

`tdc intro demo CASE` requires exactly one of these cases:

- `valid`: `R -> Alice -> Bob`.
- `bad-signature`: alter Bob's signature.
- `bad-link`: alter Bob's `Prev` and correctly re-sign with Alice.
- `wrong-root`: present `X -> Alice -> Bob` while independently expecting `R`.
- `root-cycle`: correctly sign and link `R -> Alice -> R`.

Each run creates fresh local `key.Handle` fixtures using the existing `key.New`
backend and round-trips the selected path through the existing encoder/decoder.
All fixtures have zero `BackupKeyIndex`.
Backup and rotation policy are untested.
The demo adds no key custody or private-key erasure guarantee.

Output reports the case, fixture path label, descendant signature checks,
expected-root comparison, and the result of `ProveFromRoot`.
For `bad-link`, stdout only:

~~~text
case: bad-link
fixture path: R -> Alice -> Bob
descendant signatures valid: true
starts at expected root: true
path check: rejected
~~~

`valid` reports `accepted` and exits zero.
Every negative case reports `rejected`, returns the underlying core proof error,
and exits nonzero; the existing CLI prints the cause once.
`go run` may also print the exit status.
Use `tdc intro demo --help` for help.

This generated-fixture demo is not a general evidence-import command or an
implementation of V19 `Introduce`, `ReceiveEdge`, or `VerifyReceived`.
It creates no `Received`/`Known` state and grants no introduction, trust,
pairwise, or device authority.
`accepted` means only that the existing `ProveFromRoot` checks returned nil for
this fixture.
It does not prove presenter key control, global unique parenthood, complete V19
conformance, or safe handling of arbitrary network-supplied paths.

## Detached acceptance demo

~~~sh
go run ./cmd/tdc intro acceptance-demo valid
go run ./cmd/tdc intro acceptance-demo transferred
go run ./cmd/tdc intro acceptance-demo bad-link
~~~

`tdc intro acceptance-demo CASE` requires exactly one supported case:

| Case | Presented fixture | Path proof | Acceptance signature |
|---|---|---|---|
| `valid` | Alice signs `R -> Alice`; present it | Pass | Pass |
| `missing` | `R -> Alice` without acceptance | Pass | Fail |
| `transferred` | Direct acceptance attached to `R -> Bob -> Alice` | Pass | Fail |
| `bad-link` | Change Direct's `Prev`, re-sign with R, then Alice | Fail | Pass |

Each run creates fresh R, Alice, and Bob handles with the existing `key.New`
backend and uses default path options.
Both proposals use the same R and Alice keys.
Normal signing first proves the offered direct path against independently
expected R and checks its final child/parent against Alice/R.
`missing` never calls Alice's signer.
`bad-link` deliberately bypasses proof before signing: both signatures are
genuine for the changed bytes, demonstrating a misbehaving signer rather than
a recommended acceptance workflow.

The presented path passes through `ParsePath`, then both `ProveFromRoot` and
`VerifyAcceptance` run before reporting.
Stdout for `transferred` is exactly:

~~~text
case: transferred
fixture path: R -> Bob -> Alice
path proof passes: true
acceptance signature verifies: false
checks: rejected
~~~

`valid` reports `checks: passed` and exits zero.
The other cases report `checks: rejected` and exit nonzero.
Separately on stderr, the root CLI prints the underlying error:
`ErrBadAcceptance` for `missing`/`transferred`, or `ErrBrokenPath` for `bad-link`.
`go run` may additionally print `exit status 1` on stderr.
The stdout block above is not a complete terminal transcript.
Use `tdc intro acceptance-demo --help` for help; completion lists all four cases.

Passing means only that both local checks returned nil; it is not enrollment.
The path label describes a fixture, not an authority decision.
This command implements no V19 state transition and changes no `Received`,
`Known`, introduction, trust, device, or PW state.
It establishes neither human consent nor one-time acceptance/global parent
uniqueness and selects no tree-position or conflict-resolution policy.
Only the final child's acceptance is signed, not a new chain of acceptance
certificates for every ancestor.

## Remembered acceptance choice demo

~~~sh
tdc intro choice-demo root root
tdc intro choice-demo root bob
~~~

`tdc intro choice-demo FIRST SECOND` takes exactly two fixture selectors:
`root` is `R -> Alice`; `bob` is `R -> Bob -> Alice`.
Both proposals share R and Alice keys, use default options, and pass individual
path proof; expected parent keys come independently from the fixture handles.
Both requests happen in one invocation through one `AcceptanceChoice`.
The owner's explicit first request chooses either proposal; incoming evidence
is not automatically accepted and there is no root preference.
An exact retry reuses the original proposal bytes.
Completion offers both selectors at both positions, including `root root`.

| Arguments | Second request | Exit |
|---|---|---|
| `root root` | Return the cached direct acceptance | 0 |
| `bob bob` | Return the cached indirect acceptance | 0 |
| `root bob` | Refuse with `ErrDifferentAcceptance` | Nonzero |
| `bob root` | Refuse with `ErrDifferentAcceptance` | Nonzero |

For `root bob`, stdout only:

~~~text
first proposal: R -> Alice
first acceptance verifies: true
second proposal: R -> Bob -> Alice
second path proof passes: true
second request: refused
same signature returned: false
~~~

The root CLI prints the returned refusal diagnostic on stderr and exits nonzero.
`go run ./cmd/tdc intro choice-demo root bob` also prints `exit status 1` on stderr.
The stdout block is not a full terminal transcript.
`same signature returned` requires success and actual byte equality;
the command does not measure signing-call counts.

Each invocation starts with fresh fixture keys and a fresh in-memory choice.
This creates no persistent wallet and does not enforce once-only enrollment.
It adds no reset API, file import, storage, network, or key-custody mechanism.
Only auxiliary signing state changes: no model `Edges`, `Received`, `Known`,
trust, device, recovery, or pairwise state changes.
It implements neither V19 `Introduce`/`VerifyReceived` nor the global
`CanIntroduce` no-existing-parent guard.

## Stored choice across database reopening

~~~sh
tdc intro stored-choice-demo root root
tdc intro stored-choice-demo root bob
~~~

`tdc intro stored-choice-demo FIRST SECOND` takes exactly two selectors:
`root` is `R -> Alice`; `bob` is `R -> Bob -> Alice`.
The invocation explicitly chooses either offer first, with no root preference
or automatic acceptance of incoming evidence.
Both positions complete both selectors, including repeated choices.

The first request calls `onboarding.SignAfterStoredChoice` and verifies the
acceptance, then closes the Vault and bbolt database.
The second request opens the same file and existing Alice/R Vault, independently
proves its selected path, and calls the same helper with the correct parent.
It reuses the exact signed proposals, provider, and fixture signing handles.

| Arguments | Second request after reopening | Exit |
|---|---|---|
| `root root` | Verify and return the saved direct acceptance | 0 |
| `bob bob` | Verify and return the saved indirect acceptance | 0 |
| `root bob` | Refuse with `ErrDifferentAcceptance` before signing | Nonzero |
| `bob root` | Refuse with `ErrDifferentAcceptance` before signing | Nonzero |

For `root bob`, stdout only:

~~~text
first proposal: R -> Alice
first acceptance verifies: true
database reopened: true
second proposal: R -> Bob -> Alice
second path proof passes: true
second request: refused
second acceptance verifies: false
~~~

Exact retries report `completed` and `second acceptance verifies: true`.
The helper commits selection before signing, verifies the signature, and saves
it in a separate transaction before returning success.
A completed retry rechecks the offer, expected root/parent, and matching child
handle, then verifies and returns the saved bytes without signing or encryption.
A selection without an acceptance is pending: signing or save failure returns
no signature, and an explicit retry of the same offer may sign again.
Invalid saved results are refused without signing or automatic repair.
Signing and saving are not atomic; this does not promise exactly-once signing
or message delivery. The CLI reports verification against the selected proposal,
not an unmeasured signing count.
The root CLI prints refusal diagnostics on stderr; `go run ./cmd/tdc` may also
report its nonzero exit there. The stdout block is not a full terminal transcript.

Each invocation is disposable: fresh fixture keys, a private temporary bbolt
file, and a random 32-byte provider secret.
Both success and refusal close resources, clear that secret, and remove the file.
There are no database-path, key-file, reset, or arbitrary-evidence options.
The private provider keeps one synchronized `1 << 24` development encryption
budget across reopening, independent of the two requests.
This is a demo policy, not durable lifetime accounting or production key custody.

This demonstrates same-process reopening of an intact file, not process restart
or production wallet recovery. Other Vaults, restored files, and direct key use
remain outside the guard. Only auxiliary choice and its completed acceptance
are persisted, not membership, human consent, or ancestor consent.
It changes no model `Edges`, `Received`, `Known`, trust, device, recovery, or
pairwise state and adds no V19 action; see the existing
[stored-choice rationale](../../docs/architecture/introduction-onboarding-rationale.md#stored-choice-application-helper).

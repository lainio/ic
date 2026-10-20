# Introduction path and acceptance demos

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

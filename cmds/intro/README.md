# Introduction path demo

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

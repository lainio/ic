# Managed storage — current system map

**Original reviewed baseline:** `01d27cb368b748f599739c597de753704f8561c4`.
**Naming update starting HEAD:** `7d16ccc5e5afcd38011edda9623250732369b8f8`
on `new-managed-db-c1-v3`.
**Purpose:** Explain implemented code, not authorize additional features.

This working-tree update uses `Database.OpenVault`, `Vault.Close`, and
`ErrVaultClosed` for the former `Database.UnlockVault`, `Vault.Lock`, and
`ErrLocked`.
The original baseline used the old names; current names below describe the
same lifecycle, with the sentinel message now `storage: vault handle closed`.

## Deployment at a glance

~~~text
One Go process
  Application owner / tests             Consumer with one Vault
             |                                    |
             +------> Database / Vault API <-------+
                              |       |
           admission / leases |       +-- Application-owned provider
                              |           (finite in-process test fixture)
                 Storage adapters
                      |                     |
                Internal Engine      record.Scope / codec
                /            \              |
       bbolt adapter     Memory adapter     local spending gate
             |                |
       bbolt library      Go heap tree
             |            (ephemeral)
    Memory-mapped DB file
         (persistent)

Engine backends are alternatives for a Database, not two stacked stores.
The codec is used with both. No external database service is required.
~~~

This is a map of the storage tests and library components.
It is not a claim that the IntroTree CLI is integrated with this storage API.
The application-owned provider is an in-process fixture shared by the consumer
test and `storage/example_test.go`.
Production key provisioning and lifetime accounting remain open.

The bbolt adapter calls bbolt's own `DB.View` and `DB.Update`.
It does not replace bbolt's durable transaction machinery.
The memory adapter independently implements the shared transaction contract.
A memory read snapshot is a stable view of an existing tree, not a backup file.

## What the boundaries mean

- **`Database`:** Owns one backend instance and the lifetime of its
  `Vault` handles.
- **`Vault`:** An open handle bound to one expected vault ID and key version.
- **Transaction adapter:** Routes logical namespaces, seals/opens records,
  and reports its first operation failure to the underlying transaction.
- **Record scope:** Owns derived encryption/index keys and invokes the codec.
- **Engine adapter:** Exposes the common storage operations to the facade.
- **bbolt:** Owns durable transactions, buckets, pages, and the database file.

The current abort-on-ignored-error policy is a wrapper policy.
It is not the definition of a bbolt transaction.
The naming update retains that policy.

The application supplies the expected vault ID, key ID, and provider to
`Database.OpenVault`.
The provider decides whether access is allowed and supplies the secret.
Storage verifies the existing encrypted identity record (manifest) before
returning a handle for reading and updating that vault.
`OpenVault` never creates or repairs missing or invalid state;
`CreateVault` creates absent state separately and returns no open handle.

`Vault.Close` ends only that handle's access.
It rejects new operations, waits for accepted work through engine completion,
clears owned key buffers best-effort, and releases the lease once.
Other independently opened handles and stored records remain usable and
unchanged.
The closed handle cannot be reopened; `Database.OpenVault` returns a new one
after provider authorization and a new reservation, which may be `0`.
Closing cannot revoke previously returned caller-owned data.
Repeated or concurrent calls wait for cleanup and return the same result,
including any admission denial and lease-release error.
A cleanup error does not make the closed handle reusable.
Accepted work retains its precharged allowance while closing waits;
closing does not recheck authorization.

`Database.Close` shuts down the engine and its remaining handles.
It stops new work, drains pending operations and handles,
attempts every cleanup, and retains cleanup and engine errors.
Repeated or concurrent calls wait for completion and return the same result.
Lifecycle calls from provider or operation callbacks remain unsupported.

New operations on an already closing handle return `ErrVaultClosed`, preserving
any stored admission-denial cause in the error chain.
`ErrClosed` takes precedence when the database is closed;
expired transactions still return `ErrTxClosed`.
An initial provider denial and cleanup failures retain their own causes;
they do not all become `ErrVaultClosed`.

## UML source diagrams

The diagrams share component names across deployment and sequence views.
They are editable PlantUML source, not screenshot images.
Detailed helper calls are grouped; see the source locators below.

### Use cases

~~~plantuml
@startuml
left to right direction
skinparam shadowing false
title Current API use cases — naming update from 7d16ccc
actor "Application owner\n(bootstrap / test setup)" as Owner
actor "Scoped consumer\n(receives one Vault)" as Consumer
actor "Application key provider\n(current fixture: in-process)" as Provider
rectangle "Managed storage API — implemented" {
    usecase "Create vault" as Create
    usecase "Open existing vault" as OpenExisting
    usecase "Read / update / iterate\nown namespace records" as Use
    usecase "Close this handle" as CloseVault
    usecase "Close database" as CloseDatabase
}
Owner -- Create
Owner -- OpenExisting
Owner -- CloseDatabase
Consumer -- Use
Consumer -- CloseVault
Provider -- Create
Provider -- OpenExisting
Provider -- Use : lease check at admission
note right of Use
  Precondition: a successfully opened handle.
  The consumer receives no Database, provider,
  raw engine, or other Vault through this API.
end note
note bottom of CloseDatabase
  Storage API roles, not claims about an integrated CLI.
  Snapshot export/import is not implemented here.
end note
@enduml
~~~

### Deployment

~~~plantuml
@startuml
skinparam shadowing false
title Current test deployment — one process, alternative backends
node "Development host" {
    node "One Go test process" {
        component "Application owner / test setup" as Owner
        component "Scoped consumer" as Consumer
        component "Database + Vault" as API
        component "Storage adapters" as Tx
        component "record.Scope + codec" as Codec
        component "Application-owned provider + leases\nFinite test fixture" as Provider
        component "Precharged local spending gate" as Gate
        interface "Internal Engine" as Engine
        component "bbolt adapter" as BoltAdapter
        component "bbolt library\nOwns durable transactions" as Bolt
        component "Memory adapter\nCopy-on-write transaction tree" as Memory
        artifact "Go heap tree\nEphemeral" as Heap
    }
    artifact "Database file\nMemory-mapped by bbolt" as File
}
Owner --> API : open database / create vault / open handle / close
Owner --> Provider : supply
Consumer --> API : own Vault only
API --> Provider : acquire / check / reserve / release
API --> Tx : admitted operation
Tx --> Codec : tokens / seal / verify
Provider --> Gate : allocates test allowance
Codec --> Gate : spend before seal
Tx --> Engine
Engine --> BoltAdapter : persistent backend
Engine --> Memory : alternative test backend
BoltAdapter --> Bolt
Bolt --> File
Memory --> Heap
note bottom of Engine
  Choose one backend per Database.
  Both are libraries in this process, not services.
end note
note bottom of Provider
  External means application-owned, not necessarily remote.
  No production accounting ledger is implemented.
end note
@enduml
~~~

### Open an existing vault

~~~plantuml
@startuml
skinparam shadowing false
autonumber
title Open an existing vault — current bbolt path
actor "Application owner" as Owner
participant "Database + Vault" as DB
participant "Provider / Lease" as Provider
participant "Storage adapters" as Tx
participant "record.Scope + codec" as Codec
participant "Engine adapter" as Engine
participant "bbolt" as Bolt
note over Owner, Bolt
  Happy path for existing state. Identity is supplied by the caller.
  Provider calls and crypto details are grouped for readability.
end note
Owner -> DB : OpenVault(ctx, VaultID, KeyID, provider, allowance)
DB -> DB : admit pending operation
DB -> Provider : Acquire; Check; Reserve; Secret
Provider --> DB : owned lease, borrowed secret, finite gate
DB -> Codec : Derive(secret, expected identities, gate)
Codec --> DB : key-owning Scope
DB -> DB : recheck admission and lease
DB -> Engine : View(verifyVaultState)
Engine -> Bolt : DB.View(callback)
Bolt -> Engine : read transaction callback
Engine -> Tx : storage verification callback
Tx -> Engine : read manifest in this transaction
Engine -> Bolt : Bucket.Get
Bolt --> Tx : encrypted bytes via adapter
Tx -> Codec : Token; Open at expected location
Codec --> Tx : verified manifest bytes
Tx -> Tx : check version and expected identities
Tx --> Engine : callback result
Engine --> Bolt : callback result
Bolt --> Engine : read transaction finished
Engine --> DB : verification result
DB -> DB : recheck publication; register handle
DB --> Owner : open Vault handle
note over DB, Codec
  Failed open: no handle is published.
  Clear temporary Scope and Release acquired lease.
  Verification does not create or repair missing/invalid state.
end note
@enduml
~~~

### Update encrypted records

~~~plantuml
@startuml
skinparam shadowing false
autonumber
title Update records — current bbolt path, not multiple DB transactions
actor "Scoped consumer" as Consumer
participant "Database + Vault" as Vault
participant "Provider / Lease" as Lease
participant "Storage adapters" as Tx
participant "record.Scope + codec" as Codec
participant "Local spending gate" as Gate
participant "Engine adapter" as Engine
participant "bbolt" as Bolt
Consumer -> Vault : Update(fn)
Vault -> Lease : Check at admission
Lease --> Vault : allowed
Vault -> Vault : pin Scope / active work
Vault -> Engine : Update(engine callback)
Engine -> Bolt : DB.Update(callback)
Bolt -> Engine : callback with one bbolt transaction
Engine -> Tx : construct scoped root handle
Tx -> Consumer : fn(scoped transaction)
Consumer -> Tx : Put(logical key, value)
Tx -> Codec : Token; verify existing record if present
Tx -> Codec : Seal(logical key, value)
Codec -> Gate : spend one precharged allowance
Gate --> Codec : allowed
Codec --> Tx : encrypted envelope
Tx -> Engine : Put(token, envelope)
Engine -> Bolt : Bucket.Put within active transaction
Bolt --> Tx : result via adapter
Tx --> Consumer : operation result
Consumer --> Tx : callback returns
Tx -> Tx : finalize first error; expire all handles
Tx --> Engine : final callback result
Engine --> Bolt : nil / error, or propagate panic
alt callback succeeds and no latched failure
    Bolt -> Bolt : Commit
else error or panic
    Bolt -> Bolt : Rollback
end
Bolt --> Engine : transaction completion
Engine --> Vault : result / propagated panic
Vault -> Vault : release active-work pin
Vault --> Consumer : result / propagated panic
note over Tx, Bolt
  Crypto failure can occur before Bucket.Put.
  The current adapter latches it even if the caller ignores it.
  bbolt still performs the durable commit or rollback.
end note
@enduml
~~~

## Runnable example

`ExampleVault` in `storage/example_test.go` uses a temporary bbolt file and
the finite provider from `storage/vault_consumer_test.go`.
Its `Output:` is checked by `go test`.
It creates a vault, opens a handle, writes and reads a nested greeting, closes
the handle and database, then reopens the file and reads through a new handle.
It demonstrates the library API within one process; it adds no CLI integration.

The provider's `vault` field is the ID of the vault it serves, not a secret.
Its `id` is the ID of the key version, neither the secret nor a cipher selector.
`rand.Read` fills the 32-byte `secret` buffer with random bytes;
storage derives its keys from those bytes.
The example keeps the provider and secret alive across file reopening.
The provider's mutex protects its counters; it is not a vault permission.

The initial `remaining: 2` counts encryptions not yet allocated
by this provider, not storage capacity or remaining reads.
One encryption is for the encrypted identity record and one for the greeting.
`CreateVault` reserves and spends the first;
`OpenVault(..., 1)` reserves the other before `Put` spends it.
Reopening with `0` reserves no new encryptions and still permits reading.
Authorized deletion and namespace creation also require no new encryption,
so zero allowance does not mean read-only access.
This provider's accounting is a test fixture, not a production guarantee.
Snapshots and production provider features remain deferred.

## Source locators

The component and helper locators originate at the original reviewed baseline.
They use the current names from this update based on the recorded starting HEAD;
`OpenVault` and `Vault.Close` were `UnlockVault` and `Vault.Lock`
at that baseline.
The example locator reflects the example already present at the starting HEAD.
The original map's provenance is not evidence of new test execution;
validation of this naming update is recorded in its run report.

- `storage/db.go`: `OpenBolt`, `NewMemory`, `CreateVault`, `OpenVault`,
  `releaseScope`, `Close`.
- `storage/vault.go`: `Vault`, `withScope`, `Close`.
- `storage/tx.go`: `Vault.View`, `Vault.Update`, `txState.finish`,
  `readTx.Get`, `writeTx.Put`, `writeTx.Delete`.
- `storage/namespace.go`: `ReadNS`, `WriteNS`, `Child`, `EnsureChild`, `Each`.
- `storage/internal/engine/bbolt.go`: `View`, `Update`, `Get`, `Put`.
- `storage/internal/engine/memory.go`: `begin`, `View`, `Update`, `Close`.
- `storage/internal/record/scope.go`: `Derive`, `Token`, `Seal`, `Open`,
  `Clear`.
- `storage/vault_consumer_test.go`: `consumerProvider`, `consumeVault`,
  `TestVaultConsumer`.
- `storage/example_test.go`: `ExampleVault`.

Snapshot persistence remains deferred.
The narrowed snapshot document records the scope decision that led to the
existing example; this naming update does not expand it.

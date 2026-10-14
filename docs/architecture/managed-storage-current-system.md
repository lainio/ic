# Managed storage — current system map

**Reviewed revision:** `01d27cb368b748f599739c597de753704f8561c4`.
**Purpose:** Explain implemented code, not authorize additional features.

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
The application-owned provider is an in-process fixture in the consumer test.
Production key provisioning and lifetime accounting remain open.

The bbolt adapter calls bbolt's own `DB.View` and `DB.Update`.
It does not replace bbolt's durable transaction machinery.
The memory adapter independently implements the shared transaction contract.
A memory read snapshot is a stable view of an existing tree, not a backup file.

## What the boundaries mean

- **Database:** Owns one backend instance and the lifetime of its Vault handles.
- **Vault:** A handle bound to one expected vault identity and key generation.
- **Transaction adapter:** Routes logical namespaces, seals/opens records,
  and reports its first operation failure to the underlying transaction.
- **Record scope:** Owns derived encryption/index keys and invokes the codec.
- **Engine adapter:** Exposes the common storage operations to the facade.
- **bbolt:** Owns durable transactions, buckets, pages, and the database file.

The current abort-on-ignored-error policy is a wrapper policy.
It is not the definition of a bbolt transaction.
Do not remove or generalize it in the next example task.

## UML source diagrams

The diagrams share component names across deployment and sequence views.
They are editable PlantUML source, not screenshot images.
Detailed helper calls are grouped; see the source locators below.

### Use cases

~~~plantuml
@startuml
left to right direction
skinparam shadowing false
title Current API use cases — 01d27cb
actor "Application owner\n(bootstrap / test setup)" as Owner
actor "Scoped consumer\n(receives one Vault)" as Consumer
actor "Application key provider\n(current fixture: in-process)" as Provider
rectangle "Managed storage API — implemented" {
    usecase "Create vault" as Create
    usecase "Unlock existing vault" as Unlock
    usecase "Read / update / iterate\nown namespace records" as Use
    usecase "Lock this handle" as Lock
    usecase "Close database" as Close
}
Owner -- Create
Owner -- Unlock
Owner -- Close
Consumer -- Use
Consumer -- Lock
Provider -- Create
Provider -- Unlock
Provider -- Use : lease check at admission
note right of Use
  Precondition: a successfully unlocked handle.
  The consumer receives no Database, provider,
  raw engine, or other Vault through this API.
end note
note bottom of Close
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
Owner --> API : open / create / unlock / close
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

### Unlock an existing vault

~~~plantuml
@startuml
skinparam shadowing false
autonumber
title Unlock an existing vault — current bbolt path
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
Owner -> DB : UnlockVault(ctx, VaultID, KeyID, provider, allowance)
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
DB --> Owner : unlocked Vault
note over DB, Codec
  Failed unlock: no handle is published.
  Clear temporary Scope and Release acquired lease.
  Verification does not create missing state.
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

## Next demonstrable use

Proposed, not yet implemented here: one `ExampleVault` using a temporary
bbolt file and a small finite provider, with `Output:` checked by `go test`.

Create/unlock, write/read one nested value, lock, close the database,
reopen it, and read with the same provider/key generation and zero new
sealing allowance within the same process.

Do not add snapshots, a production provider, or a new test framework.
This makes the current API's setup cost visible before more infrastructure.

## Source locators

All repository paths below refer to the reviewed revision above.
No new repository tests were run in producing this map.

- `storage/db.go`: `OpenBolt`, `NewMemory`, `CreateVault`, `UnlockVault`,
  `releaseScope`, `Close`.
- `storage/vault.go`: `Vault`, `withScope`, `Lock`.
- `storage/tx.go`: `Vault.View`, `Vault.Update`, `txState.finish`,
  `readTx.Get`, `writeTx.Put`, `writeTx.Delete`.
- `storage/namespace.go`: `ReadNS`, `WriteNS`, `Child`, `EnsureChild`, `Each`.
- `storage/internal/engine/bbolt.go`: `View`, `Update`, `Get`, `Put`.
- `storage/internal/engine/memory.go`: `begin`, `View`, `Update`, `Close`.
- `storage/internal/record/scope.go`: `Derive`, `Token`, `Seal`, `Open`,
  `Clear`.
- `storage/vault_consumer_test.go`: `consumerProvider`, `consumeVault`,
  `TestVaultConsumer`.

Snapshot persistence is only a proposal at this revision.
The narrowed snapshot document records the new example-first scope.

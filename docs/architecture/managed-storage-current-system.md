# Managed storage — current system map

**Original reviewed baseline:** `01d27cb368b748f599739c597de753704f8561c4`.
**Naming update starting HEAD:** `7d16ccc5e5afcd38011edda9623250732369b8f8`
on `new-managed-db-c1-v3`.
**White-box guide starting HEAD:** `1d673911aa30e092e60744e92055941e5d9d7bb1`
on `new-managed-db-c1-v3`; initially clean.
This equals `REVIEWED_BASE`, whose ancestry check passed.
**Purpose:** Explain implemented code, not authorize additional features.

Start with `notes.Put([]byte("greeting"), []byte("hello"))`.
The package adds keyed lookup, authenticated encryption of the logical
key/value, and access-handle lifetime management around that familiar operation.
It also tracks encryption quota reserved in advance, called a precharged
allowance.
bbolt still owns the durable transaction.

Read [Core concepts](#core-concepts), then the
[allowance walkthrough](#encryption-allowance-walkthrough), then the
[record walkthrough](#record-write-and-read-walkthrough).
The [deployment overview](#deployment-at-a-glance) and
[UML source diagrams](#uml-source-diagrams) show the component boundaries.

The earlier naming update introduced `Database.OpenVault`, `Vault.Close`, and
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
See [Unfinished guarantees](#unfinished-guarantees) for the production boundary.

The bbolt adapter calls bbolt's own `DB.View` and `DB.Update`.
It does not replace bbolt's durable transaction machinery.
The memory adapter independently implements the shared transaction contract.
A memory read snapshot is a stable view of an existing tree, not a backup file.

## Core concepts

These terms describe the current implementation.
Code links give functions and line ranges at the white-box guide starting HEAD.
The [source notes](#source-locators) distinguish proposals and
primitive guidance.

| Concept | Meaning here | Read the code |
|---|---|---|
| Logical key/value | Application bytes: `greeting` / `hello`; the logical key is not a cryptographic key. | `encodePlaintext`, [`encoding.go:41–71`][plaintext] |
| Provider secret, `KE`, `KI` | A supplied 32-byte secret derives `ke` for encryption and `ki` for lookup indexes. | `derive`, [`keys.go:13–32`][derive] |
| `VaultID`, `KeyID` | Supplied vault and key-version identifiers; neither is secret material or authorization. | [`keyprovider.go:5–21`][provider] |
| Lookup token | Keyed HMAC lookup result stored as the backend key; not an access credential. | `lookupToken`, [`keys.go:34–51`][token] |
| Envelope | Backend value: header, nonce, encrypted logical key/value, authentication tag. | `sealRecord`, [`record.go:15–27`][seal-record]; `sealEnvelope`, [`aead.go:18–39`][seal-envelope] |
| Cryptographic context / AAD | Expected vault/location and header/token authenticated with a record; not Go's `context.Context` or metadata secrecy. | `encodeContext`, [`encoding.go:129–151`][context]; `encodeAAD`, [`encoding.go:181–194`][aad] |
| Manifest | Encrypted vault identity record using the same record codec. | `createVaultState`, `verifyVaultState`, [`manifest.go:37–95`][manifest] |
| `record.Scope` | Owned derived keys, identity binding, and spending function; not a transaction. | `Scope`, `Derive`, [`scope.go:15–46`][scope] |
| Provider / `Lease` | Application implementation / one acquired access object supplying checks and a borrowed secret. | `KeyProvider`, `Lease`, [`keyprovider.go:12–48`][lease] |
| Admission / active-work pin | Check permission/lifetime, then track accepted work so close waits before key cleanup; no quota allocation. | `withScope`, `Close`, [`vault.go:36–87`][vault-lifecycle] |
| Unreserved budget / reserved allowance | `p.remaining` is unallocated quota; captured `n` is unused quota in one reservation. | `consumerLease.Reserve`, [`vault_consumer_test.go:45–62`][reserve] |
| Precharging / `Reserve` | Deduct quota in advance and return its spending function; create no ciphertext. | `OpenVault`, [`db.go:139–150`][open-reserve]; [`consumerLease.Reserve`][reserve] |
| Gate / local spending gate | A `func() error` consumes one reserved encryption or fails; no authorization recheck or remote call. | Closure in [`consumerLease.Reserve`][reserve]; call in [`sealEnvelope`][seal-envelope] |
| `Database` / `Vault` | One backend and its handles / one open handle bound to expected vault and key IDs. | [`db.go:23–34`][database]; [`vault.go:12–30`][vault] |
| Engine adapter | Common backend operations; the bbolt implementation delegates to bbolt. | `boltEngine.View`, `Update`, [`bbolt.go:46–74`][bolt-tx] |

The secret is input to derivation, not the logical key named `greeting`.
HKDF uses separate purpose labels for `KE` and `KI`, bound to the supplied
vault and key IDs.
Namespaces share those derived keys; their paths enter record context instead.
This is the implemented separation between encryption and equality lookup.

A lease is acquired once for a handle; admission calls its `Check` for each
`View` or `Update`.
The returned spending function has a narrower job: consume the reservation
when encryption occurs.
The example's `Check` and `Release` return `nil`; they demonstrate neither
revocation nor production key custody.

## What the boundaries mean

`Database.OpenVault` verifies the manifest against the externally supplied
identity before publishing a handle.
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

`rand.Read` fills the 32-byte `secret` buffer with random bytes;
the example keeps the provider and secret alive across file reopening.

## Encryption allowance walkthrough

The example permits two encryptions: one for the encrypted identity record
(manifest), and one for the greeting.
The two counters below track allocation and spending of that quota.

### Why count encryptions and reserve them

Current encryption uses AES-GCM with random nonces through
`newEnvelopeAEAD` in [`aead.go:59–66`][new-aead].
A nonce is the per-encryption value stored with the ciphertext.
A per-key usage limit bounds random-nonce collision risk;
it is not a bbolt capacity limit.
The installed standard-library documentation requires at most `2^32` messages
encrypted with a given key; see the separate
[primitive source note](#primitive-source).
A counter alone guarantees neither nonce uniqueness nor general cryptographic
safety.

The [record design, D2][record-design] proposes a stricter lifetime cap of
`2^24` encryptions per actual derived `KE`, across namespaces, files, processes,
reopens, and restores.
That remains a proposed lifetime guarantee.
Current `maxAllowance` and `OpenVault` bound each reservation request to `2^24`
([`db.go:21`][max-allowance], [`db.go:139–150`][open-reserve]).
Neither this request bound nor the example's tiny budget proves an enforced
lifetime total.

**Chosen policy:** reserve a batch before entering the engine transaction,
then spend locally while sealing.
The [record design's OPEN D4][record-design] and
[Vault proposal's access boundary][vault-design] state the rationale:
keep provider/accounting I/O outside the engine transaction.
`CreateVault` and `OpenVault` implement this ordering;
the [lease contract][lease] requires a local gate with no provider I/O.
AES-GCM and bbolt do not prescribe this `Reserve`/gate API.
Precharging allocates encryption quota, not pages, placeholders, money,
partially written records, or a stream format.
The example needs no remote accounting service.

### The example's counters

In [`consumerProvider` and `consumerLease.Reserve`][consumer-provider]:

- `p.remaining` is quota the provider has **not** allocated to a reservation.
- Captured `n` in the returned closure is unused quota inside **that**
  reservation; it is not another field in `consumerProvider`.

The provider's mutex protects both counters; it does not grant vault access.
These are the states after the named steps in [`ExampleVault`][example].
“Encryptions performed” is explanatory bookkeeping, not a fixture field.

| Step completed | Unreserved `p.remaining` | Unused handle allowance | Encryptions performed |
|---|---:|---:|---:|
| Provider constructed | 2 | Not applicable | 0 |
| `CreateVault` | 1 | Not applicable | 1 |
| `OpenVault(..., 1)` | 0 | 1 | 1 |
| `Put` of greeting | 0 | 0 | 2 |
| `Close` and reopen with `OpenVault(..., 0)` | 0 | 0 | 2 |
| Read greeting | 0 | 0 | 2 |

`CreateVault` has its own temporary reservation of one, spends it on the
manifest, then clears its scope and releases its lease
([`db.go:88–111`][create-vault], [`createVaultState`][manifest]).
There is no published handle at that step.
Reservation alone creates no ciphertext: after the first `OpenVault`,
`p.remaining` is zero but the handle still has permission for one encryption.
Opening verifies the manifest without spending.
The example also reads before closing; that read leaves the counters unchanged.
Reopening in the same process retains the provider's zero balance and obtains
a new gate whose captured `n` is zero.

Two separate no-refund rules apply:

- **Unused quota:** discarding a reservation forfeits its unused allowance.
  This is our conservative allocation policy, not evidence that those
  encryptions occurred.
  `Reserve` deducts the whole batch; `Scope.Clear` drops the gate and never
  refunds it ([`scope.go:96–106`][clear]).
- **Performed encryption:** rollback cannot undo an encryption already done.
  `sealEnvelope` spends before AES-GCM `Seal`, and a failed backend write or
  commit does not refund that spend ([`aead.go:30–38`][seal-envelope]).

Zero allowance is not a read-only authorization flag.
Reads, verified deletes, and namespace creation require no new encryption
in the existing API ([`Get` and `Delete`][record-ops],
[`EnsureChild` and `writeChild`][write-child]).
Replacing a record can spend another encryption even though record count stays
constant; [`writeTx.Put`][put] seals after verifying the existing record.

## Record write and read walkthrough

For the existing `notes` / `greeting` / `hello` example, the backend receives
a lookup token as its key and an envelope as its value.
The envelope encrypts the logical key **and** value, not just `hello`.
Conceptually: logical key/value → keyed token / authenticated envelope.
This is a reading route, not another wire-format specification.

`OpenVault` has already called `record.Derive` to create the scope.
[`Derive`][scope] copies the borrowed secret, derives `ke` and `ki` through
[`derive`][derive], then clears the temporary secret copy.
Derivation occurs at scope creation, not for each record or namespace.
Per-record work uses those keys for lookup and constructs the AES-GCM object
in [`newEnvelopeAEAD`][new-aead].

### Put route

1. [`Vault.Update`, `tx.go:42–58`][update] calls [`withScope`][vault-lifecycle].
   Admission checks database/handle state and `Lease.Check`, then increments
   `v.active` before entering one engine `Update` transaction.
   The scope stays pinned through engine completion, including error unwinding.
   On the bbolt path, [`boltEngine.Update`][bolt-tx] calls bbolt's `DB.Update`.
2. `EnsureChild([]byte("notes"))` routes to the nested namespace through
   [`writeChild`, `namespace.go:126–148`][write-child].
   Its cryptographic path has the reserved record prefix byte `0x01`,
   followed by the literal `notes` segment.
   [`writeTx.Put`, `tx.go:139–150`][put] calculates the token for `greeting`,
   checks namespace-name conflicts, and calls `readTx.open`.
   Any existing record must pass full verification before replacement.
3. [`Scope.Seal`, `scope.go:70–81`][scope-seal] encodes the expected context
   and calls [`sealRecord`][seal-record].
   That helper encodes both `greeting` and `hello`, computes its own token,
   and calls [`sealEnvelope`][seal-envelope].
   The latter builds the header and AAD, calls the local spending function,
   and only on success calls AES-GCM `Seal`.
   The returned envelope contains the header plus nonce, ciphertext, and tag.
4. `writeTx.Put` sends `token[:]` and the envelope to the records container.
   [`boltWriteTx.Put`, `bbolt.go:182–191`][bolt-put] copies the bytes and calls
   `Bucket.Put` inside that same transaction.
5. [`txState.fail` and `finish`, `tx.go:82–111`][tx-state] retain the first
   operation error and include it in the callback result.
   Thus an ignored codec failure still prevents commit.
   `err2` error recovery runs before finalization; unexpected/runtime panics
   abort and propagate.
   This wrapper policy is not another database log or transaction engine:
   bbolt owns durable commit/rollback, then `withScope` releases the active pin.

### Get route

1. [`Vault.View`, `tx.go:22–36`][view] uses the same admission and pinning
   boundary around one engine read transaction.
   [`Child`, `namespace.go:109–120`][child] selects `notes` without creating it.
2. [`readTx.Get` and `open`, `tx.go:113–137`][get] calculate the expected token
   from the requested `greeting` and scoped path, check name conflicts,
   and fetch the envelope.
   [`boltReadTx.Get`, `bbolt.go:108–117`][bolt-get] retrieves and copies it.
   Only backend absence yields `found == false` without an error.
3. [`Scope.Open`, `scope.go:83–94`][scope-open] supplies the expected identity
   and context to [`openRecord`, `record.go:29–51`][open-record].
   [`openEnvelope`, `aead.go:41–57`][open-envelope] checks envelope structure
   and expected `KeyID`, builds AAD from the expected location,
   and authenticates and decrypts the body.
   Stored headers never choose the secret or expected identity.
4. `openRecord` decodes the authenticated plaintext, recomputes and verifies
   its token, and compares the decoded logical key with requested `greeting`.
   [`decodePlaintext`][plaintext] returns owned key/value bytes;
   `Get` returns the verified `hello` bytes with `found == true`.
   No allowance is spent.

[`Each`, `namespace.go:150–168`][each] obtains original keys from decrypted
payloads through the same `Scope.Open`, with no requested key to compare.
It does not reverse HMAC tokens.
A token is neither a credential nor a ciphertext to decrypt.

Context/AAD binds records to their expected identity and location.
It does not hide metadata: namespace names/tree, identifiers, headers,
nonces/tags, tokens, counts, lengths, and equality/access patterns
remain visible.
The namespace structure itself is unauthenticated metadata
([`namespace.go:13–18`][namespace-contract]).
Record authentication does not provide deletion or replay protection;
authentic restored bytes do not establish fresh application authority.

## Unfinished guarantees

The current example/test providers enforce finite in-process allowances.
Durable lifetime accounting, freshness across restart/restore, and production
key custody remain unfinished.
The [Vault proposal's conditional accounting section][accounting-design]
describes obligations, not an implemented ledger or remote service.
Reopening the example's file preserves a live provider; it proves none of
those production guarantees.

Snapshot persistence remains deferred under the
[narrowed snapshot scope][snapshot-scope].
The memory backend remains ephemeral; this guide adds no CLI integration,
snapshot implementation, or V19 application-recovery guarantee.

## Source locators

The original component map and diagrams retain their earlier provenance.
`OpenVault` and `Vault.Close` were `UnlockVault` and `Vault.Lock`
at the original baseline.
All code ranges linked above were checked at
`1d673911aa30e092e60744e92055941e5d9d7bb1`, the white-box guide starting HEAD.
The two Go comment pointers added with this guide shift subsequent line numbers;
function names remain navigation aids.
Neither historical provenance nor this source inspection is new test execution.

Additional lifecycle and backend entry points at that revision:

- [`storage/db.go:36–49`][constructors]: `OpenBolt`, `NewMemory`.
- [`storage/db.go:113–170`][open-vault]: `OpenVault`, `releaseScope`.
- [`storage/db.go:172–204`][close-db]: `Database.Close`.
- [`storage/internal/engine/memory.go:48–111`][memory]: `begin`, `View`,
  `Update`, `Close`.
- [`storage/vault_consumer_test.go:64–142`][consumer]: `consumeVault`,
  `TestVaultConsumer`.

Rationale and open obligations come from the historical proposals:

- `managed-storage-record-design.md:31–39, 65`: context, derivation,
  proposed lifetime cap, and OPEN D4 accounting.
- `managed-storage-vault-design.md:31–43, 45–60`: reservation/admission policy
  and conditional production accounting.
- `managed-storage-snapshot-design.md:26–39, 79–88`: deferred scope and
  absent production guarantees.

### Primitive source

Separately from those proposals, the installed `go1.27.1 linux/arm64`
standard-library documentation was inspected with
`go doc -src crypto/cipher.NewGCMWithRandomNonce`.
Source: `/usr/local/go/src/crypto/cipher/gcm.go:79–89`,
`NewGCMWithRandomNonce`: random 96-bit nonces and at most `2^32` messages
encrypted with a given key to limit collision risk.
The preceding environment check,
`go env GOCACHE GOTOOLCHAIN GOPROXY GOSUMDB GOFLAGS`, returned
`/home/parallels/.cache/go-build`, `local`, `off`, `off`, `-mod=readonly`.
This primitive limit is separate from the proposed storage lifetime policy.

[plaintext]: ../../storage/internal/record/encoding.go#L41-L71
[derive]: ../../storage/internal/record/keys.go#L13-L32
[provider]: ../../storage/keyprovider.go#L5-L21
[token]: ../../storage/internal/record/keys.go#L34-L51
[seal-record]: ../../storage/internal/record/record.go#L15-L27
[seal-envelope]: ../../storage/internal/record/aead.go#L18-L39
[context]: ../../storage/internal/record/encoding.go#L129-L151
[aad]: ../../storage/internal/record/encoding.go#L181-L194
[manifest]: ../../storage/manifest.go#L37-L95
[scope]: ../../storage/internal/record/scope.go#L15-L46
[lease]: ../../storage/keyprovider.go#L12-L48
[vault-lifecycle]: ../../storage/vault.go#L36-L87
[reserve]: ../../storage/vault_consumer_test.go#L45-L62
[open-reserve]: ../../storage/db.go#L139-L150
[database]: ../../storage/db.go#L23-L34
[vault]: ../../storage/vault.go#L12-L30
[bolt-tx]: ../../storage/internal/engine/bbolt.go#L46-L74
[new-aead]: ../../storage/internal/record/aead.go#L59-L66
[record-design]: managed-storage-record-design.md#2-d2
[vault-design]: managed-storage-vault-design.md#proposed-access-boundary
[max-allowance]: ../../storage/db.go#L21
[consumer-provider]: ../../storage/vault_consumer_test.go#L20-L62
[example]: ../../storage/example_test.go#L16-L84
[create-vault]: ../../storage/db.go#L88-L111
[clear]: ../../storage/internal/record/scope.go#L96-L106
[record-ops]: ../../storage/tx.go#L113-L165
[write-child]: ../../storage/namespace.go#L126-L148
[put]: ../../storage/tx.go#L139-L150
[update]: ../../storage/tx.go#L42-L58
[scope-seal]: ../../storage/internal/record/scope.go#L70-L81
[bolt-put]: ../../storage/internal/engine/bbolt.go#L182-L191
[tx-state]: ../../storage/tx.go#L82-L111
[view]: ../../storage/tx.go#L22-L36
[child]: ../../storage/namespace.go#L109-L120
[get]: ../../storage/tx.go#L113-L137
[bolt-get]: ../../storage/internal/engine/bbolt.go#L108-L117
[scope-open]: ../../storage/internal/record/scope.go#L83-L94
[open-record]: ../../storage/internal/record/record.go#L29-L51
[open-envelope]: ../../storage/internal/record/aead.go#L41-L57
[each]: ../../storage/namespace.go#L150-L168
[namespace-contract]: ../../storage/namespace.go#L13-L18
[accounting-design]: managed-storage-vault-design.md#conditional-embedded-accounting
[snapshot-scope]: managed-storage-snapshot-design.md#2-what-remains-deferred
[constructors]: ../../storage/db.go#L36-L49
[open-vault]: ../../storage/db.go#L113-L170
[close-db]: ../../storage/db.go#L172-L204
[memory]: ../../storage/internal/engine/memory.go#L48-L111
[consumer]: ../../storage/vault_consumer_test.go#L64-L142

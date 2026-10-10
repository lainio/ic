# Managed Storage v0.2 — implementation plan

Status: proposal for review; inspection only, 2026-10-10. No implementation or port is authorized by this document.
Normative storage contract: `docs/architecture/managed-storage.md:L14-L88`; all new APIs and checkpoints below are proposals.
Sources are local working copies; prefixes below identify repository-relative citations:
- **T** = `/home/parallels/go/src/github.com/lainio/ic` (target).
- **L** = `/home/parallels/go/src/github.com/findy-network/findy-common-go` (read-only legacy).
- **S / SPEC_REPO** = `/home/parallels/go/src/github.com/optechlab/intro-tree` (read-only semantics).
- **B** = locally cached `/home/parallels/go/pkg/mod/go.etcd.io/bbolt@v1.4.3` (dependency source only).

## 1. Inventory and verified hazards

The target has domain packages (`chain`, `identity`, `node`, `pw`, `key`), CLI/protocol code, and `enclave` persistence; no `storage` package exists.
The current consumer path is CLI/protocol → global `enclave` → legacy `crypto/db`; user/PW serialization belongs above generic storage (`T:internal/protocol/protocol.go:L45-L66`, `T:enclave/enclave.go:L7-L32,L115-L155,L707-L711`).
Target dependencies already include Go 1.24, err2 v1.3.0, glog v1.2.5, and indirect bbolt v1.4.3; legacy uses err2 v1.0.0 and bbolt v1.3.9 (`T:go.mod:L1-L17,L40-L47`, `L:go.mod:L7-L21`). The local legacy checkout is reference code, not proof of the target's pinned v0.2.71 dependency behavior.

| Piece | Classification | Rationale and inspected source |
|---|---|---|
| err2 / assert / glog conventions | Keep | Named error results, deferred handlers, and test assertions fit the target; retain without logging secrets (`L:crypto/db/db.go:L190-L202`, `T:enclave/enclave_test.go:L48-L53`). |
| bbolt operations | Adapt | Useful embedded primitive and 0600 open; replace lazy reopening and per-call transaction wrappers (`L:crypto/db/db.go:L56-L68,L119-L135,L190-L224`). |
| Legacy `Handle` / `Data` hooks | Replace | No multi-operation closure or nested namespace API; optional transforms cannot enforce mandatory encryption or ownership (`L:crypto/db/handle.go:L8-L18`, `L:crypto/db/db.go:L138-L170`). |
| Memory backend | Replace | Per-bucket locking and direct map mutation lack transaction rollback; backup/wipe/close differ from durable behavior (`L:crypto/db/mem.go:L12-L23,L44-L90,L118-L140`). |
| AES-GCM wrapper / index hooks | Adapt / Replace | Keep standard AEAD concept; replace unversioned nonce+ciphertext with nil AAD, and unkeyed indexes (`L:crypto/crypto.go:L20-L30,L40-L64`, `T:enclave/enclave.go:L663-L677`). |
| Backup and lifecycle | Replace | Preserve snapshot intent; replace close-and-copy, auto-reopening Close, and nonterminal global shutdown (`L:crypto/db/db.go:L97-L105,L376-L400,L432-L444`). |
| Globals, ticker, filename prefix, Findy helpers | Drop | No singleton, instance registry, built-in scheduling, or magic memory filename; `backup` and `x` are removable coupling (`L:crypto/db/db.go:L14-L20,L71-L94,L342-L364`). |
| Application enclave / signing enclave | Adapt later | Keep outside storage: global storage cipher/default key and unkeyed hash do not define a Vault; signing handles are a separate concern (`T:enclave/enclave.go:L46-L98,L663-L677`, `T:key/crypto.go:L15-L31,L128-L138,L173-L181`). |

**Ownership:** ordinary `Data.get` already copies inputs; this is not an unfixed blanket write-alias bug. Untransformed/identity-transformed bulk reads still return bbolt-backed or memory-owned slices; custom Read/Write/Use callbacks can retain aliases. Plain `Data.set` copies only into the caller's existing buffer, potentially truncating (`L:crypto/db/db.go:L151-L170,L311-L325`, `L:crypto/db/mem.go:L52-L53,L84-L89,L107-L114`).
**Errors and atomicity:** inspected bbolt callbacks already propagate Update/View/ForEach errors through `try.To`; do not claim nested errors are currently discarded. The remaining API cannot group calls atomically; user-counter persistence and user persistence are separate calls (`L:crypto/db/db.go:L190-L224,L259-L274,L311-L327`, `T:enclave/enclave.go:L271-L283,L762-L781`).
**Semantic parity:** memory accepts empty keys that bbolt rejects, exposes unsynchronized status replacement, and makes Wipe a no-op (`L:crypto/db/mem.go:L44-L54,L128-L140`; `B:bucket.go:L450-L452`). Missing buckets are dereferenced rather than given a common error.
**Backup:** the instance mutex excludes its own operations throughout close/copy, so the legacy backup is not intrinsically torn under sole ownership. Closing releases the file lock, permitting another owner during copying; copying also ignores destination Close errors and provides no Sync (`L:crypto/db/db.go:L379-L400`, `L:backup/backup.go:L30-L43`; `B:db.go:L241-L249`).
**Tests:** legacy CRUD, bulk reads/transforms, memory equivalents, and dirty-backup flags exist, but DB “crypto” helpers merely clone bytes; backup tests do not reopen snapshots (`L:crypto/db/db_test.go:L103-L213,L215-L382,L387-L400`). Real crypto has only constructor/round-trip tests (`L:crypto/crypto_test.go:L17-L55`).
Target enclave tests cover memory-backed users/PWs/counters and use `assert.PushTester`; they are shared-state tests, not a backend contract suite (`T:enclave/enclave_test.go:L18-L63,L65-L153`). `make test` selects six packages, excluding enclave and future storage (`T:Makefile:L3-L9,L60-L61`).
The imported acator enclave exposes signing/wrapped-key handles, not a Vault KeyProvider; its local cached v0.2.98 source confirms `KeyHandle` and `Secure` interfaces (`github.com/findy-network/findy-agent-auth@v0.2.98/acator/enclave/enclave.go:L21-L27,L115-L134`, relative to `/home/parallels/go/pkg/mod`).

Known V19 mismatch: multi-root creation remains; global user enumeration also lacks the v0.2 consumer scope. Neither is reusable storage semantics (`T:enclave/enclave.go:L762-L769`, `T:cmds/id/users.go:L33-L46`; context: `T:docs/implementation/Current_Go_Implementation_Reality.md:L63-L73`).
All four required S references were read. V19 explicitly separates snapshot bytes from restored authority; generic snapshots cannot establish conformance (`S:docs/IntroTree_Model_Index.md:L399-L418`, `S:docs/contracts/IntroTree_StateSemantics_Contract.md:L481-L502`, `S:docs/contracts/IntroTree_Implementation_Action_Map.md:L208-L229`, `S:docs/contracts/IntroTree_Conformance_Test_Map.md:L429-L440`).

## 2. Proposed boundaries and minimal API sketch

**Physical Database** owns backend, file locks, transaction admission, close, and whole-database snapshots. **Vault** owns one cryptographic domain and scoped access. **Wallet** is an application object that receives a designated unlocked Vault; it owns serialization and IntroTree policy.
One Database can hold several Vaults; several Databases can use separate files. Neither filename nor wallet identity is a cryptographic boundary.
Provisional `storage` facade and `storage/internal/engine` keep bbolt types and raw access private. No public raw transaction API, Findy imports, wallet types, services, ORM, or protocol logic.

```go
// Pseudocode only; names and lease details require review.
OpenBolt(path string, opts Options) (*Database, error)
NewMemory(opts Options) (*Database, error)
(db *Database) CreateVault(ctx context.Context, id VaultID, keyID KeyID, p KeyProvider) error
(db *Database) SelectVault(id VaultID) (LockedVault, error)
(v LockedVault) Unlock(ctx context.Context, p KeyProvider) (Vault, error)
type Vault interface {
    View(func(ReadTx) error) error
    Update(func(WriteTx) error) error
    Lock() error
}
type ReadTx interface { Root() ReadNS }
type WriteTx interface { Root() WriteNS }
type ReadNS interface {
    Child(name []byte) (ReadNS, error)
    Get(key []byte) ([]byte, bool, error)
    Each(func(key, value []byte) error) error
}
type WriteNS interface {
    ReadNS
    ChildForUpdate(name []byte) (WriteNS, error)
    EnsureChild(name []byte) (WriteNS, error)
    Put(key, value []byte) error
    Delete(key []byte) error
}
type KeyProvider interface {
    Acquire(ctx context.Context, vault VaultID, key KeyID) (KeyLease, error)
}
type KeyLease interface { KeyID() KeyID; Secret() []byte; Check() error; Release() error }
(db *Database) Close() error
(db *Database) Snapshot(w io.Writer) error // administrative, all vaults
```

Application authorization and an appropriately scoped provider precede Unlock; knowing a VaultID/KeyID is not authorization. Creation is explicit; Unlock verifies an authenticated vault manifest and never creates missing state or substitutes a default key. Reject unrecognized database formats; legacy data migration is a later task.
View observes a stable snapshot; Update groups operations across that Vault's namespaces, with read-your-writes and all-or-nothing commit. No cross-Vault transaction guarantee. Memory initially uses serialized writers and immutable committed roots with copy-on-write transaction state.
Namespace names are byte segments, not slash-joined paths; missing namespaces return a defined error and only EnsureChild creates them in Update. Namespace/value name collisions return ErrConflict. Keys must be nonempty; empty values are distinct from absence; Delete of an absent record succeeds; Each order is unspecified on both backends.
Inputs and all returned/iteration bytes are copied. Tx/namespace handles expire with the closure and are not shared across goroutines. Return callback/commit/crypto errors; err2 error panics roll back, unexpected panics roll back then propagate. Callbacks are never retried automatically; recursive transactions and lifecycle calls inside closures are unsupported.
Close is terminal and idempotent: stop admission, drain active transactions, release leases/file locks; explicit Open creates a new instance. Vault Lock revokes that scope and drains its transactions. An application coordinates final shutdown; there is no global registry or lazy reopen.

## 3. Security requirements and proposals

Mandatory v0.2 requirements apply to memory and bbolt through the same Vault layer: independent per-Vault keys, external provisioning, authenticated encryption, no plaintext fallback, and no default/database-wide key.
**Record format proposal (approval D2):** a bounded, versioned envelope carries suite, KeyID, nonce, and ciphertext/tag. Authenticate header fields plus a domain tag, stable VaultID, canonical full namespace path, and logical-record identity; reject unknown versions/IDs, truncation, and authentication failure without returning plaintext.
**Key/nonce proposal (D2/D4):** AES-256-GCM with fresh CSPRNG 96-bit nonces and purpose-separated HKDF-SHA-256 encryption/index keys from independently provisioned 32-byte Vault secrets. Never reuse a nonce under a key, including aborted writes/retries/restores; approve and enforce an aggregate per-key usage limit below 2^32 encryptions across files/processes/restores. RNG or provider failures abort.
**Index proposal (D3):** HMAC-SHA-256 keyed lookup tokens over canonical context and logical key; never unkeyed SHA-256 for sensitive identifiers. Bind that token as the record identity in AAD; encrypt the original logical key with the value, then verify the token after decryption so Each can recover keys safely. Update any index and record together; secondary query indexes are deferred.
Public metadata may include VaultIDs, namespace structure, format/KeyIDs, sizes, counts, equality and access patterns. HMAC equality lookup does not provide range queries or hide repetition. Metadata policy and collision handling must be documented before the format is frozen.
Provider owns provisioning, authorization, key availability and revocation; storage owns AEAD/context/encoding. Scoped leases must fail closed on denial/expiry, release on all exits, and avoid provider calls under engine locks. Storage copies borrowed key bytes at acquisition and clears its copy on release, best effort; non-exportable hardware keys need a separately reviewed adapter, not a generalized plugin framework.
Isolation does not protect against a compromised process holding keys, deletion, all metadata leakage, or replay of valid old records/snapshots. Restoration must not recreate IntroTree authority; that application policy and full key rotation remain later milestones (`T:docs/architecture/managed-storage.md:L31-L60,L71-L75`).

## 4. Five proposed coding checkpoints

Each checkpoint requires a subsequent coding authorization. Only the listed new packages/files are in scope; existing consumers, the design contract, Go module files, and the other repositories stay untouched.
1. **Private bbolt transaction slice — recommended first.** Add only `storage/internal/engine/{engine.go,bbolt.go,contract_test.go,bbolt_test.go}`: explicit open/terminal close, one namespace, byte Get/Put/Delete, View/Update. Deliver two-record commit and injected-failure rollback with reopen verification; copy input/output bytes and propagate nested errors. Tests: commit, error/panic rollback, retained bytes, closed handle. No public Vault or persistent plaintext application API.
2. **Memory parity and nested namespaces.** Extend only `storage/internal/engine/`, adding `memory.go`, memory tests and namespace tests. Deliver the same contract suite for both factories with nested creation, read snapshots, serialized writes and discarded failed updates. Tests: nested rollback, missing/empty semantics, namespace/value collisions, snapshot isolation, concurrent increments, expired handles and race detection.
3. **Private encrypted record codec.** Add only `storage/internal/record/` with format, AEAD, derivation/index code and tests after D2/D3 approval. Deliver versioned context-bound envelopes and protected lookup tokens; no public persistence API yet. Tests: round trip, malformed envelopes, tampering, wrong vault/path/key/record, domain separation, RNG failure and allocation ownership.
4. **Encrypted Vault facade and external provider.** Add only `storage/{db.go,vault.go,tx.go,keyprovider.go,errors.go,doc.go,*_test.go}` and necessary internal wiring after D4 approval. Deliver explicit create/select/unlock/lock, authenticated manifests and mandatory codec use on both backends. Tests: denied/wrong-key unlock, no default key, encrypted stored keys/values, two Vaults in one file and separate files, rollback on crypto/provider error, lease release, revocation/drain and terminal shutdown. Include a `storage_test` consumer receiving only its designated Vault.
5. **Consistent snapshots.** Add only `storage/snapshot.go`, snapshot tests, internal snapshot adapters and storage API documentation after D5 approval. Deliver bbolt read-Tx WriteTo snapshots and memory snapshots of one committed root, with same-backend reopen testing; scheduling stays external. Tests: writer racing backup, no partial Update within a Vault, all Vaults from one committed database state, injected writer failures, reopen/unlock using external keys, and bbolt file-lock timeout. Document restore/authority limits.

Future validation: run package-focused `go test -mod=readonly ./storage/...` and `go test -mod=readonly -race ./storage/...` with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`; fixtures use `t.TempDir`, not legacy TestMain cleanup. Missing local tools/dependencies are blockers, not permission to download.

## 5. Acceptance matrix

Run one shared engine suite on bbolt and memory from C2, then one shared encrypted Vault suite from C4; retain bbolt-specific durability/file-lock assertions.
| Area | Required assertions | Checkpoint |
|---|---|---|
| Atomicity / rollback | Multi-record and cross-namespace commit; callback/nested/crypto errors and panic leave no partial state; errors reach caller | C1; C2 namespaces; C4 crypto |
| Isolation | Read-your-writes; repeatable View; aborted writes invisible; no lost concurrent increments | C1–C2 |
| Byte ownership | Mutating Put inputs, Get/Each outputs, retained slices after close cannot alter storage; callbacks cannot retain engine buffers | C1–C2; C4 facade |
| Namespaces | Dynamic nested creation/rollback, sibling separation, ambiguous path segments, missing namespace, empty key/value, namespace/value collision | C2; C4 binding |
| Concurrency | Readers/writers, scope Lock/Close during work, lease revocation, no races/deadlocks within supported usage | C2, C4 |
| Lifecycle | Open failure, cleanup, terminal/idempotent Close, transaction handle expiry; fresh bbolt reopen; bounded competing file open | C1–C2; C4 leases; C5 file locks |
| Vault authorization | Locked/denied access, wrong key, forged/missing manifest, scope cannot select sibling Vault, shared-file/separate-file equivalence | C4 |
| AEAD / indexes | Header/tag/nonce/ciphertext tampering; wrong Vault/path/record; unknown KeyID/version; key-purpose separation; entropy/provider failure | C3–C4 |
| Snapshot consistency | Concurrent whole-transaction updates give a single committed snapshot; reopen preserves all Vault boundaries; failed writes report failure | C5 |
| Authority replay | Snapshot is explicitly not safe application recovery; consumed grants cannot be reauthorized by restore | Later application checkpoint, per S V19 test map |

## 6. Open decisions (five maximum)

1. **D1 — package and transaction scope:** recommend extractable `storage` plus private engine; one-Vault Update, common error/ownership semantics above, no Handle compatibility. C1 can proceed without settling cryptographic format.
2. **D2 — security approval of suite/format/nonces:** recommend the AES-GCM/HKDF envelope above; approve canonical encoding, version rules and enforceable lifetime nonce budget before C3/C4. Key IDs are identifiers, never secrets or authorization.
3. **D3 — index/metadata policy:** recommend HMAC equality keys with encrypted logical keys, visible namespace metadata, explicit collision rejection, and no range/secondary index API initially. This constrains iteration and persisted layout; approve before C3.
4. **D4 — provider lifecycle/scope:** recommend a provider authorized per Vault and unlock attempt, leased software secrets, validation at transaction admission, and scope-local Lock that drains admitted work then releases keys. Define expiry/revocation and usage-budget ownership; provision/recovery stays external. Reject guessing a mapping from existing signing handles.
5. **D5 — snapshot artifact/lifecycle:** recommend whole-Database, backend-tagged snapshots (bbolt native; versioned memory encoding), reopen with external keys, no portable wallet export. Caller owns destination permissions, Sync/Close and atomic publication; storage reports stream errors. Confirm this split before C5.

Run evidence: initial target `git --no-optional-locks status --short` was empty; legacy status was also empty when inspected. No tests were executed: this run inspected sources, and legacy tests write/delete files in their checkout.
The sole new file is this plan. No code, module, approved contract, or reference-repository edits; no network, downloads, commits, branches, or tags.
Final target status: `?? docs/architecture/managed-storage-implementation-plan.md`.

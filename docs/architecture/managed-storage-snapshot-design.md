# Consistent database snapshots (D5)

Status: Proposed D5 contract for owner review; no implementation authorized.

Let the Database owner capture all Vaults without shutdown and reopen with externally authorized keys. Proposed additions:

~~~go
func (db *Database) Snapshot(w io.Writer) error
func OpenMemorySnapshot(r io.Reader) (*Database, error)
~~~

## 1. Snapshot scope and consistency

Snapshot is administrative Database access, unavailable to a caller holding only one Vault. Include every Vault, visible metadata, manifests, nested/empty namespaces, lookup tokens and opaque encrypted records. Exclude keys, Scope/Lease objects, live handles and accounting state. Never unlock, call providers, decrypt, re-encrypt or reserve/spend allowance.

Select the committed state when the backend read transaction begins or memory captures its committed root, after Database admission. All Vaults share that state. A loop over Vault.View cannot provide this guarantee; public Updates remain scoped to one Vault. Success means consistent copying, not an integrity audit. Preserve corrupt record bytes rather than silently skipping them. [A,C]

## 2. Backend formats and reopening

Use pinned bbolt's native read-transaction Tx.WriteTo, reopenable through existing OpenBolt. “Backend-tagged” means bbolt's native identification and an explicit backend choice in the caller's backup catalog, never a prepended wrapper. No ad hoc open-file copy or close/copy/reopen cycle. Native output need not be deterministic. [B]

For memory, encode one retained immutable engine tree: magic `MSMEM`, version byte 1, then recursive nodes. Nodes start with u32 entry counts. All u32s are big-endian. Entries contain a record(0)/child(1) kind byte and a u32-length-prefixed nonempty byte name. Records add a u32-length-prefixed opaque value; children add another node. Zero entries preserves empty namespaces; zero-length values are present, absence has no entry. Sort combined entries lexicographically by literal name bytes; promise deterministic output for the identical tree/version.

Propose limits of 256 levels, 1,000,000 total entries, 1 MiB names, 16 MiB values and 256 MiB input. Charge payload plus conservative node/map overhead against a 256 MiB allocation budget before allocating, with overflow checks. Reject excessive lengths/counts/depth/resources, unknown magic/version/kinds, duplicate names including cross-kind collisions, wrong-kind payloads, truncation and trailing data. Return no Database until the private tree parses successfully. These new limits exclude some currently representable engine states: approve that compatibility restriction before run 2, and make memory export reject the same limits. [C]

Add internal Engine.Snapshot implementations accessing bbolt's transaction or memory's root/maps directly. Public Each exposes logical records; engine Each also skips children. No public raw traversal, serialization framework, type registry or cross-backend migration. Reopen creates a new database without unlocked handles. UnlockVault requires original externally expected identities/keys and explicit authorization. No live replacement, implicit repair, key provisioning or allowance reset. [C,D]

## 3. Admission, shutdown and failure

Reuse db.begin(context.Background()) and deferred pending.Done(), independently of Vault Scope. Close stops new admission with ErrClosed, waits for admitted snapshots, then closes the engine. Defers release the backend read transaction/root and engine pin before the Database pending count, on success, error or panic. Preserve err2 recovery and unexpected/runtime panic propagation. Writer callbacks run outside the admission mutex. [D]

Forbid same-database reentry from transaction, provider or writer callbacks. Writers must terminate; arbitrary blocked io.Writer calls have no cancellation mechanism. Streaming may hold a bbolt read transaction, retaining pages and delaying remapping/writers. Memory retains its selected immutable root throughout streaming. No scheduler or goroutine framework. [B,C]

Use a private writer adapter exposing only Write. Remember the first original write error, return it unchanged even if WriteTo loses it, and convert a short count with nil error to io.ErrShortWrite. Stop after failure. Pinned bbolt formats metadata errors without wrapping and misses metadata short counts; io.CopyN can discard an error accompanying its final full count. Check the adapter's remembered error even after apparent backend success. Partial output is invalid, unpublished backup material; release all pins. Successful streaming proves neither durability nor decrypt-and-verify completion. [B,E]

## 4. Backup publication and restore limits

The caller schedules backups, chooses a separate temporary destination and permissions, streams, checks Snapshot/Sync/Close, atomically publishes and handles directory durability. Discard failed output. Snapshot alone is not atomic publication.

A consistent encrypted database may be stale. Authenticated records prove neither freshness, complete metadata integrity nor IntroTree authority. The external provider/allowance ledger must not roll back with it. Never refund or recreate allowances. Reusing one finite test provider across reopen proves only test-local accounting, not durable/global accounting or safe recovery of consumed grants. D4 production accounting/freshness and application recovery remain open; changing KeyID does not solve them. [F,S]

## 5. Small implementation increments and acceptance

1. Add storage/snapshot.go, Engine.Snapshot in storage/internal/engine/{engine.go,bbolt.go,memory.go}, a writer guard, API comments and focused tests. Reuse Database lifecycle. Memory returns errors.ErrUnsupported until run 2. Embedded-engine test wrappers inherit it; add snapshot barriers where needed.
2. Add storage/internal/engine/memory_snapshot.go for bounded serialization/loading, OpenMemorySnapshot and malformed-input/round-trip tests.
3. Add shared/consumer integration only as needed. Preserve existing test requirements through necessary interface/fake adaptations. [T]

Use explicit barriers, never sleeps: race atomic multi-record Update against capture and reject torn pairs; order Vault commits (A0,B0) → (A1,B0) → (A1,B1) and reject impossible (A0,B1). Never require bbolt writer completion while a reader pins remapping. Check empty/nested/binary-name trees, absent/present-empty values, original-key reopen with zero NEW allowance, unchanged provider counters during capture, failing/short/final-full-error writers, panic cleanup and shutdown draining. Keep new serialization tests separate from existing crypto/lifecycle matrices. Run focused tests, then standard and race storage suites and Makefile test/testr. [T]

First-run blockers: owner acceptance of this administrative/native-stream contract and separate coding authorization. C5 excludes CLI, production providers, rotation, portable single-wallet export, subtree deletion, queries, CI expansion and general frameworks.

## Source-locator appendix

Current source facts, not execution evidence. Paths are target-relative unless prefixed: B = `/home/parallels/go/pkg/mod/go.etcd.io/bbolt@v1.4.3`; G = `/usr/local/go`; S = `/home/parallels/go/src/github.com/optechlab/intro-tree`.

- **A — Baseline/proposal:** `docs/architecture/managed-storage.md:16`, `:51`; proposed C5/D5 at `docs/architecture/managed-storage-implementation-plan.md:76`, `:80`, `:102`, `:128`. Current scoped Updates: `storage/tx.go:38`.
- **B — Native backend:** pin `go.mod:41`; current open/read/close `storage/internal/engine/bbolt.go:24`, `:46`, `:76`; native copying `B/tx.go:387`, metadata error/short-count behavior `:434`, `:443`, data copying `:453`; consistent state `B/README.md:154`; read lifetime/remapping `B/db.go:726`, `:768`; rollback on exit/panic `:918`.
- **C — Tree/access:** `storage/internal/engine/engine.go:23`, `:45`, `:64`, `:81`; immutable memory maps/admission/publication `storage/internal/engine/memory.go:20`, `:48`, `:72`, `:101`; names/writes lack the proposed serialization caps `:187`, `:202`; public iteration/metadata `storage/namespace.go:13`, `:150`; manifests `storage/manifest.go:19`, `:49`.
- **D — Ownership/lifecycle:** `storage/db.go:22`, `:35`, `:50`, `:112`, `:163`; `storage/vault.go:12`, `:32`; external identity/provider/zero reservation `storage/keyprovider.go:11`, `:19`, `:29`.
- **E — Writer contract:** `G/src/io/io.go:90`, `:363`, `:407`, `:431`.
- **F — Accounting/restore proposals:** `docs/architecture/managed-storage-record-design.md:37`, `:39`; `docs/architecture/managed-storage-vault-design.md:45`, `:60`. Implemented finite-provider scope: `storage/vault_lifecycle_test.go:22`, `:99`, `:238`.
- **T — Existing test requirements:** atomicity/unwinding `storage/internal/engine/contract_test.go:14`, `:279`; reopen `storage/internal/engine/bbolt_test.go:31`, `:107`, `storage/tx_test.go:717`, `storage/namespace_test.go:758`; snapshot isolation `storage/internal/engine/memory_test.go:55`, `:285`, `storage/namespace_test.go:800`; draining `storage/vault_lifecycle_test.go:456`, `:477`, `:627`, `:670`; embedded wrappers `:761`, `storage/tx_test.go:559`; consumer boundary `storage/vault_consumer_test.go:61`; suites `Makefile:61`, `:64`, `:67`, `:76`; test conventions `storage/AGENTS.md:3`.
- **S — Authority remains separate:** `S/docs/IntroTree_Model_Index.md:399`; `S/docs/contracts/IntroTree_StateSemantics_Contract.md:481`; `S/docs/contracts/IntroTree_Implementation_Action_Map.md:208`; `S/docs/contracts/IntroTree_Conformance_Test_Map.md:429`. C5 copying/reopening does not implement RestoreSafeRecoverySnapshot.

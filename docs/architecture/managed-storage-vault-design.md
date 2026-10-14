# Vault access and key lifecycle (D4)

Status: Proposed for owner review.

Recommend giving each caller one explicitly unlocked Vault handle. Keep authorization, secrets, and encryption accounting under application control. Start C4 with finite test allowances. Production sealing remains conditional on the deployment below.

## Inspected facts

Full record validation and spend-before-seal exist, but composition functions are unexported. They provide neither authorization nor global accounting. [R] The proposed lifetime cap remains OPEN D4. [B]

Branch: `new-managed-db-c1-v3`. HEAD and ancestral REVIEWED_BASE: `3ce5eb82f60fe26c31161a56c7407e27d1a6b19a`. Initial Git status: clean. Owner reports passing C1/C2/C3a–C3c tests. This documentation run executed none.

## Proposed access boundary

The application provisions independent random 32-byte secrets per vault/generation and supplies authorized expected VaultID/KeyID from outside storage. IDs confer no authority. There is no singleton/default key. Database owns physical storage and its unlocked handles. Vault exposes only scoped transactions and Lock, without sibling selection, keys, provider, or raw engine access. [A]

Add an internal-package exported `record.Scope` bridge for derivation, Token, full Seal/Open, and Clear. Scope owns KE/KI and immutable identity. Copy borrowed secret bytes for derivation, then clear that copy. Lifecycle integration is new work.

~~~go
type KeyProvider interface {
    Acquire(context.Context, VaultID, KeyID) (Lease, error)
}
type Lease interface {
    Secret() []byte
    Check() error
    Reserve(n uint32) (spend func() error, err error)
    Release() error
}
~~~

Secret is borrowed until Release. Reserve returns a synchronized local gate over irrevocably precharged usage, never provider I/O during sealing. Unlock requests a bounded allowance once. Zero denies sealing.

Creation alone atomically creates absent vault state and seals its manifest. Reserve before engine entry and release on every exit. Existing state conflicts. Add a narrow child-presence probe: missing Child currently poisons the transaction. [E] Selection creates nothing. Unlock rejects missing, malformed, mismatched, or unauthenticated manifests.

Use the existing record codec for a fixed `manifest` key at internal context `[03]`, with value `layoutVersion || VaultID || KeyID`. Ordinary records use `[01] || logicalPath`. Prefixes consume existing context bounds and prevent caller-addressable manifest contexts. Authenticate the header, expected vault/context/token, logical key, and payload. Compare identity/layout against external expectations before publishing the handle. No second cryptographic format is needed. [R]

## Proposed admission and release

Serialize admission with Lock/Close through a Database gate. Check open state and Lease.Check, then pin Scope and count active work before engine entry. Successful checking/pinning is admission. Denial, expiry, or revocation closes that handle to admission. Lock sets the same closing flag: subsequent transactions must fail. Both drain admitted work without holding the gate. Admitted work retains keys and may commit after expiry. Then Clear/Release exactly once.

Lock is terminal and idempotent for one handle. Reopening requires another unlock. Database.Close is terminal and idempotent. It closes all admission, drains pending create/unlock operations and transactions, clears/releases owned scopes, then closes the engine. Handle publication rechecks admission. Unpublished/failed unlocks also release. Attempt all cleanup and preserve errors. Provider calls occur outside engine locks.

Assume provider and transaction callbacks never reenter storage. The application coordinates shutdown and ensures callbacks terminate. Preserve engine error/panic unwinding. [E] Clearing is best effort, not proof of erasing Go/runtime copies. Lock cannot revoke returned bytes.

## Conditional embedded accounting

Recommend one host and one application process owning all sealing for an actual KE. Its provider exclusively locks an external durable ledger containing immutable key bindings and charged high-water counts. Never key accounting solely by an untrusted KeyID. Serialize reservations, durably commit and sync each increase before handing out nonoverlapping allowances, and refuse totals above 2^24. Include manifest seals. An always-success callback cannot enforce this limit. [B]

**Trusted assumptions:** the application/operator preserves ledger freshness, excludes it from database restores, prevents duplicate key owners, and forbids live-process/VM cloning. A separate file is not inherently rollback-resistant. Arbitrary host/accounting rollback cannot be secured by this arrangement.

| Event | Required behavior |
|---|---|
| Restart or re-unlock | Use latest ledger. Forfeit old unused allowances and charge new ones. |
| Concurrent handles/files | Share the sole provider ledger. Reject another owning process. |
| Failed write/commit | Never refund consumed seals. |
| Exhausted/lost allowance | Fail sealing. Only a new durable reservation can replenish it. Exhausted lifetime budget still allows authorized reads. |
| Database copy/old database restore | Supported for sealing only under the same authoritative ledger/provider. Copies carry no allowance. Reauthorize access. |
| Ledger loss, old accounting snapshot, uncertain freshness, independent copied-key deployment | Disable sealing until trusted evidence establishes the current high-water bound and exclusive ownership. Never reconstruct counts from records. |

**Unavailable:** production accounting and enforceable freshness are not established here. This remains an OPEN deployment obligation, not a guarantee moved into an interface. Bounded fallback: fresh test keys with finite in-memory gates, without durability claims. Do not change KeyID to reopen: both KE and KI depend on it, affecting lookup and old-record access. [K] Nonce/derivation changes require separate review.

## Proposed integration path

Provision → explicit Create → select/unlock and verify manifest → Update → Lock/drain/release → re-unlock with the same expected generation and newly charged allowance.

Three separately authorized increments:

1. Add the thin Scope bridge and finite test provider. Check owned results, unchanged validation, exhaustion, and rejection after Clear.
2. Add authenticated creation/unlock and handle lifecycle. Check wrong keys/identity, missing/tampered manifests, failed-unlock release, denial, expiry, drain, and terminal Close.
3. Compose scoped transactions on memory and bbolt with mandatory protection. Check encrypted backend contents, shared/separate-file vault isolation, atomic rollback even for ignored codec errors, retained results, nested local namespaces/name conflicts, and no sibling/raw access from a `storage_test` consumer. Require full record/token/requested-key checks on reads, replacement, and deletion. Preserve engine unwinding and callback lifetime. [E]

Only increment-one decisions: owner authorization of bridge ownership and the test-only provider boundary. Production additionally needs demonstrated accounting custody/freshness. D4 is not approved.

Authenticated restored bytes never restore application authority. [S] Rotation, backup/export formats, hardware adapters, services, plugins, and optimization frameworks remain outside this proposal.

## Source locators

Paths are target-relative. S = `/home/parallels/go/src/github.com/optechlab/intro-tree`.

- **A:** `docs/architecture/managed-storage.md:16`, `:31`, `:53`, `:79`; `docs/architecture/managed-storage-implementation-plan.md:79`, `:92`, `:101`, `:127`.
- **R:** `storage/internal/record/record.go:15`, `:29`; `storage/internal/record/aead.go:21`, `:33`; `storage/internal/record/encoding.go:1`, `:129`, `:181`; `storage/internal/record/record_test.go:60`, `:117`, `:213`.
- **B:** `docs/architecture/managed-storage-record-design.md:37`, `:39`, `:65`; `storage/internal/record/aead_test.go:19`, `:147`.
- **K:** `storage/internal/record/keys.go:13`, `:36`; `storage/internal/record/keys_test.go:153`.
- **E:** `storage/internal/engine/engine.go:17`, `:45`, `:81`; `storage/internal/engine/bbolt.go:46`, `:62`, `:76`, `:119`; `storage/internal/engine/memory.go:48`, `:72`, `:101`; `storage/AGENTS.md:6`.
- **S:** `S/docs/IntroTree_Model_Index.md:399`; `S/docs/contracts/IntroTree_StateSemantics_Contract.md:493`; `S/docs/contracts/IntroTree_Implementation_Action_Map.md:208`; `S/docs/contracts/IntroTree_Conformance_Test_Map.md:429`.

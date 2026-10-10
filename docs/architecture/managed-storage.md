# Managed Storage — Architecture and Design Contract

**Status:** Approved design baseline v0.2  
**Proposed location:** `github.com/lainio/ic/docs/architecture/managed-storage.md`  
**Initial implementation:** `github.com/lainio/ic/storage` (provisional)

## 1. Purpose

Extract and modernize the useful managed-database concepts from
`findy-network/findy-common-go` into a small, embedded Go storage package.
Existing code is reference material, not the specification. The package must
remain independent of IntroTree semantics and extractable into its own module.

## 2. Architecture

- **Backends:** bbolt for durable storage; in-memory for tests and experiments.
  Both obey the same transactional and ownership contract.
- **Transactions:** Explicit, closure-based `View` and `Update`. Mutations in an
  `Update` commit atomically or roll back on failure.
- **Namespaces:** Dynamically created, nested namespaces. A **Vault** is the
  unit of cryptographic protection and logical access isolation; an IntroTree
  wallet can own a vault without the storage package knowing about wallets.
- **File layout:** Allow multiple vaults in one bbolt file or separate files.
  File ownership and process topology determine deployment; vault boundaries
  do not imply separate physical files.
- **Byte ownership:** Data returned beyond a transaction is caller-owned.
  Storage-owned buffers may not escape their valid lifetime.
- **Dependencies:** Embedded, with no required database server or other
  externally running service.

## 3. Vault security

- **Encrypted by default:** There is no ordinary plaintext persistent mode.
- **Per-vault keys:** Each vault has an independently managed encryption domain.
  Do not use one database-wide encryption key.
- **External keys:** Vault keys are provisioned or made available through an
  application-controlled key provider, not stored as plaintext in the database.
- **Protected records:** Use standard authenticated encryption (AEAD). Bind
  ciphertext to its vault, namespace, and logical record identity through
  authenticated associated data.
- **Protected indexes:** Treat index protection separately from encryption;
  use purpose-separated keying where keyed indexes are needed.
- **Access:** Vault access requires an explicitly authorized, unlocked scope.
  Cryptographic locking is distinct from bbolt's file/transaction locks.
- **Evolution:** Version encrypted record formats and key identifiers. Key
  rotation procedures are a later design and implementation milestone.

A vault does **not** by itself hide all storage metadata, enforce process-level
isolation, or prevent replay of an old authenticated database snapshot.

## 4. Lifecycle and backup

- Provide explicit open, close, and final-shutdown behavior.
- Provide consistent storage snapshots without requiring ordinary application
  shutdown where the backend supports it.
- Keep periodic backup scheduling outside the core storage API.
- Treat database restoration as distinct from restoring application authority;
  an old snapshot must not recreate consumed IntroTree recovery authority.
- Respect bbolt's physical file locking and single-writer constraints. Do not
  claim multi-process writable access to one file.

## 5. Implementation constraints

- Retain `err2` and `assert` for error handling and checks; use `glog` for logs.
- Avoid leaking bbolt types into domain-level APIs.
- Minimize dependencies; do not migrate unrelated Findy/SSI components.
- Review legacy features as **Keep, Adapt, Replace, or Drop** before reuse.
- Do not preserve source compatibility with the legacy `Handle` interface merely
  for compatibility's sake.

## 6. Non-goals

PostgreSQL, distributed storage, ORM/query frameworks, a universal persistence
layer, protocol/trust logic, wallet export/import, and full vault key-rotation
workflows are outside this first milestone.

## 7. Acceptance criteria

1. One transactional API supports both bbolt and memory backends.
2. Shared contract tests cover commits, rollbacks, nested namespaces, vault
   isolation, byte ownership, and lifecycle.
3. Tests cover authenticated encryption, tampering, incorrect vault/context,
   and key separation.
4. A consistent backup can be created and reopened; the limitations of
   rollback/restore are documented.
5. Go tests and race detector pass, and API guarantees are documented.
6. An IntroTree consumer can access only its designated vault through the
   normal scoped interface.

**Design principle:** Separate *physical database*, *logical vault*, and
*application wallet*. Reuse the old implementation where sound; let the new
contract determine the final API.

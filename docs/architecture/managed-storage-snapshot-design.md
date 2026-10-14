# Database snapshots (D5) — narrowed scope

**Status:** Scope revision for adoption; snapshot implementation is paused.
**Source baseline:** `01d27cb368b748f599739c597de753704f8561c4`.

This revision changes scope, not just formatting.
It replaces the previous D5 rollout after the owner adopts it.
The previous proposal remains available in Git history.
Existing storage behavior and its regression tests remain unchanged.

## 1. Next milestone: use the existing API

The next code change is one runnable Go `ExampleVault` in
`storage/example_test.go`, using the public API and temporary bbolt storage.

Show creation, unlock, a nested write/read, lock, and database reopening.
Keep the same finite test provider and key generation across reopening
within the same process.
Use a deterministic `Output:` comment.
Show the provider fixture separately; do not hide its setup cost.

This example is not a production key provider or a persistent CLI wallet.
It requires no new snapshot capability or storage abstraction.
A proposed production change must identify the example behavior it enables.

## 2. What remains deferred

The memory backend remains an ephemeral test and experiment backend.
Matching transaction behavior does not require matching persistence features.

Do not implement `MSMEM`, memory serialization, memory import,
`OpenMemorySnapshot`, or cross-backend snapshot compatibility.
Do not add their proposed resource limits to the running engine.
Do not add unsupported methods merely to make the backends look identical.

Native bbolt snapshots remain a possible follow-on, not a prerequisite
for the example or an automatically authorized coding step.
Production key-usage accounting, rotation, and application recovery
remain separate open work.

## 3. Retained bbolt snapshot direction

When a concrete backup use case is authorized, prefer native bbolt
read-transaction `Tx.WriteTo` output, reopened with `OpenBolt`.
Do not introduce another database file format.

A snapshot would copy one committed database state, including all Vaults,
metadata, manifests, nested namespaces, tokens, and encrypted records.
It would not copy keys, live handles, leases, or encryption allowances.
Copying would not unlock, decrypt, re-encrypt, repair, or spend an allowance.

A whole-database snapshot belongs to the `Database` owner.
It is not a capability of a caller holding only one Vault.

### Error and lifecycle requirements

Reuse the existing database admission and shutdown mechanism.
Release the backend read transaction before releasing the database pin.
A blocked writer may delay completion and shutdown.
Do not invent cancellation or scheduling machinery for that case.

For the pinned bbolt path, retain the original writer-failure requirement:
use a private adapter that exposes only `Write`.
Remember the first original write error and return it unchanged,
even if `WriteTo` does not preserve it.
Convert a short count with a `nil` error to `io.ErrShortWrite`.
Check the remembered error after apparent backend success.

The future implementation must verify the pinned dependency behavior.
This requirement does not authorize a general I/O framework.

### Caller responsibilities

The caller chooses a separate destination and its permissions.
It checks streaming, `Sync`, and `Close` before publishing the backup.
Failed partial output must not be published.
Snapshot consistency is neither atomic file publication nor an integrity audit.

## 4. Guarantees we are not claiming

Reopening an encrypted database does not prove that it is fresh.
It does not restore consumed application authority safely.
It must not reset or refund the external provider's usage accounting.

The existing finite test provider supports a local demonstration only.
Do not replace its finite gate with unconditional success.
A production provider and trustworthy accounting across restarts or restores
are not implemented by this document or by the next example.

## 5. Readability and feature gate

Use inline code for exact identifiers, types, methods, literals, commands,
and paths.
Start each sentence on a new source line.
Split long sentences at meaningful clause boundaries within 80 characters.
Do not reflow unrelated paragraphs for a local edit.
Exempt code, tables, and indivisible tokens when wrapping harms meaning.

Before adding a feature, state the current user action it enables,
why the existing implementation is insufficient, and what is lost
by deferring it.
Without a concrete answer, defer it rather than implement a placeholder.

## Source basis

These locators identify the reviewed baseline, not new test execution.

- `storage/db.go`: `OpenBolt`, `CreateVault`, `UnlockVault`, `Close`.
- `storage/tx.go`: `Vault.View`, `Vault.Update`, transaction finalization.
- `storage/vault_consumer_test.go`: `consumeVault`, `TestVaultConsumer`.
- Original snapshot proposal at the source baseline: sections 1–5.
- `docs/architecture/managed-storage-vault-design.md`:
  “Conditional embedded accounting”.

The scope reductions and example-first ordering above are the new decisions.
The retained snapshot requirements come from the original D5 proposal.

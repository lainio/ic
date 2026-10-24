# One saved signing identity

Use an existing, trusted, user-owned parent outside this repository.
For example, if `/home/alice/playground` already exists and belongs to you,
choose these disposable paths (replace `alice` with your own account):

~~~sh
go run ./cmd/tdc node init --dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock
go run ./cmd/tdc node info --dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock
go run ./cmd/tdc node info --dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock
~~~

Each invocation exits. All three print the same full CBOR public key:

~~~text
node public key (hex): <full CBOR public-key hex>
~~~

Both flags are required and positional arguments are rejected.
`init` creates a new mode-0700 node directory containing mode-0600
`identity.json`, plus a separate, new mode-0600 unlock file.
Both parents must already exist. The unlock file must be outside node state.
Its 32 raw random bytes wrap this one identity; this is not a password file.
Existing paths are never reused or overwritten, including symlinks.
`info` reads existing files only and restores a signer using a fresh backend.
Reads reject final-component symlinks, non-regular files, and group/other
permission bits. Existing permissions are never silently changed.

The record contains only a development format version, public key, and encrypted
private-key representation. That representation and the unlock file are private
local material: never publish them as peer evidence, QR data, or logs.
Keep both files under your ownership. Anyone with both can restore the signer.
Losing the unlock file makes this playground identity unusable.
There are no recovery, export/import, backup/restore, migration, rotation, or
multi-identity key-reuse commands. Incompatible development formats fail
explicitly; no migration or backup/restore support exists before v1.0.

Initialization is not a multi-file transaction. A failed initialization leaves
any exclusively created directory or partial files for explicit operator
inspection/removal. A retry refuses those paths; it never repairs them.
An output failure also reports failure but keeps an already saved identity.
Checked writes and closes do not promise power-loss durability.

This Linux-focused playground provides software key storage on a trusted host,
not hardware protection, UI-controlled delegation, or rollback resistance.
It does not defend against a hostile same-user process replacing ancestor paths
and does not claim secure erasure of all backend or Go-heap copies.
The separate unlock file leaves room for future owner-supplied credentials;
it is not a distributed-key-management decision.

Use this saved identity in the existing HTTP Root command:

~~~sh
go run ./cmd/tdc intro http-demo root \
  --identity-dir /home/alice/playground/node52 \
  --unlock-file /home/alice/playground/node52.unlock \
  --listen 127.0.0.1:0
~~~

Its public key equals `node info`. Stop with Ctrl+C and repeat the Root command,
without another `init`: the key stays the same and port zero may change the
endpoint. Follow the [HTTP walkthrough](../intro/README.md) for the unchanged
Alice command, fresh exchanges, and Alice's `--owner-listen` status option.
Both saved-Root flags must be supplied and nonempty; omitting both keeps the
fresh-Root behavior. Failed loading never generates a replacement key.

Only Root's signing identity survives. Its issued offer stays in memory;
Alice still has a fresh identity, temporary Vault, and temporary signing choice
per invocation. No Vault secret is persisted or reused with a reset encryption
counter. Alice persistence must retain her identity together with Vault state
and non-resetting key-use accounting, not her key with an emptied choice store.
This is not a persistent wallet or complete node service. `node init` and `info`
start no network service; HTTP shutdown leaves both identity files intact.
Manual stop/restart and owner-status verification remain pending for the owner.

This operation persists local key material only. It creates no introduction,
membership, `Known`, trust, pairwise, or device-authority transition, does not
resolve V19 global-parent uniqueness, and authorizes no new modeled action.
Saving Root's key does not establish root authority or implement V19 `Introduce`;
Alice's caller still supplies the public expected root independently.

Review order: README -> Root selection in `cmds/intro/http_demo.go` -> shared
loader in `internal/nodeidentity/files.go` -> saved-identity exchange test in
`cmds/intro/http_identity_test.go`. Existing cross-process restore coverage
remains in `TestIdentityAcrossProcesses` in `internal/nodeidentity/identity_test.go`.

## Internal Alice persistence (CLI integration pending)

`internal/nodevault` now retains one Alice's proposal and acceptance across
process exit, using the saved identity and existing onboarding operations.
The caller supplies an independent random 32-byte storage secret and the same
expected public binding each time; this component provisions no secrets.
A dedicated private directory holds encrypted `vault.db` and plain `usage.db`.
Each opening charges up to 4096 encryptions toward a fixed `1 << 24` limit.
Unused capacity is discarded; exhausting a block requires an explicit reopen.
At the lifetime limit, reads and completed-result reuse still work.
The exclusive usage-file lock permits one active Store for this file pair.
Copies, rollback, backups, restores, migrations, compatible upgrades and full
power-loss recovery are unsupported. Persistent Alice CLI/HTTP wiring is pending.
Read `ExampleStore`, then `Create`/`Open`/`Close`, the private provider, and
`TestStoreAcrossProcesses` for the bounded two-process acceptance retry.

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

Current exchange and Vault demos do not use this saved identity.
No Vault secrets are persisted and no storage encryption counters are reset.
The next integration is a node using this identity with persistent storage;
the full service is not yet restartable. No network service is started here.

This operation persists local key material only. It creates no introduction,
membership, `Known`, trust, pairwise, or device-authority transition, does not
resolve V19 global-parent uniqueness, and authorizes no new modeled action.

Review order: this README, `node.go`, `internal/nodeidentity/identity.go`, then
`TestIdentityAcrossProcesses` in `internal/nodeidentity/identity_test.go`.

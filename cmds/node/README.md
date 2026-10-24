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
endpoint. Follow the [HTTP walkthrough](../intro/README.md) for fresh exchanges
and Alice's `--owner-listen` status option.
Both saved-Root flags must be supplied and nonempty; omitting both keeps the
fresh-Root behavior. Failed loading never generates a replacement key.

In that fresh-Alice example only Root's signing identity survives.
Its issued offer stays in memory. For persistent Alice, use `init-state` below
and all three saved-state flags on HTTP accept.
This is not a complete node service. `node init`, `info` and `init-state` start
no network service; HTTP shutdown leaves identity files intact.
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

## Prepare Alice's persistent local state

The one new command is `tdc node init-state --dir ALICE_DIR
--unlock-file ALICE_UNLOCK_FILE --storage-key-file ALICE_STORAGE_KEY_FILE
--root ROOT_PUBLIC_KEY_HEX`.
All four flags must be supplied and nonempty; positional arguments and `--force`
are rejected. `node init` and `node info` are unchanged.
The identity and both parent directories must already exist.
Root is explicit expected public-key hex (nonempty, at most 16 KiB decoded),
not evidence that the supplied Root is authoritative.
Child comes from the restored identity.

Initialization exclusively creates the private `ALICE_DIR/state` directory
and a new mode-0600 file holding 32 independent random raw storage-secret bytes.
The storage-key file must be outside the entire identity directory and distinct
from the unlock file after parent normalization.
Existing paths, including symlinks, are refused without overwriting or repair.
The identity record and unlock file remain unchanged.
The Store closes before the command prints Alice's actual public key and
`local state initialized: true`.
An error may leave exclusively created partial files for explicit inspection;
it never deletes persistent files or switches keys.

Follow the single [saved-Alice HTTP walkthrough](../intro/README.md#restart-saved-alice-in-the-http-exchange)
for placeholder replacement, explicit preparation, two separate accept
invocations, and authenticated owner status.
Keep Root running: its retained proposal is still in memory.
Restarted Root returns `409` to Alice's saved acceptance; Alice keeps her choice
and never requests a replacement offer.
Owner shutdown removes only that invocation's temporary credentials, retaining
Alice's identity, state, unlock and storage-key files.

`internal/nodevault` now retains one Alice's proposal and acceptance across
process exit, using the saved identity and existing onboarding operations.
`CreateForNode` provisions the independent storage secret;
`OpenForNode` requires existing private material and never provisions it.
The underlying `Create`/`Open` APIs still borrow caller-supplied secrets.
Each invocation supplies expected Root and restores Child; the Store checks
the same binding using private layout IDs `VaultID{1}` and `KeyID{7}`.
These are neither secrets nor global node IDs, and are not CLI options.
A dedicated private directory holds encrypted `vault.db` and plain `usage.db`.
Each opening charges up to 4096 encryptions toward a fixed `1 << 24` limit.
Unused capacity is discarded; exhausting a block requires an explicit reopen.
At the lifetime limit, reads and completed-result reuse still work.
The exclusive usage-file lock permits one active Store for this file pair.
Copies, rollback, backups, restores, migrations, compatible upgrades and full
power-loss recovery are unsupported. There is no migration/backup support
before v1.0. This is temporary trusted-host file provisioning, not final
UI-assisted key management/delegation. Helper processes may sign/decrypt for
their owners within that trust boundary; no remote plaintext exposure or new
authority guarantee follows. HTTP 204 is still an unsigned peer report.
Read `ExampleStore`, then `Create`/`Open`/`Close`, the private provider, and
`TestStoreAcrossProcesses` for the bounded two-process acceptance retry.

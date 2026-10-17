# Vault playground

From the repository root:

```sh
go run ./cmd/vault-playground
```

This disposable development driver uses the public `storage` API with one
fresh random key, one temporary bbolt file, and one Vault. It operates only
on namespace `notes`, logical key `greeting`. The greeting starts absent.

```text
Disposable: fresh random key; temporary bbolt database; removed on normal exit.
> get
not found
> put hello
ok
> get
hello
> put welcome back
ok
> reopen
reopened
> get
welcome back
> quit
```

- `put TEXT`: store everything after the first space literally, including
  further spaces, quotes, and backslashes. `put ` stores empty text.
- `get`: print the greeting, or `not found` when absent.
- `reopen`: close the database and handle, then open the same file with new
  database and handle instances. The provider, secret, IDs, and counter stay
  alive; `CreateVault` is called only during initial setup.
- `help`: show these commands and the disposable-session boundary.
- `quit` or EOF: close resources, clear owned secret bytes, and remove the
  command-owned temporary directory. Forced termination cannot promise cleanup.

This is a text-line demo, not the entire byte-oriented API. Commands are
case-sensitive; only `put` accepts an argument, separated by one ASCII space.
Lines must be shorter than 64 KiB, including their line ending. Blank lines
are ignored. There is no shell quoting, escape language, or path parsing.
Prompts are also written with scripted input. Invalid commands and transaction
errors are reported and leave the loop available; input/output, setup, reopen,
and cleanup errors end the session with a nonzero exit after cleanup.

Data survives `reopen` within this process only. Each invocation starts fresh;
no existing database path, key export, secret file, or restart mode is offered.
The private provider's `demoEncryptionBudget = 1 << 24` counts permitted
encryptions for the session's single secret/`VaultID`/`KeyID` binding.
All leases share that finite demo/test counter. Storage consumes it only when
sealing; reopen never resets or refunds it. No workload prediction is needed.
This is not durable lifetime accounting. The simplified `Check` and `Release`
provide no production revocation or key custody. This driver is not the
IntroTree application CLI and makes no application-recovery guarantee.

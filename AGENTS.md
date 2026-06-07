# AGENTS.md

## Project

This repository contains the Go implementation candidate for the IntroTree system.

## Semantic source of truth

The semantic source of truth is the TLA+ specification repository.

In Codex runs, the prompt must provide the absolute path to the TLA+ repository
as `SPEC_REPO`.

Do not assume that these files exist under the Go repository's `docs/`
directory unless the prompt explicitly says a spec-context bundle has been
copied there.

Required semantic reference files:

```text
<SPEC_REPO>/docs/IntroTree_Model_Index.md
<SPEC_REPO>/docs/contracts/IntroTree_StateSemantics_Contract.md
<SPEC_REPO>/docs/contracts/IntroTree_Implementation_Action_Map.md
<SPEC_REPO>/docs/contracts/IntroTree_Conformance_Test_Map.md
```

If `SPEC_REPO` is not provided, stop and report that the TLA+ specification
repository path is missing.

## Current task class

For implementation inventory tasks:

- inspect code;
- classify code as Keep / Adapt / Split / Remove / Defer / Unknown;
- do not rewrite code unless explicitly instructed;
- do not invent missing architecture;
- report mismatches against the TLA+ V19 baseline.

## Known implementation context

Read:

- `docs/implementation/Current_Go_Implementation_Reality.md`

before making conclusions about existing code.

## `err2` package solving Go limitations

- unit testing and error handling uses `err2` package that allows developers use
  same assert statements for both runtime and for testing harness.
- `err2` also allows automatic error propagation and annotation. It brings
  automatic and runtime configurable (CLI flags) errors traces

## Git rules

In unattended `codex exec` mode:

- do not commit;
- do not tag;
- do not run destructive Git commands;
- report dirty state instead of trying to fix it.

## Cross-repo rules

The Go repo is the active implementation workspace.

The TLA+ repo, when mounted with `--add-dir`, is reference material unless
explicitly stated otherwise.

Do not modify the TLA+ repo from this Go-repo task.

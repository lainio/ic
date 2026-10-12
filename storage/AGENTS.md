# Storage conventions

- Prefer specific `assert` helpers (`ErrorIs`, `Equal`, `INil`, `Error`) before `That`.
- Use `assert.Equal` for exact error/panic identity; `assert.ErrorIs` for error chains.
- Preserve `defer assert.PushTester(t)()` in tests using `assert` or `try`.
- Keep err2 recovery explicit at transaction callback boundaries.
- Preserve defer execution order: err2 recovery, transaction finish, backend rollback.
- Preserve intentional error, runtime panic, and unexpected panic propagation tests.
- Work in small tested increments; run focused tests before storage and race suites.
- No new feature scope is authorized.

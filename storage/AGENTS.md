# Storage conventions

- Prefer specific `assert` helpers (`ErrorIs`, `Equal`, `INil`, `Error`) before `That`.
- Use `assert.Equal` for exact error/panic identity; `assert.ErrorIs` for error chains.
- Preserve `defer assert.PushTester(t)()` in tests using `assert` or `try`.
- Keep err2 recovery explicit at transaction callback boundaries.
- Preserve defer execution order: err2 recovery, transaction finish, backend rollback.
- Preserve intentional error, runtime panic, and unexpected panic propagation tests.
- Work in small tested increments; run focused tests before storage and race suites.
- No new feature scope is authorized.
- Prefer `try.To*` for branches that only propagate errors.
- Give adopting callbacks/helpers their own `(err error)` and
  `defer err2.Handle(&err, nil)`; never bind to an enclosing result.
- Keep `PushTester` on the test goroutine; workers return failures to it.
- Use scoped `defer assert.PushAsserter(assert.Plain)()` for worker assertions.
- Keep error observations, send-before-return sequences, and cleanup branches.
- Preserve signaling and stop paths; do not add blanket recovery.
- Leave deliberate engine-unwinding tests unrecovered.
- Prefer `range` for direct collection traversal or fixed repetition when
  semantics match; retain explicit loops for changing bounds, non-unit steps,
  index manipulation, or byte-wise string traversal that range would change.
- Apply this to new/modified code and tests, not unrelated bulk rewrites.

## Required conditions and error translation

- Use assertions with explicit sentinel errors when they state a requirement
  clearly; scoped assert.Plain and non-annotating err2 handling preserve identity.
- Prefer a deferred err2 handler for deliberate error translation at a clear
  stage boundary, after checks whose error classifications must stay unchanged.
- A translating defer covers the remaining function scope, not one statement;
  review its mapping before adding unrelated fallible work beneath it.
- Keep ordinary propagation, cause-preserving joining/wrapping and replacement
  distinct. Do not mechanically replace every error branch.
- Prefer specific property helpers in implementation preconditions as well as
  tests (for example SLen for slice length); equivalent forms are style
  differences, not defects. Do not perform unrelated bulk rewrites.

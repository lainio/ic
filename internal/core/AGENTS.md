# Core coding conventions

- Work in small, tested behavioral increments.
  Prefer an executable example and focused positive/negative tests over prose.
- Keep the modeled-action boundary explicit.
  Decoding, signature checking, and promotion to `Known` are distinct operations.
- Prefer `try.To*` for propagation and `try.T*` for useful call-site annotation.
  Error-returning callbacks own their named error result and `err2` handler.
  Keep recovery, compensation, and synchronization decisions visible.
- Prefer specific existing assertion helpers; use predicates when none fits.
  Do not expand the assertion API or add wrappers for style alone.
- Examples may annotate errors and use normal assertion messages.
  Exact-sentinel and unwinding tests retain their deliberate error policies.
- Use `defer assert.PushTester(t)()` in assertion-based tests.
  Worker failures return to the test goroutine.
  Use scoped `assert.Plain` only where actually required.
- Put one blank line between meaningful phases: checks/setup, construction,
  signing, and result assembly.
  Keep resource acquisition with cleanup.
  Neither compress everything nor separate every statement.
- Prefer `range` where semantics match.
  Preserve intentional panic tests.
- Use `gofmt` and aim for 80-column, meaningfully wrapped code.
  Use the already installed `golines` only on touched files.
  Never format the whole repository for a local change.
- Use inline code, semantic line breaks, and 80-column prose in Markdown.
  Use only tilde fences.
  Avoid unrelated formatting and legacy cleanup.

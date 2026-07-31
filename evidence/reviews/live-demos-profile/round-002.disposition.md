# Round 002 disposition

Reviewer: Claude Fable 5, high thinking. Overall verdict: correct, confidence 0.75.

- P3 concurrent `markSubmitting` no-op could pass the post-check: accepted because it touches the protected persistence/recovery boundary. `markSubmitting` now requires the SQLite compare-and-swap update to report exactly one changed row. A deterministic barrier test launches two runners against one effect key and proves one fulfilled runner, one rejected runner, one external submission, and one committed journal row.

Focused correction proof:

- `bun test test/live/*.test.ts`: 20 pass, 0 fail, 61 expectations.
- `bun run typecheck`: pass.

Accepted actionable findings remaining before Round 003: none known; final challenger recheck required because the accepted P3 touched persistence/recovery.

# Round 001 disposition

Reviewer: Claude Fable 5, high thinking. Frozen local diff against `HEAD`.

- P1 restart-unstable Directory payload: accepted. `catalogObservedAt` now derives from signed Listing presentation time, not caller wall-clock time. Publication replay is tested with a changed `nowMs`.
- P2 resubmission after an unobservable submission: accepted as claim-bypassing. A durable `submitting` state is recorded before adapter submission. Restart reconciliation may complete an observed effect, but absence fails closed and never resubmits. New negative test proves one submission across repeated absence.
- P3 incomplete import scan: accepted. The verifier now scans the complete `src/` tree, including `src/index.ts`.
- P3 unenforced effect allow-list: accepted because it touches the declared execution boundary. `runRecoverableEffect` now requires an admitted live profile and rejects disallowed effects before intent persistence.

Focused correction proof:

- `bun test test/live/*.test.ts`: 19 pass, 0 fail.
- `bun run typecheck`: pass.
- `bun run verify:live-import-boundary`: pass.
- Atomic write registry: 7 pass, 0 fail, 270 expectations.
- New live-effect atomic sites: 4 pass, 0 fail, 200 expectations.
- Source provenance, build, release-manifest tests, and `git diff --check`: pass.

Accepted actionable findings remaining before Round 002: none known; challenger recheck required.

# Final bounded recheck

Recheck the complete local diff against `HEAD` under the unchanged bounded contract in `round-001.prompt.md`.

Round 002 confirmed all Round-001 corrections and reported one persistence-boundary P3: concurrent callers could both pass `markSubmitting` because the no-op loser observed the winner's `submitting` state. The correction now requires SQLite's prepared-to-submitting update to change exactly one row. `test/live/effect-recovery.test.ts` uses a barrier to force two runners through initial absent reconciliation and proves exactly one submission winner and a committed result.

Verify the CAS correction, the effect state machine, SQLite/atomic registry coherence, and all original protected claims. Report only concrete observable defects within the unchanged trust/threat contract. Stopping condition remains no accepted P0/P1 or protected-claim-bypassing P2; persistence/recovery P3 findings require explicit disposition.

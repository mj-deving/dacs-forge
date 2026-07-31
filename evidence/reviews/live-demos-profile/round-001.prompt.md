# Bounded review contract

Artifact maturity: bounded Forge v0.2 fixture-qualified live-profile foundation. It is not live-qualified, deployed, registered, paid, or released.

Protected claims: ISC-68, ISC-69, ISC-70, ISC-71, and ISC-A8 only: explicit fixture/live profile separation; exact-pinned optional SDK adapter with zero SDK imports in Forge Core and clean consumer; durable intent-before-effect restart recovery without duplicate externally observable effects; chain-authoritative Listing verification before Directory projection; and zero network effects from default commands.

Trusted actors and inputs: reviewed first-party Forge source; pinned Bun, SQLite, and OS runtime; exact official dacs-sdk commit `15ceafa262299f258e2cc35bef7a5e74dc4fb225` when an optional adapter is injected.

Untrusted inputs: profile configuration, persisted effect rows, adapter/network responses, signed Listing and Directory bytes, and interruption timing.

In-scope threats: accidental defects, direct API misuse, payload or reference substitution, restart-caused duplicate effects, absent/indeterminate confusion, import-boundary drift, and default-command network effects.

Out of scope: malicious source author, hostile compiler/runtime/dependency, third-party certification, production/mainnet, actual network/service/payment execution, and a general custody or identity platform.

Review the complete local diff against `HEAD` for concrete correctness, security, persistence/recovery, protocol-binding, and claim-integrity defects. Findings must identify an observable failing path inside this contract. Do not widen the review into live deployment or normative DACS conformance. Stopping condition: no accepted P0/P1 or protected-claim-bypassing P2.

Known verification snapshot before this round:

- Focused live profile: 17 pass, 0 fail.
- Non-atomic full partition: 976 pass, 0 fail, 46,538 expectations.
- Atomic write registry: 7 pass, 0 fail, 269 expectations.
- New live-effect interruption sites: 3 pass, 0 fail, 150 expectations.
- Release manifest: 2 pass, 0 fail.
- Typecheck, build, source provenance, live import boundary, and diff check: pass.
- Mutation calibration: 17/17 killed, 100%.
- No live network or payment effect was executed.

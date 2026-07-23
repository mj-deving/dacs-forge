# Iterative semantic hardening

Most code review asks whether code looks reasonable. DACS Forge review asks whether
the behavior remains truthful under hostile composition.

The bilateral Vet slice illustrates the difference. Across 24 semantic review
rounds, iterative review produced 33 concrete findings: 32 accepted, 23 classified
P1, and 22 security-related. Sixteen corrective code commits followed before the
final Codex review returned clean at confidence 0.96.

These were not formatting findings. They forced the implementation to:

- authenticate who produced Vet evidence;
- bind it to the exact listing, agreement, party, session, and lifecycle time;
- reject replay and ambiguous authority;
- close privacy-sensitive signed schemas;
- preserve canonical bytes and complete ClaimRequirement constraints;
- contain malformed and hostile resolvers;
- refuse database migrations lacking reconstructable authority.

The important pattern was cumulative:

```text
plausible implementation
  -> adversarial counterexample
  -> correction
  -> sharper contract
  -> deeper counterexample
  -> hardened implementation
```

The first clean Codex snapshot appeared at Round 019. A cross-vendor pass then
found a privacy-schema gap; later Codex rounds found incomplete constraint
enforcement, unsigned verification claims, non-canonical resolver JSON, and a
migration edge case. Each correction exposed assumptions that the previous code
and tests could not yet express.

That is the distinction between vibe coding and hardened software. “It runs” is
only the beginning when a service agent interprets identity, signatures, settlement,
delivery, and reputation. The stronger question is whether every accepted outcome
still means exactly what it claims after mutation, restart, ambiguity, concurrency,
or unavailable infrastructure.

The sealed Vet snapshot passed 620 tests and 43,774 assertions across 45 files;
the build produced 53 modules. Those numbers are historical evidence for that
private build snapshot, not a certification of the public prototype. Raw internal
review transcripts, runtime IDs, local paths, and steering records are intentionally
not published here. Public CI independently re-runs the product test and build
surface on every pushed snapshot.

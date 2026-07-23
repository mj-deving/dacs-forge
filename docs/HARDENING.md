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

## Post-seal assurance evidence

DACS Forge may become an implementation-evidence source after a supported Forge
release and its public evidence snapshot are frozen at named revisions. In
[DACS-Standard #272](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/272#issuecomment-5049397102),
the steward invited a small first pilot of no more than five findings and preferred
three strong, independently reproducible packets over five overlapping ones.

Each packet covers one finding. It names the exact Forge and DACS revisions, states
one invariant and its normative classification, provides a minimal deterministic
counterexample, bounds the impact, and includes correction evidence. A vector
proposal must include positive and adversarial arms and must be executable by a
second implementation without importing Forge code. Packets are deduplicated
against current DACS sources, issues, corrections, and vectors before submission;
executed and inferred claims remain distinct; fixtures are synthetic or otherwise
publishable.

This intake changes no DACS requirement, conformance verdict, or implementation
obligation by itself. Normative proposals follow the ordinary public steward review
and merge process. Forge remains independent and non-normative: it supplies
evidence for classification, never the expected-answer oracle.

## Bilateral Vet evidence boundary

The public source-provenance manifest binds the shipped Bilateral Vet
implementation and tests to one exact source commit. The repository does not
publish the raw semantic-review logs behind their development, a portable generated
Vet corpus, or evidence that an accepted external conformance rig has qualified this
snapshot. Local producer, consumer, adversarial, persistence, and restart tests are
implementation evidence only; they do not establish external qualification.

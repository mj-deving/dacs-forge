# Assurance evidence snapshot

This directory contains deterministic, synthetic evidence for three proposed DACS clarifications. It is implementation evidence, not normative authority, certification, a production result, or proof of live value transfer.

Bound revisions:

- DACS Forge base: `8a18849f932621c38795f4358560b07326dd9ad3`
- DACS-Standard development pin: `9a1ca624e8cc68361cff35c85a919cd72ba25199`
- Runtime: Bun `1.3.9`, Linux

Slices:

- `FORGE-ASSURANCE-001`: a passing VerifyResult must satisfy the complete ClaimRequirement predicate, not scheme alone.
- `FORGE-ASSURANCE-002`: referenced SettlementEvidence must pass independent semantic authority before reputation admission.
- `FORGE-ASSURANCE-003`: top-level settlement evidence must map bijectively to authenticated DACS-4 payment and delivery phases; optional per-phase pointers remain optional and must agree when present.

Run:

```sh
bun run evidence:assurance
bun test test/evidence/assurance-evidence.test.ts
```

To regenerate the frozen result after an intentional fixture or manifest change:

```sh
bun tools/run-assurance-evidence.ts --write
```

The test structurally compares a fresh evaluation with the parsed frozen `results.json`; the source-provenance manifest separately pins its exact bytes. Every mutation is a bounded countermodel inside the evidence runner. No mutation touches the product implementation.

Both green and mutant verdicts come from the neutral runner model. The product-file digests prove only that the named public implementation anchors were unchanged when this snapshot was built. Separately recorded focused tests execute those product paths; neither the model nor a digest substitutes for product execution or a second implementation.

Slice 001 models only the DACS fields that qualify a resolved candidate during aggregation: scheme, exact recipe version, listing-tightened maximum age, and the required parameter-key subset. Signature, content-hash, authority, and not-yet-verified checks occur before aggregation. The neutral fixture does not copy Forge-only availability or performed-verification summary fields; `verificationRequired` remains a requirement policy field, not an invented result-matching field.

Slice 002 deliberately treats inadmissible settlement evidence symmetrically: the job contributes to neither numerator nor denominators, even when its outcome is a permanent failure. A semantic contradiction makes the job unsafe as reputation input but does not identify which party caused it. Evidence-completeness, withholding, dispute, and adjudication rules are outside this snapshot; the runner does not infer fault from invalid input.

The repository-wide `check` intentionally fails if a pinned product file changes. Refreshing such a pin is a new evidence snapshot: update its digest in `manifest.json`, regenerate `results.json`, update the affected source-provenance digests, and re-run all recorded gates. A digest mismatch is not auto-accepted.

Public product-code anchors and focused tests are listed in `manifest.json`. The neutral fixtures do not depend on private review prompts, paths, commits, or task identifiers.

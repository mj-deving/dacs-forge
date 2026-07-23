# Security policy

DACS Forge is a prototype and must not be used for live value transfer.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for `mj-deving/dacs-forge`.
Do not open a public issue for an exploitable authority, signature, secret,
settlement, or persistence defect.

Include the affected commit, attack preconditions, minimal reproduction, expected
fail-closed behavior, and observed result. Do not include real credentials,
mnemonics, private keys, or funded transaction material.

## Current boundary

Only deterministic fixture/no-spend operation is implemented. No claim is made for
live keys, live payment rails, live Demos anchors, external attestation authority,
HTTP exposure, container isolation, or production deployment.

The security model treats unavailable authority as indeterminate or blocked, never
as verified. Fixture evidence must never become live or reputation-bearing through
configuration, serialization, or provenance substitution.

Every release is assessed only for its declared capability profile. Adding live
keys, network publication, payment, settlement, or spend support requires a new
threat model and release evidence; fixture qualification cannot be reused as proof
for those capabilities.

# Security policy

DACS Forge `v0.1.0` is supported only through the exact immutable release after
attestation and live public readback. Local candidates and branch tips are
unsupported. Every form of DACS Forge, including the supported release, remains
fixture/no-spend only and must not be used for live value transfer.

## Reporting a vulnerability

If the repository Security settings visibly show private vulnerability reporting
as enabled, use that channel. Until that live readback exists, report privately
to `mariusclaude@proton.me`. Do not open a public issue for an exploitable
authority, signature, secret, settlement, or persistence defect.

Publication is not evidence that GitHub security controls are enabled. The
authorized public cutover must separately enable and read back private
vulnerability reporting and must record whether Dependabot alerts, secret
scanning, and push protection are enabled, unavailable, or unsupported.

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

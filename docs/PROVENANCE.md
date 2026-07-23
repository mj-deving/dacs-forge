# Provenance

The machine-readable [source provenance manifest](SOURCE-PROVENANCE.json) binds
the history-clean root to its allowlisted implementation source and separates
public-only packaging files. The manifest intentionally omits its own digest.

## Normative source

- DACS-Standard commit: `ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4`
- `spec/CORE.md` B.2: RFC 8785 JCS, safe-integer constraint, CF-1 NFC normalization
- `spec/CORE.md` B.1: CF-2 ClaimReference canonical bytes and CF-3 identity
- `spec/CORE.md` B.7 SIG-6: unpadded Base64URL for DACS-owned signature
  `value` fields and explicit-only legacy import
- `spec/DACS-1-IDENTIFY.md` 6.3.1: v0.1 ClaimReference registry and identifier rules
- `spec/DACS-1-IDENTIFY.md` 6.3.2-6.3.4: IdentityBundle, Listing, validation order,
  SIG-5 refusal behavior, CF-4 addressing, and the 16,384-byte final Listing cap
- `spec/DACS-3-NEGOTIATE.md` 8.4.3, 8.6, 8.8: SE-1 HTTPS rule fetching,
  60-second commit lead time, CA-1 settlement gate, and PS-1..PS-3 pipeline constraints
- `spec/DACS-2-VET.md` 7.3.9, 7.5, 7.5.2: self-signed minimal-trust semantics,
  the uniform signed `VerifyResult`, and independent attestation resolution
- `spec/DACS-4-SETTLE.md` 9.3, 9.9: current PricingSpec, DeliverableSpec,
  PaymentRailRef shapes, and PIPE-1..PIPE-5 ordering semantics
- `spec/DACS-4-SETTLE.md` 9.6.3, 9.7: attested-payload delivery and the
  `SettlementEvidence` shape, including `deliverableContentHash` and `attestationRef`
- `spec/DACS-4-SETTLE.md` 9.5.8, 9.7: SB-1/SB-2 settlement consumption identity,
  strict fallback for undefined canonical rail identities, and FP-1..FP-4 final-data propagation
- `spec/DACS-5-VERIFY.md` 10.3.1: forward-only stage transitions and post-settlement rate branch

## Implementation references

`src/protocol/canonical-json.ts` was independently hardened from the behavioral
shape in `mj-deving/dacs-verify` commit
`9500ce91716397b6fe2e5cc4864abff7941030e7`, then extended to reject cycles,
non-plain objects, lone surrogates, sparse arrays, and NFC key collisions.

No runtime code is imported from an unpublished dacs-sdk branch.

`vectors/dacs-standard-canonicalize-db9f9c0.json` materializes the seven
`area: canonicalize` cases first pinned at `db9f9c0`. Those cases remain part of
the current DACS-Standard conformance manifest at `ad48d16`.

`vectors/dacs-standard-listing-preserve-unknown-c4ace08.json` is an exact copy
of `conformance/vectors/security/listing-preserve-unknown-v0.1.json` at the
current pin. File SHA-256:
`7dbe60aa89d44321a3bb04661b1d71fc15bc84501b76f23b486a05cb905f91bd`.

`vectors/dacs-standard-signature-value-encoding-c4ace08.json` is a local test
projection of all ten wire cases in
`conformance/vectors/security/signature-value-encoding-v0.1.json` at the current
pin. Local projection SHA-256:
`bdffb94642e4e1d0d96db5d6bf1abc604484c3ee75e121471e344102a03b2f36`.
Upstream source SHA-256:
`bf47cd0a42b0e0e30f2ff032327395d5a1b820758e6188c51212eb9129ba8312`.

`vectors/dacs-standard-settlement-finalization-ad48d16.json` is a local decision
projection of all six cases in
`conformance/vectors/security/settlement-finalization-propagation-v0.3.json`.
The exact upstream source SHA-256 is
`98c6356157b180d62e1049201143ab5681d9db2e71eb6f9aef6fdf20f787c555`.
The fixture settlement path exercises FP-1 and FP-2. The fixture DACS-5 path also
propagates and independently verifies the implemented FP-3/FP-4 terminal outcomes.

The same upstream pin added DACS-3 CA-6/CA-7 commitment-authority vectors. The
fixture lifecycle now produces, persists, resolves, and independently verifies an
orchestrator-signed commitment anchor. Verification requires an authenticated
canonical session-orchestrator binding; restart readback accepts only the current
signer or an exact `(signer, commitmentHash)` historical trust pin. This is local
fixture implementation evidence, not external vector qualification, live Demos
anchor resolution, or a full DACS conformance claim.

DACS-4 SB-1 currently defines byte-identical consumption keys for EVM-backed
x402, Solana, and Demos references, but not for AP2 or x402 provider-receipt-only
references. Those two forms are `refused-unsupported`; this implementation does
not mint a private canonical spelling that other consumers could not reproduce.

The fixture delivery path uses DACS-2 `self-signed` exactly as a minimal-trust
method: it verifies possession of the configured fixture key, canonical assertion
bytes, the DACS-2 signature envelope, and the complete assertion-to-VerifyResult-to-
delivery chain. Its implementation-defined assertion payload and logical addresses
are fixture provenance, not a new normative recipe or live authority claim.

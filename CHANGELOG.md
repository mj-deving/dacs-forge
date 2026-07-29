# Changelog

All notable changes to DACS Forge will be recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and release versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

## [0.1.0-preview.1] - 2026-07-29

Unsupported final Preview for the first Product Seal upgrade probe. Fixture/no-spend
only; no Product Seal, production, registration, live-value, certification, or
steward-endorsement claim.

### Added

- Integrated fixture service lifecycle that binds one admission to the Agreement and service request, uses the canonical handler output as the only Delivery payload, and replays the terminal graph without handler or settlement/delivery effects.
- Initial fixture/no-spend reference substrate and service-agent extension surface.
- Producer, consumer, lifecycle, persistence, conformance, and adversarial test rig.
- Public security, contribution, provenance, forking, governance, and versioning contracts.
- Protected session-admission HTTP boundaries with durable rate limits, bounded bodies and
  responses, verified artifact streaming, and deployment-scoped 256-bit capabilities.
- Administrator and bilateral party-capability lifecycle with proof-of-possession,
  revocation, bounded renewal, offline recovery, and clone identity rotation.
- Agreement-bound anonymous artifact disclosure requiring verified public delivery,
  signed seller policy, current buyer consent, and exact artifact binding.
- Explicit fixture/no-spend Directory registration after operator authorization,
  independent anchor verification, and exact post-registration read-back.
- Local digest-pinned container supply-chain qualification with Syft SPDX output,
  fresh Trivy evidence, zero-Critical policy, and bounded High dispositions.
- Experimental draft PR #290 evidence-bound fault bundle production, persistence,
  SEB-1..SEB-6 validation, distinct pointer/signature domains, and independent
  dacs-verify cross-check fixture; no released-conformance claim.

The immutable tag and GitHub release remain approval-gated until exact candidate
and live readback authorization.

# Governance

DACS Forge is an independent reference implementation and conformance substrate.
Its goal is a forkable, reviewable source base with explicit extension,
compatibility, and release boundaries. It makes no adoption, endorsement, or
canonical-status claim.

## Authority boundaries

- DACS-Standard owns normative protocol meaning.
- Demos specifications and implementations own their native runtime behavior.
- DACS Forge owns its implementation, extension contract, test rig, releases,
  and documented compatibility claims.
- A Forge behavior that conflicts with the normative specification is a defect,
  not a competing protocol rule.

## Maintainers

Until a broader maintainer group is recorded here, `mj-deving` is the release
maintainer. Maintainers merge contributions, classify security impact, maintain
compatibility declarations, and cut releases. No contributor affiliation grants
unilateral authority over protocol or security behavior.

## Decision standard

Changes to `service/` follow the declared extension contract. Changes to `src/`,
the release rig, authenticated bytes, authority resolution, settlement, delivery,
or persistence require explicit protocol and security justification.

Security and conformance evidence outrank convenience. Disputed normative
questions are escalated to DACS-Standard and remain blocked or fail-closed here
until resolved.

## Releases

A release requires the gates in [Versioning and releases](docs/VERSIONING.md).
Maintainers must not use a release to imply DACS steward approval, Demos-team
adoption, production readiness, or conformance beyond the evidence published for
that exact version.

During `0.x`, a breaking extension-contract or capability-profile change requires
at least a minor bump and migration guidance. Patch releases preserve the declared
extension contract and persisted-artifact compatibility.

## Security reporting

Use the private path in the [security policy](SECURITY.md). Exploitable authority,
signature, secret, settlement, or persistence defects must not be opened as public
issues.

## Contribution boundary

The [contribution guide](CONTRIBUTING.md) owns the public contribution path.
Service-specific changes stay inside `service/`; protocol, persistence, release-rig,
and authenticated-byte changes require separate protocol and security justification.

## Supported release

The first supported release is `v0.1.0`, but support activates only after its exact
immutable release readback succeeds. The same bytes in a local or public
prepublication candidate are not yet supported. The release implies no Community,
Demos-team, canonical, steward, adoption, or support organization endorsement.

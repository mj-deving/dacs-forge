# Versioning and releases

DACS Forge versions its own public contracts with Semantic Versioning. A Forge
version does not version DACS and does not imply certification, adoption,
production readiness, or steward endorsement.

## One release stream

- Preview tags use `v0.x.y-preview.N`.
- The first supported Product Seal is a `v0.x.y` release.
- There is no parallel `prototype | beta | stable` maturity taxonomy.
- `v1.0.0` is not a current target.

During `0.x`, a breaking change to the declared extension contract or capability
profile requires at least a minor bump and migration guidance. Patch releases
preserve the declared extension contract, persisted-artifact compatibility, and
capability profile. A DACS pin may change in a patch only when an impact
disposition and the complete applicable rig prove that no public contract or
behavior changed; otherwise it requires at least a minor bump and migration
guidance.

## Versioned contracts

Compatibility covers:

- the declared `service/` extension points;
- exported TypeScript APIs;
- persisted database and artifact shapes;
- CLI, HTTP, container, and operator surfaces once their capability is declared;
- exact DACS and Community pins;
- the complete applicable rig path and digests.

Forge versions never replace DACS versions. Every release records the exact DACS
profile, source revision, conformance vectors, and supported capabilities.

## Preview and Product Seal

A Preview is an immutable, unsupported evidence snapshot. The final Preview is
the only direct predecessor of the first Product Seal and supplies the base for
the mandatory extension-only update probe.

`v0.1.0-preview.1` is the historical first publication attempt. Its source and
tag remain intact, but its GitHub release predates repository release
immutability and is not the final Preview predecessor.

The replacement final Preview identity is `v0.1.0-preview.2`. Its source
candidate remains non-publishable as a package and becomes the final Preview
only after repository release immutability is enabled through the profile-pinned
authenticated PUT and confirmed through its profile-pinned authenticated GET,
the exact annotated tag and draft-to-published GitHub release are approved, CI
and public clone readback pass, and `gh release verify v0.1.0-preview.2` verifies the immutable release
attestation. Release immutability applies only to future releases and does not
retroactively qualify `v0.1.0-preview.1`.

The first Product Seal is one supported `v0.x.y` source release. It requires all
live product criteria to be green on one immutable commit, including fork and
update qualification, the complete applicable rig, compatibility guidance,
public governance, and exact upstream pins.

The first Product Seal version is `v0.1.0`. Its repository bytes may be prepared
and qualified as a prepublication candidate, but support and the Product Seal
claim activate only after the exact annotated tag, immutable GitHub release,
attestation, and public clone readback succeed. Candidate wording is operational
state, not a second public maturity taxonomy.

## Fork and update contract

The supported path is a Git fork or clone retaining shared history and an
`upstream` remote. Template-generated unrelated history is not a supported update
path.

Service forks keep their changes inside the declared `service/` extension paths.
A fork that changes protocol core, persistence, or the rig becomes a substrate
fork and receives no extension-only compatibility claim.

Every supported release publishes `UPGRADING.md` and a machine-readable
compatibility disposition for each claimed predecessor. Direct compatibility is
claimed only when an exact reference fork advances through shared history,
changes only extension paths, preserves signed artifacts and evidence, and passes
the unchanged complete release rig. Untested predecessors are explicitly
unsupported or use a documented multi-hop path whose every edge is tested.

Automatic conflict-free merging is not promised. The contract is a narrow
extension boundary, explicit migration guidance, and an executable compatibility
decision.

## Release evidence

Every supported release binds:

- immutable tag and source commit;
- package and repository version agreement;
- exact DACS and Community compatibility pins;
- capability profile and explicit unsupported surfaces;
- fresh-clone frozen install, full applicable tests, typecheck, build, and rig;
- changelog and migration disposition;
- reviewed public provenance manifest;
- MIT license, security-reporting path, contribution boundary, and no-endorsement statement.

A signed annotated tag and artifact attestation are desirable. They become
mandatory if Forge distributes executable packages or images, or when a concrete
consumer trust model requires them.

Skipped, failed, unavailable, or indeterminate required checks block a supported
release. Evidence from another commit, tag, manifest, or capability profile does
not qualify the release under review.

## Source cutover is not a release

Publishing the history-clean source root transfers implementation-source
authority only after its exact candidate is verified and approved. It does not
create a Preview or Product Seal, declare a supported capability, or transfer any
normative authority.

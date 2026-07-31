# DACS Forge

[![CI](https://github.com/mj-deving/dacs-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/mj-deving/dacs-forge/actions/workflows/ci.yml)

A hardened, forkable DACS reference service and conformance kit for building
specific DACS service agents.

> Release contract: **v0.1.1 Product Seal evidence correction**. Fixture/no-spend only. Support
> applies only to the exact immutable `v0.1.1` release after GitHub attestation
> and public readback; branch tips and prepublication candidates are unsupported.
> Not canonical, not production ready, and not suitable for live value transfer.

## What it proves

DACS Forge currently exercises a deterministic fixture lifecycle across:

```text
listing -> bilateral Vet -> agreement -> commitment
        -> settle/deliver -> role-local DACS-5 bundle verification
```

The implementation independently produces and consumes canonical bytes, hashes,
signatures, references, settlement evidence, delivery attestations, and DACS-5
bundle copies. Restart, replay, mutation, concurrency, migration, authority, and
failure-path tests are first-class release evidence.

It does **not** currently claim live Demos anchoring, live payment rails, external
attestation authority, an already published supported Product Seal, reputation
eligibility, or steward designation.

## The 90-second model

A service fork owns five paths under `service/`: metadata, input schema, output
schema, handler, and fixtures. Forge owns everything around them: admission,
schema validation, canonical bytes and hashes, signing, independent verification,
SQLite persistence, replay, the fixture protocol lifecycle, and role-local DACS-5
evidence bundles.

The handler is trusted application code, not a sandbox. It receives validated,
deep-frozen input and inert run metadata, but no signer, database, wallet, network
client, payment capability, or raw key through the handler API.

Two tests prove different things:

- `test/runtime/service-runtime.test.ts` executes the fork-owned handler and checks
  its output, signed work-product receipt, persistence, and replay.
- `test/e2e/full-handshake.test.ts` exercises the wider fixture lifecycle from a
  signed Listing through bilateral Vet, settlement, delivery, and role-local
  DACS-5 bundle verification.

Read the [architecture](docs/ARCHITECTURE.md) for the component and artifact flow,
then use [Forking DACS Forge](docs/FORKING.md) to build a first service.

## Quickstart

Requires Bun `1.3.9` on Linux.

```sh
git clone https://github.com/mj-deving/dacs-forge.git
cd dacs-forge
bun install --frozen-lockfile
bun test --timeout 10000 test/runtime/service-runtime.test.ts
bun test --timeout 10000 test/e2e/full-handshake.test.ts
bun run check
bun run build
```

The first focused test proves the builder-owned service path. The second proves
the complete implemented fixture handshake. `bun run check` verifies source
provenance, runs strict TypeScript validation, and executes the full test suite,
including pinned DACS vectors, independent canonicalization runs, adversarial
protocol probes, recovery tests, and cross-process SQLite tests.

### Local container fixture

The container is a local prototype artifact. It starts only after the fork-owned
service runtime and complete no-spend fixture handshake pass inside the image.
It has no live-mode command, runs as a non-root user, and needs no outbound
network for the lifecycle.

```sh
docker build --pull -t dacs-forge:fixture-local .
docker run --rm --network none --read-only \
  --tmpfs /runtime:rw,noexec,nosuid,nodev,uid=1000,gid=1000,mode=0700 \
  dacs-forge:fixture-local self-test
docker compose up --build --wait
docker compose down
```

The Compose service uses the same image entrypoint and health contract as
`docker run`. No image is published by these commands. Run `bun run
verify:container` for the clean local build, offline self-test,
non-root/health/shutdown probes, and Docker run/Compose equivalence.

With Syft, Trivy, and Docker's containerd image store installed, `bun run
container:supply-chain` builds a fresh local candidate, emits BuildKit, SPDX,
and scanner evidence under the ignored `dist/` directory, and verifies the
exact final/base digests, fresh vulnerability database, zero Critical findings,
and bounded High dispositions. It does not push an image. Distribution-only
signature and SLSA checks remain explicitly not applicable until a release
actually distributes one.

## Build a service agent

Fork-owned customization is intentionally narrow:

- `service/service.config.ts` — service metadata and deliverable kind
- `service/input.schema.json` — accepted request contract
- `service/output.schema.json` — work-product contract
- `service/handler.ts` — deterministic service logic
- `service/fixtures/` — deterministic examples and expected outputs

The protocol-critical lifecycle, persistence, signing, independent verification,
and conformance tests live outside `service/`. See [Forking DACS Forge](docs/FORKING.md),
the [architecture](docs/ARCHITECTURE.md), and the
[service contract](docs/SERVICE-CONTRACT.md).

## From Forge to Directory

DACS Forge is designed as a repeatable supply path for the
[DACS Directory](https://github.com/DACS-Agent-commerce/Community/tree/main/reference-implementations/dacs-directory):

```text
fork Forge -> define service agent -> qualify with the shared rig
           -> publish a signed Listing -> Directory discovery
```

Each fork can implement distinct service logic while retaining the same hardened
protocol substrate. Once its Listing is published through a supported operator
path, the Directory can discover it from chain state; catalog registration is not
a discovery requirement. Live publication and anchoring remain explicit future
gates—fixture mode never performs them automatically.

## Security model

- Fixture, local-chain, and live evidence are distinct and never interchangeable.
- Missing or indeterminate authority fails closed.
- Fixture keys cannot establish live authority.
- Default development paths perform no live registration, transfer, anchor,
  broadcast, or reputation write.
- Signed objects retain unknown inert fields inside their authenticated scope.

See [SECURITY.md](SECURITY.md) and the [Listing trust boundary](docs/LISTING-TRUST-BOUNDARY.md).

## Conformance status

Overall status: **v0.1.1 Product Seal source contract**. The patch preserves the
v0.1.0 runtime and extension contract while publishing the previously external
consumer and reference-fork qualification as digest-bound release evidence. The tagged source is
supported only after the exact immutable release and live readback complete.

The machine-readable [qualification index](release/qualification/index.json)
binds the standalone consumer, serialized artifact graph, Counterparty Evidence
reference-fork source, separate product authority, reports, and release-asset
locators. These establish independent Forge product verification and one bounded
extension-only reference fork; they do not establish normative DACS conformance,
certification, registration, deployment, or live commerce.

The repository pins and exercises named DACS-Standard vectors for canonical JSON,
signature-value encoding, Listing unknown-field retention, settlement finalization,
and DACS-5 bundle convergence. It also carries an explicitly experimental adapter
for draft PR #290's `EvidenceBoundFaultAttestationBundle`: the fixture lifecycle
produces, persists, reopens, and verifies the distinct type, while a portable fixture
is cross-checked by dacs-verify. The draft adapter is candidate evidence only; it is
not released DACS authority, a golden vector, certification, or full conformance.

Normative development pin and source projections are recorded in
[docs/PROVENANCE.md](docs/PROVENANCE.md). The history-clean root is bound to its
allowlisted source snapshot by
[docs/SOURCE-PROVENANCE.json](docs/SOURCE-PROVENANCE.json). The public review narrative is in
[docs/HARDENING.md](docs/HARDENING.md); raw internal review-control artifacts are
deliberately excluded from this repository.
Upstream vector and fixture licenses are retained in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Versioning and governance

DACS Forge is intended to grow from no-spend fixtures into separately gated live
and spend-capable profiles. Each public milestone is a versioned, reproducible
reference state—not an assertion that the project has stopped evolving.

See [versioning and release gates](docs/VERSIONING.md), the
[changelog](CHANGELOG.md), and [governance](GOVERNANCE.md).

## Project boundary

DACS Forge is an independent community implementation maintained by
[@mj-deving](https://github.com/mj-deving). “DACS Forge” does not imply canonical
status, steward certification, release readiness, or ownership by the DACS
organization.

License: MIT.

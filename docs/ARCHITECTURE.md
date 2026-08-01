# DACS Forge architecture

Status: the immutable `v0.1.1` Product Seal baseline is supported for
fixture/no-spend use. `main` also contains unreleased v0.2 foundation work. This
document describes the implemented local system; branch-tip development is not
covered by the v0.1.1 support contract. It does not claim production readiness,
certification, live value transfer, external authority, or full DACS conformance.

## What a service fork owns

A normal service fork changes exactly five extension paths:

- `service/service.config.ts`: typed runtime contract consuming the canonical service descriptor
- `service/input.schema.json`: accepted request contract
- `service/output.schema.json`: emitted work-product contract
- `service/handler.ts`: deterministic application logic
- `service/fixtures/**`: canonical service descriptor, deterministic examples, expected outputs, and committed Directory-supply fixture

Forge keeps protocol and evidence machinery outside that boundary. Changing
canonicalization, signing, verification, persistence, lifecycle ordering, or the
qualification rig creates a substrate fork rather than an ordinary service fork.

## Component and artifact flow

```text
builder-owned service contract
  config + schemas + handler + fixtures
                 |
                 v
session admission -- binds job, evidence mode, contract, input, and seed
                 |
                 v
ServiceRuntime -- validates input -> executes handler -> validates output
                 |
                 v
atomic SQLite write
  canonical work-product artifact + signed work-product receipt + run ledger
                 |
                 v
independent receipt verification and byte-identical replay after restart

integrated fixture service lifecycle
  signed Listing -> bilateral Vet -> Agreement -> Commitment
  -> handler output -> fixture settlement -> attested delivery -> role-local DACS-5 bundles
                 |
                 v
independent consumers re-derive bytes, hashes, signatures, authority, and bindings
```

The service runtime and full protocol lifecycle are joined by one admitted authority.
The runtime test isolates the builder handler and template work-product receipt. The
full-handshake test executes that handler, makes its canonical output the sole Delivery
payload, and resolves it through the terminal bundles. A first-service check runs both.

## Service runtime

`ServiceRuntime` compiles the input and output JSON Schemas with strict JSON Schema
2020-12 validation. It disables coercion, defaults, and unknown-property removal.
An admitted session binds the exact service contract, input, and fixture seed
before the handler runs.

The runtime then:

1. snapshots and deep-freezes validated input;
2. claims the service run in SQLite;
3. calls the handler with the input and `{ evidenceMode, jobId, seed }`;
4. validates and canonicalizes the output;
5. atomically stores the output artifact and signed work-product receipt;
6. independently verifies stored bytes before returning them.

The returned `ServiceRunResult` contains `output`, `receipt`, `outputArtifact`, and
`receiptArtifact`. A completed job replays those stored artifacts without invoking
the handler again. Concurrent duplicate execution is refused. Crash recovery is
an explicit offline action with claim, age, and isolation checks; it is not an
automatic retry loop.

The work-product receipt binds the job, request hash, service identity and version,
schema identities and hashes, input and output hashes, deliverable kind, evidence
mode, timestamp, seller claim, and Ed25519 signature. It is a Forge-specific
pre-settlement receipt, not DACS-4 `SettlementEvidence`.

## Protocol producer and consumer

Forge contains producers for signed protocol artifacts and separate consumer
modules that parse canonical JSON, recompute hashes and signature scopes, resolve
expected bindings, and fail closed on invalid or indeterminate evidence. They are
separate implementations inside this repository and process; this supports
independent checking, not external certification.

The fixture handshake exercises:

- a signed Listing and party identity bundles;
- buyer- and seller-side Vet results and composite records;
- Agreement and authenticated Commitment;
- no-spend fixture payment and DACS-4 settlement evidence;
- DACS-2 delivery assertion, verification result, and attestation references;
- buyer, seller, and orchestrator role-local DACS-5 bundle copies;
- restart readback of persisted state and artifacts.

The current experimental candidate path emits the distinct draft PR #290
`EvidenceBoundFaultAttestationBundle`. It reuses the same lifecycle, artifact,
anchor, and SQLite boundaries; only its discriminator, signature domain, pointer
domain, and SEB-1..SEB-6 settlement-evidence exact-set validation differ. The
portable fixture is additionally consumed by dacs-verify without importing or
delegating Forge validity to that verifier. This adapter does not add a provider,
key-custody, resolver, storage, or security platform.

## Persistence and recovery

SQLite stores sessions, service runs and artifacts, fixture authorities, Listings,
Vet records, Commitments, settlement, delivery, and bundle state. Writes that must
agree are transactional. Restart checks reopen the database and repeat resolution,
canonical-byte, hash, signature, authority, and binding verification instead of
trusting an earlier in-memory result.

The unreleased v0.2 live-profile foundation adds an immutable `live_effect_intents`
journal. Anchor, registration, and payment adapters receive a persisted effect key
and canonical payload; restart reconciliation must resolve that key before retry.
The default fixture profile does not load these adapters and remains zero-effect.
See [Live testnet profile](LIVE-TESTNET-PROFILE.md).

## Listing and Directory path

The local `ListingLifecycle` verifies and stores immutable signed Listing versions
and signed withdrawals under fixture authority. Forge also validates a pinned DACS
Directory `ListingSummary` shape and can report Directory schema drift.

`dacs register` is a separate explicit operator action. It consumes an injected
adapter that must explicitly declare fixture/no-spend execution mode, verifies exact current operator scope and independently
reads the anchored Listing bytes before submission, then reports success only after
an exact Directory read-back. Startup, self-test, Doctor, and the default fixture
lifecycle do not load a registration adapter or invoke registration. Live Directory
binding remains gated; no supported command supplies a live client or credentials.

## Trust boundary

The service handler is trusted fork-owned code running in the same process. The API
does not give it a signer, database, artifact store, wallet, payment capability,
network client, or raw key. This is capability minimization, not sandboxing: the
handler can still import ambient Bun or Node APIs. Fork maintainers must keep it
deterministic and side-effect-free.

The current prototype trusts reviewed first-party source, its pinned dependencies,
the Bun runtime, the operating system, and fixture keys for fixture evidence only.
It treats service input, persisted bytes, protocol messages, signatures, bindings,
restart state, and interruption timing as data to validate. Fixture keys do not
establish live identity, external source truth, reputation, or payment authority.

## Implemented versus still open

Implemented and locally exercised:

- the integrated service entry point binds the Agreement request and service request into one admission authority, executes the handler before Delivery, rejects payload substitution, and replays persisted output and terminal lifecycle state without repeating effects;
- the five-path service contract and handler runtime;
- strict schemas, canonical artifacts, signed receipts, persistence, replay, and
  bounded stale-claim recovery;
- the no-spend fixture protocol lifecycle and role-local DACS-5 bundles;
- local Listing lifecycle, Directory summary compatibility, doctor/readiness/HTTP
  surfaces, provenance checks, and mutation calibration.
- protected session challenge/admission routes with pre-work body, concurrency, and durable
  rate guards; bounded terminal responses and verified-length immutable artifact streaming;
- deployment- and audience-scoped administrator and bilateral party capabilities with
  proof-of-possession, amendment invalidation, last-administrator protection, offline
  recovery, and clone identity rotation.
- anonymous artifact delivery only after verified `public` delivery evidence, a signed
  agreement-bound seller policy, matching buyer consent, and current bilateral authority;
  the adapter reuses caller-owned storage and key resolution rather than implementing them.

Still open or explicitly outside the current claim:

- a supported v0.2 release and its live readback;
- live Directory registration, Demos anchoring, payment rails, or value transfer;
- external attestation authority, reputation eligibility, production operation,
  certification, steward designation, or full conformance.

## Glossary

- **Service contract:** service descriptor plus input/output schemas and handler.
- **Work-product artifact:** canonical output produced by the service handler.
- **Work-product receipt:** Forge-specific signed receipt for that output.
- **Settlement evidence:** DACS-4 artifact created later in the fixture lifecycle;
  not the work-product receipt.
- **Producer:** module that creates and signs an artifact.
- **Consumer:** separate module that re-derives and verifies an artifact.
- **Role-local bundle:** buyer, seller, or orchestrator copy of a DACS-5 evidence bundle.
- **Evidence mode:** `fixture`, `local-chain`, or `live`; evidence does not transfer
  authority between modes.
- **Qualification:** bounded evidence for a named snapshot and claim, not general
  certification or release status.

See the [service contract](SERVICE-CONTRACT.md), [Listing trust boundary](LISTING-TRUST-BOUNDARY.md),
[provenance model](PROVENANCE.md), and [versioning and release gates](VERSIONING.md).

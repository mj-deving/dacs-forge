# Service contract and work-product receipt

Status: fixture-only implementation boundary. The template receipt remains
non-normative, while the lifecycle separately produces fixture DACS-2 delivery
attestation and DACS-4 settlement evidence. Nothing here claims live delivery,
live anchoring, or authority-backed external attestation.

## Fork boundary

Builders change only `service/`:

- `service.config.ts`: service identity and deliverable kind
- `input.schema.json`: accepted request shape
- `output.schema.json`: emitted work-product shape
- `handler.ts`: deterministic business logic
- `fixtures/`: deterministic proof inputs and expected outputs

`src/service/` owns schema compilation, admitted-session and exact signed-request-hash gating,
receipt production, and persistence. The handler receives only a
deep-frozen validated input plus `{ evidenceMode, jobId, seed }`. It receives no
signer, database, artifact store, network client, payment capability, or raw key.

The handler is trusted fork-owned application code running in the service process,
not a security sandbox. It can still import ambient Bun/Node APIs. Fork maintainers
must keep it deterministic and side-effect-free; the fixture rig detects output
drift but cannot constrain malicious or careless source code. Handler semantics
changes require a service-version bump because admission binds the complete service
contract identity and schema hashes.

## Validation

Ajv 8 compiles JSON Schema draft 2020-12 in strict mode. Coercion, defaults, and
unknown-property removal are disabled. `ajv-formats` registers standard formats;
unknown formats fail contract startup. Input validation completes before handler
invocation. Output validation completes before any artifact write.

## Receipt

Every successful fixture run durably claims the admitted job, then atomically stores:

1. the canonical output artifact;
2. a `dacs-template:work-product-receipt:v1` receipt.

Completed jobs replay those original artifacts without invoking the handler again.
Concurrent duplicate execution fails before the second handler call. An ordinary
handler/validation failure releases its claim; an unclean process crash leaves the
claim fail-closed rather than risking duplicate execution. Recovery is an explicit
offline operator action through `ArtifactStore.recoverStaleServiceRun`: the executor
must be stopped, and the caller must provide the observed claim fingerprint, exact
creation timestamp, positive minimum age, recovery clock, and an explicit isolation
confirmation. The transaction refuses fresh, replaced, mismatched, or completed runs.
The completed ledger retains the original seller claim so replay remains verifiable
after legitimate signer rotation.

The receipt binds the admitted `jobId`, exact service id/version, evidence mode,
admission-bound request hash (including the fixture seed), input and output content hashes,
input and output schema identities/versions/hashes,
deliverable kind, canonical timestamp, seller key claim, and Ed25519 signature.
The consumer verifier independently canonicalizes bytes, recomputes both content
hashes, reconstructs the domain-separated signature scope, and verifies the
seller key.

The work-product receipt is template-specific and uses its own versioned signing
domain. Its current version uses the normative DACS `ComponentSignature` envelope
and the shared strict SIG-6 codec, pinned against all ten upstream wire cases.
It remains a template receipt rather than DACS-4 settlement evidence.

This receipt is a pre-settlement work-product primitive. The implemented fixture
lifecycle anchors an authenticated CA-6/CA-7 agreement commitment, creates
normative DACS-4 `SettlementEvidence` only after final no-spend ledger data is
independently verified, and prevents delivery execution until every required
payment and settlement succeeds.

For `deliver-attested-payload`, the fixture lifecycle canonicalizes the cleartext
JSON before hashing it, produces a domain-separated Ed25519 assertion and a
normative DACS-2 `VerifyResult`, and atomically persists assertion, VerifyResult,
payload-bearing delivery artifact, DACS-4 evidence, and their four logical-address
bindings. All artifacts bind the admitted session, job, phase index, agreement,
payload hash, and configured fixture orchestrator. Success is returned only after
independent post-persistence verification; restart readback repeats the same
resolution, canonical-byte, hash, signature, authority, and binding checks.
The shared substrate enforces globally unique job ULIDs at admission because the
normative DACS-4 deliverable address is derived from `jobId`; instance/audience
namespaces do not make a duplicate job address safe.

The selected fixture method is `self-signed`. It proves possession of the configured
fixture key and session continuity only. It does not establish external source
truth or satisfy the still-open listing-selected verification-method criterion.
The fixture lifecycle assembles and independently verifies role-local DACS-5
bundle copies. It still does not resolve a live Demos anchor or establish external
attestation authority; those links remain explicit qualification blockers.

Delivery evidence does not reuse the delivered payload or entitlement address.
The pinned standard defines those artifact addresses but no canonical address
formula for the separate `SettlementEvidence` anchor. The producer and consumer
therefore require an explicit evidence address from the surrounding
`AttestationRef` and refuse absent, malformed, or colliding bindings. No local
address formula is presented as normative.

export type AtomicWriteOperation = "delete" | "insert" | "update";

export type AtomicWriteTransactionMode = "autocommit" | "immediate";

export interface AtomicWriteSite {
  readonly boundary: string;
  readonly id: string;
  readonly operation: AtomicWriteOperation;
  readonly owner: string;
  readonly source: string;
  readonly table: string;
  readonly transactionMode: AtomicWriteTransactionMode;
}

const SITE_ROWS = [
  ["service-run.claim", "service-run-claim", "insert", "ArtifactStore.constructor", "src/substrate/sqlite/artifact-store.ts", "service_runs"],
  ["service-run.complete", "service-run-complete", "update", "ArtifactStore.constructor", "src/substrate/sqlite/artifact-store.ts", "service_runs"],
  ["service-run.release", "service-run-release", "delete", "ArtifactStore.constructor", "src/substrate/sqlite/artifact-store.ts", "service_runs"],
  ["service-run.recover", "service-run-recover", "delete", "ArtifactStore.constructor", "src/substrate/sqlite/artifact-store.ts", "service_runs"],
  ["artifact.put-blob", "artifact-batch", "insert", "ArtifactStore.#putOne", "src/substrate/sqlite/artifact-store.ts", "artifacts"],
  ["artifact.put-kind", "artifact-batch", "insert", "ArtifactStore.#putOne", "src/substrate/sqlite/artifact-store.ts", "artifact_kinds"],
  ["admission.cleanup-challenges", "challenge-allocation", "delete", "SessionStore.#allocateTransaction", "src/substrate/sqlite/session-store.ts", "admission_challenges"],
  ["admission.allocate-challenge", "challenge-allocation", "insert", "SessionStore.#allocateTransaction", "src/substrate/sqlite/session-store.ts", "admission_challenges"],
  ["admission.consume-challenge", "session-admission", "update", "SessionStore.#admitTransaction", "src/substrate/sqlite/session-store.ts", "admission_challenges"],
  ["admission.create-session", "session-admission", "insert", "SessionStore.#admitTransaction", "src/substrate/sqlite/session-store.ts", "sessions"],
  ["admission.record-consumption", "session-admission", "insert", "SessionStore.#admitTransaction", "src/substrate/sqlite/session-store.ts", "admission_consumptions"],
  ["http-rate.cleanup", "http-rate-limit", "delete", "HttpResourceGuards.#consumeRateTransaction", "src/http/resource-guards.ts", "http_rate_buckets"],
  ["http-rate.consume", "http-rate-limit", "insert", "HttpResourceGuards.#consumeRateTransaction", "src/http/resource-guards.ts", "http_rate_buckets"],
  ["production-key.activate", "production-key-activation", "insert", "ProductionKeyLifecycle.activateInitialKey", "src/substrate/keys/production-key-lifecycle.ts", "production_signing_keys"],
  ["production-key.retain-listing", "production-key-listing-retention", "insert", "ProductionKeyLifecycle.#registerRetainedListing", "src/substrate/keys/production-key-lifecycle.ts", "production_key_listing_versions"],
  ["production-key.revoke-current", "production-key-rotation", "update", "ProductionKeyLifecycle.rotate", "src/substrate/keys/production-key-lifecycle.ts", "production_signing_keys"],
  ["production-key.activate-replacement", "production-key-rotation", "insert", "ProductionKeyLifecycle.rotate", "src/substrate/keys/production-key-lifecycle.ts", "production_signing_keys"],
  ["production-key.publish-revocation", "production-key-rotation", "insert", "ProductionKeyLifecycle.rotate", "src/substrate/keys/production-key-lifecycle.ts", "production_key_revocations"],
  ["production-key.pin-committed-session", "production-key-session-pin", "insert", "ProductionKeyLifecycle.pinCommittedSession", "src/substrate/keys/production-key-lifecycle.ts", "production_session_key_pins"],
  ["listing.reserve-anchor", "listing-publication", "insert", "ListingStore.publish", "src/substrate/sqlite/listing-store.ts", "fixture_listing_anchor_registry"],
  ["listing.publish-version", "listing-publication", "insert", "ListingStore.publish", "src/substrate/sqlite/listing-store.ts", "fixture_listing_lifecycle_versions"],
  ["listing.advance-discovery", "listing-publication", "insert", "ListingStore.publish", "src/substrate/sqlite/listing-store.ts", "fixture_listing_discovery"],
  ["listing.reserve-revocation-anchor", "listing-revocation", "insert", "ListingStore.revoke", "src/substrate/sqlite/listing-store.ts", "fixture_listing_anchor_registry"],
  ["listing.publish-revocation", "listing-revocation", "insert", "ListingStore.revoke", "src/substrate/sqlite/listing-store.ts", "fixture_listing_revocations"],
  ["listing.withdraw-discovery", "listing-revocation", "delete", "ListingStore.revoke", "src/substrate/sqlite/listing-store.ts", "fixture_listing_discovery"],
  ["listing.pin-session", "listing-session-pin", "insert", "ListingStore.pinSession", "src/substrate/sqlite/listing-store.ts", "fixture_session_listing_pins"],
  ["authority.put-listing", "agreement-commitment", "insert", "FixtureAuthorityStore.putListingWithinTransaction", "src/substrate/sqlite/fixture-authority-store.ts", "fixture_listing_authorities"],
  ["authority.put-listing-verification", "agreement-commitment", "insert", "FixtureAuthorityStore.putListingWithinTransaction", "src/substrate/sqlite/fixture-authority-store.ts", "fixture_listing_verification_authorities"],
  ["authority.put-commitment-identity", "agreement-commitment", "insert", "FixtureAuthorityStore.#putIdentityWithinTransaction", "src/substrate/sqlite/fixture-authority-store.ts", "fixture_identity_authorities"],
  ["authority.put-identity", "bundle-finalisation", "insert", "FixtureAuthorityStore.#putIdentityWithinTransaction", "src/substrate/sqlite/fixture-authority-store.ts", "fixture_identity_authorities"],
  ["vet.put-record", "vet-persistence", "insert", "FixtureVetStore.#persistWithinTransaction", "src/substrate/sqlite/fixture-vet.ts", "fixture_vet_records"],
  ["vet.put-artifact-anchor", "vet-persistence", "insert", "FixtureVetStore.#persistWithinTransaction", "src/substrate/sqlite/fixture-vet.ts", "fixture_anchors"],
  ["vet.put-requirement-anchor", "vet-persistence", "insert", "FixtureVetStore.#persistWithinTransaction", "src/substrate/sqlite/fixture-vet.ts", "fixture_anchors"],
  ["commitment.put", "agreement-commitment", "insert", "FixtureCommitmentStore.#anchorTransaction", "src/substrate/sqlite/fixture-commitment.ts", "fixture_commitments"],
  ["failure-evidence.put", "failure-evidence", "insert", "FixtureFailureEvidenceStore.record", "src/substrate/sqlite/fixture-settlement.ts", "fixture_failure_evidence"],
  ["settlement-evidence.put-anchor", "failure-evidence-anchor", "insert", "FixtureFailureEvidenceStore.persistSigned", "src/substrate/sqlite/fixture-settlement.ts", "fixture_anchors"],
  ["settlement-ledger.put", "settlement-ledger", "insert", "FixtureSettlementLedger.record", "src/substrate/sqlite/fixture-settlement.ts", "fixture_settlements"],
  ["anchor.put", "artifact-anchor", "insert", "FixtureAnchorStore.put", "src/substrate/sqlite/fixture-settlement.ts", "fixture_anchors"],
  ["settlement-consumption.put", "artifact-anchor", "insert", "FixtureAnchorStore.put", "src/substrate/sqlite/fixture-settlement.ts", "fixture_settlement_consumptions"],
  ["delivery.put-record", "attested-delivery", "insert", "FixtureDeliveryStore.deliver", "src/substrate/sqlite/fixture-delivery.ts", "fixture_deliveries"],
  ["delivery.put-anchor", "attested-delivery", "insert", "FixtureDeliveryStore.deliver", "src/substrate/sqlite/fixture-delivery.ts", "fixture_anchors"],
  ["bundle.put-anchor", "bundle-finalisation", "insert", "FixtureBundleStore.#finaliseWithinTransaction", "src/substrate/sqlite/fixture-bundle.ts", "fixture_anchors"],
  ["bundle.put-copy", "bundle-finalisation", "insert", "FixtureBundleStore.#finaliseWithinTransaction", "src/substrate/sqlite/fixture-bundle.ts", "fixture_bundles"],
  ["bundle.finalise-lifecycle", "bundle-finalisation", "update", "FixtureBundleStore.#finaliseWithinTransaction", "src/substrate/sqlite/fixture-bundle.ts", "fixture_lifecycle_runs"],
  ["lifecycle.abort", "lifecycle-abort", "update", "FixtureLifecycleOrchestrator.abort", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.claim", "lifecycle-claim", "insert", "FixtureLifecycleOrchestrator.#claimTransaction", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.recover-commit-pending", "lifecycle-recover-commit", "update", "FixtureLifecycleOrchestrator.#claimPendingRecovery", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.recover-settlement", "lifecycle-recover-settlement", "update", "FixtureLifecycleOrchestrator.#claimSettlementRecovery", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.commit-completed", "lifecycle-commit-transition", "update", "FixtureLifecycleOrchestrator.#advanceCommitted", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.settle-pending", "lifecycle-commit-transition", "update", "FixtureLifecycleOrchestrator.#advanceCommitted", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.resume-paused", "lifecycle-resume", "update", "FixtureLifecycleOrchestrator.#resumePaused", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.invoke-stage", "lifecycle-stage-invocation", "update", "FixtureLifecycleOrchestrator.#markInvocation", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.record-stage", "lifecycle-stage-result", "update", "FixtureLifecycleOrchestrator.#recordPhaseSuccess", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.complete", "lifecycle-complete", "update", "FixtureLifecycleOrchestrator.#recordDeliverySuccess", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.stop", "lifecycle-terminal-stop", "update", "FixtureLifecycleOrchestrator.#transitionStop", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
  ["lifecycle.expire-pause", "lifecycle-expire-pause", "update", "FixtureLifecycleOrchestrator.#expirePaused", "src/lifecycle/fixture-orchestrator.ts", "fixture_lifecycle_runs"],
] as const satisfies readonly (readonly [
  string,
  string,
  AtomicWriteOperation,
  string,
  string,
  string,
])[];

const AUTOCOMMIT_SITE_IDS: ReadonlySet<string> = new Set([
  "lifecycle.abort",
  "lifecycle.recover-settlement",
  "lifecycle.resume-paused",
  "lifecycle.invoke-stage",
  "lifecycle.record-stage",
  "lifecycle.complete",
  "lifecycle.stop",
  "lifecycle.expire-pause",
]);

export const ATOMIC_WRITE_SITES: readonly AtomicWriteSite[] = Object.freeze(SITE_ROWS.map(
  ([id, boundary, operation, owner, source, table]) => Object.freeze({
    boundary,
    id,
    operation,
    owner,
    source,
    table,
    transactionMode: AUTOCOMMIT_SITE_IDS.has(id) ? "autocommit" as const : "immediate" as const,
  }),
));

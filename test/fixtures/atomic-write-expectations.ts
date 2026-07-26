import type { AtomicWriteTransactionMode } from "../../src/substrate/sqlite/atomic-write-registry.ts";

export interface ExpectedAtomicWriteSite {
  readonly api: "query.run";
  readonly boundary: string;
  readonly owner: string;
  readonly ownerFrames: readonly string[];
  readonly runtimeFrame?: string;
  readonly transactionMode: AtomicWriteTransactionMode;
}

export const EXPECTED_ATOMIC_WRITE_SITES: Readonly<Record<string, ExpectedAtomicWriteSite>> = Object.freeze({
  "service-run.claim": expected("service-run-claim", "ArtifactStore.constructor", "immediate", "artifact-store.ts:137"),
  "service-run.complete": expected("service-run-complete", "ArtifactStore.constructor", "immediate", "artifact-store.ts:168"),
  "service-run.release": expected("service-run-release", "ArtifactStore.constructor", "immediate", "artifact-store.ts:200"),
  "service-run.recover": expected("service-run-recover", "ArtifactStore.constructor", "immediate", "artifact-store.ts:225"),
  "artifact.put-blob": expected("artifact-batch", "ArtifactStore.#putOne", "immediate", "artifact-store.ts:342"),
  "artifact.put-kind": expected("artifact-batch", "ArtifactStore.#putOne", "immediate", "artifact-store.ts:352"),
  "admission.cleanup-challenges": expected("challenge-allocation", "SessionStore.#allocateTransaction", "immediate", "session-store.ts:344"),
  "admission.allocate-challenge": expected("challenge-allocation", "SessionStore.#allocateTransaction", "immediate", "session-store.ts:422"),
  "admission.consume-challenge": expected("session-admission", "SessionStore.#admitTransaction", "immediate", "session-store.ts:470"),
  "admission.create-session": expected("session-admission", "SessionStore.#admitTransaction", "immediate", "session-store.ts:520"),
  "admission.record-consumption": expected("session-admission", "SessionStore.#admitTransaction", "immediate", "session-store.ts:534"),
  "listing.reserve-anchor": expected("listing-publication", "ListingStore.publish", "immediate", "listing-store.ts:71"),
  "listing.publish-version": expected("listing-publication", "ListingStore.publish", "immediate", "listing-store.ts:81"),
  "listing.advance-discovery": expected("listing-publication", "ListingStore.publish", "immediate", "listing-store.ts:95"),
  "listing.reserve-revocation-anchor": expected("listing-revocation", "ListingStore.revoke", "immediate", "listing-store.ts:152"),
  "listing.publish-revocation": expected("listing-revocation", "ListingStore.revoke", "immediate", "listing-store.ts:164"),
  "listing.withdraw-discovery": expected("listing-revocation", "ListingStore.revoke", "immediate", "listing-store.ts:171"),
  "listing.pin-session": expected("listing-session-pin", "ListingStore.pinSession", "immediate", "listing-store.ts:238"),
  "authority.put-listing": expected("agreement-commitment", "FixtureAuthorityStore.putListingWithinTransaction", "immediate", "fixture-authority-store.ts:105"),
  "authority.put-listing-verification": expected("agreement-commitment", "FixtureAuthorityStore.putListingWithinTransaction", "immediate", "fixture-authority-store.ts:124"),
  "authority.put-commitment-identity": expected(
    "agreement-commitment",
    "FixtureAuthorityStore.#putIdentityWithinTransaction",
    "immediate",
    "fixture-authority-store.ts:186",
  ),
  "authority.put-identity": expected(
    "bundle-finalisation",
    "FixtureAuthorityStore.#putIdentityWithinTransaction",
    "immediate",
    "fixture-authority-store.ts:193",
  ),
  "vet.put-record": expected("vet-persistence", "FixtureVetStore.#persistWithinTransaction", "immediate", "fixture-vet.ts:586"),
  "vet.put-artifact-anchor": expected("vet-persistence", "FixtureVetStore.#persistWithinTransaction", "immediate", "fixture-vet.ts:901", ["fixture-vet.ts:564", "fixture-vet.ts:565", "fixture-vet.ts:566"]),
  "vet.put-requirement-anchor": expected("vet-persistence", "FixtureVetStore.#persistWithinTransaction", "immediate", "fixture-vet.ts:937", ["fixture-vet.ts:556"]),
  "commitment.put": expected("agreement-commitment", "FixtureCommitmentStore.#anchorTransaction", "immediate", "fixture-commitment.ts:393"),
  "failure-evidence.put": expected("failure-evidence", "FixtureFailureEvidenceStore.record", "immediate", "fixture-settlement.ts:85"),
  "settlement-evidence.put-anchor": expected("failure-evidence-anchor", "FixtureFailureEvidenceStore.persistSigned", "immediate", "fixture-settlement.ts:126"),
  "settlement-ledger.put": expected("settlement-ledger", "FixtureSettlementLedger.record", "immediate", "fixture-settlement.ts:331"),
  "anchor.put": expected("artifact-anchor", "FixtureAnchorStore.put", "immediate", "fixture-settlement.ts:509"),
  "settlement-consumption.put": expected("artifact-anchor", "FixtureAnchorStore.put", "immediate", "fixture-settlement.ts:832", ["fixture-settlement.ts:494"]),
  "delivery.put-record": expected("attested-delivery", "FixtureDeliveryStore.deliver", "immediate", "fixture-delivery.ts:287"),
  "delivery.put-anchor": expected("attested-delivery", "FixtureDeliveryStore.deliver", "immediate", "fixture-delivery.ts:919", ["fixture-delivery.ts:262", "fixture-delivery.ts:264", "fixture-delivery.ts:266", "fixture-delivery.ts:268"]),
  "bundle.put-anchor": expected("bundle-finalisation", "FixtureBundleStore.#finaliseWithinTransaction", "immediate", "fixture-bundle.ts:336"),
  "bundle.put-copy": expected("bundle-finalisation", "FixtureBundleStore.#finaliseWithinTransaction", "immediate", "fixture-bundle.ts:349"),
  "bundle.finalise-lifecycle": expected("bundle-finalisation", "FixtureBundleStore.#finaliseWithinTransaction", "immediate", "fixture-bundle.ts:369"),
  "lifecycle.abort": expected("lifecycle-abort", "FixtureLifecycleOrchestrator.abort", "autocommit", "fixture-orchestrator.ts:397"),
  "lifecycle.claim": expected("lifecycle-claim", "FixtureLifecycleOrchestrator.#claimTransaction", "immediate", "fixture-orchestrator.ts:755"),
  "lifecycle.recover-commit-pending": expected("lifecycle-recover-commit", "FixtureLifecycleOrchestrator.#claimPendingRecovery", "immediate", "fixture-orchestrator.ts:784"),
  "lifecycle.recover-settlement": expected("lifecycle-recover-settlement", "FixtureLifecycleOrchestrator.#claimSettlementRecovery", "autocommit", "fixture-orchestrator.ts:871"),
  "lifecycle.commit-completed": expected("lifecycle-commit-transition", "FixtureLifecycleOrchestrator.#advanceCommitted", "immediate", "fixture-orchestrator.ts:900"),
  "lifecycle.settle-pending": expected("lifecycle-commit-transition", "FixtureLifecycleOrchestrator.#advanceCommitted", "immediate", "fixture-orchestrator.ts:918"),
  "lifecycle.resume-paused": expected("lifecycle-resume", "FixtureLifecycleOrchestrator.#resumePaused", "autocommit", "fixture-orchestrator.ts:959"),
  "lifecycle.invoke-stage": expected("lifecycle-stage-invocation", "FixtureLifecycleOrchestrator.#markInvocation", "autocommit", "fixture-orchestrator.ts:1012"),
  "lifecycle.record-stage": expected("lifecycle-stage-result", "FixtureLifecycleOrchestrator.#recordPhaseSuccess", "autocommit", "fixture-orchestrator.ts:1040"),
  "lifecycle.complete": expected("lifecycle-complete", "FixtureLifecycleOrchestrator.#recordDeliverySuccess", "autocommit", "fixture-orchestrator.ts:1065"),
  "lifecycle.stop": expected("lifecycle-terminal-stop", "FixtureLifecycleOrchestrator.#transitionStop", "autocommit", "fixture-orchestrator.ts:1131"),
  "lifecycle.expire-pause": expected("lifecycle-expire-pause", "FixtureLifecycleOrchestrator.#expirePaused", "autocommit", "fixture-orchestrator.ts:1206"),
} satisfies Readonly<Record<string, ExpectedAtomicWriteSite>>);

function expected(
  boundary: string,
  owner: string,
  transactionMode: AtomicWriteTransactionMode = "immediate",
  runtimeFrame?: string,
  ownerFrames?: readonly string[],
): ExpectedAtomicWriteSite {
  return Object.freeze({
    api: "query.run" as const,
    boundary,
    owner,
    ownerFrames: Object.freeze([...(ownerFrames ?? (runtimeFrame === undefined ? [] : [runtimeFrame]))]),
    transactionMode,
    ...(runtimeFrame === undefined ? {} : { runtimeFrame }),
  });
}

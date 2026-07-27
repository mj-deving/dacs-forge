import { assertFixtureAuthority, type EvidenceMode } from "../../core/evidence-mode.ts";
import { reconcileAttestationBundleReads, type BundleAddressRead, type BundleConsistencyResult } from "../../consumer/bundle-consistency.ts";
import { verifyCanonicalAttestationBundleJson } from "../../consumer/attestation-bundle-verifier.ts";
import { verifyCommittedAgreementCryptography } from "../../consumer/commitment-verifier.ts";
import { verifyDeliveryAttestation } from "../../consumer/delivery-attestation-verifier.ts";
import { verifyCanonicalSettlementEvidenceJson } from "../../consumer/settlement-evidence-verifier.ts";
import { canonicalize } from "../../protocol/canonical-json.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import {
  bundleLogicalAddress,
  signEvidenceBoundFaultAttestationBundleCopies,
  type BundlePartySigner,
  type BundleRole,
  type UnsignedAttestationBundle,
} from "../../producer/attestation-bundle.ts";
import {
  isFaultAttestationBundle, outcomeClass,
  roleRelativeOutcome,
  type BundleFaultedParty,
} from "../../protocol/fault-attestation-bundle.ts";
import type { AttestationReferenceContext } from "../../consumer/attestation-bundle-verifier.ts";
import { ArtifactIntegrityError, ArtifactStore } from "./artifact-store.ts";
import type { DacsDatabase } from "./database.ts";
import { readPersistedSessionByJobId, sessionBindingHash, type SessionRecord } from "./session-store.ts";
import {
  FixtureFailureEvidenceStore,
  verifyPersistedFixtureSettlementEvidence,
  type PersistedFixtureSettlementAuthority,
} from "./fixture-settlement.ts";
import { verifyFixtureX402Receipt } from "../fixture-x402-receipt.ts";
import { FixtureAuthorityStore } from "./fixture-authority-store.ts";
import {
  FixtureCommitmentIntegrityError,
  type FixtureCommitmentRecord,
  type FixtureCommitmentStore,
} from "./fixture-commitment.ts";
import {
  FixtureVetConflictError,
  FixtureVetIntegrityError,
  FixtureVetStore,
} from "./fixture-vet.ts";

export class FixtureBundleConflictError extends Error { override readonly name = "FixtureBundleConflictError"; }
export class FixtureBundleIntegrityError extends Error { override readonly name = "FixtureBundleIntegrityError"; }
class FixtureBundleRejectedError extends Error { override readonly name = "FixtureBundleRejectedError"; }
class FixtureBundleIndeterminateError extends Error { override readonly name = "FixtureBundleIndeterminateError"; }

export interface FixtureBundleStoreOptions {
  readonly commitments: FixtureCommitmentStore;
  readonly deploymentMode: EvidenceMode;
}
export interface FixtureBundleFinaliseInput {
  readonly anchorRoles: readonly BundleRole[];
  readonly bundle: UnsignedAttestationBundle;
  readonly createdAt: string;
  /** Required when the legacy lifecycle outcome leaves more than one non-anchor party possible. */
  readonly faultedParty?: BundleFaultedParty;
  readonly partySigners: readonly BundlePartySigner[];
  readonly partyIdentityCanonicalJsons: readonly string[];
  readonly session: SessionRecord;
}
export interface FixtureBundleRecord {
  readonly anchoredByRole: BundleRole;
  readonly artifactContentHash: string;
  readonly bundleHash: string;
  readonly canonicalJson: string;
  readonly createdAt: string;
  readonly finalisedAt: number;
  readonly jobId: string;
  readonly logicalAddress: string;
}
export interface FixtureBundleFinalisation {
  readonly bundleHash: string;
  readonly copies: readonly FixtureBundleRecord[];
  readonly state: "finalised";
}

interface LifecycleFinalisationRow {
  readonly abortActorRole: "buyer" | "seller" | null;
  readonly abortReason: string | null;
  readonly agreementArtifactHash: string;
  readonly commitmentArtifactHash: string | null;
  readonly createdAt: string;
  readonly deliveryPhaseIndex: bigint;
  readonly deliveryPhaseKind: string;
  readonly deliveryResultJson: string | null;
  readonly deliveryInvocations: bigint;
  readonly errorClass: "permanent" | "counterparty" | "transient" | "substrate" | "settlement-atomicity" | null;
  readonly endedAt: string | null;
  readonly failureReason: string | null;
  readonly failureStage: "commit" | "payment" | "settlement" | "delivery" | null;
  readonly paymentInvocations: bigint;
  readonly paymentResultJson: string | null;
  readonly requiredPaymentPhasesJson: string;
  readonly settlementResultJson: string | null;
  readonly settlementInvocations: bigint;
  readonly state: string;
  readonly terminalResultJson: string | null;
  readonly terminalState: "settle-failed" | "settle-unsupported" | "failed-substrate" | "aborted" | null;
  readonly updatedAt: string;
  readonly version: bigint;
}
interface BundleRow {
  readonly anchoredByRole: BundleRole;
  readonly artifactContentHash: string;
  readonly bundleHash: string;
  readonly createdAt: string;
  readonly finalisedAt: bigint;
  readonly jobId: string;
  readonly logicalAddress: string;
}

export class FixtureBundleStore {
  readonly #artifacts: ArtifactStore;
  readonly #authorities: FixtureAuthorityStore;
  readonly #commitments: FixtureCommitmentStore;
  readonly #database: DacsDatabase;
  readonly #failures: FixtureFailureEvidenceStore;
  readonly #finalise: (input: FixtureBundleFinaliseInput) => FixtureBundleFinalisation;
  readonly #vet: FixtureVetStore;

  constructor(database: DacsDatabase, options: FixtureBundleStoreOptions) {
    assertFixtureAuthority(options.deploymentMode, "fixture");
    this.#database = database;
    this.#artifacts = new ArtifactStore(database);
    this.#authorities = new FixtureAuthorityStore(database);
    this.#commitments = options.commitments;
    this.#failures = new FixtureFailureEvidenceStore(database, options.deploymentMode);
    this.#vet = new FixtureVetStore(database, options.deploymentMode);
    const transaction = database.transaction((input: FixtureBundleFinaliseInput) => this.#finaliseWithinTransaction(input));
    this.#finalise = (input) => transaction.immediate(input) as FixtureBundleFinalisation;
  }

  #readCommitmentAuthority(session: SessionRecord): FixtureCommitmentRecord | null {
    try {
      return this.#commitments.get(session.instanceId, session.audience, session.jobId);
    } catch (error) {
      if (error instanceof FixtureCommitmentIntegrityError || error instanceof ArtifactIntegrityError) {
        throw new FixtureBundleIntegrityError(`Persisted commitment authority is invalid: ${error.message}`);
      }
      throw error;
    }
  }

  finalise(input: FixtureBundleFinaliseInput): FixtureBundleFinalisation {
    validateSession(input.session);
    validateTimestamp(input.createdAt);
    return this.#finalise(Object.freeze({ ...input }));
  }

  get(jobId: string, role: BundleRole): FixtureBundleRecord | null {
    const expectedAddress = bundleLogicalAddress(jobId, role);
    const row = this.#database.query<BundleRow, { jobId: string; role: BundleRole }>(`
      SELECT job_id AS jobId, anchored_by_role AS anchoredByRole,
        logical_address AS logicalAddress, bundle_hash AS bundleHash,
        artifact_content_hash AS artifactContentHash, finalised_at AS finalisedAt,
        created_at AS createdAt
      FROM fixture_bundles WHERE job_id = $jobId AND anchored_by_role = $role
    `).get({ jobId, role });
    if (row === null) {
      const anchorExists = this.#database.query<{ present: bigint }, { logicalAddress: string }>(
        "SELECT count(*) AS present FROM fixture_anchors WHERE logical_address = $logicalAddress",
      ).get({ logicalAddress: expectedAddress })!.present > 0n;
      if (anchorExists || this.#finalisedRoleExpected(jobId, role)) {
        throw new FixtureBundleIntegrityError("Expected finalised role-local bundle record is missing");
      }
      return null;
    }
    if (row.logicalAddress !== bundleLogicalAddress(jobId, role)) {
      throw new FixtureBundleIntegrityError("Persisted bundle address does not match its role");
    }
    const session = readPersistedSessionByJobId(this.#database, jobId);
    if (session === null) throw new FixtureBundleIntegrityError("Persisted bundle lacks its admitted session");
    const artifact = this.#artifacts.get(row.artifactContentHash);
    if (artifact === null || !artifact.kinds.includes("dacs-5-bundle")
      || sha256Hex(artifact.canonicalJson) !== row.artifactContentHash) {
      throw new ArtifactIntegrityError("Persisted bundle artifact is unavailable or mistyped");
    }
    const anchor = this.#database.query<{
      artifactKind: string; contentHash: string; artifactContentHash: string | null;
    }, { logicalAddress: string }>(`
      SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
        artifact_content_hash AS artifactContentHash
      FROM fixture_anchors WHERE logical_address = $logicalAddress
    `).get({ logicalAddress: row.logicalAddress });
    if (anchor === null || anchor.artifactKind !== "dacs-5-bundle"
      || anchor.contentHash !== row.bundleHash || anchor.artifactContentHash !== row.artifactContentHash) {
      throw new FixtureBundleIntegrityError("Persisted role-local bundle anchor is unavailable or inconsistent");
    }
    const verification = verifyCanonicalAttestationBundleJson(artifact.canonicalJson, {
      expectedAddress: row.logicalAddress,
      expectedJobId: jobId,
      resolveListingRef: (ref) => this.#resolveListingAuthority(jobId, ref),
      resolveExecutedPhasePlan: (expectedJobId) => this.#resolveExecutedPhasePlan(expectedJobId),
      resolvePartyIdentity: (party) => this.#resolvePartyIdentityAuthority(jobId, party),
      resolveAttestationRef: (ref, context) => this.#resolveAttestationRef(ref, context, session),
    });
    if (verification.disposition === "rejected") {
      throw new FixtureBundleRejectedError(`Persisted bundle reference rejected: ${verification.reason}`);
    }
    const lifecycle = this.#readLifecycle(jobId);
    if (lifecycle === null || lifecycle.state !== "finalised") {
      throw new FixtureBundleIntegrityError("Persisted bundle lacks a finalised lifecycle snapshot");
    }
    const persistedArtifact = parsePersistedObject(artifact.canonicalJson, "Persisted bundle");
    const unsigned = { ...persistedArtifact };
    delete unsigned["anchoredByRole"];
    delete unsigned["signatures"];
    this.#validateBundleInput(unsigned as UnsignedAttestationBundle, lifecycle, session, row.anchoredByRole);
    this.#assertFinalisationChronology(jobId, Number(row.finalisedAt), lifecycle);
    if (persistedArtifact["finalisedAt"] !== Number(row.finalisedAt)
      || Date.parse(row.createdAt) !== Number(row.finalisedAt)
      || new Date(row.createdAt).toISOString() !== row.createdAt
      || lifecycle.endedAt !== row.createdAt) {
      throw new FixtureBundleIntegrityError("Persisted bundle finalisation metadata is inconsistent");
    }
    if (verification.disposition === "indeterminate") {
      throw new FixtureBundleIndeterminateError(`Persisted bundle verification is unavailable: ${verification.reason}`);
    }
    if (verification.bundleHash !== row.bundleHash) {
      throw new FixtureBundleIntegrityError("Persisted bundle failed independent verification");
    }
    return Object.freeze({
      ...row, finalisedAt: Number(row.finalisedAt), canonicalJson: artifact.canonicalJson,
    });
  }

  read(jobId: string, role: BundleRole): BundleAddressRead {
    try {
      const record = this.get(jobId, role);
      return record === null
        ? Object.freeze({ status: "absent", authority: "authoritative" })
        : Object.freeze({ status: "present", canonicalJson: record.canonicalJson });
    } catch (error) {
      if (error instanceof FixtureBundleRejectedError
        || error instanceof FixtureBundleIntegrityError
        || error instanceof FixtureBundleConflictError
        || error instanceof FixtureVetIntegrityError
        || error instanceof FixtureVetConflictError
        || error instanceof ArtifactIntegrityError) {
        return Object.freeze({ status: "rejected", reason: error.message });
      }
      if (error instanceof FixtureBundleIndeterminateError) {
        return Object.freeze({ status: "indeterminate", reason: error.message });
      }
      return Object.freeze({ status: "indeterminate", reason: message(error) });
    }
  }

  verifySession(jobId: string, scoredRole?: "buyer" | "seller"): BundleConsistencyResult {
    const session = readPersistedSessionByJobId(this.#database, jobId);
    const buyer = this.read(jobId, "buyer");
    const seller = this.read(jobId, "seller");
    return reconcileAttestationBundleReads(jobId, {
      buyer, seller, orchestrator: this.read(jobId, "orchestrator"),
    }, {
      resolveListingRef: (ref) => this.#resolveListingAuthority(jobId, ref),
      resolveExecutedPhasePlan: (expectedJobId) => this.#resolveExecutedPhasePlan(expectedJobId),
      resolvePartyIdentity: (party) => this.#resolvePartyIdentityAuthority(jobId, party),
      resolveAttestationRef: (ref, context) => session === null
        ? Object.freeze({ status: "rejected" as const, reason: "Bundle verification lacks its admitted session" })
        : this.#resolveAttestationRef(ref, context, session),
    }, scoredRole);
  }

  #finaliseWithinTransaction(input: FixtureBundleFinaliseInput): FixtureBundleFinalisation {
    if (input.bundle.jobId !== input.session.jobId || input.bundle.finalisedAt !== Date.parse(input.createdAt)) {
      throw new FixtureBundleConflictError("Bundle jobId or finalisedAt differs from its session finalisation");
    }
    const session = readPersistedSessionByJobId(this.#database, input.session.jobId);
    if (session === null
      || session.instanceId !== input.session.instanceId || session.audience !== input.session.audience
      || session.jobId !== input.session.jobId || session.evidenceMode !== input.session.evidenceMode
      || session.status !== input.session.status || session.requestHash !== input.session.requestHash
      || session.admissionFingerprint !== input.session.admissionFingerprint
      || session.version !== input.session.version || session.createdAt !== input.session.createdAt) {
      throw new FixtureBundleConflictError("Bundle session does not match persisted authority");
    }

    const lifecycle = this.#database.query<LifecycleFinalisationRow, { jobId: string }>(`
      SELECT agreement_artifact_hash AS agreementArtifactHash,
        commitment_artifact_hash AS commitmentArtifactHash,
        required_payment_phases_json AS requiredPaymentPhasesJson,
        delivery_phase_index AS deliveryPhaseIndex, delivery_phase_kind AS deliveryPhaseKind,
        payment_invocations AS paymentInvocations, settlement_invocations AS settlementInvocations,
        delivery_invocations AS deliveryInvocations, payment_result_json AS paymentResultJson,
        settlement_result_json AS settlementResultJson, delivery_result_json AS deliveryResultJson,
        terminal_result_json AS terminalResultJson, terminal_state AS terminalState,
        abort_actor_role AS abortActorRole, abort_reason AS abortReason,
        failure_stage AS failureStage, error_class AS errorClass, failure_reason AS failureReason,
        created_at AS createdAt, updated_at AS updatedAt, ended_at AS endedAt,
        state, version FROM fixture_lifecycle_runs WHERE job_id = $jobId
    `).get({ jobId: input.session.jobId });
    if (lifecycle === null) throw new FixtureBundleConflictError("Bundle lifecycle is unavailable");
    if (lifecycle.state === "finalised") return this.#assertReplay(input);
    const supportedTerminal = lifecycle.state === "settle-completed"
      || lifecycle.state === "settle-failed" || lifecycle.state === "settle-unsupported"
      || lifecycle.state === "failed-substrate" || lifecycle.state === "aborted";
    if (!supportedTerminal || lifecycle.commitmentArtifactHash === null) {
      throw new FixtureBundleConflictError("Bundle requires a supported post-commit terminal lifecycle");
    }
    const expectedOutcome = terminalBundleOutcome(lifecycle, input);
    if (input.bundle.outcome !== expectedOutcome) {
      throw new FixtureBundleConflictError(`Lifecycle requires bundle outcome ${expectedOutcome}`);
    }
    if (lifecycle.state === "settle-completed") {
      if (lifecycle.endedAt !== null || lifecycle.terminalResultJson !== null
        || lifecycle.abortActorRole !== null || lifecycle.abortReason !== null) {
        throw new FixtureBundleIntegrityError("Settle-completed lifecycle contains terminal metadata");
      }
    } else if (lifecycle.endedAt !== input.createdAt || lifecycle.terminalState !== null) {
      throw new FixtureBundleIntegrityError("Negative lifecycle terminal time or seal state is inconsistent");
    }
    this.#validateBundleInput(input.bundle, lifecycle, input.session);
    this.#assertFinalisationChronology(input.session.jobId, input.bundle.finalisedAt, lifecycle);
    const identities = input.partyIdentityCanonicalJsons.map((canonicalJson) =>
      this.#authorities.putBundleIdentityWithinTransaction(canonicalJson, input.createdAt));
    for (const party of input.bundle.parties) {
      if (!identities.some((identity) => identity.bundleHash === party.bundleHash
        && identity.primaryClaim === party.primaryClaim)) {
        throw new FixtureBundleConflictError("Bundle party lacks an exact verified IdentityBundle authority");
      }
    }
    const signed = this.#signCurrentBundle(input, lifecycle);
    const records: FixtureBundleRecord[] = [];
    for (const copy of signed.copies) {
      const artifact = this.#artifacts.putWithinTransaction("dacs-5-bundle", copy.artifact, input.createdAt);
      if (artifact.contentHash !== copy.artifactContentHash || artifact.canonicalJson !== copy.canonicalJson) {
        throw new FixtureBundleIntegrityError("Bundle artifact changed during persistence");
      }
      this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: bundle.put-anchor */
        INSERT INTO fixture_anchors (
          logical_address, artifact_kind, content_hash, artifact_content_hash, created_at
        ) VALUES ($logicalAddress, 'dacs-5-bundle', $bundleHash, $artifactContentHash, $createdAt)
      `).run({
        logicalAddress: copy.logicalAddress, bundleHash: copy.bundleHash,
        artifactContentHash: artifact.contentHash, createdAt: input.createdAt,
      });
      this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: bundle.put-copy */
        INSERT INTO fixture_bundles (
          instance_id, audience, job_id, anchored_by_role, logical_address,
          bundle_hash, artifact_content_hash, finalised_at, created_at
        ) VALUES (
          $instanceId, $audience, $jobId, $role, $logicalAddress,
          $bundleHash, $artifactContentHash, $finalisedAt, $createdAt
        )
      `).run({
        instanceId: input.session.instanceId, audience: input.session.audience,
        jobId: input.session.jobId, role: copy.anchoredByRole, logicalAddress: copy.logicalAddress,
        bundleHash: copy.bundleHash, artifactContentHash: artifact.contentHash,
        finalisedAt: input.bundle.finalisedAt, createdAt: input.createdAt,
      });
      records.push(Object.freeze({
        anchoredByRole: copy.anchoredByRole, artifactContentHash: artifact.contentHash,
        bundleHash: copy.bundleHash, canonicalJson: artifact.canonicalJson,
        createdAt: input.createdAt, finalisedAt: input.bundle.finalisedAt,
        jobId: input.session.jobId, logicalAddress: copy.logicalAddress,
      }));
    }
    const update = this.#database.query<never, Record<string, string | number | null>>(`
      /* atomic-write: bundle.finalise-lifecycle */
      UPDATE fixture_lifecycle_runs SET state = 'finalised', version = version + 1,
        terminal_state = $terminalState, updated_at = $createdAt,
        ended_at = coalesce(ended_at, $createdAt)
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = $expectedState AND version = $version
    `).run({
      instanceId: input.session.instanceId, audience: input.session.audience,
      jobId: input.session.jobId, version: Number(lifecycle.version), createdAt: input.createdAt,
      terminalState: lifecycle.state === "settle-completed" ? null : lifecycle.state,
      expectedState: lifecycle.state,
    });
    if (update.changes !== 1) throw new FixtureBundleConflictError("Bundle finalisation raced");
    return Object.freeze({
      state: "finalised",
      bundleHash: signed.copies[0]!.bundleHash,
      copies: Object.freeze(records),
    });
  }

  #signCurrentBundle(input: FixtureBundleFinaliseInput, lifecycle: LifecycleFinalisationRow) {
    const perspectiveRole = input.anchorRoles[0]!;
    const perspectiveOutcome = mappedTerminalOutcome(lifecycle, perspectiveRole);
    const faultedParty = faultedPartyForLifecycle(
      lifecycle,
      perspectiveRole,
      perspectiveOutcome,
      input.faultedParty,
    );
    const { bundleVersion: _legacyVersion, outcome: _legacyOutcome, ...shared } = input.bundle;
    return signEvidenceBoundFaultAttestationBundleCopies(
      { ...shared, evidenceBoundFaultBundleVersion: "1", faultedParty },
      outcomeClass(perspectiveOutcome),
      input.partySigners,
      input.anchorRoles,
      { deploymentMode: "fixture", requestMode: "fixture" },
      (ref, context) => this.#resolveAttestationRef(ref, context, input.session),
      {
        resolveListingRef: (ref) => this.#resolveListingAuthority(input.session.jobId, ref),
        resolveExecutedPhasePlan: (expectedJobId) => this.#resolveExecutedPhasePlan(expectedJobId),
        resolvePartyIdentity: (party) => this.#resolvePartyIdentityAuthority(input.session.jobId, party),
      },
    );
  }

  #validateBundleInput(
    bundle: UnsignedAttestationBundle,
    lifecycle: LifecycleFinalisationRow,
    session: SessionRecord,
    anchoredByRole?: BundleRole,
  ): void {
    if (bundle.jobId.length === 0) throw new FixtureBundleConflictError("Bundle jobId is required");
    if (lifecycle.state === "finalised" && anchoredByRole !== undefined
      && bundle.outcome !== expectedPersistedOutcome(lifecycle, bundle, anchoredByRole)) {
      throw new FixtureBundleIntegrityError("Persisted bundle outcome differs from sealed lifecycle authority");
    }
    const agreementArtifact = this.#artifacts.get(lifecycle.agreementArtifactHash);
    if (agreementArtifact === null) throw new FixtureBundleIntegrityError("Lifecycle agreement artifact is unavailable");
    const agreement = parsePersistedObject(agreementArtifact.canonicalJson, "Lifecycle agreement artifact");
    const agreementHash = sha256Hex(canonicalize(Object.fromEntries(
      Object.entries(agreement).filter(([key]) => key !== "signatures"),
    )));
    const commitment = this.#readCommitmentAuthority(session);
    if (commitment === null) throw new FixtureBundleIntegrityError("Lifecycle commitment anchor is unavailable");
    if (commitment.agreementArtifactHash !== lifecycle.agreementArtifactHash
      || commitment.agreementHash !== agreementHash
      || commitment.commitmentArtifactHash !== lifecycle.commitmentArtifactHash) {
      throw new FixtureBundleIntegrityError("Lifecycle commitment snapshot differs from its storage-program anchor");
    }
    const expectedAgreementRef = {
      anchor: { kind: "storage-program", locator: commitment.logicalAddress }, contentHash: agreementHash,
    };
    if (canonicalize(bundle.agreementRef) !== canonicalize(expectedAgreementRef)
      || canonicalize(bundle.listingRef) !== canonicalize(agreement["listingRef"])) {
      throw new FixtureBundleConflictError("Bundle agreement or listing reference differs from the committed agreement");
    }
    const agreementParties = (agreement["parties"] as Record<string, unknown>[]).map((party) => ({
      role: party["role"], bundleHash: party["bundleHash"], primaryClaim: party["primaryClaim"],
    }));
    const bundleParties = bundle.parties.filter((party) => party.role !== "orchestrator");
    if (canonicalize(bundleParties) !== canonicalize(agreementParties)) {
      throw new FixtureBundleConflictError("Bundle buyer/seller parties differ from the committed agreement");
    }
    const settlementEntries = parseOptionalEvidenceArray(lifecycle.settlementResultJson, "settlement");
    const deliveryEntry = parseOptionalEvidence(lifecycle.deliveryResultJson, "delivery");
    const terminalEntry = parseOptionalEvidence(lifecycle.terminalResultJson, "terminal");
    const listing = this.#readCommittedListing(bundle.jobId, agreement);
    if (listing === null) throw new FixtureBundleIntegrityError("Committed Listing authority is unavailable");
    const paymentPlan = parsePaymentPlan(lifecycle.requiredPaymentPhasesJson);
    const paymentResults = parsePhaseResultBindings(lifecycle.paymentResultJson, "payment");
    validateLifecycleExecutionBoundary(
      lifecycle,
      paymentPlan,
      paymentResults,
      settlementEntries.map(({ phaseIndex, phaseKind }) => ({ phaseIndex, phaseKind })),
    );
    if (canonicalize(settlementEntries.map(({ phaseIndex, phaseKind }) => ({ phaseIndex, phaseKind })))
      !== canonicalize(paymentPlan.slice(0, settlementEntries.length))
      || (deliveryEntry !== null && (deliveryEntry.phaseIndex !== Number(lifecycle.deliveryPhaseIndex)
        || deliveryEntry.phaseKind !== lifecycle.deliveryPhaseKind))) {
      throw new FixtureBundleIntegrityError("Persisted phase results differ from the pinned lifecycle plan");
    }
    const terminalBinding = lifecycle.failureStage === "delivery"
      ? { phaseIndex: Number(lifecycle.deliveryPhaseIndex), phaseKind: lifecycle.deliveryPhaseKind }
      : lifecycle.failureStage === "payment" || lifecycle.failureStage === "settlement"
        ? paymentPlan[settlementEntries.length] : undefined;
    if ((terminalEntry === null) !== (terminalBinding === undefined)
      || (terminalEntry !== null && (terminalEntry.phaseIndex !== terminalBinding!.phaseIndex
        || terminalEntry.phaseKind !== terminalBinding!.phaseKind))) {
      throw new FixtureBundleIntegrityError("Terminal evidence differs from the failed lifecycle phase");
    }
    const evidenceEntries = [
      ...settlementEntries,
      ...(terminalEntry === null ? [] : [terminalEntry]),
      ...(deliveryEntry === null ? [] : [deliveryEntry]),
    ];
    const completePlan = executedPhasePlan(listing, lifecycle);
    const commitPhases = completePlan.filter((phase) => phase.kind.startsWith("commit-"));
    const expectedPhases = [
      ...commitPhases.map((phase) => ({ ...phase, outcome: "ok" as const })),
      ...settlementEntries.map((entry) => ({
        index: entry.phaseIndex,
        kind: entry.phaseKind,
        outcome: "ok" as const,
        attestationRef: entry.attestationRef,
      })),
      ...(terminalEntry === null ? [] : [{
        index: terminalEntry.phaseIndex,
        kind: terminalEntry.phaseKind,
        outcome: "fail" as const,
        errorClass: lifecycle.errorClass!,
        attestationRef: terminalEntry.attestationRef,
      }]),
      ...(deliveryEntry === null ? [] : [{
        index: deliveryEntry.phaseIndex,
        kind: deliveryEntry.phaseKind,
        outcome: "ok" as const,
        attestationRef: deliveryEntry.attestationRef,
      }]),
    ].sort((left, right) => left.index - right.index);
    if (lifecycle.state === "settle-completed"
      && (settlementEntries.length !== paymentPlan.length || deliveryEntry === null || terminalEntry !== null)) {
      throw new FixtureBundleIntegrityError("Completed lifecycle lacks its full successful evidence set");
    }
    if (lifecycle.state === "aborted" && (terminalEntry !== null || deliveryEntry !== null)) {
      throw new FixtureBundleIntegrityError("Abort lifecycle contains post-abort evidence");
    }
    if (bundle.phaseSummary.length !== expectedPhases.length) {
      throw new FixtureBundleConflictError("Bundle phases do not exactly cover persisted settlement and delivery evidence");
    }
    for (const expected of expectedPhases) {
      const actual = bundle.phaseSummary.find((phase) => phase["index"] === expected.index);
      if (actual?.["kind"] !== expected.kind || actual["outcome"] !== expected.outcome
        || actual["errorClass"] !== ("errorClass" in expected ? expected.errorClass : undefined)
        || (actual["attestationRef"] !== undefined
          && (!("attestationRef" in expected)
            || canonicalize(actual["attestationRef"]) !== canonicalize(expected.attestationRef)))) {
        throw new FixtureBundleConflictError("Bundle phases do not exactly cover persisted settlement and delivery evidence");
      }
    }
    const refs = evidenceEntries.map((entry) => entry.attestationRef);
    if (canonicalize(bundle.settlementEvidence) !== canonicalize(refs)) {
      throw new FixtureBundleConflictError("Bundle evidence set is incomplete or outside this session pipeline");
    }
    const agreementVet = this.#vet.assertAgreementAuthority(
      agreement,
      session,
      commitment.committedAt,
    );
    if (agreementVet.mode === "dacs2") {
      if (agreementVet.buyer.recipeRegistryVersion !== bundle.recipeRegistryVersion
        || agreementVet.seller.recipeRegistryVersion !== bundle.recipeRegistryVersion
        || canonicalize(bundle.vetRecords) !== canonicalize([
          agreementVet.buyer.compositeReference,
          agreementVet.seller.compositeReference,
        ])) {
        throw new FixtureBundleConflictError("Bundle Vet records do not exactly match two passing persisted composites");
      }
    } else {
      if (bundle.vetRecords.length !== 0) {
        throw new FixtureBundleConflictError("Legacy Agreement cannot acquire uncommitted Vet records");
      }
    }
    const orchestratorParty = bundle.parties.find((party) => party.role === "orchestrator");
    const buyerSellerClaims = new Set(bundleParties.map((party) => party.primaryClaim));
    const thirdPartyAuthorities = new Set(evidenceEntries
      .map((entry) => entry.authorityClaim)
      .filter((claim) => !buyerSellerClaims.has(claim)));
    if (thirdPartyAuthorities.size > 1
      || (thirdPartyAuthorities.size === 1
        && orchestratorParty?.primaryClaim !== [...thirdPartyAuthorities][0])
      || (thirdPartyAuthorities.size === 0 && orchestratorParty !== undefined)) {
      throw new FixtureBundleConflictError("Bundle orchestrator does not match persisted phase authority");
    }
    for (const ref of refs) this.#assertAttestationRef(ref);
  }

  #assertAttestationRef(ref: Record<string, unknown>): void {
    const anchor = ref["anchor"] as Record<string, unknown>;
    const locator = anchor?.["locator"];
    const contentHash = ref["contentHash"];
    const row = typeof locator === "string" ? this.#database.query<{
      contentHash: string; artifactContentHash: string | null;
    }, { locator: string }>(`
      SELECT content_hash AS contentHash, artifact_content_hash AS artifactContentHash
      FROM fixture_anchors WHERE logical_address = $locator
    `).get({ locator }) : null;
    if (anchor?.["kind"] !== "storage-program" || typeof contentHash !== "string"
      || row === null || row.artifactContentHash === null || row.contentHash !== contentHash
      || this.#artifacts.get(row.artifactContentHash) === null) {
      throw new FixtureBundleConflictError("Bundle AttestationRef is not backed by persisted fixture evidence");
    }
  }

  #resolveAttestationRef(
    ref: Readonly<Record<string, unknown>>,
    context: AttestationReferenceContext,
    session: SessionRecord,
  ) {
    try {
      return this.#resolveAttestationRefUnchecked(ref, context, session);
    } catch (error) {
      return error instanceof FixtureBundleIntegrityError || error instanceof FixtureVetIntegrityError
        || error instanceof FixtureVetConflictError || error instanceof ArtifactIntegrityError
        ? Object.freeze({ status: "rejected" as const, reason: message(error) })
        : Object.freeze({ status: "indeterminate" as const, reason: message(error) });
    }
  }

  #resolveListingAuthority(jobId: string, ref: Readonly<Record<string, unknown>>) {
    const agreement = this.#readCommittedAgreement(jobId);
    if (agreement === null) return Object.freeze({ status: "absent" as const });
    const listingRef = agreement["listingRef"] as Record<string, unknown> | undefined;
    if (listingRef === undefined || canonicalize(listingRef) !== canonicalize(ref)) {
      return Object.freeze({ status: "rejected" as const, reason: "ListingRef differs from the committed agreement" });
    }
    return this.#authorities.resolveListing(jobId, ref);
  }

  #resolvePartyIdentityAuthority(jobId: string, party: Readonly<Record<string, unknown>>) {
    const agreement = this.#readCommittedAgreement(jobId);
    if (agreement === null) return Object.freeze({ status: "absent" as const });
    const role = party["role"];
    const agreementParty = (agreement["parties"] as Record<string, unknown>[])
      .find((candidate) => candidate["role"] === role);
    if (role === "orchestrator") {
      const lifecycle = this.#database.query<{
        deliveryResultJson: string | null; settlementResultJson: string | null;
        terminalResultJson: string | null;
      }, { jobId: string }>(`
        SELECT delivery_result_json AS deliveryResultJson,
          settlement_result_json AS settlementResultJson,
          terminal_result_json AS terminalResultJson
        FROM fixture_lifecycle_runs WHERE job_id = $jobId
      `).get({ jobId });
      const authorities = lifecycle === null ? [] : [
        ...parseOptionalEvidenceArray(lifecycle.settlementResultJson, "settlement"),
        ...(parseOptionalEvidence(lifecycle.terminalResultJson, "terminal") === null
          ? [] : [parseOptionalEvidence(lifecycle.terminalResultJson, "terminal")!]),
        ...(parseOptionalEvidence(lifecycle.deliveryResultJson, "delivery") === null
          ? [] : [parseOptionalEvidence(lifecycle.deliveryResultJson, "delivery")!]),
      ].map((entry) => entry.authorityClaim)
        .filter((claim) => !(agreement["parties"] as Record<string, unknown>[])
          .some((candidate) => candidate["primaryClaim"] === claim));
      if (authorities.length === 0 || new Set(authorities).size !== 1
        || authorities[0] !== party["primaryClaim"]) {
        return Object.freeze({ status: "rejected" as const, reason: "Orchestrator identity differs from persisted phase authority" });
      }
    } else if (agreementParty === undefined
      || agreementParty["bundleHash"] !== party["bundleHash"]
      || agreementParty["primaryClaim"] !== party["primaryClaim"]) {
      return Object.freeze({ status: "rejected" as const, reason: "Party identity differs from the committed agreement" });
    }
    const authority = this.#authorities.resolveIdentity(party["bundleHash"] as string);
    return authority.status !== "verified" || authority.primaryClaim === party["primaryClaim"]
      ? authority
      : Object.freeze({ status: "rejected" as const, reason: "IdentityBundle primary claim differs from the bundle party" });
  }

  #resolveExecutedPhasePlan(jobId: string) {
    const lifecycle = this.#readLifecycle(jobId);
    const agreement = this.#readCommittedAgreement(jobId);
    const session = readPersistedSessionByJobId(this.#database, jobId);
    if (lifecycle === null || agreement === null || session === null) {
      return Object.freeze({ status: "absent" as const });
    }
    if (session.status !== "admitted" || session.evidenceMode !== "fixture"
      || lifecycle.commitmentArtifactHash === null) {
      return Object.freeze({ status: "rejected" as const, reason: "Executed phase plan lacks session or commitment authority" });
    }
    try {
      const listing = this.#readCommittedListing(jobId, agreement);
      if (listing === null) throw new FixtureBundleIntegrityError("Executed phase plan lacks signed Listing authority");
      const registries = this.#database.query<{
        railRegistryVersion: bigint; recipeRegistryVersion: bigint;
      }, { jobId: string }>(`
        SELECT rail_registry_version AS railRegistryVersion,
          recipe_registry_version AS recipeRegistryVersion
        FROM fixture_listing_verification_authorities WHERE job_id = $jobId
      `).get({ jobId });
      if (registries === null) throw new FixtureBundleIntegrityError("Executed phase plan lacks registry authority");
      const railRegistryVersion = Number(registries.railRegistryVersion);
      const recipeRegistryVersion = Number(registries.recipeRegistryVersion);
      if (!Number.isSafeInteger(railRegistryVersion) || railRegistryVersion < 1
        || !Number.isSafeInteger(recipeRegistryVersion) || recipeRegistryVersion < 1) {
        throw new FixtureBundleIntegrityError("Persisted registry authority is invalid");
      }
      const phases = executedPhasePlan(listing, lifecycle);
      return Object.freeze({
        status: "verified" as const,
        phases: Object.freeze(phases),
        railRegistryVersion,
        recipeRegistryVersion,
      });
    } catch (error) {
      return error instanceof FixtureBundleIntegrityError || error instanceof ArtifactIntegrityError
        ? Object.freeze({ status: "rejected" as const, reason: message(error) })
        : Object.freeze({ status: "indeterminate" as const, reason: message(error) });
    }
  }

  #readCommittedAgreement(jobId: string): Record<string, unknown> | null {
    const session = readPersistedSessionByJobId(this.#database, jobId);
    if (session === null) return null;
    const commitment = this.#readCommitmentAuthority(session);
    if (commitment === null) return null;
    const artifact = this.#artifacts.get(commitment.agreementArtifactHash);
    if (artifact === null) throw new FixtureBundleIntegrityError("Committed agreement artifact is unavailable");
    const verified = verifyCommittedAgreementCryptography(artifact.canonicalJson, commitment.agreementHash);
    if (verified.disposition !== "verified") {
      throw new FixtureBundleIntegrityError("Committed agreement artifact cryptography is invalid");
    }
    return parsePersistedObject(artifact.canonicalJson, "Committed agreement artifact");
  }

  #readCommittedListing(
    jobId: string,
    agreement: Readonly<Record<string, unknown>>,
  ): Record<string, unknown> | null {
    const listingRef = agreement["listingRef"];
    if (listingRef === null || typeof listingRef !== "object" || Array.isArray(listingRef)) {
      throw new FixtureBundleIntegrityError("Committed agreement lacks a ListingRef");
    }
    const authority = this.#authorities.resolveListing(jobId, listingRef as Record<string, unknown>);
    if (authority.status === "absent") return null;
    if (authority.status !== "verified") {
      throw new FixtureBundleIntegrityError(`Committed Listing authority is invalid: ${authority.reason}`);
    }
    const row = this.#database.query<{ artifactContentHash: string }, {
      listingId: string; version: number;
    }>(`
      SELECT artifact_content_hash AS artifactContentHash FROM fixture_listing_authorities
      WHERE listing_id = $listingId AND listing_version = $version
    `).get({ listingId: authority.listingId, version: authority.version });
    if (row === null) throw new FixtureBundleIntegrityError("Committed Listing artifact binding is unavailable");
    const artifact = this.#artifacts.get(row.artifactContentHash);
    if (artifact === null || !artifact.kinds.includes("dacs-1-listing")) {
      throw new FixtureBundleIntegrityError("Committed Listing artifact is unavailable or mistyped");
    }
    return parsePersistedObject(artifact.canonicalJson, "Committed Listing artifact");
  }

  #resolveAttestationRefUnchecked(
    ref: Readonly<Record<string, unknown>>,
    context: AttestationReferenceContext,
    session: SessionRecord,
  ) {
    if (session.jobId !== context.expectedJobId) {
      return Object.freeze({ status: "rejected" as const, reason: "Attestation reference session differs from its bundle" });
    }
    const anchor = ref["anchor"] as Record<string, unknown> | undefined;
    const locator = anchor?.["locator"];
    if (anchor?.["kind"] !== "storage-program" || typeof locator !== "string") {
      return Object.freeze({ status: "indeterminate" as const, reason: "Fixture resolver supports storage-program references only" });
    }
    const commitment = this.#readCommitmentAuthority(session);
    if (commitment !== null && commitment.logicalAddress === locator) {
      const artifact = this.#artifacts.get(commitment.agreementArtifactHash);
      if (artifact === null) {
        throw new FixtureBundleIntegrityError("Committed agreement artifact is unavailable");
      }
      if (!artifact.kinds.includes("dacs-3-agreement")
        && !artifact.kinds.includes("dacs-3-payee-bound-agreement")) {
        return Object.freeze({ status: "rejected" as const, reason: "Agreement artifact kind binding is corrupt" });
      }
      const verified = verifyCommittedAgreementCryptography(artifact.canonicalJson, commitment.agreementHash);
      const agreement = parsePersistedObject(artifact.canonicalJson, "Referenced agreement artifact");
      return verified.disposition === "verified" && commitment.session.jobId === context.expectedJobId
        && agreement["listingRef"] !== null && typeof agreement["listingRef"] === "object"
        && Array.isArray(agreement["parties"])
        ? Object.freeze({
          status: "verified" as const,
          artifactType: "agreement" as const,
          anchorKind: "storage-program",
          anchorLocator: locator,
          contentHash: commitment.agreementHash,
          jobId: commitment.session.jobId,
          agreementListingRef: agreement["listingRef"] as Record<string, unknown>,
          agreementParties: agreement["parties"] as Record<string, unknown>[],
        })
        : Object.freeze({ status: "rejected" as const, reason: "Agreement artifact cryptography is invalid" });
    }
    const persisted = this.#database.query<{
      artifactKind: string; contentHash: string; artifactContentHash: string | null;
    }, { locator: string }>(`
      SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
        artifact_content_hash AS artifactContentHash
      FROM fixture_anchors WHERE logical_address = $locator
    `).get({ locator });
    if (persisted === null) return Object.freeze({ status: "absent" as const });
    if (persisted.artifactContentHash === null) {
      throw new FixtureBundleIntegrityError("Referenced anchor lacks its persisted artifact binding");
    }
    const artifact = this.#artifacts.get(persisted.artifactContentHash);
    if (artifact === null) {
      throw new FixtureBundleIntegrityError("Referenced local artifact is unavailable");
    }
    if (!artifact.kinds.includes(persisted.artifactKind)) {
      return Object.freeze({ status: "rejected" as const, reason: "Referenced artifact kind binding is corrupt" });
    }
    if (persisted.artifactKind === "dacs-4-evidence") {
      const value = parsePersistedObject(artifact.canonicalJson, "Referenced SettlementEvidence artifact");
      const authority = this.#referencePhaseAuthority(locator, value);
      const verified = this.#verifyFixtureSettlementEvidence(
        locator, artifact.canonicalJson, persisted.contentHash, authority,
      );
      if (verified.disposition === "indeterminate") {
        return Object.freeze({ status: "indeterminate" as const, reason: verified.reason });
      }
      if (verified.disposition !== "verified" || verified.evidenceHash !== persisted.contentHash
        || verified.logicalAddress !== locator || verified.orchestrator !== authority.signer) {
        const detail = "reason" in verified ? `: ${verified.reason}` : "";
        return Object.freeze({ status: "rejected" as const, reason: `SettlementEvidence semantics or lifecycle binding is invalid${detail}` });
      }
      const recordClass = Object.hasOwn(value, "supersedesEvidenceRef")
        ? "st8-resolved-success" as const
        : value["outcome"] === "failure"
          && (value["reason"] === "dest-revealed-source-unclaimed"
            || value["reason"] === "tank-locked-unreleased")
          ? "st8-expired-interim-failure" as const
          : "ordinary-terminal" as const;
      return Object.freeze({
        status: "verified" as const,
        artifactType: "phase-evidence" as const,
        anchorKind: "storage-program",
        anchorLocator: locator,
        contentHash: persisted.contentHash,
        jobId: authority.jobId,
        phaseIndex: authority.phaseIndex,
        phaseKind: authority.phaseKind,
        evidenceOutcome: value["outcome"] as "success" | "failure",
        recordClass,
        signer: verified.orchestrator,
        ...(value["supersedesEvidenceRef"] !== null
          && typeof value["supersedesEvidenceRef"] === "object"
          && !Array.isArray(value["supersedesEvidenceRef"])
          ? { supersedesEvidenceRef: value["supersedesEvidenceRef"] as Record<string, unknown> }
          : {}),
      });
    } else if (persisted.artifactKind === "dacs-2-composite") {
      const row = this.#database.query<{
        audience: string; evaluatedRole: "buyer" | "seller"; instanceId: string;
      }, {
        instanceId: string; audience: string; locator: string; jobId: string;
      }>(`
        SELECT audience, evaluated_role AS evaluatedRole, instance_id AS instanceId
        FROM fixture_vet_records
        WHERE instance_id = $instanceId AND audience = $audience
          AND composite_address = $locator AND job_id = $jobId
      `).get({
        instanceId: session.instanceId,
        audience: session.audience,
        locator,
        jobId: context.expectedJobId,
      });
      if (row === null) {
        return Object.freeze({ status: "rejected" as const, reason: "Vet composite lacks its session authority row" });
      }
      const record = this.#vet.get(session, row.evaluatedRole);
      return record !== null && record.compositeAddress === locator
        && record.compositeArtifactHash === persisted.contentHash
        && record.overallDecision === "pass"
        ? Object.freeze({
            status: "verified" as const,
            artifactType: "vet" as const,
            anchorKind: "storage-program",
            anchorLocator: locator,
            contentHash: record.compositeArtifactHash,
            jobId: record.jobId,
            signer: record.verifierParty,
          })
        : Object.freeze({ status: "rejected" as const, reason: "Vet composite is invalid, misbound, or non-passing" });
    } else if (persisted.artifactKind === "dacs-2-verify-result") {
      if (persisted.contentHash !== persisted.artifactContentHash) {
        return Object.freeze({ status: "rejected" as const, reason: "Delivery attestation anchor hash is corrupt" });
      }
      const verified = this.#resolveDeliveryAttestation(locator, artifact.canonicalJson, persisted.artifactContentHash);
      return verified;
    } else if (persisted.contentHash !== persisted.artifactContentHash) {
      return Object.freeze({ status: "rejected" as const, reason: "Referenced artifact content hash is corrupt" });
    }
    return Object.freeze({ status: "indeterminate" as const, reason: "Referenced artifact kind lacks an authenticated job binding" });
  }

  #resolveDeliveryAttestation(locator: string, verifyResultJson: string, artifactContentHash: string) {
    const row = this.#database.query<{
      agreementHash: string; assertionAddress: string; assertionArtifactHash: string;
      audience: string; instanceId: string; jobId: string; orchestrator: string;
      payloadContentHash: string; payloadFormat: string;
      phaseIndex: bigint; sessionBindingHash: string; verifyResultAddress: string;
      verifyResultArtifactHash: string;
    }, { locator: string }>(`
      SELECT agreement_hash AS agreementHash, assertion_address AS assertionAddress,
        assertion_artifact_hash AS assertionArtifactHash, job_id AS jobId,
        audience, instance_id AS instanceId,
        orchestrator_claim AS orchestrator, payload_content_hash AS payloadContentHash,
        payload_format AS payloadFormat, phase_index AS phaseIndex,
        session_binding_hash AS sessionBindingHash, verify_result_address AS verifyResultAddress,
        verify_result_artifact_hash AS verifyResultArtifactHash
      FROM fixture_deliveries WHERE verify_result_address = $locator
    `).get({ locator });
    if (row === null) return Object.freeze({ status: "absent" as const });
    const phaseIndex = Number(row.phaseIndex);
    const assertion = this.#artifacts.get(row.assertionArtifactHash);
    if (assertion === null || row.verifyResultAddress !== locator
      || row.verifyResultArtifactHash !== artifactContentHash || !Number.isSafeInteger(phaseIndex)) {
      return Object.freeze({ status: "rejected" as const, reason: "Delivery attestation persistence is corrupt" });
    }
    const authority = this.#deliveryPhaseAuthority(row.jobId, row.instanceId, row.audience);
    if (authority.phaseIndex !== phaseIndex || authority.phaseKind !== "deliver-attested-payload"
      || authority.signer !== row.orchestrator || authority.anchorLocator !== locator
      || authority.contentHash !== artifactContentHash) {
      return Object.freeze({ status: "rejected" as const, reason: "Delivery attestation lifecycle authority is invalid" });
    }
    const verification = verifyDeliveryAttestation(assertion.canonicalJson, verifyResultJson, {
      agreementHash: row.agreementHash,
      anchorContext: { mode: "post-anchor", read: (address) => this.#readArtifactAnchor(address) },
      deliverableContentHash: row.payloadContentHash,
      jobId: row.jobId,
      payloadFormat: row.payloadFormat,
      phaseIndex,
      sessionBindingHash: row.sessionBindingHash,
      signer: row.orchestrator,
    });
    if (verification.disposition === "verified") {
      if (verification.assertionAddress !== row.assertionAddress
        || verification.assertionArtifactHash !== row.assertionArtifactHash
        || verification.verifyResultAddress !== row.verifyResultAddress
        || verification.verifyResultArtifactHash !== row.verifyResultArtifactHash) {
        return Object.freeze({ status: "rejected" as const, reason: "Delivery attestation row differs from its verified chain" });
      }
      return Object.freeze({
        status: "verified" as const,
        artifactType: "phase-evidence" as const,
        anchorKind: "storage-program",
        anchorLocator: locator,
        contentHash: artifactContentHash,
        jobId: row.jobId,
        phaseIndex,
        phaseKind: "deliver-attested-payload",
        evidenceOutcome: "success" as const,
        signer: row.orchestrator,
      });
    }
    return verification.disposition === "indeterminate"
      ? Object.freeze({ status: "indeterminate" as const, reason: verification.reason })
      : Object.freeze({ status: "rejected" as const, reason: "Delivery attestation signature or lifecycle binding is invalid" });
  }

  #verifyFixtureSettlementEvidence(
    locator: string,
    canonicalJson: string,
    evidenceHash: string,
    authority: Readonly<{ jobId: string; phaseIndex: number; phaseKind: string; signer: string }>,
  ) {
    const evidence = parsePersistedObject(canonicalJson, "Persisted SettlementEvidence artifact");
    const expected = this.#settlementAuthority(authority, locator);
    if ("disposition" in expected) return expected;
    if (evidence["outcome"] === "failure") {
      return verifyCanonicalSettlementEvidenceJson(canonicalJson, {
        ...expected,
        anchorContext: { mode: "post-anchor", read: (address) => this.#readSettlementAnchor(address) },
        evidenceMode: "fixture",
      });
    }
    if (evidence["phase"] !== "pay-x402") {
      return verifyPersistedFixtureSettlementEvidence(
        this.#database, locator, canonicalJson, evidenceHash, expected,
      );
    }
    return verifyCanonicalSettlementEvidenceJson(canonicalJson, {
      ...expected,
      anchorContext: { mode: "post-anchor", read: (address) => this.#readSettlementAnchor(address) },
      evidenceMode: "fixture",
      paymentTransactionCheck: verifyFixtureX402Receipt,
      settlementConsumptionCheck: () => Object.freeze({
        status: "indeterminate" as const,
        reason: "DACS-4 SB-1 does not define a canonical x402 settlement consumption identifier",
      }),
    });
  }

  #settlementAuthority(
    authority: Readonly<{ jobId: string; phaseIndex: number; phaseKind: string; signer: string }>,
    evidenceLogicalAddress: string,
  ): PersistedFixtureSettlementAuthority
    | Readonly<{ disposition: "indeterminate" | "rejected"; reason: string }> {
    const agreement = this.#readCommittedAgreement(authority.jobId);
    const session = readPersistedSessionByJobId(this.#database, authority.jobId);
    const commitment = session === null ? null : this.#readCommitmentAuthority(session);
    if (agreement === null || session === null || commitment === null) {
      return Object.freeze({ disposition: "indeterminate" as const, reason: "Settlement authority context is unavailable" });
    }
    const parties = agreement["parties"] as Record<string, unknown>[];
    const payer = parties.find((party) => party["role"] === "buyer")?.["primaryClaim"];
    const payee = parties.find((party) => party["role"] === "seller")?.["primaryClaim"];
    const terms = agreement["terms"] as Record<string, unknown>;
    const rail = terms["rail"] as Record<string, unknown>;
    const railId = rail["railId"];
    const payout = (terms["payoutBindings"] as Record<string, unknown>[])
      .find((binding) => binding["phaseIndex"] === authority.phaseIndex && binding["railId"] === railId);
    const isPayment = authority.phaseKind === "pay-dem" || authority.phaseKind === "pay-x402";
    const isDelivery = authority.phaseKind.startsWith("deliver-");
    if (typeof payer !== "string" || typeof payee !== "string" || typeof railId !== "string"
      || (!isPayment && !isDelivery)
      || (isPayment && (payout === undefined || typeof payout["payeeAddress"] !== "string"))
      || (authority.phaseKind === "pay-dem" && railId !== "demos-native:DEM")
      || (authority.phaseKind === "pay-x402" && railId !== "x402:default")) {
      return Object.freeze({ disposition: "rejected" as const, reason: "Committed settlement authority is invalid" });
    }
    const pinnedRail: PersistedFixtureSettlementAuthority["pinnedRail"] = authority.phaseKind === "pay-dem" ? {
      assetCanonicalJson: '{"decimals":9,"kind":"native-dem","symbol":"DEM"}',
      assetCurrency: "DEM",
      networkKind: "demos",
      phaseHandler: "pay-dem",
      railId,
    } : authority.phaseKind === "pay-x402" ? {
      assetCanonicalJson: '{"isoCurrency":"USDC","kind":"fiat-via-ap2","provider":"fixture-provider"}',
      assetCurrency: "USDC",
      networkKind: "x402-resource",
      phaseHandler: "pay-x402",
      railId,
    } : undefined;
    return Object.freeze({
      agreementHash: commitment.agreementHash,
      ...(authority.phaseKind === "pay-dem"
        ? { expectedFinality: { model: "bft-final" as const } }
        : authority.phaseKind === "pay-x402"
          ? { expectedFinality: { model: "provider-receipt" as const } }
          : {}),
      expectedJobId: authority.jobId,
      ...(isDelivery ? { expectedEvidenceLogicalAddress: evidenceLogicalAddress } : {}),
      expectedOrchestrator: authority.signer,
      expectedPayee: payee,
      ...(isPayment ? { expectedPayeeAddress: payout!["payeeAddress"] as string } : {}),
      expectedPayer: payer,
      ...(isPayment ? { expectedPaymentAmount: terms["price"] as Record<string, unknown> } : {}),
      expectedPhase: authority.phaseKind,
      expectedSessionBindingHash: sessionBindingHash(session),
      failureStateCheck: (expected) => this.#failures.verify(expected),
      phaseIndex: authority.phaseIndex,
      ...(isPayment ? { railId } : {}),
      ...(pinnedRail === undefined ? {} : { pinnedRail }),
    });
  }

  #readSettlementAnchor(logicalAddress: string) {
    const row = this.#database.query<{
      artifactContentHash: string | null; artifactKind: string; contentHash: string;
    }, { logicalAddress: string }>(`
      SELECT artifact_content_hash AS artifactContentHash, artifact_kind AS artifactKind,
        content_hash AS contentHash FROM fixture_anchors WHERE logical_address = $logicalAddress
    `).get({ logicalAddress });
    return row === null ? Object.freeze({ status: "absent" as const })
      : row.artifactContentHash === null
        ? Object.freeze({ status: "indeterminate" as const, reason: "Settlement anchor lacks an artifact binding" })
        : Object.freeze({
          status: "resolved" as const,
          artifactContentHash: row.artifactContentHash,
          artifactKind: row.artifactKind,
          evidenceHash: row.contentHash,
          evidenceMode: "fixture" as const,
        });
  }

  #deliveryPhaseAuthority(jobId: string, instanceId: string, audience: string) {
    const lifecycle = this.#database.query<{
      audience: string; deliveryPhaseIndex: bigint; deliveryPhaseKind: string;
      deliveryResultJson: string | null; instanceId: string; state: string;
    }, { jobId: string }>(`
      SELECT audience, delivery_phase_index AS deliveryPhaseIndex,
        delivery_phase_kind AS deliveryPhaseKind, delivery_result_json AS deliveryResultJson,
        instance_id AS instanceId, state
      FROM fixture_lifecycle_runs WHERE job_id = $jobId
    `).get({ jobId });
    if (lifecycle === null || (lifecycle.state !== "settle-completed" && lifecycle.state !== "finalised")
      || lifecycle.instanceId !== instanceId || lifecycle.audience !== audience) {
      throw new FixtureBundleIntegrityError("Delivery attestation has no terminal lifecycle authority");
    }
    const phase = parseEvidence(lifecycle.deliveryResultJson, "delivery");
    const anchor = phase.attestationRef["anchor"] as Record<string, unknown> | undefined;
    if (phase.phaseIndex !== Number(lifecycle.deliveryPhaseIndex)
      || phase.phaseKind !== lifecycle.deliveryPhaseKind
      || anchor?.["kind"] !== "storage-program" || typeof anchor["locator"] !== "string"
      || typeof phase.attestationRef["contentHash"] !== "string") {
      throw new FixtureBundleIntegrityError("Delivery attestation differs from the persisted lifecycle phase");
    }
    return Object.freeze({
      anchorLocator: anchor["locator"],
      contentHash: phase.attestationRef["contentHash"],
      phaseIndex: phase.phaseIndex,
      phaseKind: phase.phaseKind,
      signer: phase.authorityClaim,
    });
  }

  #readArtifactAnchor(logicalAddress: string) {
    try {
      const row = this.#database.query<{
        artifactKind: string; artifactContentHash: string | null; contentHash: string;
      }, { logicalAddress: string }>(`
        SELECT artifact_kind AS artifactKind, artifact_content_hash AS artifactContentHash,
          content_hash AS contentHash
        FROM fixture_anchors WHERE logical_address = $logicalAddress
      `).get({ logicalAddress });
      if (row === null) return Object.freeze({ status: "absent" as const });
      if (row.artifactContentHash === null || row.contentHash !== row.artifactContentHash) {
        return Object.freeze({ status: "rejected" as const, reason: "Artifact anchor content binding is inconsistent" });
      }
      const artifact = this.#artifacts.get(row.artifactContentHash);
      return artifact === null || !artifact.kinds.includes(row.artifactKind)
        ? Object.freeze({ status: "rejected" as const, reason: "Artifact anchor target is unavailable or mistyped" })
        : Object.freeze({ status: "resolved" as const, artifactKind: row.artifactKind, artifactContentHash: row.artifactContentHash });
    } catch (error) {
      return error instanceof ArtifactIntegrityError
        ? Object.freeze({ status: "rejected" as const, reason: message(error) })
        : Object.freeze({ status: "indeterminate" as const, reason: message(error) });
    }
  }

  #referencePhaseAuthority(locator: string, evidence: Readonly<Record<string, unknown>>) {
    const jobId = evidence["jobId"];
    const phaseKind = evidence["phase"];
    if (typeof jobId !== "string" || typeof phaseKind !== "string") {
      throw new FixtureBundleIntegrityError("Referenced SettlementEvidence lacks signed authority fields");
    }
    const lifecycle = this.#database.query<LifecycleFinalisationRow & {
      instanceId: string; audience: string;
    }, { jobId: string }>(`
      SELECT agreement_artifact_hash AS agreementArtifactHash,
        commitment_artifact_hash AS commitmentArtifactHash,
        instance_id AS instanceId, audience,
        required_payment_phases_json AS requiredPaymentPhasesJson,
        delivery_phase_index AS deliveryPhaseIndex, delivery_phase_kind AS deliveryPhaseKind,
        payment_invocations AS paymentInvocations, settlement_invocations AS settlementInvocations,
        delivery_invocations AS deliveryInvocations, payment_result_json AS paymentResultJson,
        settlement_result_json AS settlementResultJson, delivery_result_json AS deliveryResultJson,
        terminal_result_json AS terminalResultJson, terminal_state AS terminalState,
        abort_actor_role AS abortActorRole, abort_reason AS abortReason,
        failure_stage AS failureStage, error_class AS errorClass, failure_reason AS failureReason,
        created_at AS createdAt, updated_at AS updatedAt, ended_at AS endedAt,
        state, version FROM fixture_lifecycle_runs WHERE job_id = $jobId
    `).get({ jobId });
    if (lifecycle === null || !new Set([
      "settle-completed", "settle-failed", "settle-unsupported", "failed-substrate", "finalised",
    ]).has(lifecycle.state)) {
      throw new FixtureBundleIntegrityError("Referenced evidence has no terminal lifecycle authority");
    }
    const session = readPersistedSessionByJobId(this.#database, jobId);
    if (session === null || session.instanceId !== lifecycle.instanceId || session.audience !== lifecycle.audience
      || session.status !== "admitted" || session.evidenceMode !== "fixture"
      || lifecycle.commitmentArtifactHash === null) {
      throw new FixtureBundleIntegrityError("Referenced evidence is not bound to an admitted fixture session and commitment");
    }
    const settlements = parseOptionalEvidenceArray(lifecycle.settlementResultJson, "settlement");
    const delivery = parseOptionalEvidence(lifecycle.deliveryResultJson, "delivery");
    const terminal = parseOptionalEvidence(lifecycle.terminalResultJson, "terminal");
    const paymentPlan = parsePaymentPlan(lifecycle.requiredPaymentPhasesJson);
    if (canonicalize(settlements.map(({ phaseIndex, phaseKind: kind }) => ({ phaseIndex, phaseKind: kind })))
      !== canonicalize(paymentPlan.slice(0, settlements.length))
      || (delivery !== null && (delivery.phaseIndex !== Number(lifecycle.deliveryPhaseIndex)
        || delivery.phaseKind !== lifecycle.deliveryPhaseKind))) {
      throw new FixtureBundleIntegrityError("Referenced evidence phase wrappers differ from the lifecycle plan");
    }
    const phase = [
      ...settlements,
      ...(terminal === null ? [] : [terminal]),
      ...(delivery === null ? [] : [delivery]),
    ].find((entry) => {
      const anchor = entry.attestationRef["anchor"] as Record<string, unknown> | undefined;
      return anchor?.["kind"] === "storage-program" && anchor["locator"] === locator;
    });
    if (phase === undefined || phase.phaseKind !== phaseKind
      || phase.attestationRef["contentHash"] !== sha256Hex(canonicalize(Object.fromEntries(
        Object.entries(evidence).filter(([key]) => key !== "signature"),
      )))) {
      throw new FixtureBundleIntegrityError("Referenced evidence is not the exact persisted lifecycle result");
    }
    return Object.freeze({
      jobId,
      phaseIndex: phase.phaseIndex,
      phaseKind,
      signer: phase.authorityClaim,
    });
  }

  #assertFinalisationChronology(
    jobId: string,
    finalisedAt: number,
    lifecycle: LifecycleFinalisationRow,
  ): void {
    if (!Number.isSafeInteger(finalisedAt) || finalisedAt < 0) {
      throw new FixtureBundleConflictError("Bundle finalisation time is invalid");
    }
    const session = readPersistedSessionByJobId(this.#database, jobId);
    const commitment = session === null ? null : this.#readCommitmentAuthority(session);
    if (session === null || commitment === null) {
      throw new FixtureBundleIntegrityError("Bundle finalisation lacks session or commitment time authority");
    }
    const committedAt = commitment.committedAt;
    const evidence = [
      ...parseOptionalEvidenceArray(lifecycle.settlementResultJson, "settlement"),
      ...(parseOptionalEvidence(lifecycle.terminalResultJson, "terminal") === null
        ? [] : [parseOptionalEvidence(lifecycle.terminalResultJson, "terminal")!]),
      ...(parseOptionalEvidence(lifecycle.deliveryResultJson, "delivery") === null
        ? [] : [parseOptionalEvidence(lifecycle.deliveryResultJson, "delivery")!]),
    ];
    const sessionStartedAt = canonicalTimestampMs(session.createdAt, "Session createdAt");
    const lifecycleStartedAt = canonicalTimestampMs(lifecycle.createdAt, "Lifecycle createdAt");
    const lifecycleUpdatedAt = canonicalTimestampMs(lifecycle.updatedAt, "Lifecycle updatedAt");
    if (!Number.isSafeInteger(committedAt)) {
      throw new FixtureBundleConflictError("Bundle commitment time is invalid");
    }
    if (lifecycleStartedAt < sessionStartedAt) {
      throw new FixtureBundleConflictError("Bundle lifecycle predates persisted session authority");
    }
    if (committedAt < lifecycleStartedAt) {
      throw new FixtureBundleConflictError("Bundle commitment predates persisted lifecycle authority");
    }
    let previousObservation = committedAt;
    for (const entry of evidence) {
      const { anchoredAt, observedAt } = this.#attestationObservationTime(entry.attestationRef);
      if (observedAt < previousObservation || anchoredAt < observedAt) {
        throw new FixtureBundleConflictError("Bundle phase observations are not chronologically ordered");
      }
      previousObservation = anchoredAt;
    }
    if (lifecycleUpdatedAt < previousObservation) {
      throw new FixtureBundleConflictError("Bundle lifecycle update predates phase observations");
    }
    if (finalisedAt < lifecycleUpdatedAt) {
      throw new FixtureBundleConflictError("Bundle finalisation predates persisted lifecycle authority");
    }
  }

  #attestationObservationTime(ref: Readonly<Record<string, unknown>>): Readonly<{
    observedAt: number;
    anchoredAt: number;
  }> {
    const anchor = ref["anchor"] as Record<string, unknown> | undefined;
    const locator = anchor?.["locator"];
    if (anchor?.["kind"] !== "storage-program" || typeof locator !== "string") {
      throw new FixtureBundleIntegrityError("Phase observation reference is not a storage-program anchor");
    }
    const row = this.#database.query<{
      artifactContentHash: string | null; artifactKind: string; createdAt: string;
    }, { locator: string }>(`
      SELECT artifact_content_hash AS artifactContentHash, artifact_kind AS artifactKind,
        created_at AS createdAt
      FROM fixture_anchors WHERE logical_address = $locator
    `).get({ locator });
    if (row === null || row.artifactContentHash === null) {
      throw new FixtureBundleIntegrityError("Phase observation lacks its persisted artifact binding");
    }
    const artifact = this.#artifacts.get(row.artifactContentHash);
    if (artifact === null || !artifact.kinds.includes(row.artifactKind)) {
      throw new FixtureBundleIntegrityError("Phase observation artifact is unavailable or mistyped");
    }
    const value = parsePersistedObject(artifact.canonicalJson, "Phase observation artifact");
    const observedAt = row.artifactKind === "dacs-4-evidence"
      ? value["observedAt"] : row.artifactKind === "dacs-2-verify-result"
        ? value["verifiedAt"] : undefined;
    if (!Number.isSafeInteger(observedAt) || (observedAt as number) < 0) {
      throw new FixtureBundleIntegrityError("Phase observation artifact lacks a valid authority timestamp");
    }
    return Object.freeze({
      observedAt: observedAt as number,
      anchoredAt: canonicalTimestampMs(row.createdAt, "Phase evidence anchor createdAt"),
    });
  }

  #readLifecycle(jobId: string): LifecycleFinalisationRow | null {
    return this.#database.query<LifecycleFinalisationRow, { jobId: string }>(`
      SELECT agreement_artifact_hash AS agreementArtifactHash,
        commitment_artifact_hash AS commitmentArtifactHash,
        required_payment_phases_json AS requiredPaymentPhasesJson,
        delivery_phase_index AS deliveryPhaseIndex, delivery_phase_kind AS deliveryPhaseKind,
        payment_invocations AS paymentInvocations, settlement_invocations AS settlementInvocations,
        delivery_invocations AS deliveryInvocations, payment_result_json AS paymentResultJson,
        settlement_result_json AS settlementResultJson, delivery_result_json AS deliveryResultJson,
        terminal_result_json AS terminalResultJson, terminal_state AS terminalState,
        abort_actor_role AS abortActorRole, abort_reason AS abortReason,
        failure_stage AS failureStage, error_class AS errorClass, failure_reason AS failureReason,
        created_at AS createdAt, updated_at AS updatedAt, ended_at AS endedAt,
        state, version FROM fixture_lifecycle_runs WHERE job_id = $jobId
    `).get({ jobId });
  }

  #finalisedRoleExpected(jobId: string, role: BundleRole): boolean {
    const lifecycle = this.#database.query<{
      state: string; terminalState: string | null;
    }, { jobId: string }>(
      "SELECT state, terminal_state AS terminalState FROM fixture_lifecycle_runs WHERE job_id = $jobId",
    ).get({ jobId });
    if (lifecycle?.state !== "finalised") return false;
    if (lifecycle.terminalState === "aborted") {
      const roles = this.#database.query<{ role: BundleRole }, { jobId: string }>(
        "SELECT anchored_by_role AS role FROM fixture_bundles WHERE job_id = $jobId",
      ).all({ jobId });
      return roles.length === 0 || roles.some((entry) => entry.role === role);
    }
    if (role === "buyer" || role === "seller") return true;
    const copy = this.#database.query<{ artifactContentHash: string }, { jobId: string }>(`
      SELECT artifact_content_hash AS artifactContentHash
      FROM fixture_bundles WHERE job_id = $jobId LIMIT 1
    `).get({ jobId });
    if (copy === null) return true;
    const artifact = this.#artifacts.get(copy.artifactContentHash);
    if (artifact === null) throw new FixtureBundleIntegrityError("Cannot determine finalised orchestrator role from corrupt copies");
    const value = parsePersistedObject(artifact.canonicalJson, "Persisted bundle artifact");
    return Array.isArray(value["parties"])
      && (value["parties"] as Record<string, unknown>[]).some((party) => party["role"] === "orchestrator");
  }

  #assertReplay(input: FixtureBundleFinaliseInput): FixtureBundleFinalisation {
    const persisted = new Map<BundleRole, FixtureBundleRecord>();
    for (const role of ["buyer", "seller", "orchestrator"] as const) {
      const copy = this.get(input.session.jobId, role);
      if (copy !== null) persisted.set(role, copy);
    }
    const expectedRoles = [...input.anchorRoles].sort();
    const persistedRoles = [...persisted.keys()].sort();
    if (canonicalize(persistedRoles) !== canonicalize(expectedRoles)) {
      throw new FixtureBundleIntegrityError("Finalised bundle replay role set differs from persisted copies");
    }
    const records = input.anchorRoles.map((role) => persisted.get(role)!);
    const proposed = this.#signCurrentBundle(input, this.#readLifecycle(input.session.jobId)!);
    if (proposed.copies.some((copy, index) => copy.bundleHash !== records[index]!.bundleHash
      || copy.canonicalJson !== records[index]!.canonicalJson)) {
      throw new FixtureBundleConflictError("Bundle replay differs from the finalised artifact set");
    }
    return Object.freeze({ state: "finalised", bundleHash: records[0]!.bundleHash, copies: Object.freeze(records) });
  }
}

function parseEvidenceArray(value: string | null, label: string): ReturnType<typeof parseEvidence>[] {
  if (value === null) throw new FixtureBundleIntegrityError(`Lifecycle ${label} evidence is unavailable`);
  const parsed = parsePersistedJson(value, `Lifecycle ${label} evidence`);
  if (!Array.isArray(parsed) || canonicalize(parsed) !== value) {
    throw new FixtureBundleIntegrityError(`Lifecycle ${label} evidence is invalid or non-canonical`);
  }
  return parsed.map((entry) => parseEvidence(canonicalize(entry), label));
}
function parseOptionalEvidenceArray(value: string | null, label: string): ReturnType<typeof parseEvidence>[] {
  return value === null ? [] : parseEvidenceArray(value, label);
}
function parseOptionalEvidence(value: string | null, label: string): ReturnType<typeof parseEvidence> | null {
  return value === null ? null : parseEvidence(value, label);
}
function parsePaymentPlan(value: string): readonly Readonly<{ phaseIndex: number; phaseKind: string }>[] {
  const parsed = parsePersistedJson(value, "Persisted payment phase plan");
  if (!Array.isArray(parsed) || canonicalize(parsed) !== value) {
    throw new FixtureBundleIntegrityError("Persisted payment phase plan is not a canonical array");
  }
  const phases = parsed.map((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new FixtureBundleIntegrityError("Persisted payment phase binding is invalid");
    }
    const phaseIndex = (entry as Record<string, unknown>)["phaseIndex"];
    const phaseKind = (entry as Record<string, unknown>)["phaseKind"];
    if (!Number.isSafeInteger(phaseIndex) || (phaseIndex as number) < 0
      || typeof phaseKind !== "string" || phaseKind.length === 0) {
      throw new FixtureBundleIntegrityError("Persisted payment phase binding is invalid");
    }
    return Object.freeze({ phaseIndex: phaseIndex as number, phaseKind });
  });
  return Object.freeze(phases);
}
function parsePhaseResultBindings(
  value: string | null,
  label: string,
): readonly Readonly<{ phaseIndex: number; phaseKind: string }>[] {
  if (value === null) return Object.freeze([]);
  const parsed = parsePersistedJson(value, `Lifecycle ${label} results`);
  if (!Array.isArray(parsed) || canonicalize(parsed) !== value) {
    throw new FixtureBundleIntegrityError(`Lifecycle ${label} results are not a canonical array`);
  }
  return Object.freeze(parsed.map((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new FixtureBundleIntegrityError(`Lifecycle ${label} result wrapper is invalid`);
    }
    const record = entry as Record<string, unknown>;
    if (!Number.isSafeInteger(record["phaseIndex"]) || (record["phaseIndex"] as number) < 0
      || typeof record["phaseKind"] !== "string" || record["phaseKind"].length === 0
      || record["value"] === null || typeof record["value"] !== "object" || Array.isArray(record["value"])) {
      throw new FixtureBundleIntegrityError(`Lifecycle ${label} result wrapper is invalid`);
    }
    return Object.freeze({
      phaseIndex: record["phaseIndex"] as number,
      phaseKind: record["phaseKind"],
    });
  }));
}

function validateLifecycleExecutionBoundary(
  lifecycle: LifecycleFinalisationRow,
  plan: readonly Readonly<{ phaseIndex: number; phaseKind: string }>[],
  payments: readonly Readonly<{ phaseIndex: number; phaseKind: string }>[],
  settlements: readonly Readonly<{ phaseIndex: number; phaseKind: string }>[],
): void {
  if (canonicalize(payments) !== canonicalize(plan.slice(0, payments.length))
    || canonicalize(settlements) !== canonicalize(plan.slice(0, settlements.length))) {
    throw new FixtureBundleIntegrityError("Lifecycle phase results do not follow the pinned payment plan");
  }
  const paymentInvocations = Number(lifecycle.paymentInvocations);
  const settlementInvocations = Number(lifecycle.settlementInvocations);
  const deliveryInvocations = Number(lifecycle.deliveryInvocations);
  if (!Number.isSafeInteger(paymentInvocations) || paymentInvocations < 0
    || !Number.isSafeInteger(settlementInvocations) || settlementInvocations < 0
    || (deliveryInvocations !== 0 && deliveryInvocations !== 1)) {
    throw new FixtureBundleIntegrityError("Lifecycle invocation counts are invalid");
  }
  const state = lifecycle.state === "finalised"
    ? lifecycle.terminalState ?? "settle-completed" : lifecycle.state;
  const completed = payments.length === plan.length && settlements.length === plan.length
    && paymentInvocations === payments.length && settlementInvocations === settlements.length
    && deliveryInvocations === 1;
  if (state === "settle-completed") {
    if (!completed) throw new FixtureBundleIntegrityError("Completed lifecycle invocation boundary is inconsistent");
    return;
  }
  if (state === "aborted") {
    const clean = paymentInvocations === payments.length
      && settlementInvocations === settlements.length && deliveryInvocations === 0
      && payments.length === settlements.length;
    const paymentPending = paymentInvocations === payments.length + 1
      && settlementInvocations === settlements.length && deliveryInvocations === 0
      && payments.length === settlements.length && payments.length < plan.length;
    const settlementPending = paymentInvocations === payments.length
      && settlementInvocations === settlements.length + 1 && deliveryInvocations === 0
      && payments.length === settlements.length + 1;
    const deliveryPending = completed;
    if (!clean && !paymentPending && !settlementPending && !deliveryPending) {
      throw new FixtureBundleIntegrityError("Abort lifecycle invocation boundary is inconsistent");
    }
    return;
  }
  const validFailure = lifecycle.failureStage === "payment"
    ? paymentInvocations === payments.length + 1 && settlementInvocations === settlements.length
      && deliveryInvocations === 0 && payments.length === settlements.length
    : lifecycle.failureStage === "settlement"
      ? paymentInvocations === payments.length && settlementInvocations === settlements.length + 1
        && deliveryInvocations === 0 && payments.length === settlements.length + 1
      : lifecycle.failureStage === "delivery" && completed;
  if (!validFailure) throw new FixtureBundleIntegrityError("Failed lifecycle invocation boundary is inconsistent");
}
function parseEvidence(value: string | null, label: string) {
  if (value === null) throw new FixtureBundleIntegrityError(`Lifecycle ${label} evidence is unavailable`);
  const entry = parsePersistedObject(value, `Lifecycle ${label} evidence`);
  if (canonicalize(entry) !== value || !exactKeys(entry, ["authorityClaim", "phaseIndex", "phaseKind", "value"])) {
    throw new FixtureBundleIntegrityError(`Lifecycle ${label} evidence wrapper is invalid or non-canonical`);
  }
  const phaseIndex = entry["phaseIndex"];
  const phaseKind = entry["phaseKind"];
  const authorityClaim = entry["authorityClaim"];
  const evidence = entry["value"] as Record<string, unknown> | undefined;
  const attestationRef = evidence?.["attestationRef"];
  if (!Number.isSafeInteger(phaseIndex) || typeof phaseKind !== "string" || typeof authorityClaim !== "string"
    || attestationRef === null || typeof attestationRef !== "object" || Array.isArray(attestationRef)) {
    throw new FixtureBundleIntegrityError(`Lifecycle ${label} evidence lacks a durable AttestationRef`);
  }
  return Object.freeze({
    phaseIndex: phaseIndex as number,
    phaseKind,
    authorityClaim,
    attestationRef: attestationRef as Record<string, unknown>,
  });
}
function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const expectedSet = new Set(expected);
  return Object.keys(value).length === expectedSet.size
    && Object.keys(value).every((key) => expectedSet.has(key));
}
function executedPhasePlan(
  listing: Readonly<Record<string, unknown>>,
  lifecycle: LifecycleFinalisationRow,
): readonly Readonly<{ index: number; kind: string }>[] {
  const pipeline = listing["pipeline"];
  if (!Array.isArray(pipeline) || !pipeline.every((step) => step !== null
    && typeof step === "object" && !Array.isArray(step) && typeof step["kind"] === "string")) {
    throw new FixtureBundleIntegrityError("Committed agreement pipeline is invalid");
  }
  const expected = pipeline.flatMap((step, index) => {
    const kind = (step as Record<string, unknown>)["kind"] as string;
    return kind === "commit-agreement" || kind === "commit-payee-bound-agreement"
      || kind.startsWith("pay-") || kind.startsWith("deliver-") ? [{ index, kind }] : [];
  });
  const payments = parsePaymentPlan(lifecycle.requiredPaymentPhasesJson)
    .map((phase) => ({ index: phase.phaseIndex, kind: phase.phaseKind }));
  const deliveryIndex = Number(lifecycle.deliveryPhaseIndex);
  const commit = expected.filter((phase) => phase.kind.startsWith("commit-"));
  const actual = [...commit, ...payments, {
    index: deliveryIndex,
    kind: lifecycle.deliveryPhaseKind,
  }];
  if (commit.length !== 1 || !Number.isSafeInteger(deliveryIndex) || deliveryIndex < 0
    || new Set(actual.map((phase) => phase.index)).size !== actual.length
    || canonicalize(actual) !== canonicalize(expected)) {
    throw new FixtureBundleIntegrityError("Persisted executed phase plan differs from the committed pipeline");
  }
  return Object.freeze(actual.map((phase) => Object.freeze(phase)));
}
function parsePersistedJson(value: string, label: string): unknown {
  try { return JSON.parse(value) as unknown; }
  catch { throw new FixtureBundleIntegrityError(`${label} is not valid JSON`); }
}
function parsePersistedObject(value: string, label: string): Record<string, unknown> {
  const parsed = parsePersistedJson(value, label);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new FixtureBundleIntegrityError(`${label} is not an object`);
  }
  return parsed as Record<string, unknown>;
}
function canonicalTimestampMs(value: string, label: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || new Date(timestamp).toISOString() !== value) {
    throw new FixtureBundleIntegrityError(`${label} is not a canonical timestamp`);
  }
  return timestamp;
}
function validateSession(session: SessionRecord): void {
  if (session === null || typeof session !== "object" || session.status !== "admitted" || session.evidenceMode !== "fixture") {
    throw new TypeError("Fixture bundle requires an admitted fixture session");
  }
}
function validateTimestamp(value: string): void {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new TypeError("Fixture bundle createdAt must be a canonical timestamp");
  }
}
function message(error: unknown): string { return error instanceof Error ? error.message : "Fixture bundle read failed"; }

function terminalBundleOutcome(
  lifecycle: LifecycleFinalisationRow,
  input: FixtureBundleFinaliseInput,
): UnsignedAttestationBundle["outcome"] {
  if (lifecycle.state === "settle-completed") return "completed";
  if (lifecycle.state === "settle-failed") {
    if (lifecycle.terminalResultJson === null || lifecycle.failureReason === null
      || lifecycle.failureStage === null || lifecycle.failureStage === "commit") {
      throw new FixtureBundleIntegrityError("Settle failure lacks authenticated terminal evidence");
    }
    return mappedTerminalOutcome(lifecycle, input.anchorRoles[0]!);
  }
  if (lifecycle.state === "settle-unsupported") {
    if (lifecycle.errorClass !== "settlement-atomicity" || lifecycle.terminalResultJson === null
      || lifecycle.failureReason === null || lifecycle.failureStage === null
      || lifecycle.failureStage === "commit") {
      throw new FixtureBundleIntegrityError("Settlement-atomicity failure lacks authenticated terminal evidence");
    }
    return mappedTerminalOutcome(lifecycle, input.anchorRoles[0]!);
  }
  if (lifecycle.state === "failed-substrate") {
    if (lifecycle.errorClass !== "substrate" || lifecycle.terminalResultJson === null
      || lifecycle.failureReason === null || lifecycle.failureStage === null
      || lifecycle.failureStage === "commit") {
      throw new FixtureBundleIntegrityError("Substrate failure lacks authenticated terminal evidence");
    }
    return mappedTerminalOutcome(lifecycle, input.anchorRoles[0]!);
  }
  if (lifecycle.state === "aborted") {
    if (lifecycle.abortActorRole === null || lifecycle.abortReason === null
      || lifecycle.errorClass !== null || lifecycle.failureStage !== null
      || lifecycle.failureReason !== null || lifecycle.terminalResultJson !== null
      || input.anchorRoles.length !== 1 || input.partySigners.length !== 1) {
      throw new FixtureBundleIntegrityError("Abort lacks an exact unilateral actor perspective");
    }
    const signerRole = input.partySigners[0]!.role;
    if (input.anchorRoles[0] !== signerRole || (signerRole !== "buyer" && signerRole !== "seller")) {
      throw new FixtureBundleConflictError("Abort bundle must be anchored by its sole buyer or seller signer");
    }
    return mappedTerminalOutcome(lifecycle, signerRole);
  }
  throw new FixtureBundleConflictError("Lifecycle state has no terminal bundle mapping");
}

function mappedTerminalOutcome(
  lifecycle: LifecycleFinalisationRow,
  role: BundleRole,
): UnsignedAttestationBundle["outcome"] {
  const state = lifecycle.state === "finalised"
    ? lifecycle.terminalState ?? "settle-completed" : lifecycle.state;
  if (state === "settle-completed") return "completed";
  if (state === "settle-failed") {
    if (lifecycle.errorClass === "permanent" || lifecycle.errorClass === "transient") return "failed-perm";
    if (lifecycle.errorClass === "counterparty") return "failed-counterparty";
  } else if (state === "settle-unsupported" && lifecycle.errorClass === "settlement-atomicity") {
    return "failed-counterparty";
  } else if (state === "failed-substrate" && lifecycle.errorClass === "substrate") {
    return "failed-substrate";
  } else if (state === "aborted" && lifecycle.abortActorRole !== null
    && (role === "buyer" || role === "seller")) {
    return role === lifecycle.abortActorRole ? "aborted-by-self" : "aborted-by-other";
  }
  throw new FixtureBundleIntegrityError("Sealed lifecycle metadata has no exact bundle outcome mapping");
}

function expectedPersistedOutcome(
  lifecycle: LifecycleFinalisationRow,
  bundle: Readonly<Record<string, unknown>>,
  role: BundleRole,
): string {
  const legacyOutcome = mappedTerminalOutcome(lifecycle, role);
  if (!isFaultAttestationBundle(bundle)) return legacyOutcome;
  if (typeof bundle["faultedParty"] !== "string") {
    throw new FixtureBundleIntegrityError("Persisted FaultAttestationBundle lacks faultedParty");
  }
  const terminalState = lifecycle.state === "finalised" ? lifecycle.terminalState : lifecycle.state;
  if (terminalState === "aborted" && bundle["faultedParty"] !== lifecycle.abortActorRole) {
    throw new FixtureBundleIntegrityError("Persisted faultedParty differs from abort authority");
  }
  return roleRelativeOutcome(outcomeClass(legacyOutcome), bundle["faultedParty"], role);
}

function faultedPartyForLifecycle(
  lifecycle: LifecycleFinalisationRow,
  perspectiveRole: BundleRole,
  perspectiveOutcome: UnsignedAttestationBundle["outcome"],
  declared: BundleFaultedParty | undefined,
): BundleFaultedParty {
  let expected: BundleFaultedParty;
  if (perspectiveOutcome === "completed" || perspectiveOutcome === "failed-substrate") {
    expected = "none";
  } else if (perspectiveOutcome === "aborted-by-self" || perspectiveOutcome === "aborted-by-other") {
    if (lifecycle.abortActorRole === null) {
      throw new FixtureBundleIntegrityError("Abort lifecycle lacks its absolute faulted party");
    }
    expected = lifecycle.abortActorRole;
  } else if (perspectiveOutcome === "failed-perm") {
    expected = perspectiveRole;
  } else {
    if (declared === undefined) {
      throw new FixtureBundleConflictError(
        "Counterparty failure requires an explicit absolute faultedParty",
      );
    }
    expected = declared;
  }
  if (declared !== undefined && declared !== expected) {
    throw new FixtureBundleConflictError("Declared faultedParty differs from lifecycle authority");
  }
  return expected;
}

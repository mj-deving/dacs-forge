import { assertFixtureAuthority, type EvidenceMode } from "../../core/evidence-mode.ts";
import { verifyDeliveryAttestation } from "../../consumer/delivery-attestation-verifier.ts";
import {
  verifyCanonicalSettlementEvidenceJson,
  type SettlementAnchorRead,
  type SettlementDeliveryCheckResult,
  type SettlementDeliveryExpectation,
} from "../../consumer/settlement-evidence-verifier.ts";
import { canonicalize } from "../../protocol/canonical-json.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import { signFixtureDeliveryAttestation } from "../../producer/delivery-attestation.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
} from "../../producer/fixture-ed25519.ts";
import {
  signSettlementEvidence,
  type SettlementAttestationRef,
  type SettlementPriceTerm,
} from "../../producer/settlement-evidence.ts";
import { ArtifactIntegrityError, ArtifactStore, type ArtifactRecord } from "./artifact-store.ts";
import type { DacsDatabase } from "./database.ts";
import {
  FixtureCommitmentIntegrityError,
  FixtureCommitmentStore,
} from "./fixture-commitment.ts";
import {
  readPersistedSession,
  sessionBindingHash,
  type SessionRecord,
} from "./session-store.ts";

const HASH = /^[0-9a-f]{64}$/;
const MAX_INLINE_DELIVERY_BYTES = 131_072;
const MAX_FORMAT_LENGTH = 256;

export class FixtureDeliveryConflictError extends Error {
  override readonly name = "FixtureDeliveryConflictError";
}

export class FixtureDeliveryIntegrityError extends Error {
  override readonly name = "FixtureDeliveryIntegrityError";
}

export class FixtureDeliverySubstrateError extends Error {
  override readonly name = "FixtureDeliverySubstrateError";
}

export interface FixtureAttestedDeliveryInput {
  readonly agreementHash: string;
  readonly createdAt: string;
  readonly observedAt: number;
  readonly payloadFormat: string;
  readonly payloadJson: string;
  readonly paymentAmount: SettlementPriceTerm;
  readonly phaseIndex: number;
  readonly session: SessionRecord;
}

export interface FixtureAttestedDeliveryRecord {
  readonly agreementHash: string;
  readonly assertionAddress: string;
  readonly assertionArtifactHash: string;
  readonly attestationRef: SettlementAttestationRef;
  readonly createdAt: string;
  readonly deliverableContentHash: string;
  readonly deliveryAddress: string;
  readonly deliveryArtifactHash: string;
  readonly deliveryCanonicalJson: string;
  readonly evidenceAddress: string;
  readonly evidenceArtifactHash: string;
  readonly evidenceCanonicalJson: string;
  readonly evidenceHash: string;
  readonly evidenceMode: "fixture";
  readonly jobId: string;
  readonly orchestrator: string;
  readonly payloadCanonicalJson: string;
  readonly payloadFormat: string;
  readonly paymentAmountCanonicalJson: string;
  readonly phaseIndex: number;
  readonly sessionBindingHash: string;
  readonly verifyResultAddress: string;
  readonly verifyResultArtifactHash: string;
}

export interface FixtureDeliveryStoreOptions {
  readonly deploymentMode: EvidenceMode;
  readonly signer: ArtifactSigner;
}

interface DeliveryRow {
  readonly agreementHash: string;
  readonly assertionAddress: string;
  readonly assertionArtifactHash: string;
  readonly audience: string;
  readonly createdAt: string;
  readonly deliveryAddress: string;
  readonly deliveryArtifactHash: string;
  readonly evidenceAddress: string;
  readonly evidenceArtifactHash: string;
  readonly evidenceHash: string;
  readonly instanceId: string;
  readonly jobId: string;
  readonly orchestrator: string;
  readonly payloadContentHash: string;
  readonly payloadFormat: string;
  readonly paymentAmountCanonicalJson: string;
  readonly phaseIndex: bigint;
  readonly sessionBindingHash: string;
  readonly verifyResultAddress: string;
  readonly verifyResultArtifactHash: string;
}

interface PreparedDelivery {
  readonly agreementHash: string;
  readonly createdAt: string;
  readonly deliveryAddress: string;
  readonly evidenceAddress: string;
  readonly observedAt: number;
  readonly payload: unknown;
  readonly payloadCanonicalJson: string;
  readonly payloadFormat: string;
  readonly paymentAmount: SettlementPriceTerm;
  readonly paymentAmountCanonicalJson: string;
  readonly phaseIndex: number;
  readonly session: SessionRecord;
  readonly sessionBindingHash: string;
}

interface DeliveryAuthorityRow {
  readonly agreementArtifactHash: string;
  readonly commitmentArtifactHash: string | null;
  readonly deliveryPhaseIndex: bigint;
  readonly deliveryPhaseKind: string;
  readonly state: string;
}

interface DeliveryAuthorityExpectation {
  readonly agreementHash: string;
  readonly paymentAmountCanonicalJson: string;
  readonly payloadFormat: string;
  readonly phaseIndex: number;
  readonly session: SessionRecord;
}

export class FixtureDeliveryStore {
  readonly #artifacts: ArtifactStore;
  readonly #commitments: FixtureCommitmentStore;
  readonly #database: DacsDatabase;
  readonly #signer: ArtifactSigner;

  constructor(database: DacsDatabase, options: FixtureDeliveryStoreOptions) {
    assertFixtureAuthority(options.deploymentMode, "fixture");
    assertFixtureSigningAuthority(options.signer, {
      deploymentMode: options.deploymentMode,
      requestMode: "fixture",
    });
    this.#database = database;
    this.#artifacts = new ArtifactStore(database);
    this.#signer = options.signer;
    this.#commitments = new FixtureCommitmentStore(database, {
      anchorTimeMs: () => 0,
      deploymentMode: options.deploymentMode,
      now: () => "1970-01-01T00:00:00.000Z",
      preAnchorTimeMs: () => 0,
      signer: options.signer,
    });
  }

  deliver(input: FixtureAttestedDeliveryInput): FixtureAttestedDeliveryRecord {
    const requested = prepare(input);
    const persistedSession = this.#requirePersistedSession(requested.session);
    const prepared = Object.freeze({
      ...requested,
      session: persistedSession,
      sessionBindingHash: sessionBindingHash(persistedSession),
    });
    const existing = this.#readRowForDelivery(prepared);
    if (existing !== null) return assertReplay(this.#resolve(existing, prepared.session), prepared);
    const persist = this.#database.transaction(() => {
      this.#assertDeliveryAuthority(prepared, false);

    const deliverableContentHash = sha256Hex(prepared.payloadCanonicalJson);
    const attestation = signFixtureDeliveryAttestation({
      agreementHash: prepared.agreementHash,
      deliverableContentHash,
      jobId: prepared.session.jobId,
      observedAt: prepared.observedAt,
      payloadFormat: prepared.payloadFormat,
      phaseIndex: prepared.phaseIndex,
      sessionBindingHash: prepared.sessionBindingHash,
      signer: this.#signer.signer,
    }, this.#signer, { deploymentMode: "fixture", requestMode: "fixture" });
    const deliveryValue = Object.freeze({
      deliveryVersion: "1",
      agreementHash: prepared.agreementHash,
      attestationRef: attestation.verifyResultRef,
      deliverableContentHash,
      jobId: prepared.session.jobId,
      payload: prepared.payload,
      payloadFormat: prepared.payloadFormat,
      phaseIndex: prepared.phaseIndex,
      sessionBindingHash: prepared.sessionBindingHash,
    });
    const deliveryCanonicalJson = canonicalize(deliveryValue);
    const deliveryArtifactHash = sha256Hex(deliveryCanonicalJson);
    const expectedDelivery = deliveryExpectation(prepared, deliverableContentHash, attestation.verifyResultRef);
    const evidence = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: prepared.session.jobId,
      phase: "deliver-attested-payload",
      outcome: "success",
      paymentAmount: prepared.paymentAmount,
      deliverableContentHash,
      deliverableAnchor: { kind: "storage-program", locator: prepared.deliveryAddress },
      attestationRef: attestation.verifyResultRef as SettlementAttestationRef,
      observedAt: prepared.observedAt,
    }, this.#signer, {
      agreementHash: prepared.agreementHash,
      deploymentMode: "fixture",
      deliveryArtifactCheck: (address, expected) => verifyDeliveryValue(
        address,
        expected,
        deliveryValue,
        expectedDelivery,
        prepared.payloadFormat,
      ),
      evidenceMode: "fixture",
      expectedEvidenceLogicalAddress: prepared.evidenceAddress,
      expectedJobId: prepared.session.jobId,
      expectedPaymentAmount: prepared.paymentAmount,
      expectedPhase: "deliver-attested-payload",
      expectedSessionBindingHash: prepared.sessionBindingHash,
      phaseIndex: prepared.phaseIndex,
      requestMode: "fixture",
    });

      const assertionArtifact = this.#artifacts.putWithinTransaction(
        "dacs-2-delivery-assertion",
        attestation.assertion,
        prepared.createdAt,
      );
      const verifyResultArtifact = this.#artifacts.putWithinTransaction(
        "dacs-2-verify-result",
        attestation.verifyResult,
        prepared.createdAt,
      );
      const deliveryArtifact = this.#artifacts.putWithinTransaction(
        "dacs-4-deliverable",
        deliveryValue,
        prepared.createdAt,
      );
      const evidenceArtifact = this.#artifacts.putWithinTransaction(
        "dacs-4-evidence",
        evidence.evidence,
        prepared.createdAt,
      );
      assertArtifact(assertionArtifact, attestation.assertionArtifactHash, attestation.assertionCanonicalJson);
      assertArtifact(verifyResultArtifact, attestation.verifyResultArtifactHash, attestation.verifyResultCanonicalJson);
      assertArtifact(deliveryArtifact, deliveryArtifactHash, deliveryCanonicalJson);
      assertArtifact(evidenceArtifact, evidence.artifactContentHash, evidence.canonicalJson);
      putAnchor(this.#database, attestation.assertionLogicalAddress, "dacs-2-delivery-assertion",
        assertionArtifact.contentHash, assertionArtifact.contentHash, prepared.createdAt);
      putAnchor(this.#database, attestation.verifyResultLogicalAddress, "dacs-2-verify-result",
        attestation.verifyResultContentHash, verifyResultArtifact.contentHash, prepared.createdAt);
      putAnchor(this.#database, prepared.deliveryAddress, "dacs-4-deliverable",
        deliveryArtifact.contentHash, deliveryArtifact.contentHash, prepared.createdAt);
      putAnchor(this.#database, prepared.evidenceAddress, "dacs-4-evidence",
        evidence.evidenceHash, evidenceArtifact.contentHash, prepared.createdAt);
      this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: delivery.put-record */
        INSERT INTO fixture_deliveries (
          instance_id, audience, job_id, phase_index, agreement_hash,
          session_binding_hash, orchestrator_claim, payment_amount_json,
          payload_format, payload_content_hash, assertion_artifact_hash,
          verify_result_artifact_hash, delivery_artifact_hash, evidence_artifact_hash,
          evidence_hash, assertion_address, verify_result_address, delivery_address,
          evidence_address, created_at
        ) VALUES (
          $instanceId, $audience, $jobId, $phaseIndex, $agreementHash,
          $sessionBindingHash, $orchestrator, $paymentAmountCanonicalJson,
          $payloadFormat, $payloadContentHash, $assertionArtifactHash,
          $verifyResultArtifactHash, $deliveryArtifactHash, $evidenceArtifactHash,
          $evidenceHash, $assertionAddress, $verifyResultAddress, $deliveryAddress,
          $evidenceAddress, $createdAt
        )
      `).run({
        instanceId: prepared.session.instanceId,
        audience: prepared.session.audience,
        jobId: prepared.session.jobId,
        phaseIndex: prepared.phaseIndex,
        agreementHash: prepared.agreementHash,
        sessionBindingHash: prepared.sessionBindingHash,
        orchestrator: this.#signer.signer,
        paymentAmountCanonicalJson: prepared.paymentAmountCanonicalJson,
        payloadFormat: prepared.payloadFormat,
        payloadContentHash: deliverableContentHash,
        assertionArtifactHash: assertionArtifact.contentHash,
        verifyResultArtifactHash: verifyResultArtifact.contentHash,
        deliveryArtifactHash: deliveryArtifact.contentHash,
        evidenceArtifactHash: evidenceArtifact.contentHash,
        evidenceHash: evidence.evidenceHash,
        assertionAddress: attestation.assertionLogicalAddress,
        verifyResultAddress: attestation.verifyResultLogicalAddress,
        deliveryAddress: prepared.deliveryAddress,
        evidenceAddress: prepared.evidenceAddress,
        createdAt: prepared.createdAt,
      });
    });
    try {
      persist.immediate();
    } catch (error) {
      let raced: DeliveryRow | null;
      try {
        raced = this.#readRow(prepared.session.instanceId, prepared.session.audience, prepared.session.jobId);
      } catch (readError) {
        throw new FixtureDeliverySubstrateError("Fixture delivery transaction recovery read failed", {
          cause: readError,
        });
      }
      if (raced !== null) return assertReplay(this.#resolve(raced, prepared.session), prepared);
      if (isPermanentDeliveryFailure(error)) throw error;
      throw new FixtureDeliverySubstrateError("Fixture delivery transaction failed", { cause: error });
    }
    const row = this.#readRowForDelivery(prepared);
    if (row === null) throw new FixtureDeliveryIntegrityError("Fixture delivery was not visible after persistence");
    return this.#resolve(row, prepared.session);
  }

  get(session: SessionRecord): FixtureAttestedDeliveryRecord | null {
    const persistedSession = this.#requirePersistedSession(session);
    const expectedSessionBinding = sessionBindingHash(persistedSession);
    const row = this.#readRowForSession(persistedSession);
    if (row === null) return null;
    if (row.sessionBindingHash !== expectedSessionBinding) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery belongs to a different admitted session");
    }
    return this.#resolve(row, persistedSession);
  }

  verifyDeliveryArtifact(
    logicalAddress: string,
    expected: SettlementDeliveryExpectation,
  ): SettlementDeliveryCheckResult {
    try {
      const row = readDeliveryRow(this.#database, { kind: "address", logicalAddress });
      if (row === null) return Object.freeze({ status: "rejected", reason: "Fixture delivery is authoritatively absent" });
      if (row.orchestrator !== this.#signer.signer) {
        return Object.freeze({ status: "rejected", reason: "Fixture delivery signer is not the configured authority" });
      }
      const anchor = getAnchor(this.#database, this.#artifacts, logicalAddress);
      if (anchor === null) {
        return Object.freeze({ status: "rejected", reason: "Fixture delivery anchor is authoritatively absent" });
      }
      if (anchor.artifactKind !== "dacs-4-deliverable"
        || anchor.contentHash !== row.deliveryArtifactHash
        || anchor.artifact.contentHash !== row.deliveryArtifactHash) {
        return Object.freeze({ status: "rejected", reason: "Fixture delivery anchor does not match the persisted delivery" });
      }
      const verifyResult = requiredArtifact(
        this.#artifacts,
        row.verifyResultArtifactHash,
        "dacs-2-verify-result",
      );
      const verifyResultContentHash = signedContentHash(verifyResult.canonicalJson);
      const verifyResultAnchor = getAnchor(this.#database, this.#artifacts, row.verifyResultAddress);
      if (verifyResultAnchor === null || verifyResultAnchor.artifactKind !== "dacs-2-verify-result"
        || verifyResultAnchor.contentHash !== verifyResultContentHash
        || verifyResultAnchor.artifact.contentHash !== row.verifyResultArtifactHash) {
        return Object.freeze({ status: "rejected", reason: "Fixture delivery attestation anchor does not match the persisted VerifyResult" });
      }
      const delivery = anchor.artifact;
      return verifyDeliveryValue(
        logicalAddress,
        expected,
        parseCanonical(delivery.canonicalJson),
        rowExpectation(row, verifyResultContentHash),
        row.payloadFormat,
      );
    } catch (error) {
      return Object.freeze({ status: "indeterminate", reason: `Fixture delivery read failed: ${message(error)}` });
    }
  }

  readEvidenceAnchor(logicalAddress: string): SettlementAnchorRead {
    try {
      const anchor = getAnchor(this.#database, this.#artifacts, logicalAddress);
      return anchor === null ? { status: "absent" } : {
        status: "resolved",
        artifactContentHash: anchor.artifact.contentHash,
        artifactKind: anchor.artifactKind,
        evidenceHash: anchor.contentHash,
        evidenceMode: "fixture",
      };
    } catch (error) {
      return { status: "indeterminate", reason: `Fixture anchor read failed: ${message(error)}` };
    }
  }

  #resolve(row: DeliveryRow, session: SessionRecord): FixtureAttestedDeliveryRecord {
    const phaseIndex = Number(row.phaseIndex);
    if (!Number.isSafeInteger(phaseIndex) || phaseIndex < 0
      || row.sessionBindingHash !== sessionBindingHash(session)
      || row.jobId !== session.jobId || row.instanceId !== session.instanceId
      || row.audience !== session.audience || !HASH.test(row.agreementHash)
      || row.orchestrator !== this.#signer.signer
      || !HASH.test(row.payloadContentHash) || !HASH.test(row.evidenceHash)) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery row binding is corrupt");
    }
    this.#assertDeliveryAuthority({
      agreementHash: row.agreementHash,
      paymentAmountCanonicalJson: row.paymentAmountCanonicalJson,
      payloadFormat: row.payloadFormat,
      phaseIndex,
      session,
    }, true);
    const assertion = this.#requiredArtifactForResolve(row.assertionArtifactHash, "dacs-2-delivery-assertion");
    const verifyResult = this.#requiredArtifactForResolve(row.verifyResultArtifactHash, "dacs-2-verify-result");
    const delivery = this.#requiredArtifactForResolve(row.deliveryArtifactHash, "dacs-4-deliverable");
    const evidence = this.#requiredArtifactForResolve(row.evidenceArtifactHash, "dacs-4-evidence");
    const verifyResultContentHash = signedContentHash(verifyResult.canonicalJson);
    this.#assertAnchorForResolve(
      row.assertionAddress,
      "dacs-2-delivery-assertion",
      row.assertionArtifactHash,
      row.assertionArtifactHash,
    );
    this.#assertAnchorForResolve(
      row.verifyResultAddress,
      "dacs-2-verify-result",
      verifyResultContentHash,
      row.verifyResultArtifactHash,
    );
    this.#assertAnchorForResolve(
      row.deliveryAddress,
      "dacs-4-deliverable",
      row.deliveryArtifactHash,
      row.deliveryArtifactHash,
    );
    this.#assertAnchorForResolve(
      row.evidenceAddress,
      "dacs-4-evidence",
      row.evidenceHash,
      row.evidenceArtifactHash,
    );
    const attestationVerification = verifyDeliveryAttestation(assertion.canonicalJson, verifyResult.canonicalJson, {
      agreementHash: row.agreementHash,
      anchorContext: { mode: "post-anchor", read: (address) => attestationAnchorRead(this.#database, this.#artifacts, address) },
      deliverableContentHash: row.payloadContentHash,
      jobId: row.jobId,
      payloadFormat: row.payloadFormat,
      phaseIndex,
      sessionBindingHash: row.sessionBindingHash,
      signer: row.orchestrator,
    });
    if (attestationVerification.disposition === "indeterminate") {
      throw new FixtureDeliverySubstrateError(
        `Fixture delivery attestation read failed: ${attestationVerification.reason}`,
      );
    }
    if (attestationVerification.disposition !== "verified") {
      const reason = "reason" in attestationVerification ? attestationVerification.reason : attestationVerification.disposition;
      throw new FixtureDeliveryIntegrityError(`Fixture delivery attestation failed: ${reason}`);
    }
    if (row.assertionAddress !== attestationVerification.assertionAddress
      || row.assertionArtifactHash !== attestationVerification.assertionArtifactHash
      || row.verifyResultAddress !== attestationVerification.verifyResultAddress
      || row.verifyResultArtifactHash !== attestationVerification.verifyResultArtifactHash
      || verifyResultContentHash !== attestationVerification.verifyResultContentHash) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery attestation row addresses or hashes are corrupt");
    }
    const deliveryValue = parseCanonical(delivery.canonicalJson);
    const expected = rowExpectation(row, verifyResultContentHash);
    const deliveryCheck = verifyDeliveryValue(
      row.deliveryAddress,
      expected,
      deliveryValue,
      expected,
      row.payloadFormat,
    );
    if (deliveryCheck.status !== "verified") {
      throw new FixtureDeliveryIntegrityError(`Fixture delivery artifact failed: ${deliveryCheck.reason}`);
    }
    const evidenceVerification = verifyCanonicalSettlementEvidenceJson(evidence.canonicalJson, {
      agreementHash: row.agreementHash,
      anchorContext: { mode: "post-anchor", read: (address) => this.readEvidenceAnchor(address) },
      deliveryArtifactCheck: (address, expectation) => this.verifyDeliveryArtifact(address, expectation),
      evidenceMode: "fixture",
      expectedEvidenceLogicalAddress: row.evidenceAddress,
      expectedJobId: row.jobId,
      expectedOrchestrator: row.orchestrator,
      expectedPaymentAmount: parseCanonical(row.paymentAmountCanonicalJson),
      expectedPhase: "deliver-attested-payload",
      expectedSessionBindingHash: row.sessionBindingHash,
      phaseIndex,
    });
    if (evidenceVerification.disposition === "indeterminate") {
      throw new FixtureDeliverySubstrateError(
        `Fixture delivery evidence read failed: ${evidenceVerification.reason}`,
      );
    }
    if (evidenceVerification.disposition !== "verified" || evidenceVerification.evidenceHash !== row.evidenceHash) {
      const reason = "reason" in evidenceVerification ? evidenceVerification.reason : evidenceVerification.disposition;
      throw new FixtureDeliveryIntegrityError(`Fixture delivery evidence failed: ${reason}`);
    }
    const attestationRef = (deliveryValue["attestationRef"] as SettlementAttestationRef);
    const payloadCanonicalJson = canonicalize(deliveryValue["payload"]);
    if (sha256Hex(payloadCanonicalJson) !== row.payloadContentHash) {
      throw new FixtureDeliveryIntegrityError("Fixture cleartext payload hash does not match the delivery row");
    }
    return Object.freeze({
      agreementHash: row.agreementHash,
      assertionAddress: row.assertionAddress,
      assertionArtifactHash: row.assertionArtifactHash,
      attestationRef,
      createdAt: row.createdAt,
      deliverableContentHash: row.payloadContentHash,
      deliveryAddress: row.deliveryAddress,
      deliveryArtifactHash: row.deliveryArtifactHash,
      deliveryCanonicalJson: delivery.canonicalJson,
      evidenceAddress: row.evidenceAddress,
      evidenceArtifactHash: row.evidenceArtifactHash,
      evidenceCanonicalJson: evidence.canonicalJson,
      evidenceHash: row.evidenceHash,
      evidenceMode: "fixture",
      jobId: row.jobId,
      orchestrator: row.orchestrator,
      payloadCanonicalJson,
      payloadFormat: row.payloadFormat,
      paymentAmountCanonicalJson: row.paymentAmountCanonicalJson,
      phaseIndex,
      sessionBindingHash: row.sessionBindingHash,
      verifyResultAddress: row.verifyResultAddress,
      verifyResultArtifactHash: row.verifyResultArtifactHash,
    });
  }

  #assertDeliveryAuthority(
    expected: DeliveryAuthorityExpectation,
    existingDelivery: boolean,
  ): void {
    const commitment = (() => {
      try {
        return this.#commitments.get(
          expected.session.instanceId,
          expected.session.audience,
          expected.session.jobId,
        );
      } catch (error) {
        if (error instanceof FixtureCommitmentIntegrityError
          || error instanceof ArtifactIntegrityError) {
          throw new FixtureDeliveryIntegrityError("Fixture delivery commitment authority is corrupt", {
            cause: error,
          });
        }
        throw new FixtureDeliverySubstrateError("Fixture delivery commitment authority read failed", {
          cause: error,
        });
      }
    })();
    if (commitment === null || commitment.agreementHash !== expected.agreementHash) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery lacks its exact persisted agreement commitment");
    }
    let lifecycle: DeliveryAuthorityRow | null;
    try {
      lifecycle = this.#database.query<DeliveryAuthorityRow, {
        instanceId: string; audience: string; existingDelivery: number; jobId: string;
      }>(`
        SELECT agreement_artifact_hash AS agreementArtifactHash,
          commitment_artifact_hash AS commitmentArtifactHash,
          delivery_phase_index AS deliveryPhaseIndex,
          delivery_phase_kind AS deliveryPhaseKind, state
        FROM fixture_lifecycle_runs
        WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
          AND ($existingDelivery = 1 OR state = 'settle-pending')
      `).get({
        instanceId: expected.session.instanceId,
        audience: expected.session.audience,
        jobId: expected.session.jobId,
        existingDelivery: existingDelivery ? 1 : 0,
      });
    } catch (error) {
      throw new FixtureDeliverySubstrateError("Fixture delivery lifecycle authority read failed", {
        cause: error,
      });
    }
    const phaseIndex = lifecycle === null ? -1 : Number(lifecycle.deliveryPhaseIndex);
    const validExistingState = lifecycle !== null && (
      lifecycle.state === "settle-pending"
      || lifecycle.state === "substrate-failure-paused"
      || lifecycle.state === "failed-substrate"
      || lifecycle.state === "settle-completed"
      || lifecycle.state === "finalised"
    );
    if (lifecycle === null || !Number.isSafeInteger(phaseIndex)
      || (existingDelivery ? !validExistingState : lifecycle.state !== "settle-pending")
      || phaseIndex !== expected.phaseIndex
      || lifecycle.deliveryPhaseKind !== "deliver-attested-payload"
      || lifecycle.agreementArtifactHash !== commitment.agreementArtifactHash
      || lifecycle.commitmentArtifactHash !== commitment.commitmentArtifactHash) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery does not match the persisted lifecycle plan");
    }
    let agreementArtifact: ArtifactRecord | null;
    try {
      agreementArtifact = this.#artifacts.get(commitment.agreementArtifactHash);
    } catch (error) {
      if (error instanceof ArtifactIntegrityError) {
        throw new FixtureDeliveryIntegrityError("Fixture delivery committed agreement is corrupt", {
          cause: error,
        });
      }
      throw new FixtureDeliverySubstrateError("Fixture delivery committed agreement read failed", {
        cause: error,
      });
    }
    const agreement = agreementArtifact === null
      ? null : parseCanonical(agreementArtifact.canonicalJson);
    const terms = agreement?.["terms"];
    const agreedTerms = terms !== null && typeof terms === "object" && !Array.isArray(terms)
      ? terms as Record<string, unknown> : null;
    const agreedPrice = agreedTerms?.["price"];
    if (agreedPrice === undefined || canonicalize(agreedPrice) !== expected.paymentAmountCanonicalJson) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery payment amount does not match committed terms");
    }
    const deliverable = agreedTerms?.["deliverable"];
    const agreedDeliverable = deliverable !== null && typeof deliverable === "object"
      && !Array.isArray(deliverable) ? deliverable as Record<string, unknown> : null;
    const schemaUrl = agreedDeliverable?.["schemaUrl"];
    const selectedSelfSignedSpec = {
      kind: "attested-payload",
      payloadFormat: expected.payloadFormat,
      verificationMethod: { kind: "self-signed" },
      ...(schemaUrl === undefined ? {} : { schemaUrl }),
    };
    if (agreedDeliverable?.["deliverableType"] !== "attested-payload"
      || typeof agreedDeliverable["hash"] !== "string"
      || agreedDeliverable["hash"] !== sha256Hex(canonicalize(selectedSelfSignedSpec))) {
      throw new FixtureDeliveryIntegrityError(
        "Fixture delivery format or verification method does not match committed terms",
      );
    }
  }

  #readRow(instanceId: string, audience: string, jobId: string): DeliveryRow | null {
    return readDeliveryRow(this.#database, { kind: "session", instanceId, audience, jobId });
  }

  #readRowForDelivery(prepared: PreparedDelivery): DeliveryRow | null {
    try {
      return this.#readRow(prepared.session.instanceId, prepared.session.audience, prepared.session.jobId);
    } catch (error) {
      throw new FixtureDeliverySubstrateError("Fixture delivery persistence read failed", { cause: error });
    }
  }

  #readRowForSession(session: SessionRecord): DeliveryRow | null {
    try {
      return this.#readRow(session.instanceId, session.audience, session.jobId);
    } catch (error) {
      throw new FixtureDeliverySubstrateError("Fixture delivery restart row read failed", { cause: error });
    }
  }

  #requirePersistedSession(session: SessionRecord): SessionRecord {
    let persisted: SessionRecord | null;
    try {
      persisted = readPersistedSession(
        this.#database,
        session.instanceId,
        session.audience,
        session.jobId,
      );
    } catch (error) {
      throw new FixtureDeliverySubstrateError("Fixture delivery session read failed", { cause: error });
    }
    if (persisted === null || !sameSessionRecord(persisted, session)) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery session does not match persisted admission");
    }
    let jobSessionCount: bigint;
    try {
      jobSessionCount = this.#database.query<{ count: bigint }, { jobId: string }>(`
        SELECT count(*) AS count FROM sessions WHERE job_id = $jobId
      `).get({ jobId: session.jobId })?.count ?? 0n;
    } catch (error) {
      throw new FixtureDeliverySubstrateError("Fixture delivery global session binding read failed", { cause: error });
    }
    if (jobSessionCount !== 1n) {
      throw new FixtureDeliveryIntegrityError("Fixture delivery jobId is not globally unique");
    }
    return persisted;
  }

  #requiredArtifactForResolve(hash: string, kind: string): ArtifactRecord {
    try {
      return requiredArtifact(this.#artifacts, hash, kind);
    } catch (error) {
      if (error instanceof ArtifactIntegrityError) throw error;
      throw new FixtureDeliverySubstrateError(`Fixture delivery ${kind} read failed`, { cause: error });
    }
  }

  #assertAnchorForResolve(
    address: string,
    kind: string,
    contentHash: string,
    artifactHash: string,
  ): void {
    let anchor: ReturnType<typeof getAnchor>;
    try {
      anchor = getAnchor(this.#database, this.#artifacts, address);
    } catch (error) {
      if (error instanceof ArtifactIntegrityError) throw error;
      throw new FixtureDeliverySubstrateError(`Fixture delivery ${kind} anchor read failed`, { cause: error });
    }
    if (anchor === null || anchor.artifactKind !== kind
      || anchor.contentHash !== contentHash || anchor.artifact.contentHash !== artifactHash) {
      throw new FixtureDeliveryIntegrityError(`Fixture delivery ${kind} anchor binding is corrupt or absent`);
    }
  }
}

function sameSessionRecord(left: SessionRecord, right: SessionRecord): boolean {
  return left.instanceId === right.instanceId && left.audience === right.audience
    && left.jobId === right.jobId && left.evidenceMode === right.evidenceMode
    && left.requestHash === right.requestHash
    && left.admissionFingerprint === right.admissionFingerprint
    && left.status === right.status && left.version === right.version
    && left.createdAt === right.createdAt;
}

function isPermanentDeliveryFailure(error: unknown): boolean {
  return error instanceof FixtureDeliveryConflictError
    || error instanceof FixtureDeliveryIntegrityError
    || error instanceof ArtifactIntegrityError;
}

function prepare(input: FixtureAttestedDeliveryInput): PreparedDelivery {
  if (input === null || typeof input !== "object" || Array.isArray(input)
    || !HASH.test(input.agreementHash) || !Number.isSafeInteger(input.phaseIndex) || input.phaseIndex < 0
    || typeof input.payloadFormat !== "string" || input.payloadFormat.length === 0
    || input.payloadFormat.length > MAX_FORMAT_LENGTH || !Number.isSafeInteger(input.observedAt)
    || input.observedAt < 0 || typeof input.createdAt !== "string") {
    throw new TypeError("Fixture attested delivery input is invalid");
  }
  if (input.session.evidenceMode !== "fixture" || input.session.status !== "admitted") {
    throw new TypeError("Fixture attested delivery requires an admitted fixture session");
  }
  if (typeof input.payloadJson !== "string"
    || Buffer.byteLength(input.payloadJson, "utf8") > MAX_INLINE_DELIVERY_BYTES) {
    throw new TypeError(`Fixture inline payload exceeds ${MAX_INLINE_DELIVERY_BYTES} bytes`);
  }
  let payload: unknown;
  try {
    payload = JSON.parse(input.payloadJson) as unknown;
  } catch {
    throw new TypeError("Fixture delivery payload JSON is invalid");
  }
  const payloadCanonicalJson = canonicalize(payload);
  if (Buffer.byteLength(payloadCanonicalJson, "utf8") > MAX_INLINE_DELIVERY_BYTES) {
    throw new TypeError(`Fixture canonical payload exceeds ${MAX_INLINE_DELIVERY_BYTES} bytes`);
  }
  const paymentAmountCanonicalJson = canonicalize(input.paymentAmount);
  const paymentAmount = parseCanonical(paymentAmountCanonicalJson) as SettlementPriceTerm;
  const bindingHash = sessionBindingHash(input.session);
  validateTimestamp(input.createdAt);
  return Object.freeze({
    agreementHash: input.agreementHash,
    createdAt: input.createdAt,
    deliveryAddress: `dacs4:deliverable:${input.session.jobId}`,
    evidenceAddress: `dacs4:delivery-evidence:${input.session.jobId}:${input.phaseIndex}`,
    observedAt: input.observedAt,
    payload,
    payloadCanonicalJson,
    payloadFormat: input.payloadFormat,
    paymentAmount,
    paymentAmountCanonicalJson,
    phaseIndex: input.phaseIndex,
    session: input.session,
    sessionBindingHash: bindingHash,
  });
}

function deliveryExpectation(
  input: PreparedDelivery,
  deliverableContentHash: string,
  attestationRef: Readonly<Record<string, unknown>>,
): SettlementDeliveryExpectation {
  return Object.freeze({
    agreementHash: input.agreementHash,
    attestationRefCanonicalJson: canonicalize(attestationRef),
    deliverableAnchorCanonicalJson: canonicalize({ kind: "storage-program", locator: input.deliveryAddress }),
    deliverableContentHash,
    evidenceLogicalAddress: input.evidenceAddress,
    evidenceMode: "fixture",
    jobId: input.session.jobId,
    paymentAmountCanonicalJson: input.paymentAmountCanonicalJson,
    phase: "deliver-attested-payload",
    phaseIndex: input.phaseIndex,
    sessionBindingHash: input.sessionBindingHash,
  });
}

function rowExpectation(
  row: DeliveryRow,
  verifyResultContentHash: string,
): SettlementDeliveryExpectation {
  return Object.freeze({
    agreementHash: row.agreementHash,
    attestationRefCanonicalJson: canonicalize({
      anchor: { kind: "storage-program", locator: row.verifyResultAddress },
      contentHash: verifyResultContentHash,
      signer: row.orchestrator,
    }),
    deliverableAnchorCanonicalJson: canonicalize({ kind: "storage-program", locator: row.deliveryAddress }),
    deliverableContentHash: row.payloadContentHash,
    evidenceLogicalAddress: row.evidenceAddress,
    evidenceMode: "fixture",
    jobId: row.jobId,
    paymentAmountCanonicalJson: row.paymentAmountCanonicalJson,
    phase: "deliver-attested-payload",
    phaseIndex: Number(row.phaseIndex),
    sessionBindingHash: row.sessionBindingHash,
  });
}

function verifyDeliveryValue(
  logicalAddress: string,
  expected: SettlementDeliveryExpectation,
  value: Readonly<Record<string, unknown>>,
  authoritative: SettlementDeliveryExpectation,
  authoritativePayloadFormat: string,
): SettlementDeliveryCheckResult {
  const attestationRef = value["attestationRef"];
  const payload = value["payload"];
  if (logicalAddress !== `dacs4:deliverable:${expected.jobId}`
    || value["deliveryVersion"] !== "1" || value["jobId"] !== expected.jobId
    || value["phaseIndex"] !== expected.phaseIndex || value["agreementHash"] !== expected.agreementHash
    || value["payloadFormat"] !== authoritativePayloadFormat
    || value["sessionBindingHash"] !== expected.sessionBindingHash
    || value["deliverableContentHash"] !== expected.deliverableContentHash
    || sha256Hex(canonicalize(payload)) !== expected.deliverableContentHash
    || canonicalize(attestationRef) !== expected.attestationRefCanonicalJson
    || !sameExpectation(expected, authoritative)) {
    return Object.freeze({ status: "rejected", reason: "Fixture delivery does not bind the exact payload, attestation, agreement, phase, and session" });
  }
  return Object.freeze({ status: "verified", ...expected });
}

function sameExpectation(left: SettlementDeliveryExpectation, right: SettlementDeliveryExpectation): boolean {
  return canonicalize(left) === canonicalize(right);
}

function assertReplay(record: FixtureAttestedDeliveryRecord, input: PreparedDelivery): FixtureAttestedDeliveryRecord {
  if (record.agreementHash !== input.agreementHash || record.phaseIndex !== input.phaseIndex
    || record.sessionBindingHash !== input.sessionBindingHash || record.payloadFormat !== input.payloadFormat
    || record.payloadCanonicalJson !== input.payloadCanonicalJson
    || record.paymentAmountCanonicalJson !== input.paymentAmountCanonicalJson) {
    throw new FixtureDeliveryConflictError("Fixture delivery session already anchors different immutable content");
  }
  return record;
}

function readDeliveryRow(
  database: DacsDatabase,
  selector: { readonly kind: "address"; readonly logicalAddress: string }
    | { readonly kind: "session"; readonly instanceId: string; readonly audience: string; readonly jobId: string },
): DeliveryRow | null {
  return database.query<DeliveryRow, {
    audience: string; instanceId: string; jobId: string; logicalAddress: string; selector: string;
  }>(`SELECT instance_id AS instanceId, audience, job_id AS jobId,
    phase_index AS phaseIndex, agreement_hash AS agreementHash,
    session_binding_hash AS sessionBindingHash, orchestrator_claim AS orchestrator,
    payment_amount_json AS paymentAmountCanonicalJson, payload_format AS payloadFormat,
    payload_content_hash AS payloadContentHash, assertion_artifact_hash AS assertionArtifactHash,
    verify_result_artifact_hash AS verifyResultArtifactHash,
    delivery_artifact_hash AS deliveryArtifactHash, evidence_artifact_hash AS evidenceArtifactHash,
    evidence_hash AS evidenceHash, assertion_address AS assertionAddress,
    verify_result_address AS verifyResultAddress, delivery_address AS deliveryAddress,
    evidence_address AS evidenceAddress, created_at AS createdAt
    FROM fixture_deliveries
    WHERE ($selector = 'address' AND delivery_address = $logicalAddress)
      OR ($selector = 'session' AND instance_id = $instanceId
        AND audience = $audience AND job_id = $jobId)
  `).get(selector.kind === "address"
    ? { selector: "address", logicalAddress: selector.logicalAddress, instanceId: "", audience: "", jobId: "" }
    : {
      selector: "session",
      logicalAddress: "",
      instanceId: selector.instanceId,
      audience: selector.audience,
      jobId: selector.jobId,
    });
}

function requiredArtifact(store: ArtifactStore, hash: string, kind: string): ArtifactRecord {
  const artifact = store.get(hash);
  if (artifact === null || !artifact.kinds.includes(kind)) {
    throw new ArtifactIntegrityError(`Fixture delivery cannot resolve ${kind}`);
  }
  return artifact;
}

function assertArtifact(record: ArtifactRecord, hash: string, canonicalJson: string): void {
  if (record.contentHash !== hash || record.canonicalJson !== canonicalJson) {
    throw new ArtifactIntegrityError("Fixture delivery artifact persistence changed canonical bytes");
  }
}

function putAnchor(
  database: DacsDatabase,
  logicalAddress: string,
  artifactKind: string,
  contentHash: string,
  artifactContentHash: string,
  createdAt: string,
): void {
  const existing = database.query<{
    artifactKind: string; contentHash: string; artifactContentHash: string | null;
  }, { logicalAddress: string }>(`
    SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
      artifact_content_hash AS artifactContentHash
    FROM fixture_anchors WHERE logical_address = $logicalAddress
  `).get({ logicalAddress });
  if (existing !== null) {
    if (existing.artifactKind !== artifactKind || existing.contentHash !== contentHash
      || existing.artifactContentHash !== artifactContentHash) {
      throw new FixtureDeliveryConflictError("Fixture delivery anchor already contains different content");
    }
    return;
  }
  database.query<never, Record<string, string>>(`
    /* atomic-write: delivery.put-anchor */
    INSERT INTO fixture_anchors (
      logical_address, artifact_kind, content_hash, artifact_content_hash, created_at
    ) VALUES ($logicalAddress, $artifactKind, $contentHash, $artifactContentHash, $createdAt)
  `).run({ logicalAddress, artifactKind, contentHash, artifactContentHash, createdAt });
}

function getAnchor(
  database: DacsDatabase,
  artifacts: ArtifactStore,
  logicalAddress: string,
): { readonly artifact: ArtifactRecord; readonly artifactKind: string; readonly contentHash: string } | null {
  const row = database.query<{
    artifactKind: string; contentHash: string; artifactContentHash: string | null;
  }, { logicalAddress: string }>(`
    SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
      artifact_content_hash AS artifactContentHash
    FROM fixture_anchors WHERE logical_address = $logicalAddress
  `).get({ logicalAddress });
  if (row === null) return null;
  if (row.artifactContentHash === null) throw new ArtifactIntegrityError("Fixture anchor has no artifact binding");
  return Object.freeze({
    artifact: requiredArtifact(artifacts, row.artifactContentHash, row.artifactKind),
    artifactKind: row.artifactKind,
    contentHash: row.contentHash,
  });
}

function attestationAnchorRead(database: DacsDatabase, artifacts: ArtifactStore, address: string) {
  try {
    const anchor = getAnchor(database, artifacts, address);
    if (anchor === null) return { status: "absent" as const };
    return {
      status: "resolved" as const,
      artifactContentHash: anchor.artifact.contentHash,
      artifactKind: anchor.artifactKind,
      contentHash: anchor.contentHash,
    };
  } catch (error) {
    return { status: "indeterminate" as const, reason: message(error) };
  }
}

function signedContentHash(canonicalJson: string): string {
  const value = parseCanonical(canonicalJson);
  const unsigned = { ...value };
  delete unsigned["signature"];
  return sha256Hex(canonicalize(unsigned));
}

function parseCanonical(canonicalJson: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(canonicalJson) as unknown;
  } catch {
    throw new ArtifactIntegrityError("Fixture delivery artifact contains invalid JSON");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || canonicalize(value) !== canonicalJson) {
    throw new ArtifactIntegrityError("Fixture delivery artifact is not a canonical object");
  }
  return value as Record<string, unknown>;
}

function validateTimestamp(value: string): void {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError("Fixture delivery createdAt must be canonical ISO 8601");
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : "fixture delivery verification failed";
}

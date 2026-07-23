import type { EvidenceMode } from "../../core/evidence-mode.ts";
import { assertFixtureAuthority } from "../../core/evidence-mode.ts";
import { canonicalize, withoutFields } from "../../protocol/canonical-json.ts";
import { canonicalizeGenericClaimReference } from "../../protocol/claim-reference.ts";
import { isCanonicalPositiveDecimal } from "../../protocol/decimal.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import {
  verifyCanonicalSettlementEvidenceJson,
  type SettlementConsumptionCheckResult,
  type SettlementConsumptionExpectation,
  type SettlementEvidenceVerificationOptions,
  type SettlementFailureCheckResult,
  type SettlementFailureExpectation,
  type SettlementTransactionCheckResult,
  type SettlementTransactionExpectation,
} from "../../consumer/settlement-evidence-verifier.ts";
import {
  signSettlementEvidence,
  settlementEvidenceVerificationOptions,
  type SettlementEvidenceSigningOptions,
  type SignedSettlementEvidence,
  type UnsignedSettlementEvidence,
} from "../../producer/settlement-evidence.ts";
import type { ArtifactSigner } from "../../producer/fixture-ed25519.ts";
import { ArtifactIntegrityError, ArtifactStore } from "./artifact-store.ts";
import type { DacsDatabase } from "./database.ts";
import {
  readPersistedSessionByJobId,
  sessionBindingHash,
} from "./session-store.ts";

const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const TX_HASH = /^(?:0x)?([0-9a-fA-F]{64})$/;
const FIXTURE_SIGNER_CLAIM = /^key:[0-9a-f]{64}$/;
const DEMOS_ADDRESS = /^0x[0-9a-f]{64}$/;
const FIXTURE_DEM_ASSET_JSON = '{"decimals":9,"kind":"native-dem","symbol":"DEM"}';
const MAX_SETTLEMENT_EVIDENCE_BYTES = 1_048_576;

export class FixtureSettlementConflictError extends Error {
  override readonly name = "FixtureSettlementConflictError";
}

interface FixtureFailureEvidenceRow {
  readonly createdAt: string;
  readonly evidenceHash: string;
  readonly expectationJson: string;
  readonly jobId: string;
  readonly orchestrator: string;
  readonly phaseIndex: bigint;
  readonly phaseKind: string;
}

export class FixtureFailureEvidenceStore {
  readonly #artifacts: ArtifactStore;
  readonly #database: DacsDatabase;

  constructor(database: DacsDatabase, deploymentMode: EvidenceMode) {
    assertFixtureAuthority(deploymentMode, "fixture");
    this.#database = database;
    this.#artifacts = new ArtifactStore(database);
  }

  record(expectation: SettlementFailureExpectation, createdAt: string): SettlementFailureExpectation {
    const normalized = this.#validateAuthority(expectation);
    validateTimestamp(createdAt);
    const expectationJson = canonicalize(normalized);
    const persist = this.#database.transaction(() => {
      const existing = this.#read(normalized.evidenceHash);
      if (existing !== null) {
        if (existing.expectationJson !== expectationJson || existing.createdAt !== createdAt) {
          throw new FixtureSettlementConflictError("Fixture failure evidence replay differs from persisted authority");
        }
        return normalized;
      }
      this.#database.query<never, Record<string, string | number>>( `
        /* atomic-write: failure-evidence.put */
        INSERT INTO fixture_failure_evidence (
          evidence_hash, job_id, phase_index, phase_kind, orchestrator_claim,
          expectation_json, created_at
        ) VALUES (
          $evidenceHash, $jobId, $phaseIndex, $phase, $orchestrator,
          $expectationJson, $createdAt
        )
      `).run({ ...normalized, expectationJson, createdAt });
      return normalized;
    });
    return persist.immediate() as SettlementFailureExpectation;
  }

  persistSigned(
    unsigned: UnsignedSettlementEvidence,
    signer: ArtifactSigner,
    options: Omit<SettlementEvidenceSigningOptions, "failureStateCheck">,
    expectation: SettlementFailureExpectation,
    createdAt: string,
  ): SignedSettlementEvidence {
    if (unsigned.outcome !== "failure") {
      throw new FixtureSettlementConflictError("Fixture failure store accepts only failure evidence");
    }
    const persist = this.#database.transaction(() => {
      this.record(expectation, createdAt);
      const signed = signSettlementEvidence(unsigned, signer, {
        ...options,
        failureStateCheck: (expected) => this.verify(expected),
      });
      if (signed.evidenceHash !== expectation.evidenceHash) {
        throw new FixtureSettlementConflictError("Signed failure evidence hash differs from persisted authority");
      }
      const artifact = this.#artifacts.putWithinTransaction("dacs-4-evidence", signed.evidence, createdAt);
      if (artifact.contentHash !== signed.artifactContentHash || artifact.canonicalJson !== signed.canonicalJson) {
        throw new FixtureSettlementConflictError("Failure artifact changed during persistence");
      }
      const existing = this.#database.query<{
        artifactContentHash: string | null; artifactKind: string; contentHash: string;
      }, { logicalAddress: string }>(`
        SELECT artifact_content_hash AS artifactContentHash, artifact_kind AS artifactKind,
          content_hash AS contentHash FROM fixture_anchors WHERE logical_address = $logicalAddress
      `).get({ logicalAddress: signed.logicalAddress });
      if (existing === null) {
        this.#database.query<never, Record<string, string>>(`
          /* atomic-write: settlement-evidence.put-anchor */
          INSERT INTO fixture_anchors (
            logical_address, artifact_kind, content_hash, artifact_content_hash, created_at
          ) VALUES ($logicalAddress, 'dacs-4-evidence', $evidenceHash, $artifactContentHash, $createdAt)
        `).run({
          logicalAddress: signed.logicalAddress,
          evidenceHash: signed.evidenceHash,
          artifactContentHash: signed.artifactContentHash,
          createdAt,
        });
      } else if (existing.artifactKind !== "dacs-4-evidence"
        || existing.contentHash !== signed.evidenceHash
        || existing.artifactContentHash !== signed.artifactContentHash) {
        throw new FixtureSettlementConflictError("Failure logical address already anchors different content");
      }
      const verified = verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
        ...settlementEvidenceVerificationOptions(signer.signer, {
          ...options,
          failureStateCheck: (expected) => this.verify(expected),
        }),
        anchorContext: {
          mode: "post-anchor",
          read: (address) => address === signed.logicalAddress
            ? Object.freeze({
              status: "resolved" as const,
              artifactContentHash: signed.artifactContentHash,
              artifactKind: "dacs-4-evidence",
              evidenceHash: signed.evidenceHash,
              evidenceMode: "fixture" as const,
            })
            : Object.freeze({ status: "absent" as const }),
        },
      });
      if (verified.disposition !== "verified" || verified.evidenceHash !== signed.evidenceHash) {
        const reason = "reason" in verified ? verified.reason : "unexpected verifier disposition";
        throw new FixtureSettlementConflictError(`Persisted failure evidence did not verify: ${reason}`);
      }
      return signed;
    });
    return persist.immediate() as SignedSettlementEvidence;
  }

  verify(expected: SettlementFailureExpectation): SettlementFailureCheckResult {
    let normalized: SettlementFailureExpectation;
    try { normalized = normalizeFailureExpectation(expected); }
    catch (error) {
      return Object.freeze({ status: "rejected", reason: `Failure expectation is invalid: ${message(error)}` });
    }
    const row = this.#read(normalized.evidenceHash);
    if (row === null) {
      return Object.freeze({ status: "rejected", reason: "Fixture failure evidence is authoritatively absent" });
    }
    if (row.expectationJson !== canonicalize(normalized)
      || row.jobId !== normalized.jobId || Number(row.phaseIndex) !== normalized.phaseIndex
      || row.phaseKind !== normalized.phase || row.orchestrator !== normalized.orchestrator) {
      return Object.freeze({ status: "rejected", reason: "Fixture failure evidence differs from persisted authority" });
    }
    return Object.freeze({ status: "verified", ...normalized });
  }

  #read(evidenceHash: string): FixtureFailureEvidenceRow | null {
    return this.#database.query<FixtureFailureEvidenceRow, { evidenceHash: string }>(`
      SELECT evidence_hash AS evidenceHash, job_id AS jobId, phase_index AS phaseIndex,
        phase_kind AS phaseKind, orchestrator_claim AS orchestrator,
        expectation_json AS expectationJson, created_at AS createdAt
      FROM fixture_failure_evidence WHERE evidence_hash = $evidenceHash
    `).get({ evidenceHash });
  }

  #validateAuthority(expectation: SettlementFailureExpectation): SettlementFailureExpectation {
    const normalized = normalizeFailureExpectation(expectation);
    const session = readPersistedSessionByJobId(this.#database, normalized.jobId);
    if (session === null || session.status !== "admitted" || session.evidenceMode !== "fixture"
      || sessionBindingHash(session) !== normalized.sessionBindingHash) {
      throw new FixtureSettlementConflictError("Fixture failure evidence lacks admitted session authority");
    }
    const commitment = this.#database.query<{
      agreementArtifactHash: string; agreementHash: string;
    }, { jobId: string }>(`
      SELECT agreement_artifact_hash AS agreementArtifactHash, agreement_hash AS agreementHash
      FROM fixture_commitments WHERE job_id = $jobId
    `).get({ jobId: normalized.jobId });
    if (commitment === null || commitment.agreementHash !== normalized.agreementHash) {
      throw new FixtureSettlementConflictError("Fixture failure evidence lacks commitment authority");
    }
    const artifact = this.#artifacts.get(commitment.agreementArtifactHash);
    if (artifact === null) throw new FixtureSettlementConflictError("Fixture failure agreement is unavailable");
    const agreement = JSON.parse(artifact.canonicalJson) as Record<string, unknown>;
    const parties = agreement["parties"] as Record<string, unknown>[];
    const payer = parties.find((party) => party["role"] === "buyer")?.["primaryClaim"];
    const payee = parties.find((party) => party["role"] === "seller")?.["primaryClaim"];
    const terms = agreement["terms"] as Record<string, unknown>;
    const lifecycle = this.#database.query<{
      deliveryPhaseIndex: bigint; deliveryPhaseKind: string; paymentPlanJson: string; state: string;
    }, { jobId: string }>(`
      SELECT required_payment_phases_json AS paymentPlanJson,
        delivery_phase_index AS deliveryPhaseIndex, delivery_phase_kind AS deliveryPhaseKind, state
      FROM fixture_lifecycle_runs WHERE job_id = $jobId
    `).get({ jobId: normalized.jobId });
    if (payer !== normalized.payer || payee !== normalized.payee || lifecycle?.state !== "settle-pending") {
      throw new FixtureSettlementConflictError("Fixture failure evidence differs from lifecycle party authority");
    }
    const paymentPlan = JSON.parse(lifecycle.paymentPlanJson) as Record<string, unknown>[];
    const phaseBound = paymentPlan.some((phase) => phase["phaseIndex"] === normalized.phaseIndex
      && phase["phaseKind"] === normalized.phase)
      || (Number(lifecycle.deliveryPhaseIndex) === normalized.phaseIndex
        && lifecycle.deliveryPhaseKind === normalized.phase);
    if (!phaseBound) throw new FixtureSettlementConflictError("Fixture failure evidence phase is outside the pinned plan");
    if (normalized.paymentAmountCanonicalJson !== undefined
      && normalized.paymentAmountCanonicalJson !== canonicalize(terms["price"])) {
      throw new FixtureSettlementConflictError("Fixture failure payment amount differs from the agreement");
    }
    if (normalized.payeeAddress !== undefined) {
      const rail = terms["rail"] as Record<string, unknown>;
      const payout = (terms["payoutBindings"] as Record<string, unknown>[]).find((binding) =>
        binding["phaseIndex"] === normalized.phaseIndex && binding["railId"] === rail["railId"]);
      if (payout?.["payeeAddress"] !== normalized.payeeAddress) {
        throw new FixtureSettlementConflictError("Fixture failure payee address differs from the agreement");
      }
    }
    return normalized;
  }
}

export interface FixtureSettlementInput {
  readonly agreementHash: string;
  readonly blockNumber: number;
  readonly createdAt: string;
  readonly finalityObservedAt: number;
  readonly jobId: string;
  readonly orchestrator: string;
  readonly payee: string;
  readonly payeeAddress: string;
  readonly payer: string;
  readonly paymentAmount: Readonly<Record<string, unknown>>;
  readonly phaseIndex: number;
  readonly sessionBindingHash: string;
}

export interface FixtureSettlementRecord extends Omit<FixtureSettlementInput, "paymentAmount"> {
  readonly evidenceMode: "fixture";
  readonly paymentAmountCanonicalJson: string;
  readonly txHash: string;
}

export type PersistedFixtureSettlementAuthority = Readonly<Omit<
  SettlementEvidenceVerificationOptions,
  "anchorContext" | "evidenceMode" | "paymentTransactionCheck" | "settlementConsumptionCheck"
>>;

interface FixtureSettlementRow {
  readonly agreementHash: string;
  readonly blockNumber: bigint;
  readonly createdAt: string;
  readonly finalityObservedAt: bigint;
  readonly jobId: string;
  readonly orchestrator: string;
  readonly payee: string;
  readonly payeeAddress: string;
  readonly payer: string;
  readonly paymentAmountCanonicalJson: string;
  readonly phaseIndex: bigint;
  readonly sessionBindingHash: string;
  readonly txHash: string;
}

interface FixtureSettlementConsumptionRow {
  readonly canonicalSettlementTxIdsJson: string;
  readonly evidenceHash: string;
  readonly jobId: string;
  readonly observedAt: bigint;
  readonly phaseIndex: bigint;
  readonly settlementTxId: string;
  readonly txHash: string;
}

export class FixtureSettlementLedger {
  readonly #database: DacsDatabase;

  constructor(database: DacsDatabase, deploymentMode: EvidenceMode) {
    assertFixtureAuthority(deploymentMode, "fixture");
    this.#database = database;
  }

  record(input: FixtureSettlementInput): FixtureSettlementRecord {
    const normalized = normalizeInput(input);
    const persist = this.#database.transaction(() => {
      const persistedSession = readPersistedSessionByJobId(this.#database, normalized.jobId);
      if (persistedSession === null || persistedSession.evidenceMode !== "fixture"
        || persistedSession.status !== "admitted"
        || sessionBindingHash(persistedSession) !== normalized.sessionBindingHash) {
        throw new FixtureSettlementConflictError(
          "Fixture settlement does not match the persisted admitted session",
        );
      }
      const txHash = fixtureSettlementHash(normalized);
      const existing = this.getBySession(normalized.jobId, normalized.phaseIndex);
      if (existing !== null) return assertReplay(existing, txHash);
      this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: settlement-ledger.put */
        INSERT INTO fixture_settlements (
          tx_hash, job_id, phase_index, agreement_hash, orchestrator_claim, payer_claim, payee_claim,
          payee_address, payment_amount_json, block_number, finality_observed_at,
          session_binding_hash, created_at
        ) VALUES (
          $txHash, $jobId, $phaseIndex, $agreementHash, $orchestrator, $payer, $payee,
          $payeeAddress, $paymentAmountCanonicalJson, $blockNumber, $finalityObservedAt,
          $sessionBindingHash, $createdAt
        )
      `).run({ ...normalized, txHash });
      const stored = this.get(txHash);
      if (stored === null) throw new Error("Fixture settlement was not visible after persistence");
      return stored;
    });
    return persist.immediate() as FixtureSettlementRecord;
  }

  get(txHash: string): FixtureSettlementRecord | null {
    const normalizedHash = normalizeTxHash(txHash);
    const row = this.#database.query<FixtureSettlementRow, { txHash: string }>(`
      SELECT tx_hash AS txHash, job_id AS jobId, phase_index AS phaseIndex,
        agreement_hash AS agreementHash, orchestrator_claim AS orchestrator,
        payer_claim AS payer, payee_claim AS payee,
        payee_address AS payeeAddress,
        payment_amount_json AS paymentAmountCanonicalJson, block_number AS blockNumber,
        finality_observed_at AS finalityObservedAt,
        session_binding_hash AS sessionBindingHash, created_at AS createdAt
      FROM fixture_settlements
      WHERE tx_hash = $txHash
    `).get({ txHash: normalizedHash });
    return row === null ? null : fromRow(row);
  }

  verifyTransaction(
    txRef: Readonly<Record<string, unknown>>,
    expected: SettlementTransactionExpectation,
  ): SettlementTransactionCheckResult {
    if (txRef["kind"] !== "demos" || typeof txRef["txHash"] !== "string") {
      return Object.freeze({ status: "rejected", reason: "Fixture ledger accepts only Demos transaction references" });
    }
    let record: FixtureSettlementRecord | null;
    try {
      record = this.get(txRef["txHash"]);
    } catch (error) {
      return Object.freeze({
        status: "indeterminate",
        reason: `Fixture settlement ledger read failed: ${message(error)}`,
      });
    }
    if (record === null) {
      return Object.freeze({ status: "rejected", reason: "Fixture settlement transaction is authoritatively absent" });
    }
    if (txRef["blockNumber"] !== record.blockNumber) {
      return Object.freeze({ status: "rejected", reason: "Fixture settlement blockNumber does not match the ledger" });
    }
    if (normalizeTxHash(txRef["txHash"]) !== record.txHash) {
      return Object.freeze({ status: "rejected", reason: "Fixture settlement transaction hash does not match" });
    }
    return Object.freeze({
      status: "verified",
      agreementHash: record.agreementHash,
      assetCanonicalJson: FIXTURE_DEM_ASSET_JSON,
      canonicalTxRefJson: expected.canonicalTxRefJson,
      evidenceMode: record.evidenceMode,
      finalityModel: "bft-final",
      finalityObservedAt: record.finalityObservedAt,
      jobId: record.jobId,
      payee: record.payee,
      payeeAddress: record.payeeAddress,
      payer: record.payer,
      paymentAmountCanonicalJson: record.paymentAmountCanonicalJson,
      phaseIndex: record.phaseIndex,
      sessionBindingHash: record.sessionBindingHash,
      settlementTxId: `demos:${record.txHash}`,
    });
  }

  verifyConsumption(
    settlementTxIds: readonly string[],
    expected: SettlementConsumptionExpectation,
  ): SettlementConsumptionCheckResult {
    const validated = validateConsumptionInputs(this.#database, settlementTxIds, expected);
    if (validated !== null) return validated;
    for (const settlementTxId of settlementTxIds) {
      const existing = getConsumption(this.#database, settlementTxId);
      if (existing === null) {
        return Object.freeze({
          status: "rejected",
          reason: "Fixture settlement transaction has no authoritative consumption binding",
        });
      }
      const conflict = compareConsumption(existing, expected);
      if (conflict !== null) return conflict;
    }
    return Object.freeze({ status: "verified", ...expected });
  }

  #getRowBySession(jobId: string, phaseIndex: number): FixtureSettlementRow | null {
    return this.#database.query<FixtureSettlementRow, { jobId: string; phaseIndex: number }>(`
      SELECT tx_hash AS txHash, job_id AS jobId, phase_index AS phaseIndex,
        agreement_hash AS agreementHash, orchestrator_claim AS orchestrator,
        payer_claim AS payer, payee_claim AS payee,
        payee_address AS payeeAddress,
        payment_amount_json AS paymentAmountCanonicalJson, block_number AS blockNumber,
        finality_observed_at AS finalityObservedAt,
        session_binding_hash AS sessionBindingHash, created_at AS createdAt
      FROM fixture_settlements
      WHERE job_id = $jobId AND phase_index = $phaseIndex
    `).get({ jobId, phaseIndex });
  }

  private getBySession(jobId: string, phaseIndex: number): FixtureSettlementRecord | null {
    const row = this.#getRowBySession(jobId, phaseIndex);
    return row === null ? null : fromRow(row);
  }

}

export interface FixtureAnchorRecord {
  readonly artifactContentHash: string;
  readonly artifactKind: string;
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly createdAt: string;
  readonly evidenceMode: "fixture";
  readonly logicalAddress: string;
}

interface FixtureAnchorRow extends Omit<
  FixtureAnchorRecord,
  "artifactContentHash" | "canonicalJson" | "evidenceMode"
> {
  readonly artifactContentHash: string | null;
}

export class FixtureAnchorStore {
  readonly #artifacts: ArtifactStore;
  readonly #database: DacsDatabase;

  constructor(database: DacsDatabase, deploymentMode: EvidenceMode) {
    assertFixtureAuthority(deploymentMode, "fixture");
    this.#database = database;
    this.#artifacts = new ArtifactStore(database);
  }

  put(
    logicalAddress: string,
    artifactKind: string,
    contentHash: string,
    canonicalJson: string,
    createdAt: string,
  ): FixtureAnchorRecord {
    validateAnchor(logicalAddress, artifactKind, contentHash, createdAt);
    if (typeof canonicalJson !== "string"
      || Buffer.byteLength(canonicalJson, "utf8") > MAX_SETTLEMENT_EVIDENCE_BYTES) {
      throw new TypeError(`Fixture SettlementEvidence exceeds ${MAX_SETTLEMENT_EVIDENCE_BYTES} bytes`);
    }
    const artifactValue = parseCanonicalArtifact(canonicalJson);
    assertAnchoredArtifactHash(artifactKind, artifactValue, contentHash);
    const consumption = settlementConsumptionFromArtifact(logicalAddress, artifactValue, contentHash);
    verifyFixtureSettlementArtifact(
      this.#database,
      logicalAddress,
      canonicalJson,
      contentHash,
      consumption,
    );
    const persist = this.#database.transaction((): FixtureAnchorRecord => {
      const artifact = this.#artifacts.putWithinTransaction(artifactKind, artifactValue, createdAt);
      if (artifact.canonicalJson !== canonicalJson) {
        throw new ArtifactIntegrityError("Fixture anchor input was not canonical JSON");
      }
      const claimed = claimConsumption(this.#database, consumption.settlementTxIds, consumption.expected);
      if (claimed.status !== "verified") {
        throw new FixtureSettlementConflictError(claimed.reason);
      }
      const existing = this.get(logicalAddress);
      if (existing !== null) {
        return assertAnchorReplay(existing, artifactKind, contentHash, artifact.contentHash);
      }
      this.#database.query<never, Record<string, string>>(`
        /* atomic-write: anchor.put */
        INSERT INTO fixture_anchors (
          logical_address, artifact_kind, content_hash, artifact_content_hash, created_at
        ) VALUES (
          $logicalAddress, $artifactKind, $contentHash, $artifactContentHash, $createdAt
        )
      `).run({
        logicalAddress,
        artifactKind,
        contentHash,
        artifactContentHash: artifact.contentHash,
        createdAt,
      });
      const stored = this.get(logicalAddress);
      if (stored === null) throw new Error("Fixture anchor was not visible after persistence");
      return stored;
    });
    return persist.immediate() as FixtureAnchorRecord;
  }

  get(logicalAddress: string): FixtureAnchorRecord | null {
    if (typeof logicalAddress !== "string" || logicalAddress.length === 0) {
      throw new TypeError("Fixture anchor logical address is required");
    }
    const row = this.#database.query<FixtureAnchorRow, { logicalAddress: string }>(`
      SELECT logical_address AS logicalAddress, artifact_kind AS artifactKind,
        content_hash AS contentHash, artifact_content_hash AS artifactContentHash,
        created_at AS createdAt
      FROM fixture_anchors
      WHERE logical_address = $logicalAddress
    `).get({ logicalAddress });
    if (row === null) return null;
    if (row.artifactContentHash === null) {
      throw new ArtifactIntegrityError("Fixture anchor has no persisted artifact binding");
    }
    const artifactContentHash = row.artifactContentHash;
    const artifact = this.#artifacts.get(artifactContentHash);
    if (artifact === null || !artifact.kinds.includes(row.artifactKind)) {
      throw new ArtifactIntegrityError("Fixture anchor does not resolve to its typed artifact");
    }
    assertAnchoredArtifactHash(
      row.artifactKind,
      parseCanonicalArtifact(artifact.canonicalJson),
      row.contentHash,
    );
    return Object.freeze({
      ...row,
      artifactContentHash,
      canonicalJson: artifact.canonicalJson,
      evidenceMode: "fixture" as const,
    });
  }
}

function normalizeInput(input: FixtureSettlementInput): Omit<FixtureSettlementRecord, "evidenceMode" | "txHash"> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Fixture settlement input must be an object");
  }
  if (!ULID.test(input.jobId)) throw new TypeError("Fixture settlement jobId must be a canonical ULID");
  if (!Number.isSafeInteger(input.phaseIndex) || input.phaseIndex < 0) {
    throw new TypeError("Fixture settlement phaseIndex is invalid");
  }
  if (!HASH.test(input.agreementHash)) throw new TypeError("Fixture settlement agreementHash is invalid");
  if (!HASH.test(input.sessionBindingHash)) {
    throw new TypeError("Fixture settlement sessionBindingHash is invalid");
  }
  const orchestrator = canonicalizeGenericClaimReference(input.orchestrator).canonicalReference;
  const payer = canonicalizeGenericClaimReference(input.payer).canonicalReference;
  const payee = canonicalizeGenericClaimReference(input.payee).canonicalReference;
  if (orchestrator !== input.orchestrator || payer !== input.payer || payee !== input.payee) {
    throw new TypeError("Fixture settlement orchestrator and parties must be canonical ClaimReferences");
  }
  if (!FIXTURE_SIGNER_CLAIM.test(orchestrator)) {
    throw new TypeError("Fixture settlement orchestrator must be a resolvable Ed25519 key ClaimReference");
  }
  if (!DEMOS_ADDRESS.test(input.payeeAddress)) {
    throw new TypeError("Fixture settlement payeeAddress must be a canonical Demos address");
  }
  const paymentAmountCanonicalJson = canonicalize(input.paymentAmount);
  const paymentAmount = JSON.parse(paymentAmountCanonicalJson) as Record<string, unknown>;
  if (typeof paymentAmount["amount"] !== "string"
    || !isCanonicalPositiveDecimal(paymentAmount["amount"])
    || typeof paymentAmount["currency"] !== "string"
    || paymentAmount["currency"] !== "DEM"
    || (Object.hasOwn(paymentAmount, "unit")
      && (typeof paymentAmount["unit"] !== "string" || paymentAmount["unit"].length === 0))) {
    throw new TypeError("Fixture pay-dem settlement payment amount must be canonical DEM");
  }
  if (!Number.isSafeInteger(input.blockNumber) || input.blockNumber < 0
    || !Number.isSafeInteger(input.finalityObservedAt) || input.finalityObservedAt < 0) {
    throw new TypeError("Fixture settlement finality is invalid");
  }
  validateTimestamp(input.createdAt);
  return Object.freeze({
    agreementHash: input.agreementHash,
    blockNumber: input.blockNumber,
    createdAt: input.createdAt,
    finalityObservedAt: input.finalityObservedAt,
    jobId: input.jobId,
    orchestrator,
    payee,
    payeeAddress: input.payeeAddress,
    payer,
    paymentAmountCanonicalJson,
    phaseIndex: input.phaseIndex,
    sessionBindingHash: input.sessionBindingHash,
  });
}

function normalizeFailureExpectation(input: SettlementFailureExpectation): SettlementFailureExpectation {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Fixture failure expectation must be an object");
  }
  if (!ULID.test(input.jobId) || !HASH.test(input.agreementHash)
    || !HASH.test(input.evidenceHash) || !HASH.test(input.sessionBindingHash)
    || input.evidenceMode !== "fixture" || !Number.isSafeInteger(input.phaseIndex)
    || input.phaseIndex < 0 || typeof input.phase !== "string" || input.phase.length === 0
    || typeof input.reason !== "string" || input.reason.trim().length === 0) {
    throw new TypeError("Fixture failure expectation has invalid core fields");
  }
  const orchestrator = canonicalizeGenericClaimReference(input.orchestrator).canonicalReference;
  const payer = canonicalizeGenericClaimReference(input.payer).canonicalReference;
  const payee = canonicalizeGenericClaimReference(input.payee).canonicalReference;
  if (orchestrator !== input.orchestrator || payer !== input.payer || payee !== input.payee
    || !FIXTURE_SIGNER_CLAIM.test(orchestrator)) {
    throw new TypeError("Fixture failure expectation has invalid party authority");
  }
  const txRefs = JSON.parse(input.canonicalTxRefsJson) as unknown;
  if (!Array.isArray(txRefs) || canonicalize(txRefs) !== input.canonicalTxRefsJson) {
    throw new TypeError("Fixture failure transaction references are not canonical");
  }
  for (const field of ["paymentAmountCanonicalJson", "paymentFeeCanonicalJson"] as const) {
    const value = input[field];
    if (value !== undefined && canonicalize(JSON.parse(value) as unknown) !== value) {
      throw new TypeError(`Fixture failure ${field} is not canonical`);
    }
  }
  if (input.payeeAddress !== undefined
    && (input.payeeAddress.length === 0 || input.payeeAddress.length > 512 || /\s/.test(input.payeeAddress))) {
    throw new TypeError("Fixture failure payeeAddress is malformed");
  }
  if (input.phase === "pay-dem" && input.payeeAddress !== undefined
    && !DEMOS_ADDRESS.test(input.payeeAddress)) {
    throw new TypeError("Fixture pay-dem failure payeeAddress must be a canonical Demos address");
  }
  return Object.freeze({
    agreementHash: input.agreementHash,
    canonicalTxRefsJson: input.canonicalTxRefsJson,
    evidenceHash: input.evidenceHash,
    evidenceMode: "fixture",
    jobId: input.jobId,
    orchestrator,
    payee,
    ...(input.payeeAddress === undefined ? {} : { payeeAddress: input.payeeAddress }),
    payer,
    phase: input.phase,
    phaseIndex: input.phaseIndex,
    ...(input.paymentAmountCanonicalJson === undefined
      ? {} : { paymentAmountCanonicalJson: input.paymentAmountCanonicalJson }),
    ...(input.paymentFeeCanonicalJson === undefined
      ? {} : { paymentFeeCanonicalJson: input.paymentFeeCanonicalJson }),
    reason: input.reason.trim(),
    sessionBindingHash: input.sessionBindingHash,
  });
}

function fromRow(row: FixtureSettlementRow): FixtureSettlementRecord {
  const blockNumber = Number(row.blockNumber);
  const finalityObservedAt = Number(row.finalityObservedAt);
  const phaseIndex = Number(row.phaseIndex);
  if (!Number.isSafeInteger(blockNumber) || !Number.isSafeInteger(finalityObservedAt)
    || !Number.isSafeInteger(phaseIndex)) {
    throw new FixtureSettlementConflictError("Fixture settlement contains unsafe integers");
  }
  let paymentAmount: Readonly<Record<string, unknown>>;
  try {
    paymentAmount = JSON.parse(row.paymentAmountCanonicalJson) as Readonly<Record<string, unknown>>;
  } catch {
    throw new FixtureSettlementConflictError("Fixture settlement contains invalid payment JSON");
  }
  const normalized = normalizeInput({
    agreementHash: row.agreementHash,
    blockNumber,
    createdAt: row.createdAt,
    finalityObservedAt,
    jobId: row.jobId,
    orchestrator: row.orchestrator,
    payee: row.payee,
    payeeAddress: row.payeeAddress,
    payer: row.payer,
    paymentAmount,
    phaseIndex,
    sessionBindingHash: row.sessionBindingHash,
  });
  if (normalized.paymentAmountCanonicalJson !== row.paymentAmountCanonicalJson
    || !HASH.test(row.txHash)
    || fixtureSettlementHash(normalized) !== row.txHash) {
    throw new FixtureSettlementConflictError("Fixture settlement failed persisted-state integrity verification");
  }
  return Object.freeze({ ...normalized, evidenceMode: "fixture", txHash: row.txHash });
}

function fixtureSettlementHash(
  settlement: Omit<FixtureSettlementRecord, "evidenceMode" | "txHash">,
): string {
  return sha256Hex(canonicalize({
    fixtureSettlementVersion: "1",
    jobId: settlement.jobId,
    phaseIndex: settlement.phaseIndex,
    sessionBindingHash: settlement.sessionBindingHash,
    agreementHash: settlement.agreementHash,
    orchestrator: settlement.orchestrator,
    payer: settlement.payer,
    payee: settlement.payee,
    payeeAddress: settlement.payeeAddress,
    paymentAmount: JSON.parse(settlement.paymentAmountCanonicalJson),
    blockNumber: settlement.blockNumber,
    finalityObservedAt: settlement.finalityObservedAt,
  }));
}

function assertReplay(record: FixtureSettlementRecord, expectedHash: string): FixtureSettlementRecord {
  if (record.txHash !== expectedHash) {
    throw new FixtureSettlementConflictError("Fixture settlement session already has different immutable terms");
  }
  return record;
}

function normalizeTxHash(value: string): string {
  const match = TX_HASH.exec(value);
  if (match === null) throw new TypeError("Fixture settlement txHash must be exactly 32-byte hexadecimal");
  return match[1]!.toLowerCase();
}

function fixtureSettlementIdHash(settlementTxId: string): string {
  const match = /^demos:([0-9a-f]{64})$/.exec(settlementTxId);
  if (match === null) {
    throw new TypeError("Fixture settlement consumption accepts only canonical Demos transaction IDs");
  }
  return match[1]!;
}

function getSettlementByHash(database: DacsDatabase, txHash: string): FixtureSettlementRecord | null {
  const row = database.query<FixtureSettlementRow, { txHash: string }>(`
    SELECT tx_hash AS txHash, job_id AS jobId, phase_index AS phaseIndex,
      agreement_hash AS agreementHash, orchestrator_claim AS orchestrator,
      payer_claim AS payer, payee_claim AS payee,
      payee_address AS payeeAddress,
      payment_amount_json AS paymentAmountCanonicalJson, block_number AS blockNumber,
      finality_observed_at AS finalityObservedAt,
      session_binding_hash AS sessionBindingHash, created_at AS createdAt
    FROM fixture_settlements
    WHERE tx_hash = $txHash
  `).get({ txHash });
  if (row === null) return null;
  try { return fromRow(row); }
  catch (error) {
    if (error instanceof FixtureSettlementConflictError) throw error;
    throw new FixtureSettlementConflictError(`Fixture settlement row is invalid: ${message(error)}`);
  }
}

function getConsumption(
  database: DacsDatabase,
  settlementTxId: string,
): FixtureSettlementConsumptionRow | null {
  return database.query<FixtureSettlementConsumptionRow, { settlementTxId: string }>(`
    SELECT settlement_tx_id AS settlementTxId, tx_hash AS txHash,
      settlement_tx_ids_json AS canonicalSettlementTxIdsJson,
      evidence_hash AS evidenceHash, job_id AS jobId,
      phase_index AS phaseIndex, observed_at AS observedAt
    FROM fixture_settlement_consumptions
    WHERE settlement_tx_id = $settlementTxId
  `).get({ settlementTxId });
}

function validateConsumptionInputs(
  database: DacsDatabase,
  settlementTxIds: readonly string[],
  expected: SettlementConsumptionExpectation,
): SettlementConsumptionCheckResult | null {
  if (settlementTxIds.length === 0 || new Set(settlementTxIds).size !== settlementTxIds.length
    || settlementTxIds.some((id) => !/^demos:[0-9a-f]{64}$/.test(id))
    || canonicalize(settlementTxIds) !== expected.canonicalSettlementTxIdsJson
    || expected.evidenceMode !== "fixture" || !HASH.test(expected.evidenceHash)
    || !ULID.test(expected.jobId) || !Number.isSafeInteger(expected.phaseIndex)
    || expected.phaseIndex < 0 || !Number.isSafeInteger(expected.observedAt)
    || expected.observedAt < 0) {
    return Object.freeze({ status: "rejected", reason: "Fixture settlement consumption input is invalid" });
  }
  for (const settlementTxId of settlementTxIds) {
    const record = getSettlementByHash(database, fixtureSettlementIdHash(settlementTxId));
    if (record === null || record.jobId !== expected.jobId || record.phaseIndex !== expected.phaseIndex) {
      return Object.freeze({
        status: "rejected",
        reason: "Fixture settlement transaction is already bound to another job or phase",
      });
    }
  }
  return null;
}

function claimConsumption(
  database: DacsDatabase,
  settlementTxIds: readonly string[],
  expected: SettlementConsumptionExpectation,
): SettlementConsumptionCheckResult {
  const validated = validateConsumptionInputs(database, settlementTxIds, expected);
  if (validated !== null) return validated;
  const existingRows = settlementTxIds.map((settlementTxId) => ({
    settlementTxId,
    row: getConsumption(database, settlementTxId),
  }));
  for (const { row } of existingRows) {
    if (row === null) continue;
    const conflict = compareConsumption(row, expected);
    if (conflict !== null) return conflict;
  }
  for (const { settlementTxId, row } of existingRows) {
    if (row !== null) continue;
    database.query<never, Record<string, string | number>>(`
      /* atomic-write: settlement-consumption.put */
      INSERT INTO fixture_settlement_consumptions (
        settlement_tx_id, tx_hash, settlement_tx_ids_json, evidence_hash,
        job_id, phase_index, observed_at
      ) VALUES (
        $settlementTxId, $txHash, $canonicalSettlementTxIdsJson, $evidenceHash,
        $jobId, $phaseIndex, $observedAt
      )
    `).run({
      settlementTxId,
      txHash: fixtureSettlementIdHash(settlementTxId),
      canonicalSettlementTxIdsJson: expected.canonicalSettlementTxIdsJson,
      evidenceHash: expected.evidenceHash,
      jobId: expected.jobId,
      phaseIndex: expected.phaseIndex,
      observedAt: expected.observedAt,
    });
  }
  return Object.freeze({ status: "verified", ...expected });
}

function settlementConsumptionFromArtifact(
  logicalAddress: string,
  value: unknown,
  evidenceHash: string,
): Readonly<{
  settlementTxIds: readonly string[];
  expected: SettlementConsumptionExpectation;
}> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new FixtureSettlementConflictError("Fixture anchor requires a SettlementEvidence object");
  }
  const evidence = value as Record<string, unknown>;
  if (evidence["outcome"] !== "success" || typeof evidence["phase"] !== "string"
    || !evidence["phase"].startsWith("pay-")) {
    throw new FixtureSettlementConflictError("Fixture anchor currently supports only successful no-spend payment evidence");
  }
  if (evidence["phase"] !== "pay-dem") {
    throw new FixtureSettlementConflictError("Fixture settlement publication supports only no-spend pay-dem evidence");
  }
  const jobId = evidence["jobId"];
  const observedAt = evidence["observedAt"];
  const refs = evidence["paymentTxRefs"];
  const addressPrefix = typeof jobId === "string"
    ? `dacs4:payment:${jobId}:demos-native%3ADEM:` : "";
  const phaseIndexText = logicalAddress.startsWith(addressPrefix)
    ? logicalAddress.slice(addressPrefix.length) : "";
  if (!ULID.test(jobId as string) || !Number.isSafeInteger(observedAt) || (observedAt as number) < 0
    || !/^(?:0|[1-9][0-9]*)$/.test(phaseIndexText) || !Array.isArray(refs) || refs.length !== 1) {
    throw new FixtureSettlementConflictError("Fixture settlement artifact cannot derive its consumption binding");
  }
  const phaseIndex = Number(phaseIndexText);
  const ref = refs[0] as Record<string, unknown>;
  if (!Number.isSafeInteger(phaseIndex) || phaseIndex < 0 || ref?.["kind"] !== "demos"
    || typeof ref["txHash"] !== "string") {
    throw new FixtureSettlementConflictError("Fixture settlement artifact has an invalid transaction binding");
  }
  const settlementTxIds = Object.freeze([`demos:${normalizeTxHash(ref["txHash"])}`]);
  return Object.freeze({
    settlementTxIds,
    expected: Object.freeze({
      canonicalSettlementTxIdsJson: canonicalize(settlementTxIds),
      evidenceHash,
      evidenceMode: "fixture" as const,
      jobId: jobId as string,
      observedAt: observedAt as number,
      phaseIndex,
    }),
  });
}

function verifyFixtureSettlementArtifact(
  database: DacsDatabase,
  logicalAddress: string,
  canonicalJson: string,
  evidenceHash: string,
  consumption: Readonly<{
    settlementTxIds: readonly string[];
    expected: SettlementConsumptionExpectation;
  }>,
): void {
  const txHash = fixtureSettlementIdHash(consumption.settlementTxIds[0]!);
  const settlement = getSettlementByHash(database, txHash);
  if (settlement === null) {
    throw new FixtureSettlementConflictError("Fixture settlement transaction is authoritatively absent");
  }
  const ledger = new FixtureSettlementLedger(database, "fixture");
  const options: SettlementEvidenceVerificationOptions = {
    agreementHash: settlement.agreementHash,
    anchorContext: { mode: "pre-anchor" },
    evidenceMode: "fixture",
    expectedFinality: { model: "bft-final" },
    expectedJobId: settlement.jobId,
    expectedOrchestrator: settlement.orchestrator,
    expectedPayee: settlement.payee,
    expectedPayeeAddress: settlement.payeeAddress,
    expectedPayer: settlement.payer,
    expectedPaymentAmount: JSON.parse(settlement.paymentAmountCanonicalJson) as Record<string, unknown>,
    expectedPhase: "pay-dem",
    expectedSessionBindingHash: settlement.sessionBindingHash,
    phaseIndex: settlement.phaseIndex,
    railId: "demos-native:DEM",
    paymentTransactionCheck: (txRef, expected) => ledger.verifyTransaction(txRef, expected),
    pinnedRail: {
      assetCanonicalJson: FIXTURE_DEM_ASSET_JSON,
      assetCurrency: "DEM",
      networkKind: "demos",
      phaseHandler: "pay-dem",
      railId: "demos-native:DEM",
    },
  };
  const verification = verifyCanonicalSettlementEvidenceJson(canonicalJson, options);
  if (verification.disposition !== "provisionally-verified"
    || verification.evidenceHash !== evidenceHash
    || verification.logicalAddress !== logicalAddress) {
    const reason = "reason" in verification ? `: ${verification.reason}` : "";
    throw new FixtureSettlementConflictError(`Fixture anchor rejected unverified SettlementEvidence${reason}`);
  }
}

export function verifyPersistedFixtureSettlementEvidence(
  database: DacsDatabase,
  logicalAddress: string,
  canonicalJson: string,
  evidenceHash: string,
  authority: PersistedFixtureSettlementAuthority,
) {
  const artifact = parseCanonicalArtifact(canonicalJson);
  const consumption = settlementConsumptionFromArtifact(logicalAddress, artifact, evidenceHash);
  let settlement: FixtureSettlementRecord | null;
  try {
    settlement = getSettlementByHash(database, fixtureSettlementIdHash(consumption.settlementTxIds[0]!));
  } catch (error) {
    return error instanceof FixtureSettlementConflictError
      ? Object.freeze({
        disposition: "rejected" as const,
        reason: `Fixture settlement persisted state is invalid: ${message(error)}`,
      })
      : Object.freeze({
        disposition: "indeterminate" as const,
        reason: `Fixture settlement store is unavailable: ${message(error)}`,
      });
  }
  if (settlement === null) {
    return Object.freeze({ disposition: "rejected" as const, reason: "Fixture settlement transaction is authoritatively absent" });
  }
  if (settlement.agreementHash !== authority.agreementHash
    || settlement.jobId !== authority.expectedJobId
    || settlement.orchestrator !== authority.expectedOrchestrator
    || settlement.payee !== authority.expectedPayee
    || settlement.payeeAddress !== authority.expectedPayeeAddress
    || settlement.payer !== authority.expectedPayer
    || settlement.paymentAmountCanonicalJson !== canonicalize(authority.expectedPaymentAmount)
    || settlement.phaseIndex !== authority.phaseIndex
    || settlement.sessionBindingHash !== authority.expectedSessionBindingHash) {
    return Object.freeze({
      disposition: "rejected" as const,
      reason: "Fixture settlement row contradicts committed agreement or session authority",
    });
  }
  const ledger = new FixtureSettlementLedger(database, "fixture");
  return verifyCanonicalSettlementEvidenceJson(canonicalJson, {
    ...authority,
    anchorContext: {
      mode: "post-anchor",
      read: (address) => {
        const row = database.query<{
          artifactContentHash: string | null; artifactKind: string; contentHash: string;
        }, { address: string }>(`
          SELECT artifact_content_hash AS artifactContentHash, artifact_kind AS artifactKind,
            content_hash AS contentHash FROM fixture_anchors WHERE logical_address = $address
        `).get({ address });
        return row === null ? { status: "absent" as const }
          : row.artifactContentHash === null
            ? { status: "indeterminate" as const, reason: "Fixture anchor lacks an artifact binding" }
            : {
              status: "resolved" as const,
              artifactContentHash: row.artifactContentHash,
              artifactKind: row.artifactKind,
              evidenceHash: row.contentHash,
              evidenceMode: "fixture" as const,
            };
      },
    },
    evidenceMode: "fixture",
    paymentTransactionCheck: (txRef, expected) => ledger.verifyTransaction(txRef, expected),
    settlementConsumptionCheck: (ids, expected) => ledger.verifyConsumption(ids, expected),
  });
}

function compareConsumption(
  row: FixtureSettlementConsumptionRow,
  expected: SettlementConsumptionExpectation,
): SettlementConsumptionCheckResult | null {
  const phaseIndex = Number(row.phaseIndex);
  const observedAt = Number(row.observedAt);
  if (!Number.isSafeInteger(phaseIndex) || !Number.isSafeInteger(observedAt)
    || row.txHash !== fixtureSettlementIdHash(row.settlementTxId)) {
    throw new FixtureSettlementConflictError("Fixture settlement consumption state is corrupt");
  }
  if (row.canonicalSettlementTxIdsJson !== expected.canonicalSettlementTxIdsJson
    || row.evidenceHash !== expected.evidenceHash || row.jobId !== expected.jobId
    || phaseIndex !== expected.phaseIndex || observedAt !== expected.observedAt) {
    return Object.freeze({
      status: "rejected",
      reason: "Fixture settlement transaction is already consumed by different evidence",
    });
  }
  return null;
}

function validateAnchor(
  logicalAddress: string,
  artifactKind: string,
  contentHash: string,
  createdAt: string,
): void {
  if (typeof logicalAddress !== "string" || logicalAddress.length === 0) {
    throw new TypeError("Fixture anchor address and artifact kind are required");
  }
  if (artifactKind !== "dacs-4-evidence") {
    throw new TypeError("Fixture anchor accepts only dacs-4-evidence artifacts");
  }
  if (!HASH.test(contentHash)) throw new TypeError("Fixture anchor content hash is invalid");
  validateTimestamp(createdAt);
}

function parseCanonicalArtifact(canonicalJson: string): unknown {
  if (typeof canonicalJson !== "string" || canonicalJson.length === 0) {
    throw new TypeError("Fixture anchor canonical JSON is required");
  }
  let value: unknown;
  try {
    value = JSON.parse(canonicalJson);
  } catch {
    throw new TypeError("Fixture anchor canonical JSON is invalid");
  }
  if (canonicalize(value) !== canonicalJson) {
    throw new TypeError("Fixture anchor input must use canonical JSON bytes");
  }
  return value;
}

function assertAnchoredArtifactHash(
  artifactKind: string,
  value: unknown,
  expectedHash: string,
): void {
  if (artifactKind !== "dacs-4-evidence" || value === null || typeof value !== "object"
    || Array.isArray(value) || !Object.hasOwn(value, "signature")) {
    throw new ArtifactIntegrityError("Fixture anchor artifact cannot produce its semantic hash");
  }
  const derivedHash = sha256Hex(canonicalize(withoutFields(
    value as Readonly<Record<string, unknown>>,
    "signature",
  )));
  if (derivedHash !== expectedHash) {
    throw new ArtifactIntegrityError("Fixture anchor hash does not match the persisted artifact");
  }
}

function assertAnchorReplay(
  existing: FixtureAnchorRecord,
  artifactKind: string,
  contentHash: string,
  artifactContentHash: string,
): FixtureAnchorRecord {
  if (existing.artifactKind !== artifactKind
    || existing.contentHash !== contentHash
    || existing.artifactContentHash !== artifactContentHash) {
    throw new FixtureSettlementConflictError("Fixture logical address already anchors different content");
  }
  return existing;
}

function validateTimestamp(value: string): void {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError("Fixture settlement timestamp must be canonical ISO 8601");
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : "Fixture settlement verification failed";
}

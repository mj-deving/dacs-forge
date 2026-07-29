import type { AgreementVerificationOptions } from "../../consumer/agreement-verifier.ts";
import { verifyCanonicalAgreementJson } from "../../consumer/agreement-verifier.ts";
import {
  verifyCanonicalCommitmentJson,
  verifyCommittedAgreementCryptography,
} from "../../consumer/commitment-verifier.ts";
import { assertFixtureAuthority, type EvidenceMode } from "../../core/evidence-mode.ts";
import { canonicalize, deepFreezeJson, withoutFields } from "../../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../../protocol/claim-reference.ts";
import { integratedServiceLifecycleRequestHash } from "../../protocol/integrated-service-request.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import {
  commitmentLogicalAddress,
  signCommitmentRecord,
  type CommitmentRecord,
} from "../../producer/commitment.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
} from "../../producer/fixture-ed25519.ts";
import type { SessionRecord } from "./session-store.ts";
import { ArtifactIntegrityError, ArtifactStore } from "./artifact-store.ts";
import type { DacsDatabase } from "./database.ts";
import {
  FixtureAuthorityStore,
  FixtureAuthorityIntegrityError,
  type FixtureListingVerificationAuthority,
} from "./fixture-authority-store.ts";
import { FixtureVetIntegrityError, FixtureVetStore } from "./fixture-vet.ts";

export const MAX_FIXTURE_AGREEMENT_BYTES = 1_048_576;

export class FixtureCommitmentIntegrityError extends Error {
  override readonly name = "FixtureCommitmentIntegrityError";
}

export type AgreementCommitVerification = Omit<
  AgreementVerificationOptions,
  "expectedJobId" | "temporalContext"
> & {
  readonly listingAuthority: FixtureListingVerificationAuthority;
  readonly partyIdentityCanonicalJsons: readonly string[];
};

export interface TrustedHistoricalCommitment {
  readonly commitmentHash: string;
  readonly signer: string;
}

export interface FixtureCommitmentStoreOptions {
  readonly anchorTimeMs: () => number;
  readonly deploymentMode: EvidenceMode;
  readonly now: () => string;
  readonly preAnchorTimeMs: () => number;
  readonly signer: ArtifactSigner;
  readonly trustedHistoricalCommitments?: readonly TrustedHistoricalCommitment[];
}

export interface FixtureCommitmentInput {
  readonly agreementCanonicalJson: string;
  readonly serviceRequestHash?: string;
  readonly session: SessionRecord;
  readonly verification: AgreementCommitVerification;
}

export interface FixtureCommitmentRecord {
  readonly agreementArtifactHash: string;
  readonly agreementHash: string;
  readonly anchorTxHash: string;
  readonly canonicalJson: string;
  readonly commitment: Readonly<CommitmentRecord>;
  readonly commitmentArtifactHash: string;
  readonly commitmentHash: string;
  readonly committedAt: number;
  readonly createdAt: string;
  readonly evidenceMode: "fixture";
  readonly logicalAddress: string;
  readonly orchestratorClaim: string;
  readonly session: Readonly<Pick<SessionRecord, "instanceId" | "audience" | "jobId">>;
}

export type FixtureCommitmentResult =
  | { readonly disposition: "committed"; readonly record: FixtureCommitmentRecord }
  | {
    readonly disposition: "rejected";
    readonly stage: "recommit" | "pre-anchor" | "post-anchor";
    readonly reason: string;
    readonly record?: FixtureCommitmentRecord;
  };

interface CommitmentRow {
  readonly agreementArtifactHash: string;
  readonly agreementHash: string;
  readonly anchorTxHash: string;
  readonly audience: string;
  readonly commitmentArtifactHash: string;
  readonly commitmentHash: string;
  readonly committedAt: bigint;
  readonly createdAt: string;
  readonly instanceId: string;
  readonly jobId: string;
  readonly logicalAddress: string;
  readonly orchestratorClaim: string;
}

export class FixtureCommitmentStore {
  readonly #anchor: (input: AnchorInput) => FixtureCommitmentRecord;
  readonly #anchorTimeMs: () => number;
  readonly #artifacts: ArtifactStore;
  readonly #authorities: FixtureAuthorityStore;
  readonly #database: DacsDatabase;
  readonly #now: () => string;
  readonly #preAnchorTimeMs: () => number;
  readonly #signer: ArtifactSigner;
  readonly #trustedHistoricalCommitments: ReadonlySet<string>;
  readonly #vet: FixtureVetStore;

  constructor(database: DacsDatabase, options: FixtureCommitmentStoreOptions) {
    assertFixtureAuthority(options.deploymentMode, "fixture");
    assertFixtureSigningAuthority(options.signer, {
      deploymentMode: options.deploymentMode,
      requestMode: "fixture",
    });
    if (typeof options.anchorTimeMs !== "function" || typeof options.preAnchorTimeMs !== "function"
      || typeof options.now !== "function") {
      throw new TypeError("Fixture commitment store requires deterministic clocks");
    }
    this.#database = database;
    this.#artifacts = new ArtifactStore(database);
    this.#authorities = new FixtureAuthorityStore(database);
    this.#vet = new FixtureVetStore(database, options.deploymentMode);
    this.#signer = options.signer;
    const trustedHistoricalCommitments = new Set<string>();
    for (const trust of options.trustedHistoricalCommitments ?? []) {
      if (trust === null || typeof trust !== "object" || Array.isArray(trust)
        || typeof trust.signer !== "string" || typeof trust.commitmentHash !== "string"
        || !/^[0-9a-f]{64}$/.test(trust.commitmentHash)) {
        throw new TypeError("Historical commitment trust entry is invalid");
      }
      const canonical = canonicalizeClaimReference(trust.signer).canonicalReference;
      if (canonical !== trust.signer || !/^key:[0-9a-f]{64}$/.test(canonical)) {
        throw new TypeError("Historical commitment signer must be a canonical direct key");
      }
      trustedHistoricalCommitments.add(historicalTrustKey(canonical, trust.commitmentHash));
    }
    this.#trustedHistoricalCommitments = trustedHistoricalCommitments;
    this.#anchorTimeMs = options.anchorTimeMs;
    this.#preAnchorTimeMs = options.preAnchorTimeMs;
    this.#now = options.now;
    const anchor = database.transaction((input: AnchorInput) => this.#anchorTransaction(input));
    this.#anchor = (input) => anchor.immediate(input) as FixtureCommitmentRecord;
  }

  commit(input: FixtureCommitmentInput): FixtureCommitmentResult {
    const agreementCanonicalJson = snapshotCanonicalJson(
      input.agreementCanonicalJson,
      input.verification.maxArtifactBytes,
    );
    assertAdmittedFixtureSession(input.session);
    this.#assertPersistedAdmission(input.session, agreementCanonicalJson, input.serviceRequestHash);
    const existing = this.#getByLogicalAddress(commitmentLogicalAddress(input.session.jobId));
    if (existing !== null) {
      return Object.freeze({
        disposition: "rejected",
        stage: "recommit",
        reason: "Agreement commitment already exists for this jobId (CA-3)",
      });
    }
    const preAnchorTime = safeTimestamp(this.#preAnchorTimeMs(), "pre-anchor clock");
    const preAnchor = verifyCanonicalAgreementJson(agreementCanonicalJson, {
      ...input.verification,
      expectedJobId: input.session.jobId,
      temporalContext: { mode: "pre-anchor", nowMs: preAnchorTime },
    });
    if (preAnchor.disposition !== "provisionally-verified") {
      return Object.freeze({
        disposition: "rejected",
        stage: "pre-anchor",
        reason: preAnchor.disposition === "verified"
          ? "Agreement verifier returned an unexpected post-anchor verdict"
          : `${preAnchor.stage}: ${preAnchor.reason}`,
      });
    }
    const agreement = JSON.parse(agreementCanonicalJson) as Record<string, unknown>;
    try {
      this.#vet.assertAgreementAuthority(agreement, input.session, preAnchorTime);
    } catch (error) {
      if (error instanceof FixtureVetIntegrityError || error instanceof ArtifactIntegrityError) {
        return Object.freeze({
          disposition: "rejected",
          stage: "pre-anchor",
          reason: error.message,
        });
      }
      throw error;
    }
    const committedAt = safeTimestamp(this.#anchorTimeMs(), "fixture anchor clock");
    if (committedAt < preAnchorTime) {
      throw new FixtureCommitmentIntegrityError("Fixture anchor clock regressed before commitment");
    }
    const signatures = agreement["signatures"] as Record<string, unknown>[];
    const signed = signCommitmentRecord({
      dacsVersion: "1",
      jobId: input.session.jobId,
      agreementHash: preAnchor.agreementHash,
      listingRef: agreement["listingRef"] as {
        listingId: string; version: number; contentHash: string;
      },
      parties: signatures.map((signature) => signature["party"] as string),
      pattern: agreement["derivedFromPattern"] as "fixed-price" | "rfq" | "sealed-envelope",
      committedAt,
    }, this.#signer, {
      deploymentMode: "fixture",
      requestMode: input.session.evidenceMode,
    });
    const commitmentVerification = verifyCanonicalCommitmentJson(signed.canonicalJson, {
      expectedAgreementHash: preAnchor.agreementHash,
      expectedJobId: input.session.jobId,
      expectedOrchestrator: this.#signer.signer,
    });
    if (commitmentVerification.disposition !== "verified"
      || commitmentVerification.commitmentHash !== signed.commitmentHash) {
      throw new FixtureCommitmentIntegrityError("Produced commitment failed independent verification");
    }
    let record: FixtureCommitmentRecord;
    try {
      record = this.#anchor({
        agreement,
        agreementCanonicalJson,
        agreementHash: preAnchor.agreementHash,
        committedAt,
        session: input.session,
        signed,
        verification: input.verification,
      });
    } catch (error) {
      const raced = this.#getByLogicalAddress(commitmentLogicalAddress(input.session.jobId));
      if (raced !== null) {
        return Object.freeze({
          disposition: "rejected",
          stage: "recommit",
          reason: "Agreement commitment already exists for this jobId (CA-3)",
        });
      }
      if (error instanceof FixtureAuthorityIntegrityError) {
        return Object.freeze({
          disposition: "rejected",
          stage: "pre-anchor",
          reason: error.message,
        });
      }
      throw error;
    }
    const postAnchor = verifyCanonicalAgreementJson(agreementCanonicalJson, {
      ...input.verification,
      expectedJobId: input.session.jobId,
      temporalContext: {
        mode: "post-anchor",
        committedAt: record.committedAt,
        agreementHash: record.agreementHash,
      },
    });
    if (postAnchor.disposition !== "verified") {
      return Object.freeze({
        disposition: "rejected",
        stage: "post-anchor",
        reason: postAnchor.disposition === "provisionally-verified"
          ? "Agreement verifier returned an unexpected pre-anchor verdict"
          : `${postAnchor.stage}: ${postAnchor.reason}`,
        record,
      });
    }
    return Object.freeze({ disposition: "committed", record });
  }

  get(instanceId: string, audience: string, jobId: string): FixtureCommitmentRecord | null {
    const row = this.#database.query<CommitmentRow, {
      instanceId: string; audience: string; jobId: string;
    }>(`
      SELECT instance_id AS instanceId, audience, job_id AS jobId,
        logical_address AS logicalAddress, agreement_hash AS agreementHash,
        commitment_hash AS commitmentHash, agreement_artifact_hash AS agreementArtifactHash,
        commitment_artifact_hash AS commitmentArtifactHash, anchor_tx_hash AS anchorTxHash,
        committed_at AS committedAt, created_at AS createdAt,
        orchestrator_claim AS orchestratorClaim
      FROM fixture_commitments
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
    `).get({ instanceId, audience, jobId });
    return row === null ? null : this.#fromRow(row);
  }

  assertVetAuthority(record: FixtureCommitmentRecord): void {
    const persisted = this.get(record.session.instanceId, record.session.audience, record.session.jobId);
    if (persisted === null || persisted.commitmentArtifactHash !== record.commitmentArtifactHash
      || persisted.agreementArtifactHash !== record.agreementArtifactHash) {
      throw new FixtureCommitmentIntegrityError("Commitment Vet recheck lacks exact persisted authority");
    }
    const agreement = this.#artifacts.get(record.agreementArtifactHash);
    if (agreement === null || agreement.contentHash !== record.agreementArtifactHash
      || (!agreement.kinds.includes("dacs-3-agreement")
        && !agreement.kinds.includes("dacs-3-payee-bound-agreement"))) {
      throw new FixtureCommitmentIntegrityError("Commitment Vet recheck cannot resolve its Agreement");
    }
    this.#vet.assertAgreementAuthority(
      JSON.parse(agreement.canonicalJson) as Record<string, unknown>,
      record.session,
      record.committedAt,
    );
  }

  #getByLogicalAddress(logicalAddress: string): FixtureCommitmentRecord | null {
    const row = this.#database.query<CommitmentRow, { logicalAddress: string }>(`
      SELECT instance_id AS instanceId, audience, job_id AS jobId,
        logical_address AS logicalAddress, agreement_hash AS agreementHash,
        commitment_hash AS commitmentHash, agreement_artifact_hash AS agreementArtifactHash,
        commitment_artifact_hash AS commitmentArtifactHash, anchor_tx_hash AS anchorTxHash,
        committed_at AS committedAt, created_at AS createdAt,
        orchestrator_claim AS orchestratorClaim
      FROM fixture_commitments WHERE logical_address = $logicalAddress
    `).get({ logicalAddress });
    return row === null ? null : this.#fromRow(row);
  }

  #assertPersistedAdmission(
    session: SessionRecord,
    agreementCanonicalJson: string,
    serviceRequestHash?: string,
  ): void {
    const persisted = this.#database.query<{
      evidenceMode: string; requestHash: string; status: string;
    }, { instanceId: string; audience: string; jobId: string }>(`
      SELECT s.evidence_mode AS evidenceMode, s.status,
        c.request_hash AS requestHash
      FROM sessions AS s
      JOIN admission_consumptions AS c
        ON c.instance_id = s.instance_id
        AND c.audience = s.audience
        AND c.session_id = s.job_id
      WHERE s.instance_id = $instanceId AND s.audience = $audience AND s.job_id = $jobId
    `).get({ instanceId: session.instanceId, audience: session.audience, jobId: session.jobId });
    if (persisted === null || persisted.status !== "admitted" || persisted.evidenceMode !== "fixture"
      || persisted.requestHash !== session.requestHash
      || !fixtureCommitmentRequestMatches(
        session.requestHash,
        agreementCanonicalJson,
        serviceRequestHash,
      )) {
      throw new FixtureCommitmentIntegrityError(
        "Agreement commitment does not match the persisted admitted request binding",
      );
    }
  }

  #anchorTransaction(input: AnchorInput): FixtureCommitmentRecord {
    const existing = this.get(input.session.instanceId, input.session.audience, input.session.jobId);
    if (existing !== null) throw new FixtureCommitmentIntegrityError("Commitment already exists");
    const createdAt = this.#now();
    this.#authorities.putListingWithinTransaction(
      input.session.jobId,
      input.verification.listingCanonicalJson,
      createdAt,
      input.verification.listingAuthority,
    );
    const identities = input.verification.partyIdentityCanonicalJsons.map((canonicalJson) =>
      this.#authorities.putCommitmentIdentityWithinTransaction(canonicalJson, createdAt));
    for (const party of input.agreement["parties"] as Record<string, unknown>[]) {
      if (!identities.some((identity) => identity.bundleHash === party["bundleHash"]
        && identity.primaryClaim === party["primaryClaim"])) {
        throw new FixtureCommitmentIntegrityError(
          "Agreement party lacks an exact verified IdentityBundle authority",
        );
      }
    }
    const agreementKind = input.agreement["payeeBoundAgreementVersion"] === "1"
      ? "dacs-3-payee-bound-agreement" : "dacs-3-agreement";
    const agreementArtifact = this.#artifacts.putWithinTransaction(agreementKind, input.agreement, createdAt);
    if (agreementArtifact.canonicalJson !== input.agreementCanonicalJson) {
      throw new ArtifactIntegrityError("Agreement commitment input was not canonical JSON");
    }
    const commitmentArtifact = this.#artifacts.putWithinTransaction(
      "dacs-3-commitment",
      input.signed.commitment,
      createdAt,
    );
    const logicalAddress = commitmentLogicalAddress(input.session.jobId);
    const anchorTxHash = sha256Hex(canonicalize({
      fixtureAnchorVersion: "1",
      logicalAddress,
      commitmentHash: input.signed.commitmentHash,
      committedAt: input.committedAt,
    }));
    this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: commitment.put */
      INSERT INTO fixture_commitments (
        instance_id, audience, job_id, logical_address, agreement_hash, commitment_hash,
        orchestrator_claim, agreement_artifact_hash, commitment_artifact_hash,
        anchor_tx_hash, committed_at, created_at
      ) VALUES (
        $instanceId, $audience, $jobId, $logicalAddress, $agreementHash, $commitmentHash,
        $orchestratorClaim, $agreementArtifactHash, $commitmentArtifactHash,
        $anchorTxHash, $committedAt, $createdAt
      )
    `).run({
      instanceId: input.session.instanceId,
      audience: input.session.audience,
      jobId: input.session.jobId,
      logicalAddress,
      agreementHash: input.agreementHash,
      commitmentHash: input.signed.commitmentHash,
      orchestratorClaim: this.#signer.signer,
      agreementArtifactHash: agreementArtifact.contentHash,
      commitmentArtifactHash: commitmentArtifact.contentHash,
      anchorTxHash,
      committedAt: input.committedAt,
      createdAt,
    });
    const stored = this.get(input.session.instanceId, input.session.audience, input.session.jobId);
    if (stored === null) throw new FixtureCommitmentIntegrityError("Commitment was not visible after persistence");
    return stored;
  }

  #fromRow(row: CommitmentRow): FixtureCommitmentRecord {
    const committedAt = Number(row.committedAt);
    safeTimestamp(committedAt, "persisted commitment timestamp");
    if (row.logicalAddress !== commitmentLogicalAddress(row.jobId)) {
      throw new FixtureCommitmentIntegrityError("Persisted commitment logical address is invalid");
    }
    const agreementArtifact = this.#artifacts.get(row.agreementArtifactHash);
    const commitmentArtifact = this.#artifacts.get(row.commitmentArtifactHash);
    if (agreementArtifact === null || commitmentArtifact === null
      || !commitmentArtifact.kinds.includes("dacs-3-commitment")) {
      throw new FixtureCommitmentIntegrityError("Persisted commitment artifacts are missing or mistyped");
    }
    const agreement = JSON.parse(agreementArtifact.canonicalJson) as Record<string, unknown>;
    const expectedAgreementKind = agreement["payeeBoundAgreementVersion"] === "1"
      ? "dacs-3-payee-bound-agreement" : "dacs-3-agreement";
    const agreementCryptography = verifyCommittedAgreementCryptography(
      agreementArtifact.canonicalJson,
      row.agreementHash,
      { maxArtifactBytes: MAX_FIXTURE_AGREEMENT_BYTES },
    );
    if (!agreementArtifact.kinds.includes(expectedAgreementKind)
      || sha256Hex(canonicalize(withoutFields(agreement, "signatures"))) !== row.agreementHash
      || agreementCryptography.disposition !== "verified") {
      throw new FixtureCommitmentIntegrityError("Persisted agreement commitment binding is corrupt");
    }
    const claimedOrchestrator = commitmentSigner(commitmentArtifact.canonicalJson);
    const persistedAuthorityAccepted = row.orchestratorClaim === this.#signer.signer
      || this.#trustedHistoricalCommitments.has(historicalTrustKey(
        row.orchestratorClaim,
        row.commitmentHash,
      ));
    if (claimedOrchestrator !== row.orchestratorClaim || !persistedAuthorityAccepted) {
      throw new FixtureCommitmentIntegrityError("Persisted commitment orchestrator authority is corrupt");
    }
    const verification = verifyCanonicalCommitmentJson(commitmentArtifact.canonicalJson, {
      expectedAgreementHash: row.agreementHash,
      expectedJobId: row.jobId,
      expectedOrchestrator: row.orchestratorClaim,
    });
    if (verification.disposition !== "verified" || verification.commitmentHash !== row.commitmentHash
      || verification.committedAt !== committedAt) {
      throw new FixtureCommitmentIntegrityError("Persisted commitment failed independent verification");
    }
    if (canonicalize(verification.disposition === "verified"
      ? (JSON.parse(commitmentArtifact.canonicalJson) as Record<string, unknown>)["parties"]
      : []) !== canonicalize(agreementCryptography.signingParties)) {
      throw new FixtureCommitmentIntegrityError("Commitment signing parties do not match the agreement signatures");
    }
    const expectedAnchorTxHash = sha256Hex(canonicalize({
      fixtureAnchorVersion: "1",
      logicalAddress: row.logicalAddress,
      commitmentHash: row.commitmentHash,
      committedAt,
    }));
    if (expectedAnchorTxHash !== row.anchorTxHash) {
      throw new FixtureCommitmentIntegrityError("Persisted commitment anchor reference is corrupt");
    }
    return Object.freeze({
      agreementArtifactHash: row.agreementArtifactHash,
      agreementHash: row.agreementHash,
      anchorTxHash: row.anchorTxHash,
      canonicalJson: commitmentArtifact.canonicalJson,
      commitment: deepFreezeJson(JSON.parse(commitmentArtifact.canonicalJson) as CommitmentRecord),
      commitmentArtifactHash: row.commitmentArtifactHash,
      commitmentHash: row.commitmentHash,
      committedAt,
      createdAt: row.createdAt,
      evidenceMode: "fixture",
      logicalAddress: row.logicalAddress,
      orchestratorClaim: row.orchestratorClaim,
      session: Object.freeze({ instanceId: row.instanceId, audience: row.audience, jobId: row.jobId }),
    });
  }
}

function historicalTrustKey(signer: string, commitmentHash: string): string {
  return `${signer}\0${commitmentHash}`;
}

function commitmentSigner(canonicalJson: string): string | null {
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const signature = (parsed as Record<string, unknown>)["signature"];
    if (signature === null || typeof signature !== "object" || Array.isArray(signature)) return null;
    const signer = (signature as Record<string, unknown>)["signer"];
    return typeof signer === "string" ? signer : null;
  } catch {
    return null;
  }
}

interface AnchorInput {
  readonly agreement: Record<string, unknown>;
  readonly agreementCanonicalJson: string;
  readonly agreementHash: string;
  readonly committedAt: number;
  readonly session: SessionRecord;
  readonly signed: ReturnType<typeof signCommitmentRecord>;
  readonly verification: AgreementCommitVerification;
}

function assertAdmittedFixtureSession(session: SessionRecord): void {
  if (session.status !== "admitted") throw new TypeError("Agreement commitment requires an admitted session");
  assertFixtureAuthority("fixture", session.evidenceMode);
}

function snapshotCanonicalJson(value: string, configuredMaxBytes?: number): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("Agreement canonical JSON is required");
  }
  const maxBytes = configuredMaxBytes ?? MAX_FIXTURE_AGREEMENT_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_FIXTURE_AGREEMENT_BYTES) {
    throw new TypeError(
      `Agreement artifact byte limit must be between 1 and ${MAX_FIXTURE_AGREEMENT_BYTES} bytes`,
    );
  }
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new TypeError(`Agreement exceeds implementation input limit of ${maxBytes} bytes`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new TypeError(`Agreement is not JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (canonicalize(parsed) !== value) throw new TypeError("Agreement is not canonical JSON");
  return value;
}

function safeTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} returned an invalid timestamp`);
  return value;
}

export function fixtureCommitmentRequestHash(agreementCanonicalJson: string): string {
  const canonical = snapshotCanonicalJson(agreementCanonicalJson);
  const agreement = JSON.parse(canonical) as Record<string, unknown>;
  const parties = agreement["parties"];
  if (!Array.isArray(parties)) throw new TypeError("Agreement parties are invalid");
  const requestScope = {
    ...withoutFields(agreement, "signatures"),
    parties: parties.map((value) => {
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError("Agreement party is invalid");
      }
      return withoutFields(value as Record<string, unknown>, "vetRecordRef");
    }),
  };
  return sha256Hex(canonicalize({
    fixtureLifecycleRequestVersion: "2",
    requestScope,
  }));
}

export function fixtureCommitmentRequestMatches(
  requestHash: string,
  agreementCanonicalJson: string,
  serviceRequestHash?: string,
): boolean {
  if (serviceRequestHash !== undefined) {
    return requestHash === integratedServiceLifecycleRequestHash(
      fixtureCommitmentRequestHash(agreementCanonicalJson),
      serviceRequestHash,
    );
  }
  return requestHash === fixtureCommitmentRequestHash(agreementCanonicalJson)
    || requestHash === legacyFixtureCommitmentRequestHash(agreementCanonicalJson);
}

export function legacyFixtureCommitmentRequestHash(agreementCanonicalJson: string): string {
  const canonical = snapshotCanonicalJson(agreementCanonicalJson);
  return sha256Hex(canonicalize({
    fixtureLifecycleRequestVersion: "1",
    agreementArtifactHash: sha256Hex(canonical),
  }));
}

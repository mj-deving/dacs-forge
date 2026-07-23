import type { DacsDatabase } from "./database.ts";
import { canonicalize } from "../../protocol/canonical-json.ts";
import { sha256Hex } from "../../protocol/hash.ts";

export class ArtifactIntegrityError extends Error {
  override readonly name = "ArtifactIntegrityError";
}

export class ServiceRunConflictError extends Error {
  override readonly name = "ServiceRunConflictError";
}

export interface ArtifactRecord {
  readonly contentHash: string;
  readonly kinds: readonly string[];
  readonly canonicalJson: string;
  readonly byteLength: bigint;
  readonly createdAt: string;
}

export interface ArtifactInput {
  readonly kind: string;
  readonly value: unknown;
}

export interface ServiceRunBinding {
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly requestHash: string;
  readonly contractHash: string;
}

export interface CompletedServiceRun extends ServiceRunBinding {
  readonly status: "completed";
  readonly seller: string;
  readonly outputContentHash: string;
  readonly receiptContentHash: string;
  readonly createdAt: string;
  readonly completedAt: string;
}

export interface RunningServiceRun extends ServiceRunBinding {
  readonly status: "running";
  readonly seller: string;
  readonly claimFingerprint: string;
  readonly createdAt: string;
}

export interface StaleServiceRunRecovery {
  readonly expectedClaimFingerprint: string;
  readonly expectedCreatedAt: string;
  readonly observedAt: string;
  readonly minimumAgeMs: number;
  readonly executorIsolationConfirmed: true;
}

export interface NewServiceRunClaim {
  readonly claimToken: string;
  readonly createdAt: string;
}

export type ServiceRunClaimResult =
  | ({ readonly disposition: "claimed" } & NewServiceRunClaim)
  | { readonly disposition: "in-progress"; readonly run: RunningServiceRun }
  | { readonly disposition: "replayed"; readonly run: CompletedServiceRun };

interface ServiceRunRow extends ServiceRunBinding {
  readonly seller: string;
  readonly status: "running" | "completed";
  readonly claimToken: string;
  readonly outputContentHash: string | null;
  readonly receiptContentHash: string | null;
  readonly createdAt: string;
  readonly completedAt: string | null;
}

interface ArtifactRow extends Omit<ArtifactRecord, "kinds"> {}

export class ArtifactStore {
  private readonly database: DacsDatabase;
  readonly #putBatch: (
    entries: readonly ArtifactInput[],
    createdAt: string,
  ) => readonly ArtifactRecord[];
  readonly #claimServiceRun: (
    binding: ServiceRunBinding,
    seller: string,
    createClaim: () => NewServiceRunClaim,
  ) => ServiceRunClaimResult;
  readonly #completeServiceRun: (
    binding: ServiceRunBinding,
    claimToken: string,
    output: ArtifactInput,
    receipt: ArtifactInput,
    completedAt: string,
  ) => CompletedServiceRun;
  readonly #releaseServiceRun: (binding: ServiceRunBinding, claimToken: string) => boolean;
  readonly #recoverStaleServiceRun: (
    binding: ServiceRunBinding,
    recovery: StaleServiceRunRecovery,
  ) => boolean;

  constructor(database: DacsDatabase) {
    this.database = database;
    const transaction = database.transaction(
      (entries: readonly ArtifactInput[], createdAt: string): readonly ArtifactRecord[] =>
        entries.map((entry) => this.#putOne(entry, createdAt)),
    );
    this.#putBatch = (entries, createdAt) =>
      transaction.immediate(entries, createdAt) as readonly ArtifactRecord[];

    const claim = database.transaction((
      binding: ServiceRunBinding,
      seller: string,
      createClaim: () => NewServiceRunClaim,
    ): ServiceRunClaimResult => {
      const existing = this.#getServiceRun(binding);
      if (existing !== null) {
        assertSameRunBinding(existing, binding);
        return existing.status === "completed"
          ? { disposition: "replayed", run: completedRun(existing) }
          : { disposition: "in-progress", run: runningRun(existing) };
      }
      const { claimToken, createdAt } = createClaim();
      validateClaimToken(claimToken);
      validateCanonicalTimestamp(createdAt, "createdAt");
      this.database.query<never, Record<string, string>>(`
        /* atomic-write: service-run.claim */
        INSERT INTO service_runs (
          instance_id, audience, job_id, request_hash, contract_hash, seller_claim,
          status, claim_token, created_at
        ) VALUES (
          $instanceId, $audience, $jobId, $requestHash, $contractHash, $seller,
          'running', $claimToken, $createdAt
        )
      `).run({ ...binding, seller, claimToken, createdAt });
      return { disposition: "claimed", claimToken, createdAt };
    });
    this.#claimServiceRun = (binding, seller, createClaim) =>
      claim.immediate(binding, seller, createClaim) as ServiceRunClaimResult;

    const complete = database.transaction((
      binding: ServiceRunBinding,
      claimToken: string,
      output: ArtifactInput,
      receipt: ArtifactInput,
      completedAt: string,
    ): CompletedServiceRun => {
      const existing = this.#getServiceRun(binding);
      if (existing === null || existing.status !== "running") {
        throw new ServiceRunConflictError("Service run is not held by an active claim");
      }
      assertSameRunBinding(existing, binding);
      if (existing.claimToken !== claimToken) {
        throw new ServiceRunConflictError("Service run claim token does not match");
      }
      const outputRecord = this.#putOne(output, completedAt);
      const receiptRecord = this.#putOne(receipt, completedAt);
      const update = this.database.query<never, Record<string, string>>(`
        /* atomic-write: service-run.complete */
        UPDATE service_runs
        SET status = 'completed', output_content_hash = $outputContentHash,
          receipt_content_hash = $receiptContentHash, completed_at = $completedAt
        WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
          AND request_hash = $requestHash AND contract_hash = $contractHash
          AND status = 'running' AND claim_token = $claimToken
      `).run({
        ...binding,
        claimToken,
        outputContentHash: outputRecord.contentHash,
        receiptContentHash: receiptRecord.contentHash,
        completedAt,
      });
      if (update.changes !== 1) {
        throw new ServiceRunConflictError("Service run completion lost its claim");
      }
      const stored = this.#getServiceRun(binding);
      if (stored === null || stored.status !== "completed") {
        throw new ArtifactIntegrityError("Completed service run was not visible");
      }
      return completedRun(stored);
    });
    this.#completeServiceRun = (binding, claimToken, output, receipt, completedAt) =>
      complete.immediate(
        binding,
        claimToken,
        output,
        receipt,
        completedAt,
      ) as CompletedServiceRun;

    const release = database.transaction((binding: ServiceRunBinding, claimToken: string): boolean =>
      this.database.query<never, Record<string, string>>(`
        /* atomic-write: service-run.release */
        DELETE FROM service_runs
        WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
          AND request_hash = $requestHash AND contract_hash = $contractHash
          AND status = 'running' AND claim_token = $claimToken
      `).run({ ...binding, claimToken }).changes === 1,
    );
    this.#releaseServiceRun = (binding, claimToken) =>
      release.immediate(binding, claimToken) as boolean;

    const recover = database.transaction((
      binding: ServiceRunBinding,
      recovery: StaleServiceRunRecovery,
    ): boolean => {
      const existing = this.#getServiceRun(binding);
      if (existing === null) return false;
      assertSameRunBinding(existing, binding);
      if (existing.status !== "running") return false;
      if (
        existing.createdAt !== recovery.expectedCreatedAt
        || sha256Hex(existing.claimToken) !== recovery.expectedClaimFingerprint
      ) return false;
      const ageMs = Date.parse(recovery.observedAt) - Date.parse(existing.createdAt);
      if (ageMs < recovery.minimumAgeMs) return false;
      return this.database.query<never, Record<string, string>>(`
        /* atomic-write: service-run.recover */
        DELETE FROM service_runs
        WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
          AND request_hash = $requestHash AND contract_hash = $contractHash
          AND status = 'running' AND claim_token = $claimToken AND created_at = $expectedCreatedAt
      `).run({
        ...binding,
        claimToken: existing.claimToken,
        expectedCreatedAt: recovery.expectedCreatedAt,
      }).changes === 1;
    });
    this.#recoverStaleServiceRun = (binding, recovery) =>
      recover.immediate(binding, recovery) as boolean;
  }

  put(kind: string, value: unknown, createdAt: string): ArtifactRecord {
    const record = this.putBatch([{ kind, value }], createdAt)[0];
    if (record === undefined) throw new ArtifactIntegrityError("Artifact batch returned no record");
    return record;
  }

  putBatch(entries: readonly ArtifactInput[], createdAt: string): readonly ArtifactRecord[] {
    if (entries.length === 0) throw new TypeError("Artifact batch must not be empty");
    if (createdAt.length === 0) throw new TypeError("Artifact createdAt must not be empty");
    const snapshot = entries.map(({ kind, value }) => {
      if (typeof kind !== "string" || kind.length === 0) {
        throw new TypeError("Artifact kind must not be empty");
      }
      return Object.freeze({ kind, value });
    });
    return Object.freeze([...this.#putBatch(snapshot, createdAt)]);
  }

  putWithinTransaction(
    kind: string,
    value: unknown,
    createdAt: string,
  ): ArtifactRecord {
    validateArtifactInput({ kind, value });
    validateCanonicalTimestamp(createdAt, "createdAt");
    if (!this.database.inTransaction) {
      throw new TypeError("Artifact transactional write requires an active SQLite transaction");
    }
    return this.#putOne(Object.freeze({ kind, value }), createdAt);
  }

  claimServiceRun(
    binding: ServiceRunBinding,
    seller: string,
    createClaim: () => NewServiceRunClaim,
  ): ServiceRunClaimResult {
    validateRunBinding(binding);
    if (seller.length === 0) throw new TypeError("Service run seller is required");
    if (typeof createClaim !== "function") {
      throw new TypeError("Service run claim factory must be a function");
    }
    return this.#claimServiceRun(Object.freeze({ ...binding }), seller, createClaim);
  }

  completeServiceRun(
    binding: ServiceRunBinding,
    claimToken: string,
    output: ArtifactInput,
    receipt: ArtifactInput,
    completedAt: string,
  ): CompletedServiceRun {
    validateRunBinding(binding);
    validateClaimToken(claimToken);
    validateArtifactInput(output);
    validateArtifactInput(receipt);
    if (completedAt.length === 0) throw new TypeError("Service run completedAt is required");
    return this.#completeServiceRun(binding, claimToken, output, receipt, completedAt);
  }

  releaseServiceRun(binding: ServiceRunBinding, claimToken: string): boolean {
    validateRunBinding(binding);
    validateClaimToken(claimToken);
    return this.#releaseServiceRun(binding, claimToken);
  }

  recoverStaleServiceRun(
    binding: ServiceRunBinding,
    recovery: StaleServiceRunRecovery,
  ): boolean {
    validateRunBinding(binding);
    validateRecovery(recovery);
    return this.#recoverStaleServiceRun(
      Object.freeze({ ...binding }),
      Object.freeze({ ...recovery }),
    );
  }

  get(contentHash: string): ArtifactRecord | null {
    const row = this.#getBlob(contentHash);
    if (row === null) return null;

    const kinds = this.database.query<{ kind: string }, { contentHash: string }>(`
      SELECT kind
      FROM artifact_kinds
      WHERE content_hash = $contentHash
      ORDER BY kind
    `).all({ contentHash }).map(({ kind }) => kind);
    if (kinds.length === 0) {
      throw new ArtifactIntegrityError("Stored artifact has no kind association");
    }
    return { ...row, kinds };
  }

  #putOne({ kind, value }: ArtifactInput, createdAt: string): ArtifactRecord {
    const canonicalJson = canonicalize(value);
    const contentHash = sha256Hex(canonicalJson);
    const byteLength = Buffer.byteLength(canonicalJson, "utf8");
    this.database.query<never, {
      contentHash: string;
      canonicalJson: string;
      byteLength: number;
      createdAt: string;
    }>(`
      /* atomic-write: artifact.put-blob */
      INSERT INTO artifacts (content_hash, canonical_json, byte_length, created_at)
      VALUES ($contentHash, $canonicalJson, $byteLength, $createdAt)
      ON CONFLICT(content_hash) DO NOTHING
    `).run({ contentHash, canonicalJson, byteLength, createdAt });
    const stored = this.#getBlob(contentHash);
    if (stored === null || stored.canonicalJson !== canonicalJson) {
      throw new ArtifactIntegrityError("Content hash resolved to conflicting artifact bytes");
    }
    this.database.query<never, { contentHash: string; kind: string; createdAt: string }>(`
      /* atomic-write: artifact.put-kind */
      INSERT INTO artifact_kinds (content_hash, kind, created_at)
      VALUES ($contentHash, $kind, $createdAt)
      ON CONFLICT(content_hash, kind) DO NOTHING
    `).run({ contentHash, kind, createdAt });
    const record = this.get(contentHash);
    if (record === null || !record.kinds.includes(kind)) {
      throw new ArtifactIntegrityError("Artifact kind association was not visible");
    }
    return record;
  }

  #getServiceRun(binding: ServiceRunBinding): ServiceRunRow | null {
    return this.database.query<ServiceRunRow, Pick<
      ServiceRunBinding,
      "instanceId" | "audience" | "jobId"
    >>(`
      SELECT instance_id AS instanceId, audience, job_id AS jobId,
        request_hash AS requestHash, contract_hash AS contractHash, seller_claim AS seller, status,
        claim_token AS claimToken, output_content_hash AS outputContentHash,
        receipt_content_hash AS receiptContentHash, created_at AS createdAt,
        completed_at AS completedAt
      FROM service_runs
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
    `).get(binding);
  }

  #getBlob(contentHash: string): ArtifactRow | null {
    const row = this.database.query<ArtifactRow, { contentHash: string }>(`
      SELECT
        content_hash AS contentHash,
        canonical_json AS canonicalJson,
        byte_length AS byteLength,
        created_at AS createdAt
      FROM artifacts
      WHERE content_hash = $contentHash
    `).get({ contentHash });
    if (row === null) return null;

    const recomputed = sha256Hex(row.canonicalJson);
    const actualLength = BigInt(Buffer.byteLength(row.canonicalJson, "utf8"));
    if (recomputed !== row.contentHash || actualLength !== row.byteLength) {
      throw new ArtifactIntegrityError("Stored artifact failed hash or length verification");
    }
    return row;
  }
}

function validateArtifactInput(input: ArtifactInput): void {
  if (typeof input.kind !== "string" || input.kind.length === 0) {
    throw new TypeError("Artifact kind must not be empty");
  }
}

function validateRunBinding(binding: ServiceRunBinding): void {
  for (const field of ["instanceId", "audience", "jobId"] as const) {
    if (typeof binding[field] !== "string" || binding[field].length === 0) {
      throw new TypeError(`Service run ${field} is required`);
    }
  }
  if (!/^[0-9a-f]{64}$/.test(binding.requestHash)
    || !/^[0-9a-f]{64}$/.test(binding.contractHash)) {
    throw new TypeError("Service run hashes must be lowercase SHA-256");
  }
}

function validateClaimToken(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("Service run claim token must be 32 bytes of lowercase hexadecimal");
  }
}

function validateRecovery(recovery: StaleServiceRunRecovery): void {
  if (recovery === null || typeof recovery !== "object" || Array.isArray(recovery)) {
    throw new TypeError("Service run recovery must be an object");
  }
  if (recovery.executorIsolationConfirmed !== true) {
    throw new TypeError("Service run recovery requires confirmed executor isolation");
  }
  if (!/^[0-9a-f]{64}$/.test(recovery.expectedClaimFingerprint)) {
    throw new TypeError("Service run recovery claim fingerprint must be lowercase SHA-256");
  }
  validateCanonicalTimestamp(recovery.expectedCreatedAt, "expectedCreatedAt");
  validateCanonicalTimestamp(recovery.observedAt, "observedAt");
  if (!Number.isSafeInteger(recovery.minimumAgeMs) || recovery.minimumAgeMs <= 0) {
    throw new TypeError("Service run recovery minimumAgeMs must be a positive safe integer");
  }
}

function validateCanonicalTimestamp(value: string, field: string): void {
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    throw new TypeError(`Service run ${field} must be a canonical ISO timestamp`);
  }
}

function assertSameRunBinding(existing: ServiceRunRow, binding: ServiceRunBinding): void {
  if (existing.requestHash !== binding.requestHash || existing.contractHash !== binding.contractHash) {
    throw new ServiceRunConflictError("Service run binding conflicts with persisted state");
  }
}

function completedRun(row: ServiceRunRow): CompletedServiceRun {
  if (
    row.status !== "completed"
    || row.outputContentHash === null
    || row.receiptContentHash === null
    || row.completedAt === null
  ) throw new ArtifactIntegrityError("Completed service run is missing artifact bindings");
  return Object.freeze({
    instanceId: row.instanceId,
    audience: row.audience,
    jobId: row.jobId,
    requestHash: row.requestHash,
    contractHash: row.contractHash,
    status: "completed",
    seller: row.seller,
    outputContentHash: row.outputContentHash,
    receiptContentHash: row.receiptContentHash,
    createdAt: row.createdAt,
    completedAt: row.completedAt,
  });
}

function runningRun(row: ServiceRunRow): RunningServiceRun {
  if (row.status !== "running") {
    throw new ArtifactIntegrityError("Running service run has an invalid status");
  }
  return Object.freeze({
    instanceId: row.instanceId,
    audience: row.audience,
    jobId: row.jobId,
    requestHash: row.requestHash,
    contractHash: row.contractHash,
    status: "running",
    seller: row.seller,
    claimFingerprint: sha256Hex(row.claimToken),
    createdAt: row.createdAt,
  });
}

import { randomBytes as operatingSystemRandomBytes } from "node:crypto";
import {
  assertFixtureAuthority,
  parseEvidenceMode,
  type EvidenceMode,
} from "../../core/evidence-mode.ts";
import { canonicalize } from "../../protocol/canonical-json.ts";
import {
  canonicalizeClaimReference,
  type CanonicalClaimReference,
} from "../../protocol/claim-reference.ts";
import { contentHash } from "../../protocol/hash.ts";
import type { DacsDatabase } from "./database.ts";

const ADMISSION_DOMAIN = "dacs-template:session-admission:v1:";
const ALLOCATION_DOMAIN = "dacs-template:session-challenge-allocation:v1:";
const DEFAULT_NONCE_LIFETIME_MS = 300_000;
const LOWER_HEX_32 = /^[0-9a-f]{32}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const MAX_ALLOCATION_AGE_MS = 60_000;
const MAX_ALLOCATION_FUTURE_SKEW_MS = 30_000;
const MAX_FIELD_LENGTH = 4_096;
const MAX_NONCE_COLLISION_ATTEMPTS = 8;
const MAX_OUTSTANDING_CHALLENGES = 4;

export interface ChallengeBinding {
  readonly instanceId: string;
  readonly audience: string;
  readonly principal: string;
  readonly jobId: string;
  readonly evidenceMode: EvidenceMode;
}

export interface ChallengeAllocationInput extends ChallengeBinding {
  readonly clientNonce: string;
  readonly clientIdempotencyKey: string;
  readonly requestedAtMs: number;
  readonly proof: string;
}

export interface ChallengeRecord extends ChallengeBinding {
  readonly nonce: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

export type ChallengeAllocationResult =
  | { readonly disposition: "created" | "replayed"; readonly challenge: ChallengeRecord }
  | { readonly disposition: "conflict" | "rejected" | "quota-exceeded" };

export interface AdmissionInput extends ChallengeBinding {
  readonly nonce: string;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly proof: string;
}

export interface SessionRecord {
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly evidenceMode: EvidenceMode;
  readonly requestHash: string;
  readonly admissionFingerprint: string;
  readonly status: "admitted" | "failed";
  readonly version: bigint;
  readonly createdAt: string;
}

export function sessionBindingHash(session: SessionRecord): string {
  if (session === null || typeof session !== "object" || Array.isArray(session)
    || typeof session.instanceId !== "string" || session.instanceId.length === 0
    || typeof session.audience !== "string" || session.audience.length === 0
    || typeof session.jobId !== "string" || !ULID.test(session.jobId)
    || (session.evidenceMode !== "fixture" && session.evidenceMode !== "local-chain"
      && session.evidenceMode !== "live")
    || typeof session.requestHash !== "string" || !LOWER_HEX_64.test(session.requestHash)
    || typeof session.admissionFingerprint !== "string"
    || !LOWER_HEX_64.test(session.admissionFingerprint)
    || session.status !== "admitted"
    || typeof session.createdAt !== "string" || session.createdAt.length === 0) {
    throw new TypeError("Session binding requires an admitted canonical session record");
  }
  return contentHash({
    bindingVersion: "1",
    instanceId: session.instanceId,
    audience: session.audience,
    jobId: session.jobId,
    evidenceMode: session.evidenceMode,
    requestHash: session.requestHash,
    admissionFingerprint: session.admissionFingerprint,
    createdAt: session.createdAt,
  });
}

export type AdmissionRejection =
  | "unknown-challenge"
  | "consumed-challenge"
  | "expired-challenge"
  | "clock-regression"
  | "challenge-binding-mismatch"
  | "invalid-admission"
  | "authentication-failed";

export type AdmissionResult =
  | { readonly disposition: "created"; readonly session: SessionRecord }
  | { readonly disposition: "conflict"; readonly existingJobId: string }
  | { readonly disposition: "rejected"; readonly reason: AdmissionRejection };

export interface PrincipalProofVerification {
  readonly principal: CanonicalClaimReference;
  readonly proof: string;
  readonly signedBytes: string;
}

export interface PrincipalProofAuthenticator {
  verify(input: PrincipalProofVerification): boolean;
}

export interface JobAdmissionAuthorization extends ChallengeBinding {
  readonly principalIdentity: CanonicalClaimReference;
}

export interface JobAdmissionAuthorizer {
  authorize(input: JobAdmissionAuthorization): boolean;
}

export interface SessionStoreOptions {
  readonly audience: string;
  readonly authenticator: PrincipalProofAuthenticator;
  readonly deploymentMode: EvidenceMode;
  readonly instanceId: string;
  readonly jobAuthorizer: JobAdmissionAuthorizer;
  readonly now?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly nonceLifetimeMs?: number;
}

interface ChallengeRow {
  readonly nonce: string;
  readonly jobId: string;
  readonly instanceId: string;
  readonly audience: string;
  readonly principalRef: string;
  readonly principalScheme: string;
  readonly principalIdentifier: string;
  readonly evidenceMode: EvidenceMode;
  readonly allocationFingerprint: string;
  readonly issuedAtMs: bigint;
  readonly expiresAtMs: bigint;
  readonly consumedAtMs: bigint | null;
}

interface ConsumptionRow {
  readonly sessionId: string;
}

interface SessionRow {
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly evidenceMode: EvidenceMode;
  readonly requestHash: string;
  readonly admissionFingerprint: string;
  readonly status: "admitted" | "failed";
  readonly version: bigint;
  readonly createdAt: string;
}

export function readPersistedSession(
  database: DacsDatabase,
  instanceId: string,
  audience: string,
  jobId: string,
): SessionRecord | null {
  return database.query<SessionRow, {
    instanceId: string; audience: string; jobId: string;
  }>(`
    SELECT s.instance_id AS instanceId, s.audience, s.job_id AS jobId, s.evidence_mode AS evidenceMode,
      c.request_hash AS requestHash, s.admission_fingerprint AS admissionFingerprint,
      s.status, s.version, s.created_at AS createdAt
    FROM sessions AS s
    JOIN admission_consumptions AS c
      ON c.instance_id = s.instance_id
      AND c.audience = s.audience
      AND c.session_id = s.job_id
    WHERE s.instance_id = $instanceId AND s.audience = $audience AND s.job_id = $jobId
  `).get({ instanceId, audience, jobId });
}

export function readPersistedSessionByJobId(
  database: DacsDatabase,
  jobId: string,
): SessionRecord | null {
  const rows = database.query<SessionRow, { jobId: string }>(`
    SELECT s.instance_id AS instanceId, s.audience, s.job_id AS jobId, s.evidence_mode AS evidenceMode,
      c.request_hash AS requestHash, s.admission_fingerprint AS admissionFingerprint,
      s.status, s.version, s.created_at AS createdAt
    FROM sessions AS s
    JOIN admission_consumptions AS c
      ON c.instance_id = s.instance_id
      AND c.audience = s.audience
      AND c.session_id = s.job_id
    WHERE s.job_id = $jobId
  `).all({ jobId });
  if (rows.length > 1) throw new Error("Persisted global jobId uniqueness is corrupt");
  return rows[0] ?? null;
}

interface NormalizedAllocation {
  readonly input: ChallengeAllocationInput;
  readonly principal: CanonicalClaimReference;
  readonly fingerprint: string;
}

export class SessionStore {
  readonly #allocate: (allocation: NormalizedAllocation) => ChallengeAllocationResult;
  readonly #audience: string;
  readonly #authenticate: PrincipalProofAuthenticator;
  readonly #createAdmission: (input: AdmissionInput) => AdmissionResult;
  readonly #deploymentMode: EvidenceMode;
  readonly #instanceId: string;
  readonly #jobAuthorizer: JobAdmissionAuthorizer;
  readonly #nonceLifetimeMs: number;
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Uint8Array;

  constructor(
    private readonly database: DacsDatabase,
    options: SessionStoreOptions,
  ) {
    if (
      options === undefined
      || options.authenticator === undefined
      || options.jobAuthorizer === undefined
    ) {
      throw new TypeError(
        "SessionStore requires principal proof authentication and job admission authorization",
      );
    }
    this.#authenticate = options.authenticator;
    this.#jobAuthorizer = options.jobAuthorizer;
    validateConfiguredBinding("instanceId", options.instanceId);
    validateConfiguredBinding("audience", options.audience);
    this.#instanceId = options.instanceId;
    this.#audience = options.audience;
    this.#deploymentMode = parseEvidenceMode(options.deploymentMode);
    if (this.#deploymentMode !== "fixture") {
      throw new TypeError("This implementation slice supports fixture deployment only");
    }
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? operatingSystemRandomBytes;
    this.#nonceLifetimeMs = options.nonceLifetimeMs ?? DEFAULT_NONCE_LIFETIME_MS;
    if (!Number.isSafeInteger(this.#nonceLifetimeMs) || this.#nonceLifetimeMs <= 0) {
      throw new TypeError("Nonce lifetime must be a positive safe integer");
    }

    const allocate = database.transaction((allocation: NormalizedAllocation) =>
      this.#allocateTransaction(allocation));
    this.#allocate = (allocation) =>
      allocate.immediate(allocation) as ChallengeAllocationResult;

    const admit = database.transaction((input: AdmissionInput): AdmissionResult =>
      this.#admitTransaction(input));
    this.#createAdmission = (input) => admit.immediate(input) as AdmissionResult;
  }

  allocateChallenge(input: ChallengeAllocationInput): ChallengeAllocationResult {
    let principal: CanonicalClaimReference;
    let request: ChallengeAllocationInput;
    try {
      request = snapshotRecord(input, "Challenge allocation");
      validateChallengeAllocation(request);
      if (request.instanceId !== this.#instanceId || request.audience !== this.#audience) {
        return { disposition: "rejected" };
      }
      assertFixtureAuthority(this.#deploymentMode, request.evidenceMode);
      principal = Object.freeze(canonicalizeClaimReference(request.principal));
    } catch {
      return { disposition: "rejected" };
    }

    const nowMs = this.#safeNow();
    if (
      request.requestedAtMs < nowMs - MAX_ALLOCATION_AGE_MS
      || request.requestedAtMs > nowMs + MAX_ALLOCATION_FUTURE_SKEW_MS
    ) return { disposition: "rejected" };
    if (this.#authenticate.verify({
      principal,
      proof: request.proof,
      signedBytes: challengeAllocationSigningBytes(request),
    }) !== true) return { disposition: "rejected" };
    if (this.#jobAuthorizer.authorize({
      instanceId: request.instanceId,
      audience: request.audience,
      principal: principal.canonicalReference,
      principalIdentity: principal,
      jobId: request.jobId,
      evidenceMode: request.evidenceMode,
    }) !== true) return { disposition: "rejected" };

    const fingerprint = contentHash(allocationSignedScope(request));
    return this.#allocate({ input: request, principal, fingerprint });
  }

  admit(input: AdmissionInput): AdmissionResult {
    let snapshot: AdmissionInput;
    try {
      snapshot = snapshotRecord(input, "Admission");
    } catch {
      return { disposition: "rejected", reason: "invalid-admission" };
    }
    return this.#createAdmission(snapshot);
  }

  get(jobId: string): SessionRecord | null {
    return readPersistedSession(this.database, this.#instanceId, this.#audience, jobId);
  }

  count(): bigint {
    return this.database.query<{ count: bigint }, { instanceId: string; audience: string }>(`
      SELECT count(*) AS count FROM sessions
      WHERE instance_id = $instanceId AND audience = $audience
    `).get({ instanceId: this.#instanceId, audience: this.#audience })?.count ?? 0n;
  }

  #allocateTransaction(allocation: NormalizedAllocation): ChallengeAllocationResult {
    const { input, principal, fingerprint } = allocation;
    const nowMs = this.#safeNow();
    if (
      input.requestedAtMs < nowMs - MAX_ALLOCATION_AGE_MS
      || input.requestedAtMs > nowMs + MAX_ALLOCATION_FUTURE_SKEW_MS
    ) return { disposition: "rejected" };
    this.database.query<never, { nowMs: number; instanceId: string; audience: string }>(`
      /* atomic-write: admission.cleanup-challenges */
      DELETE FROM admission_challenges
      WHERE retain_until_ms <= $nowMs
        AND instance_id = $instanceId AND audience = $audience
        AND NOT EXISTS (
          SELECT 1 FROM admission_consumptions
          WHERE admission_consumptions.nonce = admission_challenges.nonce
        )
    `).run({ nowMs, instanceId: this.#instanceId, audience: this.#audience });

    const existing = this.database.query<ChallengeRow, {
      instanceId: string; audience: string; principalScheme: string;
      principalIdentifier: string; clientNonce: string; clientIdempotencyKey: string;
    }>(`
      SELECT nonce, job_id AS jobId, instance_id AS instanceId, audience,
        principal_ref AS principalRef, principal_scheme AS principalScheme,
        principal_identifier AS principalIdentifier, evidence_mode AS evidenceMode,
        allocation_fingerprint AS allocationFingerprint, issued_at_ms AS issuedAtMs,
        expires_at_ms AS expiresAtMs, consumed_at_ms AS consumedAtMs
      FROM admission_challenges
      WHERE instance_id = $instanceId AND audience = $audience
        AND principal_scheme = $principalScheme AND principal_identifier = $principalIdentifier
        AND (client_nonce = $clientNonce OR client_idempotency_key = $clientIdempotencyKey)
      LIMIT 1
    `).get({
      instanceId: input.instanceId,
      audience: input.audience,
      principalScheme: principal.scheme,
      principalIdentifier: principal.identifier,
      clientNonce: input.clientNonce,
      clientIdempotencyKey: input.clientIdempotencyKey,
    });
    if (existing !== null) {
      return existing.allocationFingerprint === fingerprint
        ? { disposition: "replayed", challenge: challengeRecord(existing) }
        : { disposition: "conflict" };
    }

    const outstanding = this.database.query<{ count: bigint }, {
      nowMs: number; instanceId: string; audience: string;
      principalScheme: string; principalIdentifier: string;
    }>(`
      SELECT count(*) AS count FROM admission_challenges
      WHERE consumed_at_ms IS NULL AND expires_at_ms > $nowMs
        AND instance_id = $instanceId AND audience = $audience
        AND principal_scheme = $principalScheme AND principal_identifier = $principalIdentifier
    `).get({
      nowMs,
      instanceId: input.instanceId,
      audience: input.audience,
      principalScheme: principal.scheme,
      principalIdentifier: principal.identifier,
    })?.count ?? 0n;
    if (outstanding >= BigInt(MAX_OUTSTANDING_CHALLENGES)) {
      return { disposition: "quota-exceeded" };
    }

    if (this.#nonceLifetimeMs > Number.MAX_SAFE_INTEGER - nowMs) {
      throw new Error("Nonce expiry exceeds the safe integer time range");
    }
    const expiresAtMs = nowMs + this.#nonceLifetimeMs;
    const proofRetentionEnd = input.requestedAtMs
      + MAX_ALLOCATION_AGE_MS
      + MAX_ALLOCATION_FUTURE_SKEW_MS;
    if (!Number.isSafeInteger(proofRetentionEnd)) {
      throw new Error("Challenge retention exceeds the safe integer time range");
    }
    const retainUntilMs = Math.max(expiresAtMs, proofRetentionEnd);
    for (let attempt = 0; attempt < MAX_NONCE_COLLISION_ATTEMPTS; attempt += 1) {
      const entropy = this.#randomBytes(16);
      if (entropy.byteLength !== 16) {
        throw new Error("Nonce entropy provider must return exactly 16 bytes");
      }
      const nonce = Buffer.from(entropy).toString("hex");
      const result = this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: admission.allocate-challenge */
        INSERT INTO admission_challenges (
          nonce, job_id, instance_id, audience, principal_ref, principal_scheme,
          principal_identifier, evidence_mode, client_nonce, client_idempotency_key,
          allocation_fingerprint, requested_at_ms, issued_at_ms, expires_at_ms,
          retain_until_ms
        ) VALUES (
          $nonce, $jobId, $instanceId, $audience, $principalRef, $principalScheme,
          $principalIdentifier, $evidenceMode, $clientNonce, $clientIdempotencyKey,
          $fingerprint, $requestedAtMs, $issuedAtMs, $expiresAtMs, $retainUntilMs
        ) ON CONFLICT(nonce) DO NOTHING
      `).run({
        nonce, jobId: input.jobId, instanceId: input.instanceId, audience: input.audience,
        principalRef: principal.canonicalReference, principalScheme: principal.scheme,
        principalIdentifier: principal.identifier, evidenceMode: input.evidenceMode,
        clientNonce: input.clientNonce, clientIdempotencyKey: input.clientIdempotencyKey,
        fingerprint, requestedAtMs: input.requestedAtMs, issuedAtMs: nowMs, expiresAtMs,
        retainUntilMs,
      });
      if (result.changes === 1) {
        return {
          disposition: "created",
          challenge: {
            instanceId: input.instanceId, audience: input.audience,
            principal: principal.canonicalReference, jobId: input.jobId,
            evidenceMode: input.evidenceMode, nonce, issuedAtMs: nowMs, expiresAtMs,
          },
        };
      }
    }
    throw new Error("Nonce entropy provider produced repeated collisions");
  }

  #admitTransaction(input: AdmissionInput): AdmissionResult {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      return { disposition: "rejected", reason: "invalid-admission" };
    }
    if (!LOWER_HEX_32.test(input.nonce)) {
      return { disposition: "rejected", reason: "unknown-challenge" };
    }
    if (input.instanceId !== this.#instanceId || input.audience !== this.#audience) {
      return { disposition: "rejected", reason: "challenge-binding-mismatch" };
    }
    const challenge = this.#findChallenge(input.nonce);
    if (challenge === null) return { disposition: "rejected", reason: "unknown-challenge" };
    if (challenge.consumedAtMs !== null) {
      return { disposition: "rejected", reason: "consumed-challenge" };
    }

    const nowMs = this.#safeNow();
    const clockRegressed = BigInt(nowMs) < challenge.issuedAtMs;
    const consumedAtMs = clockRegressed ? Number(challenge.issuedAtMs) : nowMs;
    const consumption = this.database.query<never, {
      nonce: string; nowMs: number; instanceId: string; audience: string;
    }>(`
      /* atomic-write: admission.consume-challenge */
      UPDATE admission_challenges SET consumed_at_ms = $nowMs
      WHERE nonce = $nonce AND instance_id = $instanceId AND audience = $audience
        AND consumed_at_ms IS NULL
    `).run({
      nonce: input.nonce, nowMs: consumedAtMs,
      instanceId: this.#instanceId, audience: this.#audience,
    });
    if (consumption.changes !== 1) {
      return { disposition: "rejected", reason: "consumed-challenge" };
    }
    if (clockRegressed) return { disposition: "rejected", reason: "clock-regression" };
    if (BigInt(nowMs) >= challenge.expiresAtMs) {
      return { disposition: "rejected", reason: "expired-challenge" };
    }

    let principal: CanonicalClaimReference;
    try {
      validateAdmission(input);
      assertFixtureAuthority(this.#deploymentMode, input.evidenceMode);
      principal = Object.freeze(canonicalizeClaimReference(input.principal));
    } catch {
      return { disposition: "rejected", reason: "invalid-admission" };
    }
    if (!challengeMatches(challenge, input, principal)) {
      return { disposition: "rejected", reason: "challenge-binding-mismatch" };
    }
    if (this.#authenticate.verify({
      principal,
      proof: input.proof,
      signedBytes: admissionSigningBytes(input),
    }) !== true) return { disposition: "rejected", reason: "authentication-failed" };

    const fingerprint = contentHash(admissionSignedScope(input));
    const existingByJobId = this.database.query<{ jobId: string }, { jobId: string }>(`
      SELECT job_id AS jobId FROM sessions WHERE job_id = $jobId LIMIT 1
    `).get({ jobId: input.jobId });
    if (existingByJobId !== null) {
      return { disposition: "conflict", existingJobId: input.jobId };
    }
    const existingByIdempotency = this.#findByIdempotency(input, principal);
    if (existingByIdempotency !== null) {
      return { disposition: "conflict", existingJobId: existingByIdempotency.sessionId };
    }

    const createdAt = new Date(nowMs).toISOString();
    this.database.query<never, { instanceId: string; audience: string; jobId: string;
      evidenceMode: EvidenceMode; fingerprint: string; createdAt: string }>(`
      /* atomic-write: admission.create-session */
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint, status, created_at
      ) VALUES (
        $instanceId, $audience, $jobId, $evidenceMode, $fingerprint, 'admitted', $createdAt
      )
    `).run({
      instanceId: this.#instanceId, audience: this.#audience, jobId: input.jobId,
      evidenceMode: input.evidenceMode, fingerprint, createdAt,
    });

    this.database.query<never, Record<string, string>>(`
      /* atomic-write: admission.record-consumption */
      INSERT INTO admission_consumptions (
        nonce, instance_id, audience, principal_ref, principal_scheme, principal_identifier,
        idempotency_key, request_hash, admission_fingerprint, session_id, consumed_at
      ) VALUES (
        $nonce, $instanceId, $audience, $principalRef, $principalScheme, $principalIdentifier,
        $idempotencyKey, $requestHash, $fingerprint, $sessionId, $consumedAt
      )
    `).run({
      nonce: input.nonce, instanceId: input.instanceId, audience: input.audience,
      principalRef: principal.canonicalReference, principalScheme: principal.scheme,
      principalIdentifier: principal.identifier, idempotencyKey: input.idempotencyKey,
      requestHash: input.requestHash, fingerprint, sessionId: input.jobId, consumedAt: createdAt,
    });

    const session = this.get(input.jobId);
    if (session === null) throw new Error("Session disappeared during admission transaction");
    return { disposition: "created", session };
  }

  #findChallenge(nonce: string): ChallengeRow | null {
    return this.database.query<ChallengeRow, {
      nonce: string; instanceId: string; audience: string;
    }>(`
      SELECT nonce, job_id AS jobId, instance_id AS instanceId, audience,
        principal_ref AS principalRef, principal_scheme AS principalScheme,
        principal_identifier AS principalIdentifier, evidence_mode AS evidenceMode,
        allocation_fingerprint AS allocationFingerprint, issued_at_ms AS issuedAtMs,
        expires_at_ms AS expiresAtMs, consumed_at_ms AS consumedAtMs
      FROM admission_challenges
      WHERE nonce = $nonce AND instance_id = $instanceId AND audience = $audience
    `).get({ nonce, instanceId: this.#instanceId, audience: this.#audience });
  }

  #findByIdempotency(
    input: AdmissionInput,
    principal: CanonicalClaimReference,
  ): ConsumptionRow | null {
    return this.database.query<ConsumptionRow, Record<string, string>>(`
      SELECT session_id AS sessionId FROM admission_consumptions
      WHERE instance_id = $instanceId AND audience = $audience
        AND principal_scheme = $principalScheme AND principal_identifier = $principalIdentifier
        AND idempotency_key = $idempotencyKey
    `).get({
      instanceId: input.instanceId, audience: input.audience,
      principalScheme: principal.scheme, principalIdentifier: principal.identifier,
      idempotencyKey: input.idempotencyKey,
    });
  }

  #safeNow(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("Clock returned an invalid time");
    return now;
  }
}

export function challengeAllocationSigningBytes(input: ChallengeAllocationInput): string {
  const snapshot = snapshotRecord<ChallengeAllocationInput>(input, "Challenge allocation");
  return `${ALLOCATION_DOMAIN}${canonicalize(allocationSignedScope(snapshot))}`;
}

export function admissionSigningBytes(input: AdmissionInput): string {
  const snapshot = snapshotRecord<AdmissionInput>(input, "Admission");
  return `${ADMISSION_DOMAIN}${canonicalize(admissionSignedScope(snapshot))}`;
}

function allocationSignedScope(input: ChallengeAllocationInput): Record<string, unknown> {
  const principal = canonicalizeClaimReference(input.principal);
  return {
    audience: input.audience, clientIdempotencyKey: input.clientIdempotencyKey,
    clientNonce: input.clientNonce, evidenceMode: input.evidenceMode,
    instanceId: input.instanceId, jobId: input.jobId,
    principal: principal.canonicalReference, requestedAtMs: input.requestedAtMs,
  };
}

function admissionSignedScope(input: AdmissionInput): Record<string, unknown> {
  const principal = canonicalizeClaimReference(input.principal);
  return {
    audience: input.audience, evidenceMode: input.evidenceMode,
    idempotencyKey: input.idempotencyKey, instanceId: input.instanceId,
    jobId: input.jobId, nonce: input.nonce, principal: principal.canonicalReference,
    requestHash: input.requestHash,
  };
}

function challengeRecord(row: ChallengeRow): ChallengeRecord {
  return {
    instanceId: row.instanceId, audience: row.audience, principal: row.principalRef,
    jobId: row.jobId, evidenceMode: row.evidenceMode, nonce: row.nonce,
    issuedAtMs: Number(row.issuedAtMs), expiresAtMs: Number(row.expiresAtMs),
  };
}

function challengeMatches(
  challenge: ChallengeRow,
  input: AdmissionInput,
  principal: CanonicalClaimReference,
): boolean {
  return challenge.jobId === input.jobId && challenge.instanceId === input.instanceId
    && challenge.audience === input.audience && challenge.evidenceMode === input.evidenceMode
    && challenge.principalRef === principal.canonicalReference
    && challenge.principalScheme === principal.scheme
    && challenge.principalIdentifier === principal.identifier;
}

function validateChallengeAllocation(input: ChallengeAllocationInput): void {
  const stringFields = [
    "instanceId", "audience", "principal", "jobId", "evidenceMode",
    "clientNonce", "clientIdempotencyKey", "proof",
  ] as const;
  validateExactFields(input, "Challenge allocation", [...stringFields, "requestedAtMs"]);
  validateRequiredStringFields(input, "Challenge allocation", stringFields, ["principal"]);
  if (!LOWER_HEX_32.test(input.clientNonce)) {
    throw new TypeError("Challenge clientNonce must be 32 lowercase hexadecimal characters");
  }
  if (!ULID.test(input.jobId)) {
    throw new TypeError("Challenge jobId must be a canonical ULID");
  }
  if (!Number.isSafeInteger(input.requestedAtMs) || input.requestedAtMs < 0) {
    throw new TypeError("Challenge requestedAtMs must be a non-negative safe integer");
  }
  parseEvidenceMode(input.evidenceMode);
}

function validateAdmission(input: AdmissionInput): void {
  const stringFields = [
    "instanceId", "audience", "principal", "jobId", "evidenceMode",
    "nonce", "idempotencyKey", "requestHash", "proof",
  ] as const;
  validateExactFields(input, "Admission", stringFields);
  validateRequiredStringFields(input, "Admission", stringFields, ["principal"]);
  if (!LOWER_HEX_32.test(input.nonce)) {
    throw new TypeError("Admission nonce must be 32 lowercase hexadecimal characters");
  }
  if (!LOWER_HEX_64.test(input.requestHash)) {
    throw new TypeError("Admission requestHash must be 64 lowercase hexadecimal characters");
  }
  if (!ULID.test(input.jobId)) {
    throw new TypeError("Admission jobId must be a canonical ULID");
  }
  parseEvidenceMode(input.evidenceMode);
}

function validateRequiredStringFields(
  input: object,
  label: string,
  fields: readonly string[],
  nfcNormalizationFields: readonly string[] = [],
): void {
  const record = input as Record<string, unknown>;
  const normalizedByProtocol = new Set(nfcNormalizationFields);
  for (const name of fields) {
    const value = record[name];
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_LENGTH) {
      throw new TypeError(`${label} ${name} must be a bounded non-empty string`);
    }
    if (!isWellFormedUnicode(value)) {
      throw new TypeError(`${label} ${name} must contain only Unicode scalar values`);
    }
    if (!normalizedByProtocol.has(name) && value !== value.normalize("NFC")) {
      throw new TypeError(`${label} ${name} must already be NFC-normalized`);
    }
  }
}

function validateExactFields(input: object, label: string, fields: readonly string[]): void {
  const expected = new Set(fields);
  const actual = Object.keys(input);
  if (actual.length !== expected.size || actual.some((name) => !expected.has(name))) {
    throw new TypeError(`${label} must contain exactly the declared fields`);
  }
}

function snapshotRecord<T>(value: T, label: string): T {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return { ...value };
}

function validateConfiguredBinding(name: string, value: unknown): asserts value is string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_FIELD_LENGTH
    || !isWellFormedUnicode(value)
    || value !== value.normalize("NFC")
  ) throw new TypeError(`Configured ${name} must be a bounded NFC string`);
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

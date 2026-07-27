import {
  createHash,
  randomBytes as operatingSystemRandomBytes,
  timingSafeEqual,
} from "node:crypto";
import { canonicalize } from "../../protocol/canonical-json.ts";
import type { Dacs2KeyCurrentnessResolver } from "../keys/production-key-lifecycle.ts";
import type { DacsDatabase } from "./database.ts";
import { acquireAuthorityServiceLease, type AuthorityServiceLease } from "../authority-offline.ts";
import type {
  AdministratorCapabilityScope,
  CapabilityGrant,
  CapabilityOperation,
  CapabilityScope,
  PartyCapabilityScope,
} from "../../http/capability-authority.ts";
import {
  MAX_ADMINISTRATOR_CAPABILITY_MS,
  MAX_ADMINISTRATOR_CAPABILITY_HISTORY,
  MAX_CAPABILITY_SCOPE_BYTES,
  MAX_PARTY_CAPABILITY_HISTORY,
} from "../capability-limits.ts";

const ALLOCATION_DOMAIN = "dacs-forge:party-capability-allocation:v1:";
const EXCHANGE_DOMAIN = "dacs-forge:party-capability-exchange:v1:";
const RENEWAL_DOMAIN = "dacs-forge:party-capability-renewal:v1:";
const REVOCATION_DOMAIN = "dacs-forge:capability-revocation:v1:";
const AMENDMENT_DOMAIN = "dacs-forge:session-authority-amendment:v1:";
const CAPABILITY_BYTES = 32;
const CHALLENGE_BYTES = 16;
const CHALLENGE_LIFETIME_MS = 300_000;
const ALLOCATION_PAST_MS = 60_000;
const ALLOCATION_FUTURE_MS = 30_000;
const AUTHORITY_REQUEST_PAST_MS = 60_000;
const AUTHORITY_REQUEST_FUTURE_MS = 30_000;
const MAX_AGREEMENT_CAPABILITY_MS = 3_600_000;
const MAX_CHALLENGES_PER_JOB_ROLE = 4;
const MAX_COLLISION_ATTEMPTS = 8;
const MAX_FIELD_LENGTH = 4_096;
const MAX_ADMINISTRATOR_SESSION_RESULTS = 512;
const MAX_PREPARED_CAPABILITIES = 256;
const PREPARED_CAPABILITY_LIFETIME_MS = 300_000;
const LOWER_HEX_32 = /^[0-9a-f]{32}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

export interface AuthorityProofVerifier {
  verify(input: Readonly<{
    readonly key: string;
    readonly proof: string;
    readonly signedBytes: string;
  }>): boolean;
}

export class CapabilityPreparationLimitError extends Error {
  override readonly name = "CapabilityPreparationLimitError";
}

export class AdministratorSessionLimitError extends Error {
  override readonly name = "AdministratorSessionLimitError";
}

export class CapabilityHistoryLimitError extends Error {
  override readonly name = "CapabilityHistoryLimitError";
}

export type PartyAuthorityResolution =
  | Readonly<{
    readonly disposition: "current";
    readonly principal: string;
    readonly authority: Readonly<{
      readonly kind: "admission";
      readonly key: string;
    }>;
  }>
  | Readonly<{
    readonly disposition: "current";
    readonly principal: string;
    readonly authority: Readonly<{
      readonly kind: "agreement";
      readonly key: string;
      readonly agreementHash: string;
      readonly counterpartyKey: string;
    }>;
  }>
  | Readonly<{ readonly disposition: "unavailable" }>;

export interface PartyAuthorityResolver {
  resolve(input: Readonly<{
    readonly checkedAt: number;
    readonly jobId: string;
    readonly role: "buyer" | "seller";
  }>): PartyAuthorityResolution;
}

export interface PartyChallengeAllocationInput {
  readonly clientIdempotencyKey: string;
  readonly clientNonce: string;
  readonly jobId: string;
  readonly operations: readonly CapabilityOperation[];
  readonly principal: string;
  readonly proof: string;
  readonly requestedAtMs: number;
  readonly role: "buyer" | "seller";
}

export interface PartyChallengeRecord {
  readonly expiresAtMs: number;
  readonly issuedAtMs: number;
  readonly jobId: string;
  readonly nonce: string;
  readonly role: "buyer" | "seller";
}

export type PartyChallengeAllocationResult =
  | Readonly<{
    readonly disposition: "created" | "replayed";
    readonly challenge: PartyChallengeRecord;
  }>
  | Readonly<{ readonly disposition: "conflict" | "quota-exceeded" | "rejected" }>;

export interface PartyCapabilityExchangeInput {
  readonly expiresAtMs: number;
  readonly nonce: string;
  readonly proof: string;
  readonly replacementToken: string;
}

export type PartyCapabilityExchangeResult =
  | Readonly<{ readonly disposition: "created"; readonly grant: CapabilityGrant<PartyCapabilityScope> }>
  | Readonly<{ readonly disposition: "quota-exceeded" | "rejected" }>;

export interface SessionAuthorityAmendment {
  readonly agreementHash: string;
  readonly anchor: string;
  readonly buyerProof: string;
  readonly counterpartyKey: string;
  readonly expiresAtMs: number;
  readonly jobId: string;
  readonly newKey: string;
  readonly oldKey: string;
  readonly operations: readonly CapabilityOperation[];
  readonly role: "buyer" | "seller";
  readonly sellerProof: string;
}

export interface SessionAuthorityAmendmentVerifier {
  verifyAnchor(input: Readonly<{
    readonly agreementHash: string;
    readonly anchor: string;
    readonly digest: string;
    readonly jobId: string;
  }>): boolean;
}

export interface PartyAuthorityLifecycleOptions {
  readonly audience: string;
  readonly instanceId: string;
  readonly keyCurrentness: Dacs2KeyCurrentnessResolver;
  readonly now?: () => number;
  readonly partyAuthority: PartyAuthorityResolver;
  readonly proofVerifier: AuthorityProofVerifier;
  readonly randomBytes?: (size: number) => Uint8Array;
}

interface InstanceRow {
  readonly audience: string;
  readonly generation: bigint;
  readonly instanceId: string;
  readonly recoveryKey: string;
}

interface CapabilityRow {
  readonly agreementHash: string | null;
  readonly audience: string;
  readonly authorityKey: string | null;
  readonly authorityKind: "admission" | "agreement" | null;
  readonly capabilityDigest: string;
  readonly configuredKey: string | null;
  readonly expiresAtMs: bigint;
  readonly generation: bigint;
  readonly instanceId: string;
  readonly issuedAtMs: bigint;
  readonly jobId: string | null;
  readonly kind: "administrator" | "party";
  readonly operationsJson: string;
  readonly principal: string;
  readonly role: "buyer" | "seller" | null;
  readonly state: "active" | "revoked";
}

interface ChallengeRow {
  readonly agreementHash: string | null;
  readonly allocationFingerprint: string;
  readonly audience: string;
  readonly authorityKey: string;
  readonly authorityKind: "admission" | "agreement";
  readonly consumedAtMs: bigint | null;
  readonly expiresAtMs: bigint;
  readonly generation: bigint;
  readonly instanceId: string;
  readonly issuedAtMs: bigint;
  readonly jobId: string;
  readonly nonce: string;
  readonly operationsJson: string;
  readonly principal: string;
  readonly role: "buyer" | "seller";
}

interface AmendmentRow {
  readonly agreementHash: string;
  readonly expiresAtMs: bigint;
  readonly newKey: string;
  readonly oldKey: string;
  readonly operationsJson: string;
}

export class PartyAuthorityLifecycle {
  readonly #audience: string;
  readonly #exchange: (input: Readonly<{
    readonly exchange: PartyCapabilityExchangeInput;
    readonly token: string;
    readonly digest: string;
  }>) => PartyCapabilityExchangeResult;
  readonly #instanceId: string;
  readonly #keyCurrentness: Dacs2KeyCurrentnessResolver;
  readonly #now: () => number;
  readonly #partyAuthority: PartyAuthorityResolver;
  readonly #proofVerifier: AuthorityProofVerifier;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #serviceLease: AuthorityServiceLease;
  #closed = false;

  constructor(
    private readonly database: DacsDatabase,
    options: PartyAuthorityLifecycleOptions,
  ) {
    validateField("instanceId", options?.instanceId);
    validateField("audience", options?.audience);
    if (options.keyCurrentness?.resolve === undefined
      || options.partyAuthority?.resolve === undefined
      || options.proofVerifier?.verify === undefined) {
      throw new TypeError("Party authority lifecycle requires proof and currentness authorities");
    }
    this.#instanceId = options.instanceId;
    this.#audience = options.audience;
    this.#keyCurrentness = options.keyCurrentness;
    this.#partyAuthority = options.partyAuthority;
    this.#proofVerifier = options.proofVerifier;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? operatingSystemRandomBytes;
    this.#safeNow();
    const databaseFile = database.query<{ file: string }, []>("PRAGMA database_list").all()
      .find((entry) => entry.file !== "")?.file;
    if (databaseFile === undefined) {
      throw new Error("Party authority lifecycle requires a persistent database path");
    }
    this.#serviceLease = acquireAuthorityServiceLease(databaseFile);
    const exchange = database.transaction((input: Readonly<{
      readonly exchange: PartyCapabilityExchangeInput;
      readonly token: string;
      readonly digest: string;
    }>) => this.#exchangeTransaction(input));
    this.#exchange = (input) => exchange.immediate(input) as PartyCapabilityExchangeResult;
  }

  allocatePartyChallenge(input: PartyChallengeAllocationInput): PartyChallengeAllocationResult {
    this.#assertOpen();
    let snapshot: PartyChallengeAllocationInput;
    try {
      snapshot = normalizeAllocation(input);
    } catch {
      return Object.freeze({ disposition: "rejected" });
    }
    const now = this.#safeNow();
    if (snapshot.requestedAtMs < now - ALLOCATION_PAST_MS
      || snapshot.requestedAtMs > now + ALLOCATION_FUTURE_MS) {
      return Object.freeze({ disposition: "rejected" });
    }
    const authority = this.#resolvedAuthority(snapshot.jobId, snapshot.role, now);
    if (authority === null || authority.principal !== snapshot.principal) {
      return Object.freeze({ disposition: "rejected" });
    }
    if (authority.operations !== null
      && !snapshot.operations.every((operation) => authority.operations!.includes(operation))) {
      return Object.freeze({ disposition: "rejected" });
    }
    const signedBytes = partyChallengeAllocationSigningBytes(snapshot);
    if (!this.#proofVerifier.verify({
      key: authority.key,
      proof: snapshot.proof,
      signedBytes,
    })) return Object.freeze({ disposition: "rejected" });
    const fingerprint = hashHex(signedBytes);
    return this.database.transaction(() => {
      const instance = this.#instance();
      if (instance === null) return Object.freeze({ disposition: "rejected" as const });
      this.database.query<never, { now: number; instanceId: string; audience: string }>(`
        /* atomic-write: party-authority.cleanup-challenges */
        DELETE FROM party_authority_challenges
        WHERE retain_until_ms <= $now AND instance_id = $instanceId AND audience = $audience
      `).run({ now, instanceId: this.#instanceId, audience: this.#audience });
      const existing = this.database.query<ChallengeRow, {
        instanceId: string; audience: string; principal: string;
        clientNonce: string; clientIdempotencyKey: string;
      }>(`
        SELECT nonce, instance_id AS instanceId, audience, principal, job_id AS jobId,
          role, operations_json AS operationsJson, authority_kind AS authorityKind,
          authority_key AS authorityKey, agreement_hash AS agreementHash,
          allocation_fingerprint AS allocationFingerprint, issued_at_ms AS issuedAtMs,
          expires_at_ms AS expiresAtMs, consumed_at_ms AS consumedAtMs, generation
        FROM party_authority_challenges
        WHERE instance_id = $instanceId AND audience = $audience AND principal = $principal
          AND (client_nonce = $clientNonce OR client_idempotency_key = $clientIdempotencyKey)
        LIMIT 1
      `).get({
        instanceId: this.#instanceId,
        audience: this.#audience,
        principal: snapshot.principal,
        clientNonce: snapshot.clientNonce,
        clientIdempotencyKey: snapshot.clientIdempotencyKey,
      });
      if (existing !== null) {
        if (existing.allocationFingerprint !== fingerprint
          || existing.generation !== instance.generation
          || existing.consumedAtMs !== null) {
          return Object.freeze({ disposition: "conflict" as const });
        }
        return Object.freeze({
          disposition: "replayed" as const,
          challenge: challengeRecord(existing),
        });
      }
      const count = this.database.query<{ count: bigint }, {
        instanceId: string; audience: string; jobId: string; role: string; now: number;
      }>(`
        SELECT count(*) AS count FROM party_authority_challenges
        WHERE instance_id = $instanceId AND audience = $audience
          AND job_id = $jobId AND role = $role AND expires_at_ms > $now
          AND consumed_at_ms IS NULL
      `).get({
        instanceId: this.#instanceId,
        audience: this.#audience,
        jobId: snapshot.jobId,
        role: snapshot.role,
        now,
      })?.count ?? 0n;
      if (count >= BigInt(MAX_CHALLENGES_PER_JOB_ROLE)) {
        return Object.freeze({ disposition: "quota-exceeded" as const });
      }
      const nonce = this.#uniqueNonce();
      const expiresAtMs = now + CHALLENGE_LIFETIME_MS;
      this.database.query<never, Record<string, string | number | null>>(`
        /* atomic-write: party-authority.allocate-challenge */
        INSERT INTO party_authority_challenges (
          nonce, instance_id, audience, principal, job_id, role, operations_json,
          authority_kind, authority_key, agreement_hash, client_nonce,
          client_idempotency_key, allocation_fingerprint, requested_at_ms,
          issued_at_ms, expires_at_ms, retain_until_ms, consumed_at_ms, generation
        ) VALUES (
          $nonce, $instanceId, $audience, $principal, $jobId, $role, $operationsJson,
          $authorityKind, $authorityKey, $agreementHash, $clientNonce,
          $clientIdempotencyKey, $fingerprint, $requestedAtMs,
          $issuedAtMs, $expiresAtMs, $expiresAtMs, NULL, $generation
        )
      `).run({
        nonce,
        instanceId: this.#instanceId,
        audience: this.#audience,
        principal: snapshot.principal,
        jobId: snapshot.jobId,
        role: snapshot.role,
        operationsJson: canonicalize(snapshot.operations),
        authorityKind: authority.kind,
        authorityKey: authority.key,
        agreementHash: authority.agreementHash,
        clientNonce: snapshot.clientNonce,
        clientIdempotencyKey: snapshot.clientIdempotencyKey,
        fingerprint,
        requestedAtMs: snapshot.requestedAtMs,
        issuedAtMs: now,
        expiresAtMs,
        generation: Number(instance.generation),
      });
      return Object.freeze({
        disposition: "created" as const,
        challenge: Object.freeze({ nonce, issuedAtMs: now, expiresAtMs, jobId: snapshot.jobId,
          role: snapshot.role }),
      });
    }).immediate() as PartyChallengeAllocationResult;
  }

  exchangePartyChallenge(input: PartyCapabilityExchangeInput): PartyCapabilityExchangeResult {
    this.#assertOpen();
    let exchange: PartyCapabilityExchangeInput;
    try {
      exchange = normalizeExchange(input);
    } catch {
      return Object.freeze({ disposition: "rejected" });
    }
    let grant: Readonly<{ token: string; digest: string }>;
    try {
      grant = this.#preparedGrant(exchange.replacementToken, this.#safeNow());
    } catch {
      return Object.freeze({ disposition: "rejected" });
    }
    const { token, digest } = grant;
    try {
      return this.#exchange(Object.freeze({ exchange, token, digest }));
    } catch (error) {
      if (error instanceof CapabilityHistoryLimitError) {
        return Object.freeze({ disposition: "quota-exceeded" });
      }
      throw error;
    }
  }

  prepareCapabilityReplacement(): string {
    this.#assertOpen();
    const now = this.#safeNow();
    return this.database.transaction(() => {
      this.database.query<never, { instanceId: string; audience: string; now: number }>(`
        /* atomic-write: party-authority.cleanup-preparations */
        DELETE FROM party_capability_preparations
        WHERE instance_id = $instanceId AND audience = $audience AND expires_at_ms <= $now
      `).run({ instanceId: this.#instanceId, audience: this.#audience, now });
      const count = this.database.query<{ count: bigint }, { instanceId: string; audience: string }>(`
        SELECT count(*) AS count FROM party_capability_preparations
        WHERE instance_id = $instanceId AND audience = $audience
      `).get({ instanceId: this.#instanceId, audience: this.#audience })?.count ?? 0n;
      if (count >= BigInt(MAX_PREPARED_CAPABILITIES)) {
        throw new CapabilityPreparationLimitError("Prepared capability capacity is exhausted");
      }
      for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
        const token = this.#token("capability replacement");
        const digest = hashHex(token);
        if (this.#digestExists(digest) || this.#preparationExists(digest)) continue;
        this.database.query<never, {
          digest: string; instanceId: string; audience: string; now: number; expiresAtMs: number;
        }>(`
          /* atomic-write: party-authority.prepare-capability */
          INSERT INTO party_capability_preparations (
            capability_digest, instance_id, audience, created_at_ms, expires_at_ms
          ) VALUES ($digest, $instanceId, $audience, $now, $expiresAtMs)
        `).run({
          digest,
          instanceId: this.#instanceId,
          audience: this.#audience,
          now,
          expiresAtMs: now + PREPARED_CAPABILITY_LIFETIME_MS,
        });
        return token;
      }
      throw new Error("Capability entropy provider produced repeated collisions");
    }).immediate() as string;
  }

  authorize(token: string, expectedScope: CapabilityScope): boolean {
    this.#assertOpen();
    if (!LOWER_HEX_64.test(token)) return false;
    let scope: CapabilityScope;
    try {
      scope = normalizeScope(expectedScope);
    } catch {
      return false;
    }
    const now = this.#safeNow();
    const row = this.#matchingActiveDigest(token, now);
    if (row === null || canonicalize(scope) !== canonicalize(scopeFromRow(row))) return false;
    if (row.instanceId !== this.#instanceId || row.audience !== this.#audience) return false;
    return this.#rowAuthorityCurrent(row, now);
  }

  renew(input: Readonly<{
    readonly expiresAtMs: number;
    readonly proof: string;
    readonly replacementToken: string;
    readonly requestedAtMs: number;
    readonly token: string;
  }>): CapabilityGrant {
    this.#assertOpen();
    const now = this.#safeNow();
    if (!requestIsCurrent(input.requestedAtMs, now)
      || !Number.isSafeInteger(input.expiresAtMs)
      || input.expiresAtMs <= now || !LOWER_HEX_64.test(input.token)
      || !LOWER_HEX_64.test(input.replacementToken)) {
      throw new TypeError("Capability renewal request is invalid");
    }
    const row = this.#matchingActiveDigest(input.token, now);
    if (row === null || !this.#rowAuthorityCurrent(row, now)) {
      throw new Error("Capability renewal authority is unavailable");
    }
    if (row.kind === "party" && row.authorityKind === "agreement"
      && input.expiresAtMs > now + MAX_AGREEMENT_CAPABILITY_MS) {
      throw new Error("Agreement capability renewal exceeds one hour");
    }
    if (row.kind === "administrator"
      && input.expiresAtMs > now + MAX_ADMINISTRATOR_CAPABILITY_MS) {
      throw new Error("Administrator capability renewal exceeds one day");
    }
    const key = row.kind === "administrator" ? row.configuredKey : row.authorityKey;
    if (key === null || !this.#proofVerifier.verify({
      key,
      proof: input.proof,
      signedBytes: capabilityRenewalSigningBytes({
        tokenDigest: hashHex(input.token),
        replacementDigest: hashHex(input.replacementToken),
        requestedAtMs: input.requestedAtMs,
        expiresAtMs: input.expiresAtMs,
      }),
    })) throw new Error("Capability renewal proof is invalid");
    const previous = scopeFromRow(row);
    const replacement = normalizeScope({ ...previous, expiresAtMs: input.expiresAtMs });
    const grant = this.#preparedGrant(input.replacementToken, now);
    this.database.transaction(() => {
      this.#revokeDigest(row.capabilityDigest, now);
      this.#insertGrantRow(grant.digest, replacement, Number(row.generation), now, row.agreementHash);
      this.#consumePrepared(grant.digest, now);
    }).immediate();
    const { token } = grant;
    return Object.freeze({ token, scope: replacement });
  }

  revoke(input: Readonly<{
    readonly authorization: string;
    readonly proof: string;
    readonly requestedAtMs: number;
    readonly targetToken: string;
  }>): void {
    this.#assertOpen();
    const now = this.#safeNow();
    if (!requestIsCurrent(input.requestedAtMs, now) || !LOWER_HEX_64.test(input.authorization)
      || !LOWER_HEX_64.test(input.targetToken)) throw new TypeError("Capability revocation request is invalid");
    const actor = this.#matchingActiveDigest(input.authorization, now);
    const target = this.#matchingActiveDigest(input.targetToken, now);
    if (actor === null || target === null
      || !this.#rowAuthorityCurrent(actor, now)) throw new Error("Capability revocation is unauthorized");
    const self = constantDigestEqual(actor.capabilityDigest, target.capabilityDigest);
    const actorOperations = operationsFrom(rowOperations(actor));
    if (!self && (actor.kind !== "administrator" || !actorOperations.includes("capability:revoke"))) {
      throw new Error("Capability revocation is unauthorized");
    }
    const actorKey = actor.kind === "administrator" ? actor.configuredKey : actor.authorityKey;
    if (actorKey === null || !this.#proofVerifier.verify({
      key: actorKey,
      proof: input.proof,
      signedBytes: capabilityRevocationSigningBytes({
        authorizationDigest: actor.capabilityDigest,
        targetDigest: target.capabilityDigest,
        requestedAtMs: input.requestedAtMs,
      }),
    })) throw new Error("Capability revocation proof is invalid");
    this.database.transaction(() => {
      if (target.kind === "administrator"
        && !this.#hasOtherCurrentAdministrator(target.capabilityDigest, now)) {
        throw new Error("The last administrator cannot be revoked without an atomic replacement");
      }
      this.#revokeDigest(target.capabilityDigest, now);
    }).immediate();
  }

  rotateAdministrator(input: Readonly<{
    readonly authorization: string;
    readonly expiresAtMs: number;
    readonly newConfiguredKey: string;
    readonly newKeyProof: string;
    readonly newPrincipal: string;
    readonly operations: readonly CapabilityOperation[];
    readonly proof: string;
    readonly replacementToken: string;
    readonly requestedAtMs: number;
  }>): CapabilityGrant<AdministratorCapabilityScope> {
    this.#assertOpen();
    const now = this.#safeNow();
    if (!requestIsCurrent(input.requestedAtMs, now) || !LOWER_HEX_64.test(input.authorization)
      || !LOWER_HEX_64.test(input.replacementToken)) {
      throw new TypeError("Administrator rotation request is invalid");
    }
    const actor = this.#matchingActiveDigest(input.authorization, now);
    if (actor === null || actor.kind !== "administrator"
      || !operationsFrom(rowOperations(actor)).includes("administrator:rotate")
      || !this.#rowAuthorityCurrent(actor, now) || actor.configuredKey === null) {
      throw new Error("Administrator rotation is unauthorized");
    }
    const scope = normalizeScope({
      kind: "administrator",
      instanceId: this.#instanceId,
      audience: this.#audience,
      principal: input.newPrincipal,
      operations: input.operations,
      expiresAtMs: input.expiresAtMs,
      configuredKey: input.newConfiguredKey,
    }) as AdministratorCapabilityScope;
    if (scope.expiresAtMs <= now
      || scope.expiresAtMs > now + MAX_ADMINISTRATOR_CAPABILITY_MS) {
      throw new TypeError("Administrator replacement expiry must be within one day");
    }
    this.#assertKeyCurrent(scope.configuredKey, now);
    const signedBytes = administratorRotationSigningBytes({
      authorizationDigest: actor.capabilityDigest,
      replacementDigest: hashHex(input.replacementToken),
      replacementScope: scope,
      requestedAtMs: input.requestedAtMs,
    });
    if (!this.#proofVerifier.verify({
      key: actor.configuredKey,
      proof: validatedField("proof", input.proof),
      signedBytes,
    }) || !this.#proofVerifier.verify({
      key: scope.configuredKey,
      proof: validatedField("newKeyProof", input.newKeyProof),
      signedBytes,
    })) throw new Error("Administrator rotation proofs are invalid");
    const grant = this.#preparedGrant(input.replacementToken, now);
    this.database.transaction(() => {
      this.#insertGrantRow(grant.digest, scope, Number(actor.generation), now, null);
      this.#revokeDigest(actor.capabilityDigest, now);
      this.#consumePrepared(grant.digest, now);
    }).immediate();
    const { token } = grant;
    return Object.freeze({ token, scope });
  }

  applySessionAmendment(
    amendment: SessionAuthorityAmendment,
    verifier: SessionAuthorityAmendmentVerifier,
  ): void {
    this.#assertOpen();
    const snapshot = normalizeAmendment(amendment);
    const now = this.#safeNow();
    if (snapshot.expiresAtMs <= now) throw new Error("Session authority amendment is expired");
    const resolved = this.#partyAuthority.resolve({
      checkedAt: now,
      jobId: snapshot.jobId,
      role: snapshot.role,
    });
    if (resolved.disposition !== "current" || resolved.authority.kind !== "agreement"
      || resolved.authority.key !== snapshot.oldKey
      || resolved.authority.agreementHash !== snapshot.agreementHash) {
      throw new Error("Session authority amendment does not match committed authority");
    }
    if (snapshot.oldKey === snapshot.counterpartyKey
      || snapshot.newKey === snapshot.counterpartyKey) {
      throw new Error("Session authority amendment requires distinct party keys");
    }
    this.#assertKeyCurrent(snapshot.newKey, now);
    const signedBytes = sessionAuthorityAmendmentSigningBytes(snapshot);
    const replacementProof = snapshot.role === "buyer" ? snapshot.buyerProof : snapshot.sellerProof;
    const counterpartyProof = snapshot.role === "buyer" ? snapshot.sellerProof : snapshot.buyerProof;
    if (!this.#proofVerifier.verify({
      key: snapshot.newKey,
      proof: replacementProof,
      signedBytes,
    }) || !this.#proofVerifier.verify({
      key: snapshot.counterpartyKey,
      proof: counterpartyProof,
      signedBytes,
    })) {
      throw new Error("Session authority amendment requires both party proofs");
    }
    const digest = hashHex(signedBytes);
    if (verifier.verifyAnchor({
      agreementHash: snapshot.agreementHash,
      anchor: snapshot.anchor,
      digest,
      jobId: snapshot.jobId,
    }) !== true) throw new Error("Session authority amendment anchor is invalid");
    this.database.transaction(() => {
      const existing = this.database.query<{ amendmentDigest: string }, {
        jobId: string; role: string;
      }>(`
        SELECT amendment_digest AS amendmentDigest FROM party_authority_amendments
        WHERE job_id = $jobId AND role = $role
      `).get({ jobId: snapshot.jobId, role: snapshot.role });
      if (existing?.amendmentDigest === digest) return;
      if (existing !== null) {
        throw new Error("Session authority amendment is already fixed for this role");
      }
      const counterparty = this.#resolvedAuthority(
        snapshot.jobId,
        snapshot.role === "buyer" ? "seller" : "buyer",
        now,
      );
      if (counterparty === null || counterparty.kind !== "agreement"
        || counterparty.agreementHash !== snapshot.agreementHash
        || counterparty.key !== snapshot.counterpartyKey) {
        throw new Error("Session authority amendment does not match current counterparty authority");
      }
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: party-authority.apply-amendment */
        INSERT INTO party_authority_amendments (
          job_id, role, agreement_hash, old_key, new_key, operations_json,
          expires_at_ms, anchor, amendment_digest, applied_at_ms
        ) VALUES (
          $jobId, $role, $agreementHash, $oldKey, $newKey, $operationsJson,
          $expiresAtMs, $anchor, $digest, $appliedAtMs
        )
      `).run({
        agreementHash: snapshot.agreementHash,
        anchor: snapshot.anchor,
        expiresAtMs: snapshot.expiresAtMs,
        jobId: snapshot.jobId,
        newKey: snapshot.newKey,
        oldKey: snapshot.oldKey,
        role: snapshot.role,
        operationsJson: canonicalize(snapshot.operations),
        digest,
        appliedAtMs: now,
      });
      this.database.query<never, { jobId: string; role: string; now: number }>(`
        /* atomic-write: party-authority.invalidate-amended-capabilities */
        UPDATE party_capabilities SET state = 'revoked', revoked_at_ms = $now
        WHERE job_id = $jobId AND role = $role AND state = 'active'
      `).run({ jobId: snapshot.jobId, role: snapshot.role, now });
      this.database.query<never, { jobId: string; role: string; now: number }>(`
        /* atomic-write: party-authority.invalidate-amended-challenges */
        UPDATE party_authority_challenges SET consumed_at_ms = $now
        WHERE job_id = $jobId AND role = $role AND consumed_at_ms IS NULL
      `).run({ jobId: snapshot.jobId, role: snapshot.role, now });
    }).immediate();
  }

  listAdministratorSessions(token: string): readonly string[] {
    this.#assertOpen();
    const now = this.#safeNow();
    const row = this.#matchingActiveDigest(token, now);
    if (row === null || row.kind !== "administrator"
      || !operationsFrom(rowOperations(row)).includes("session:inspect")
      || !this.#rowAuthorityCurrent(row, now)) throw new Error("Session inspection is unauthorized");
    const rows = this.database.query<{ jobId: string }, {
      instanceId: string; audience: string;
    }>(`
      SELECT job_id AS jobId FROM sessions
      WHERE instance_id = $instanceId AND audience = $audience
      ORDER BY job_id
      LIMIT 513
    `).all({ instanceId: this.#instanceId, audience: this.#audience });
    if (rows.length > MAX_ADMINISTRATOR_SESSION_RESULTS) {
      throw new AdministratorSessionLimitError("Administrator session result exceeds its bound");
    }
    return Object.freeze(rows.map((item) => item.jobId));
  }

  #exchangeTransaction(input: Readonly<{
    readonly exchange: PartyCapabilityExchangeInput;
    readonly token: string;
    readonly digest: string;
  }>): PartyCapabilityExchangeResult {
    const now = this.#safeNow();
    const row = this.database.query<ChallengeRow, { nonce: string }>(`
      SELECT nonce, instance_id AS instanceId, audience, principal, job_id AS jobId,
        role, operations_json AS operationsJson, authority_kind AS authorityKind,
        authority_key AS authorityKey, agreement_hash AS agreementHash,
        allocation_fingerprint AS allocationFingerprint, issued_at_ms AS issuedAtMs,
        expires_at_ms AS expiresAtMs, consumed_at_ms AS consumedAtMs, generation
      FROM party_authority_challenges WHERE nonce = $nonce
    `).get({ nonce: input.exchange.nonce });
    const instance = this.#instance();
    if (row === null || instance === null || row.instanceId !== this.#instanceId
      || row.audience !== this.#audience || row.generation !== instance.generation
      || row.consumedAtMs !== null || Number(row.expiresAtMs) <= now
      || input.exchange.expiresAtMs <= now) return Object.freeze({ disposition: "rejected" });
    if (row.authorityKind === "agreement"
      && input.exchange.expiresAtMs > now + MAX_AGREEMENT_CAPABILITY_MS) {
      return Object.freeze({ disposition: "rejected" });
    }
    let scope: PartyCapabilityScope;
    try {
      scope = normalizeScope(scopeFromChallenge(row, input.exchange.expiresAtMs)) as PartyCapabilityScope;
    } catch {
      return Object.freeze({ disposition: "rejected" });
    }
    if (!this.#authorityCurrentForScope(scope, now, row.agreementHash)
      || !this.#proofVerifier.verify({
        key: row.authorityKey,
        proof: input.exchange.proof,
        signedBytes: partyCapabilityExchangeSigningBytes({
          nonce: row.nonce,
          replacementDigest: input.digest,
          scope,
        }),
      })) return Object.freeze({ disposition: "rejected" });
    const consumed = this.database.query<never, { nonce: string; now: number }>(`
      /* atomic-write: party-authority.consume-challenge */
      UPDATE party_authority_challenges SET consumed_at_ms = $now
      WHERE nonce = $nonce AND consumed_at_ms IS NULL AND expires_at_ms > $now
    `).run({ nonce: row.nonce, now });
    if (consumed.changes !== 1) return Object.freeze({ disposition: "rejected" });
    this.#insertGrantRow(input.digest, scope, Number(row.generation), now, row.agreementHash);
    this.#consumePrepared(input.digest, now);
    return Object.freeze({
      disposition: "created",
      grant: Object.freeze({ token: input.token, scope }),
    });
  }

  #preparedGrant(token: string, now: number): Readonly<{ token: string; digest: string }> {
    const digest = hashHex(token);
    const prepared = this.database.query<{ found: bigint }, {
      digest: string; instanceId: string; audience: string; now: number;
    }>(`
      SELECT count(*) AS found FROM party_capability_preparations
      WHERE capability_digest = $digest AND instance_id = $instanceId
        AND audience = $audience AND expires_at_ms > $now
    `).get({
      digest,
      instanceId: this.#instanceId,
      audience: this.#audience,
      now,
    })?.found ?? 0n;
    if (prepared !== 1n || this.#digestExists(digest)) {
      throw new Error("Replacement capability was not prepared by this service instance");
    }
    return Object.freeze({ token, digest });
  }

  #preparationExists(digest: string): boolean {
    return this.database.query<{ found: bigint }, { digest: string }>(
      "SELECT count(*) AS found FROM party_capability_preparations WHERE capability_digest = $digest",
    ).get({ digest })?.found !== 0n;
  }

  #consumePrepared(digest: string, now: number): void {
    const consumed = this.database.query<never, {
      digest: string; instanceId: string; audience: string; now: number;
    }>(`
      /* atomic-write: party-authority.consume-preparation */
      DELETE FROM party_capability_preparations
      WHERE capability_digest = $digest AND instance_id = $instanceId
        AND audience = $audience AND expires_at_ms > $now
    `).run({ digest, instanceId: this.#instanceId, audience: this.#audience, now });
    if (consumed.changes !== 1) throw new Error("Capability preparation raced");
  }

  #digestExists(digest: string): boolean {
    return this.database.query<{ found: bigint }, { digest: string }>(
      "SELECT count(*) AS found FROM party_capabilities WHERE capability_digest = $digest",
    ).get({ digest })?.found !== 0n;
  }

  #insertGrantRow(
    digest: string,
    scope: CapabilityScope,
    generation: number,
    issuedAtMs: number,
    agreementHash: string | null,
  ): void {
    const party = scope.kind === "party" ? scope : null;
    if ((party?.authority.kind === "agreement") !== (agreementHash !== null)) {
      throw new Error("Capability agreement binding is inconsistent");
    }
    if (scope.kind === "party") {
      this.database.query<never, {
        instanceId: string; audience: string; issuedAtMs: number;
      }>(`
        /* atomic-write: party-authority.reclaim-party-capabilities */
        DELETE FROM party_capabilities
        WHERE instance_id = $instanceId AND audience = $audience AND kind = 'party'
          AND (state = 'revoked' OR expires_at_ms <= $issuedAtMs)
      `).run({
        instanceId: scope.instanceId,
        audience: scope.audience,
        issuedAtMs,
      });
    }
    const historyLimit = scope.kind === "administrator"
      ? MAX_ADMINISTRATOR_CAPABILITY_HISTORY : MAX_PARTY_CAPABILITY_HISTORY;
    const history = this.database.query<{ count: bigint }, {
      instanceId: string; audience: string; kind: string;
    }>(`
      SELECT count(*) AS count FROM party_capabilities
      WHERE instance_id = $instanceId AND audience = $audience AND kind = $kind
    `).get({ instanceId: scope.instanceId, audience: scope.audience, kind: scope.kind })?.count ?? 0n;
    if (history >= BigInt(historyLimit)) {
      throw new CapabilityHistoryLimitError("Capability history capacity is exhausted");
    }
    this.database.query<never, Record<string, string | number | null>>(`
      /* atomic-write: party-authority.issue-capability */
      INSERT INTO party_capabilities (
        capability_digest, instance_id, audience, kind, principal, operations_json,
        expires_at_ms, configured_key, job_id, role, authority_kind, authority_key,
        agreement_hash, state, issued_at_ms, revoked_at_ms, generation
      ) VALUES (
        $digest, $instanceId, $audience, $kind, $principal, $operationsJson,
        $expiresAtMs, $configuredKey, $jobId, $role, $authorityKind, $authorityKey,
        $agreementHash, 'active', $issuedAtMs, NULL, $generation
      )
    `).run({
      digest,
      instanceId: scope.instanceId,
      audience: scope.audience,
      kind: scope.kind,
      principal: scope.principal,
      operationsJson: canonicalize(scope.operations),
      expiresAtMs: scope.expiresAtMs,
      configuredKey: scope.kind === "administrator" ? scope.configuredKey : null,
      jobId: party?.jobId ?? null,
      role: party?.role ?? null,
      authorityKind: party?.authority.kind ?? null,
      authorityKey: party?.authority.key ?? null,
      agreementHash,
      issuedAtMs,
      generation,
    });
  }

  #revokeDigest(digest: string, now: number): void {
    const changed = this.database.query<never, { digest: string; now: number }>(`
      /* atomic-write: party-authority.revoke-capability */
      UPDATE party_capabilities SET state = 'revoked', revoked_at_ms = $now
      WHERE capability_digest = $digest AND state = 'active'
    `).run({ digest, now });
    if (changed.changes !== 1) throw new Error("Capability revocation raced");
  }

  #matchingActiveDigest(token: string, now: number): CapabilityRow | null {
    const digest = hashHex(token);
    const row = this.database.query<CapabilityRow, {
      digest: string; instanceId: string; audience: string; now: number;
    }>(`
      SELECT capability_digest AS capabilityDigest, instance_id AS instanceId, audience,
        kind, principal, operations_json AS operationsJson, expires_at_ms AS expiresAtMs,
        configured_key AS configuredKey, job_id AS jobId, role,
        authority_kind AS authorityKind, authority_key AS authorityKey,
        agreement_hash AS agreementHash, state, issued_at_ms AS issuedAtMs, generation
      FROM party_capabilities
      WHERE capability_digest = $digest AND instance_id = $instanceId
        AND audience = $audience AND state = 'active' AND expires_at_ms > $now
      LIMIT 1
    `).get({ digest, instanceId: this.#instanceId, audience: this.#audience, now });
    return row !== null && constantDigestEqual(digest, row.capabilityDigest) ? row : null;
  }

  #rowAuthorityCurrent(row: CapabilityRow, now: number): boolean {
    if (row.kind === "administrator") {
      if (row.configuredKey === null) return false;
      return this.#keyIsCurrent(row.configuredKey, now);
    }
    return this.#authorityCurrentForScope(
      scopeFromRow(row) as PartyCapabilityScope,
      now,
      row.agreementHash,
    );
  }

  #authorityCurrentForScope(
    scope: PartyCapabilityScope,
    now: number,
    agreementHash: string | null,
  ): boolean {
    const resolved = this.#resolvedAuthority(scope.jobId, scope.role, now);
    return resolved !== null && resolved.kind === scope.authority.kind
      && resolved.key === scope.authority.key && resolved.principal === scope.principal
      && resolved.agreementHash === agreementHash
      && (resolved.operations === null
        || scope.operations.every((operation) => resolved.operations!.includes(operation)));
  }

  #resolvedAuthority(
    jobId: string,
    role: "buyer" | "seller",
    now: number,
  ): null | Readonly<{
    readonly principal: string;
    readonly kind: "admission" | "agreement";
    readonly key: string;
    readonly agreementHash: string | null;
    readonly operations: readonly CapabilityOperation[] | null;
  }> {
    const resolved = this.#partyAuthority.resolve({ checkedAt: now, jobId, role });
    if (resolved.disposition !== "current") return null;
    validateField("resolved principal", resolved.principal);
    validateField("resolved key", resolved.authority.key);
    if (resolved.authority.kind === "admission") {
      if (!this.#keyIsCurrent(resolved.authority.key, now)) return null;
      return Object.freeze({
        principal: resolved.principal,
        kind: "admission" as const,
        key: resolved.authority.key,
        agreementHash: null,
        operations: null,
      });
    }
    validateHash(resolved.authority.agreementHash, "agreementHash");
    const amendment = this.#amendment(jobId, role);
    if (amendment === null) {
      if (!this.#keyIsCurrent(resolved.authority.key, now)) return null;
      return Object.freeze({
        principal: resolved.principal,
        kind: "agreement" as const,
        key: resolved.authority.key,
        agreementHash: resolved.authority.agreementHash,
        operations: null,
      });
    }
    if (amendment.agreementHash !== resolved.authority.agreementHash
      || amendment.oldKey !== resolved.authority.key
      || Number(amendment.expiresAtMs) <= now
      || !this.#keyIsCurrent(amendment.newKey, now)) return null;
    return Object.freeze({
      principal: resolved.principal,
      kind: "agreement" as const,
      key: amendment.newKey,
      agreementHash: amendment.agreementHash,
      operations: operationsFrom(amendment.operationsJson),
    });
  }

  #amendment(jobId: string, role: "buyer" | "seller"): AmendmentRow | null {
    return this.database.query<AmendmentRow, { jobId: string; role: string }>(`
      SELECT agreement_hash AS agreementHash, old_key AS oldKey, new_key AS newKey,
        operations_json AS operationsJson, expires_at_ms AS expiresAtMs
      FROM party_authority_amendments WHERE job_id = $jobId AND role = $role
    `).get({ jobId, role });
  }

  #keyIsCurrent(key: string, checkedAt: number): boolean {
    try {
      const result = this.#keyCurrentness.resolve({ keyClaim: key, checkedAt });
      return result.disposition === "current" && result.currentClaim === key
        && result.checkedAt === checkedAt;
    } catch {
      return false;
    }
  }

  #assertKeyCurrent(key: string, checkedAt: number): void {
    if (!this.#keyIsCurrent(key, checkedAt)) throw new Error("Capability key is not current");
  }

  #hasOtherCurrentAdministrator(excludedDigest: string, now: number): boolean {
    const rows = this.database.query<{ configuredKey: string }, {
      excludedDigest: string; instanceId: string; audience: string; now: number;
    }>(`
      SELECT configured_key AS configuredKey FROM party_capabilities
      WHERE instance_id = $instanceId AND audience = $audience
        AND kind = 'administrator' AND state = 'active' AND expires_at_ms > $now
        AND capability_digest <> $excludedDigest
    `).all({
      excludedDigest,
      instanceId: this.#instanceId,
      audience: this.#audience,
      now,
    });
    return rows.some((row) => this.#keyIsCurrent(row.configuredKey, now));
  }

  #instance(): InstanceRow | null {
    return this.database.query<InstanceRow, { instanceId: string; audience: string }>(`
      SELECT instance_id AS instanceId, audience, recovery_key AS recoveryKey, generation
      FROM party_authority_instances
      WHERE instance_id = $instanceId AND audience = $audience
    `).get({ instanceId: this.#instanceId, audience: this.#audience });
  }

  #uniqueNonce(): string {
    for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
      const nonce = Buffer.from(this.#entropy(CHALLENGE_BYTES, "challenge")).toString("hex");
      const exists = this.database.query<{ found: bigint }, { nonce: string }>(
        "SELECT count(*) AS found FROM party_authority_challenges WHERE nonce = $nonce",
      ).get({ nonce })?.found ?? 0n;
      if (exists === 0n) return nonce;
    }
    throw new Error("Party challenge entropy provider produced repeated collisions");
  }

  #token(stage: string): string {
    return Buffer.from(this.#entropy(CAPABILITY_BYTES, stage)).toString("hex");
  }

  #entropy(size: number, stage: string): Uint8Array {
    const bytes = this.#randomBytes(size);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== size) {
      throw new Error(`${stage} entropy provider must return exactly ${size} bytes`);
    }
    return Uint8Array.from(bytes);
  }

  #safeNow(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("Authority clock is invalid");
    return now;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#serviceLease.close();
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error("Party authority lifecycle is closed");
    this.#serviceLease.assertActive();
  }
}

export function partyChallengeAllocationSigningBytes(
  input: Omit<PartyChallengeAllocationInput, "proof">,
): string {
  return `${ALLOCATION_DOMAIN}${canonicalize({
    clientIdempotencyKey: input.clientIdempotencyKey,
    clientNonce: input.clientNonce,
    jobId: input.jobId,
    operations: normalizeOperations(input.operations),
    principal: input.principal,
    requestedAtMs: input.requestedAtMs,
    role: input.role,
  })}`;
}

export function partyCapabilityExchangeSigningBytes(input: Readonly<{
  readonly nonce: string;
  readonly replacementDigest: string;
  readonly scope: PartyCapabilityScope;
}>): string {
  validateHash(input.replacementDigest, "replacementDigest");
  return `${EXCHANGE_DOMAIN}${canonicalize({
    nonce: input.nonce,
    replacementDigest: input.replacementDigest,
    scope: normalizeScope(input.scope),
  })}`;
}

export function capabilityRenewalSigningBytes(input: Readonly<{
  readonly expiresAtMs: number;
  readonly replacementDigest: string;
  readonly requestedAtMs: number;
  readonly tokenDigest: string;
}>): string {
  validateHash(input.tokenDigest, "tokenDigest");
  validateHash(input.replacementDigest, "replacementDigest");
  return `${RENEWAL_DOMAIN}${canonicalize(input)}`;
}

export function capabilityRevocationSigningBytes(input: Readonly<{
  readonly authorizationDigest: string;
  readonly requestedAtMs: number;
  readonly targetDigest: string;
}>): string {
  validateHash(input.authorizationDigest, "authorizationDigest");
  validateHash(input.targetDigest, "targetDigest");
  return `${REVOCATION_DOMAIN}${canonicalize(input)}`;
}

export function administratorRotationSigningBytes(input: Readonly<{
  readonly authorizationDigest: string;
  readonly replacementDigest: string;
  readonly replacementScope: AdministratorCapabilityScope;
  readonly requestedAtMs: number;
}>): string {
  validateHash(input.authorizationDigest, "authorizationDigest");
  validateHash(input.replacementDigest, "replacementDigest");
  return `${REVOCATION_DOMAIN}rotate:${canonicalize({
    authorizationDigest: input.authorizationDigest,
    replacementDigest: input.replacementDigest,
    replacementScope: normalizeScope(input.replacementScope),
    requestedAtMs: input.requestedAtMs,
  })}`;
}

export function sessionAuthorityAmendmentSigningBytes(
  input: Omit<SessionAuthorityAmendment, "buyerProof" | "sellerProof">,
): string {
  return `${AMENDMENT_DOMAIN}${canonicalize({
    agreementHash: input.agreementHash,
    anchor: input.anchor,
    counterpartyKey: input.counterpartyKey,
    expiresAtMs: input.expiresAtMs,
    jobId: input.jobId,
    newKey: input.newKey,
    oldKey: input.oldKey,
    operations: normalizeOperations(input.operations),
    role: input.role,
  })}`;
}

function normalizeAllocation(input: PartyChallengeAllocationInput): PartyChallengeAllocationInput {
  if (input === null || typeof input !== "object" || Array.isArray(input)
    || input.role !== "buyer" && input.role !== "seller"
    || !LOWER_HEX_32.test(input.clientNonce)
    || !Number.isSafeInteger(input.requestedAtMs) || input.requestedAtMs < 0) {
    throw new TypeError("Party challenge allocation is invalid");
  }
  return Object.freeze({
    clientIdempotencyKey: validatedField("clientIdempotencyKey", input.clientIdempotencyKey),
    clientNonce: input.clientNonce,
    jobId: validatedField("jobId", input.jobId),
    operations: normalizeOperations(input.operations),
    principal: validatedField("principal", input.principal),
    proof: validatedField("proof", input.proof),
    requestedAtMs: input.requestedAtMs,
    role: input.role,
  });
}

function requestIsCurrent(requestedAtMs: number, now: number): boolean {
  return Number.isSafeInteger(requestedAtMs) && requestedAtMs >= 0
    && requestedAtMs >= now - AUTHORITY_REQUEST_PAST_MS
    && requestedAtMs <= now + AUTHORITY_REQUEST_FUTURE_MS;
}

function normalizeExchange(input: PartyCapabilityExchangeInput): PartyCapabilityExchangeInput {
  if (input === null || typeof input !== "object" || Array.isArray(input)
    || !LOWER_HEX_32.test(input.nonce)
    || !LOWER_HEX_64.test(input.replacementToken)
    || !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= 0) {
    throw new TypeError("Party capability exchange is invalid");
  }
  return Object.freeze({
    expiresAtMs: input.expiresAtMs,
    nonce: input.nonce,
    proof: validatedField("proof", input.proof),
    replacementToken: input.replacementToken,
  });
}

function normalizeScope(scope: CapabilityScope): CapabilityScope {
  if (scope?.kind === "administrator") {
    return boundedScope(Object.freeze({
      kind: "administrator" as const,
      instanceId: validatedField("instanceId", scope.instanceId),
      audience: validatedField("audience", scope.audience),
      principal: validatedField("principal", scope.principal),
      operations: normalizeOperations(scope.operations),
      expiresAtMs: validatedTimestamp(scope.expiresAtMs),
      configuredKey: validatedField("configuredKey", scope.configuredKey),
    }));
  }
  if (scope?.kind === "party" && (scope.role === "buyer" || scope.role === "seller")
    && (scope.authority?.kind === "admission" || scope.authority?.kind === "agreement")) {
    return boundedScope(Object.freeze({
      kind: "party" as const,
      instanceId: validatedField("instanceId", scope.instanceId),
      audience: validatedField("audience", scope.audience),
      principal: validatedField("principal", scope.principal),
      operations: normalizeOperations(scope.operations),
      expiresAtMs: validatedTimestamp(scope.expiresAtMs),
      jobId: validatedField("jobId", scope.jobId),
      role: scope.role,
      authority: Object.freeze({
        kind: scope.authority.kind,
        key: validatedField("authority.key", scope.authority.key),
      }),
    }));
  }
  throw new TypeError("Capability scope is invalid");
}

function boundedScope<TScope extends CapabilityScope>(scope: TScope): TScope {
  if (Buffer.byteLength(canonicalize(scope), "utf8") > MAX_CAPABILITY_SCOPE_BYTES) {
    throw new TypeError("Capability scope exceeds its aggregate byte bound");
  }
  return scope;
}

function normalizeAmendment(input: SessionAuthorityAmendment): SessionAuthorityAmendment {
  if (input === null || typeof input !== "object" || Array.isArray(input)
    || input.role !== "buyer" && input.role !== "seller") {
    throw new TypeError("Session authority amendment is invalid");
  }
  validateHash(input.agreementHash, "agreementHash");
  return Object.freeze({
    agreementHash: input.agreementHash,
    anchor: validatedField("anchor", input.anchor),
    buyerProof: validatedField("buyerProof", input.buyerProof),
    counterpartyKey: validatedField("counterpartyKey", input.counterpartyKey),
    expiresAtMs: validatedTimestamp(input.expiresAtMs),
    jobId: validatedField("jobId", input.jobId),
    newKey: validatedField("newKey", input.newKey),
    oldKey: validatedField("oldKey", input.oldKey),
    operations: normalizeOperations(input.operations),
    role: input.role,
    sellerProof: validatedField("sellerProof", input.sellerProof),
  });
}

function scopeFromChallenge(row: ChallengeRow, expiresAtMs: number): PartyCapabilityScope {
  return Object.freeze({
    kind: "party",
    instanceId: row.instanceId,
    audience: row.audience,
    principal: row.principal,
    operations: operationsFrom(row.operationsJson),
    expiresAtMs,
    jobId: row.jobId,
    role: row.role,
    authority: Object.freeze({ kind: row.authorityKind, key: row.authorityKey }),
  });
}

function scopeFromRow(row: CapabilityRow): CapabilityScope {
  const base = {
    instanceId: row.instanceId,
    audience: row.audience,
    principal: row.principal,
    operations: operationsFrom(rowOperations(row)),
    expiresAtMs: Number(row.expiresAtMs),
  };
  if (row.kind === "administrator" && row.configuredKey !== null) {
    return Object.freeze({ kind: "administrator", ...base, configuredKey: row.configuredKey });
  }
  if (row.kind === "party" && row.jobId !== null && row.role !== null
    && row.authorityKind !== null && row.authorityKey !== null) {
    return Object.freeze({
      kind: "party",
      ...base,
      jobId: row.jobId,
      role: row.role,
      authority: Object.freeze({ kind: row.authorityKind, key: row.authorityKey }),
    });
  }
  throw new Error("Persisted capability scope is corrupt");
}

function challengeRecord(row: ChallengeRow): PartyChallengeRecord {
  return Object.freeze({
    nonce: row.nonce,
    issuedAtMs: Number(row.issuedAtMs),
    expiresAtMs: Number(row.expiresAtMs),
    jobId: row.jobId,
    role: row.role,
  });
}

function rowOperations(row: CapabilityRow): string {
  return row.operationsJson;
}

function operationsFrom(value: string): readonly string[] {
  const parsed = JSON.parse(value) as unknown;
  return normalizeOperations(parsed as readonly string[]);
}

function normalizeOperations(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new TypeError("Capability operations must contain 1 through 64 entries");
  }
  const operations = value.map((operation) => validatedField("operation", operation));
  if (new Set(operations).size !== operations.length) {
    throw new TypeError("Capability operations must be unique");
  }
  return Object.freeze([...operations].sort());
}

function constantDigestEqual(left: string, right: string): boolean {
  if (!LOWER_HEX_64.test(left) || !LOWER_HEX_64.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function hashHex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function validateHash(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !LOWER_HEX_64.test(value)) {
    throw new TypeError(`${name} must be lowercase SHA-256`);
  }
}

function validatedTimestamp(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError("Capability timestamp is invalid");
  return value;
}

function validatedField(name: string, value: string): string {
  validateField(name, value);
  return value;
}

function validateField(name: string, value: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_LENGTH
    || value !== value.normalize("NFC")) throw new TypeError(`${name} is invalid`);
}

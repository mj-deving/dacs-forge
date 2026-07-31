import { createPublicKey, verify as verifyBytes } from "node:crypto";
import type { ArtifactSigner } from "../../src/producer/fixture-ed25519.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  decodeComponentSignatureValue,
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import type { ServiceRunInput, ServiceRunResult } from "../../src/service/runtime.ts";
import {
  admissionSigningBytes,
  challengeAllocationSigningBytes,
  sessionBindingHash,
  type AdmissionInput,
  type ChallengeAllocationInput,
  type SessionRecord,
} from "../../src/substrate/sqlite/session-store.ts";

const DOMAIN = "dacs-forge:buyer-session-authorization:v1:";
const KEY_CLAIM = /^key:([0-9a-f]{64})$/;
const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const LOWER_HEX_32 = /^[0-9a-f]{32}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIGNING_CONTEXT = Object.freeze({ deploymentMode: "fixture" as const, requestMode: "fixture" as const });

export interface BuyerSessionAuthorizationInput {
  readonly jobId: string;
  readonly agreementHash: string;
  readonly sessionBindingHash: string;
  readonly phaseIndex: number;
  readonly railId: string;
  readonly seller: string;
  readonly orchestrator: string;
  readonly authorizedAt: string;
}

export interface BuyerSessionAuthorization {
  readonly canonicalJson: string;
  readonly contentHash: string;
}

export interface ExternalBuyerHarness {
  readonly primaryClaim: string;
  readonly identityCanonicalJson: string;
  createChallengeAllocation(input: Readonly<{
    clientNonce: string;
    idempotencyKey: string;
    requestedAtMs: number;
  }>): ChallengeAllocationInput;
  createAdmission(input: Readonly<{
    idempotencyKey: string;
    nonce: string;
  }>): AdmissionInput;
  authorize(input: BuyerSessionAuthorizationInput): BuyerSessionAuthorization;
}

export interface BuyerAdmissionPolicy {
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly evidenceMode: "fixture";
  readonly requestHash: string;
}

export interface BuyerAuthorizationExpectation extends BuyerSessionAuthorizationInput {
  readonly buyer: string;
}

export interface BuyerExecutionAuthority {
  readonly jobId: string;
  readonly agreementHash: string;
  readonly phaseIndex: number;
  readonly railId: string;
  readonly buyer: string;
  readonly seller: string;
  readonly orchestrator: string;
  readonly authorizedAt: string;
}

export interface ExternalBuyerServiceRunner<TInput, TOutput> {
  run(input: Readonly<{
    authorizationCanonicalJson: string;
    request: ServiceRunInput<TInput>;
  }>): Promise<ServiceRunResult<TInput, TOutput>>;
}

export function createExternalBuyerServiceRunner<TInput, TOutput>(options: Readonly<{
  authority: { get(jobId: string): BuyerExecutionAuthority | null };
  runtime: { run(request: ServiceRunInput<TInput>): Promise<ServiceRunResult<TInput, TOutput>> };
  sessions: { get(jobId: string): Readonly<{ session: SessionRecord; principal: string }> | null };
}>): ExternalBuyerServiceRunner<TInput, TOutput> {
  if (options === null || typeof options !== "object"
    || typeof options.authority?.get !== "function"
    || typeof options.runtime?.run !== "function"
    || typeof options.sessions?.get !== "function") {
    throw new TypeError("External buyer runner requires session, agreement, and runtime authority");
  }
  return Object.freeze({
    async run(input): Promise<ServiceRunResult<TInput, TOutput>> {
      if (input === null || typeof input !== "object" || Array.isArray(input)
        || typeof input.authorizationCanonicalJson !== "string"
        || Buffer.byteLength(input.authorizationCanonicalJson, "utf8") > 16_384
        || input.request === null || typeof input.request !== "object") {
        throw new TypeError("External buyer execution request is invalid");
      }
      const jobId = input.request.jobId;
      const sessionAuthority = options.sessions.get(jobId);
      const authority = options.authority.get(jobId);
      if (sessionAuthority === null || sessionAuthority.session.status !== "admitted"
        || sessionAuthority.session.jobId !== jobId
        || authority === null || authority.jobId !== jobId
        || sessionAuthority.principal !== authority.buyer) {
        throw new Error("External buyer execution authority is unavailable");
      }
      const expected: BuyerAuthorizationExpectation = Object.freeze({
        buyer: authority.buyer,
        seller: authority.seller,
        orchestrator: authority.orchestrator,
        jobId,
        agreementHash: authority.agreementHash,
        sessionBindingHash: sessionBindingHash(sessionAuthority.session),
        phaseIndex: authority.phaseIndex,
        railId: authority.railId,
        authorizedAt: authority.authorizedAt,
      });
      if (!verifyBuyerSessionAuthorization(input.authorizationCanonicalJson, expected)) {
        throw new Error("External buyer execution authorization is invalid");
      }
      return options.runtime.run(input.request);
    },
  });
}

export function createExternalBuyerHarness(
  paymentSigner: ArtifactSigner,
  identityCanonicalJson: string,
  admissionPolicy: BuyerAdmissionPolicy,
): ExternalBuyerHarness {
  if (KEY_CLAIM.exec(paymentSigner.signer) === null) throw new TypeError("Buyer signer claim is invalid");
  if (!verifyBuyerIdentity(identityCanonicalJson, paymentSigner.signer)) {
    throw new TypeError("Buyer identity does not bind the injected payment signer");
  }
  validateAdmissionPolicy(admissionPolicy);
  const policy = Object.freeze({
    instanceId: admissionPolicy.instanceId,
    audience: admissionPolicy.audience,
    jobId: admissionPolicy.jobId,
    evidenceMode: admissionPolicy.evidenceMode,
    requestHash: admissionPolicy.requestHash,
  });
  return Object.freeze({
    primaryClaim: paymentSigner.signer,
    identityCanonicalJson,
    createChallengeAllocation(input): ChallengeAllocationInput {
      const request = Object.freeze({
        clientNonce: input?.clientNonce,
        idempotencyKey: input?.idempotencyKey,
        requestedAtMs: input?.requestedAtMs,
      });
      validateChallengeRequest(request);
      const unsigned: ChallengeAllocationInput = {
        instanceId: policy.instanceId,
        audience: policy.audience,
        principal: paymentSigner.signer,
        jobId: policy.jobId,
        evidenceMode: policy.evidenceMode,
        clientNonce: request.clientNonce,
        clientIdempotencyKey: request.idempotencyKey,
        requestedAtMs: request.requestedAtMs,
        proof: "pending",
      };
      return Object.freeze({
        ...unsigned,
        proof: signAdmissionBytes(paymentSigner, challengeAllocationSigningBytes(unsigned)),
      });
    },
    createAdmission(input): AdmissionInput {
      const request = Object.freeze({
        idempotencyKey: input?.idempotencyKey,
        nonce: input?.nonce,
      });
      validateAdmissionRequest(request);
      const unsigned: AdmissionInput = {
        instanceId: policy.instanceId,
        audience: policy.audience,
        principal: paymentSigner.signer,
        jobId: policy.jobId,
        evidenceMode: policy.evidenceMode,
        nonce: request.nonce,
        idempotencyKey: request.idempotencyKey,
        requestHash: policy.requestHash,
        proof: "pending",
      };
      return Object.freeze({
        ...unsigned,
        proof: signAdmissionBytes(paymentSigner, admissionSigningBytes(unsigned)),
      });
    },
    authorize(input: BuyerSessionAuthorizationInput): BuyerSessionAuthorization {
      const authorization = Object.freeze({
        jobId: input?.jobId,
        agreementHash: input?.agreementHash,
        sessionBindingHash: input?.sessionBindingHash,
        phaseIndex: input?.phaseIndex,
        railId: input?.railId,
        seller: input?.seller,
        orchestrator: input?.orchestrator,
        authorizedAt: input?.authorizedAt,
      });
      validateInput(authorization, paymentSigner.signer);
      if (authorization.jobId !== policy.jobId) {
        throw new TypeError("Buyer authorization job does not match admission policy");
      }
      const scope = Object.freeze({
        authorizationVersion: "1",
        buyer: paymentSigner.signer,
        seller: authorization.seller,
        orchestrator: authorization.orchestrator,
        jobId: authorization.jobId,
        agreementHash: authorization.agreementHash,
        sessionBindingHash: authorization.sessionBindingHash,
        phaseIndex: authorization.phaseIndex,
        railId: authorization.railId,
        authorizedAt: authorization.authorizedAt,
      });
      const scopeHash = sha256Hex(canonicalize(scope));
      const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
        paymentSigner.sign(new TextEncoder().encode(`${DOMAIN}${scopeHash}`), SIGNING_CONTEXT),
        "standard-base64-padded",
        64,
      ));
      const canonicalJson = canonicalize({
        ...scope,
        signature: { algorithm: "ed25519", signer: paymentSigner.signer, value: signature },
      });
      return Object.freeze({ canonicalJson, contentHash: sha256Hex(canonicalJson) });
    },
  });
}

export function verifyBuyerPrincipalProof(
  signedBytes: string,
  proof: string,
  expectedBuyer: string,
): boolean {
  try {
    validateCanonicalAdmissionBytes(signedBytes);
    return verifyEd25519(expectedBuyer, new TextEncoder().encode(signedBytes), proof);
  } catch {
    return false;
  }
}

export function verifyBuyerSessionAuthorization(
  canonicalJson: string,
  expected: BuyerAuthorizationExpectation,
): boolean {
  let value: Record<string, unknown>;
  try {
    value = JSON.parse(canonicalJson) as Record<string, unknown>;
    if (canonicalize(value) !== canonicalJson) return false;
  } catch {
    return false;
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([
    "agreementHash", "authorizationVersion", "authorizedAt", "buyer", "jobId", "orchestrator",
    "phaseIndex", "railId", "seller", "sessionBindingHash", "signature",
  ].sort())) return false;
  for (const [key, expectedValue] of Object.entries({ authorizationVersion: "1", ...expected })) {
    if (value[key] !== expectedValue) return false;
  }
  if (expected.buyer === expected.seller || expected.buyer === expected.orchestrator) return false;
  const signature = value["signature"] as Record<string, unknown>;
  if (signature === null || typeof signature !== "object" || Array.isArray(signature)
    || JSON.stringify(Object.keys(signature).sort()) !== JSON.stringify(["algorithm", "signer", "value"].sort())
    || signature["algorithm"] !== "ed25519" || signature["signer"] !== expected.buyer
    || typeof signature["value"] !== "string") return false;
  const keyMatch = KEY_CLAIM.exec(expected.buyer);
  if (keyMatch === null) return false;
  const scope = { ...value };
  delete scope["signature"];
  try {
    return verifyEd25519(
      expected.buyer,
      Buffer.from(`${DOMAIN}${sha256Hex(canonicalize(scope))}`, "utf8"),
      signature["value"],
    );
  } catch {
    return false;
  }
}

function validateInput(input: BuyerSessionAuthorizationInput, buyer: string): void {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Buyer authorization input is invalid");
  }
  if (typeof input.jobId !== "string" || typeof input.agreementHash !== "string"
    || typeof input.sessionBindingHash !== "string" || !ULID.test(input.jobId)
    || !HASH.test(input.agreementHash) || !HASH.test(input.sessionBindingHash)) {
    throw new TypeError("Buyer authorization session binding is invalid");
  }
  if (!Number.isSafeInteger(input.phaseIndex) || input.phaseIndex < 0
    || typeof input.railId !== "string" || input.railId.length === 0 || input.railId.length > 128
    || typeof input.seller !== "string" || typeof input.orchestrator !== "string"
    || KEY_CLAIM.exec(input.seller) === null || KEY_CLAIM.exec(input.orchestrator) === null
    || buyer === input.seller || buyer === input.orchestrator) {
    throw new TypeError("Buyer authorization party or rail binding is invalid");
  }
  if (typeof input.authorizedAt !== "string") {
    throw new TypeError("Buyer authorization timestamp is invalid");
  }
  const authorizedAtMs = Date.parse(input.authorizedAt);
  if (!Number.isFinite(authorizedAtMs)
    || new Date(authorizedAtMs).toISOString() !== input.authorizedAt) {
    throw new TypeError("Buyer authorization timestamp is invalid");
  }
}

function validateAdmissionPolicy(policy: BuyerAdmissionPolicy): void {
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)
    || !ULID.test(policy.jobId) || !HASH.test(policy.requestHash)
    || policy.evidenceMode !== "fixture"
    || typeof policy.instanceId !== "string" || policy.instanceId.length === 0 || policy.instanceId.length > 4_096
    || typeof policy.audience !== "string" || policy.audience.length === 0 || policy.audience.length > 4_096) {
    throw new TypeError("Buyer admission policy is invalid");
  }
}

function validateChallengeRequest(input: Readonly<{
  clientNonce: string; idempotencyKey: string; requestedAtMs: number;
}>): void {
  if (input === null || typeof input !== "object" || Array.isArray(input)
    || !LOWER_HEX_32.test(input.clientNonce)
    || !boundedText(input.idempotencyKey)
    || !Number.isSafeInteger(input.requestedAtMs) || input.requestedAtMs < 0) {
    throw new TypeError("Buyer challenge request is invalid");
  }
}

function validateAdmissionRequest(input: Readonly<{ idempotencyKey: string; nonce: string }>): void {
  if (input === null || typeof input !== "object" || Array.isArray(input)
    || !LOWER_HEX_32.test(input.nonce) || !boundedText(input.idempotencyKey)) {
    throw new TypeError("Buyer admission request is invalid");
  }
}

function boundedText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096;
}

function signAdmissionBytes(signer: ArtifactSigner, signedBytes: string): string {
  return encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(signedBytes), SIGNING_CONTEXT),
    "standard-base64-padded",
    64,
  ));
}

function validateCanonicalAdmissionBytes(signedBytes: string): void {
  if (typeof signedBytes !== "string" || signedBytes.length > 8_192) {
    throw new TypeError("Buyer admission bytes are invalid");
  }
  const domains = [
    Object.freeze({
      value: "dacs-template:session-challenge-allocation:v1:",
      keys: ["audience", "clientIdempotencyKey", "clientNonce", "evidenceMode", "instanceId", "jobId", "principal", "requestedAtMs"],
    }),
    Object.freeze({
      value: "dacs-template:session-admission:v1:",
      keys: ["audience", "evidenceMode", "idempotencyKey", "instanceId", "jobId", "nonce", "principal", "requestHash"],
    }),
  ];
  const domain = domains.find(({ value }) => signedBytes.startsWith(value));
  if (domain === undefined) throw new TypeError("Buyer admission domain is invalid");
  const canonicalJson = signedBytes.slice(domain.value.length);
  const parsed = JSON.parse(canonicalJson) as Record<string, unknown>;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || canonicalize(parsed) !== canonicalJson
    || JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify([...domain.keys].sort())) {
    throw new TypeError("Buyer admission scope is invalid");
  }
}

function verifyBuyerIdentity(canonicalJson: string, expectedBuyer: string): boolean {
  let identity: Record<string, unknown>;
  try {
    identity = JSON.parse(canonicalJson) as Record<string, unknown>;
    if (canonicalize(identity) !== canonicalJson
      || identity["bundleVersion"] !== "1"
      || identity["presentedBy"] !== expectedBuyer
      || !Array.isArray(identity["claims"])
      || !(identity["claims"] as Record<string, unknown>[]).some(({ ref }) => ref === expectedBuyer)) {
      return false;
    }
    const presentation = identity["presentation"] as Record<string, unknown>;
    const signatures = presentation?.["signatures"];
    if (presentation?.["kind"] !== "per-claim" || !Array.isArray(signatures)) return false;
    const primary = signatures.find((entry) =>
      entry !== null && typeof entry === "object"
      && (entry as Record<string, unknown>)["ref"] === expectedBuyer
    ) as Record<string, unknown> | undefined;
    if (typeof primary?.["signature"] !== "string") return false;
    const unsigned = { ...identity };
    delete unsigned["presentation"];
    return verifyEd25519(
      expectedBuyer,
      Buffer.from(`dacs-bundle-presentation:v1:${sha256Hex(canonicalize(unsigned))}`, "utf8"),
      encodeComponentSignatureValue(importLegacyComponentSignatureValue(
        primary["signature"],
        "standard-base64-padded",
        64,
      )),
    );
  } catch {
    return false;
  }
}

function verifyEd25519(claim: string, payload: Uint8Array, signature: string): boolean {
  const keyMatch = KEY_CLAIM.exec(claim);
  if (keyMatch === null) return false;
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyMatch[1]!, "hex")]),
    format: "der",
    type: "spki",
  });
  return verifyBytes(null, Buffer.from(payload), publicKey, decodeComponentSignatureValue(signature, 64));
}

import { canonicalize } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import type {
  AuthorityProofVerifier,
  DisclosureAuthorityResolution,
} from "../substrate/sqlite/party-authority-lifecycle.ts";
import { HttpResourceGuards, boundedArtifactResponse } from "./resource-guards.ts";
import { terminalErrorResponse } from "./terminal-server.ts";

export const PUBLIC_DELIVERY_POLICY_DOMAIN = "dacs-template:artifact-public-policy:v1:";
export const PUBLIC_DISCLOSURE_CONSENT_DOMAIN =
  "dacs-template:artifact-public-disclosure:v1:";
export const PUBLIC_ARTIFACT_ROUTE = "public-artifact";

const HASH = /^[0-9a-f]{64}$/;
const MAX_FIELD_LENGTH = 4_096;
const MAX_REQUEST_URL_LENGTH = 8_192;
const PUBLIC_ARTIFACT_PATH = /^\/v1\/public-artifacts\/([0-9a-f]{64})$/;

export interface VerifiedPublicDelivery {
  readonly disposition: "verified";
  readonly accessModel: "public" | "buyer-only" | "encrypt-to-buyer";
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly agreementHash: string;
  readonly artifactRef: string;
  readonly artifactHash: string;
}

export interface SignedPublicDeliveryPolicy {
  readonly policyVersion: "1";
  readonly accessModel: "public";
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly agreementHash: string;
  readonly artifactRef: string;
  readonly artifactHash: string;
  readonly expiresAtMs: number;
  readonly sellerKey: string;
  readonly signature: string;
}

export interface SignedPublicDisclosureConsent {
  readonly consentVersion: "1";
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly agreementHash: string;
  readonly artifactRef: string;
  readonly artifactHash: string;
  readonly expiresAtMs: number;
  readonly buyerKey: string;
  readonly signature: string;
}

export interface PublicArtifactDisclosureGrant {
  readonly delivery: VerifiedPublicDelivery & { readonly accessModel: "public" };
  readonly policy: SignedPublicDeliveryPolicy;
  readonly consent: SignedPublicDisclosureConsent;
}

export type AgreementDisclosureAuthorityResolution = DisclosureAuthorityResolution;

export interface AgreementDisclosureAuthority {
  resolveDisclosureAuthority(input: Readonly<{ readonly jobId: string }> ):
    AgreementDisclosureAuthorityResolution;
}

export type PublicDeliveryEvidenceResolution = VerifiedPublicDelivery
  | Readonly<{ readonly disposition: "unavailable" }>;

export interface PublicDeliveryEvidenceAuthority {
  resolveVerifiedDelivery(input: Readonly<{ readonly artifactHash: string }> ):
    PublicDeliveryEvidenceResolution;
}

export interface PublicArtifactDisclosureAuthorityOptions {
  readonly instanceId: string;
  readonly audience: string;
  readonly agreementAuthority: AgreementDisclosureAuthority;
  readonly deliveryAuthority: PublicDeliveryEvidenceAuthority;
  readonly proofVerifier: AuthorityProofVerifier;
  readonly now?: () => number;
}

export interface PublicArtifactRecord {
  readonly artifactRef: string;
  readonly contentHash: string;
  readonly canonicalJson: string;
  readonly byteLength: number;
}

export type PublicArtifactResolution =
  | Readonly<{
    readonly disposition: "resolved";
    readonly artifact: PublicArtifactRecord;
    readonly grant: PublicArtifactDisclosureGrant;
  }>
  | Readonly<{ readonly disposition: "absent" | "rejected" | "indeterminate" }>;

export interface PublicArtifactHttpOptions {
  readonly authority: PublicArtifactDisclosureAuthority;
  readonly guards: HttpResourceGuards;
  readonly maxArtifactBytes: number;
  readonly resolve: (input: Readonly<{ readonly contentHash: string }>) =>
    PublicArtifactResolution | Promise<PublicArtifactResolution>;
  readonly onMismatch?: (reason: string) => void;
}

/**
 * DACS-specific disclosure seam. It verifies already-resolved delivery and party authority; it
 * does not implement an identity provider, storage backend, ACL, encryption, or key lifecycle.
 */
export class PublicArtifactDisclosureAuthority {
  readonly #agreementAuthority: AgreementDisclosureAuthority;
  readonly #audience: string;
  readonly #instanceId: string;
  readonly #deliveryAuthority: PublicDeliveryEvidenceAuthority;
  readonly #now: () => number;
  readonly #proofVerifier: AuthorityProofVerifier;

  constructor(options: PublicArtifactDisclosureAuthorityOptions) {
    this.#instanceId = field("instanceId", options?.instanceId);
    this.#audience = field("audience", options?.audience);
    if (options.agreementAuthority?.resolveDisclosureAuthority === undefined
      || options.deliveryAuthority?.resolveVerifiedDelivery === undefined
      || options.proofVerifier?.verify === undefined) {
      throw new TypeError("Public artifact disclosure requires delivery, agreement, and proof authorities");
    }
    this.#agreementAuthority = options.agreementAuthority;
    this.#deliveryAuthority = options.deliveryAuthority;
    this.#proofVerifier = options.proofVerifier;
    this.#now = options.now ?? Date.now;
    safeNow(this.#now);
  }

  /** Validate a grant at admission time, including buyer-key currentness via party authority. */
  grant(input: unknown): PublicArtifactDisclosureGrant {
    const grant = normalizeGrant(input);
    if (!this.#grantIsCurrent(grant)) {
      throw new TypeError("Public artifact disclosure grant is not authorized");
    }
    return grant;
  }

  /** Revalidate the complete grant and current buyer authority for every anonymous read. */
  authorizeRead(input: unknown, artifact: unknown): PublicArtifactRecord | null {
    try {
      const grant = normalizeGrant(input);
      const record = normalizeArtifact(artifact);
      return this.#grantIsCurrent(grant)
        && record.artifactRef === grant.delivery.artifactRef
        && record.contentHash === grant.delivery.artifactHash
        && Buffer.byteLength(record.canonicalJson, "utf8") === record.byteLength
        && sha256Hex(record.canonicalJson) === record.contentHash ? record : null;
    } catch {
      return null;
    }
  }

  #grantIsCurrent(grant: PublicArtifactDisclosureGrant): boolean {
    const now = safeNow(this.#now);
    if (grant.delivery.instanceId !== this.#instanceId
      || grant.delivery.audience !== this.#audience
      || grant.policy.expiresAtMs <= now || grant.consent.expiresAtMs <= now
      || !sameBinding(grant.delivery, grant.policy)
      || !sameBinding(grant.delivery, grant.consent)) return false;
    let delivery: PublicDeliveryEvidenceResolution;
    try {
      delivery = normalizeDeliveryResolution(
        this.#deliveryAuthority.resolveVerifiedDelivery({
          artifactHash: grant.delivery.artifactHash,
        }),
      );
    } catch {
      return false;
    }
    if (delivery.disposition !== "verified" || delivery.accessModel !== "public"
      || !sameDeliveryBinding(grant.delivery, delivery)) return false;
    let authority: AgreementDisclosureAuthorityResolution;
    try {
      authority = normalizeAuthorityResolution(
        this.#agreementAuthority.resolveDisclosureAuthority({ jobId: grant.delivery.jobId }),
      );
    } catch {
      return false;
    }
    if (authority?.disposition !== "current"
      || authority.agreementHash !== grant.delivery.agreementHash
      || authority.buyerKey !== grant.consent.buyerKey
      || authority.sellerKey !== grant.policy.sellerKey) return false;
    try {
      return this.#proofVerifier.verify({
        key: authority.sellerKey,
        proof: grant.policy.signature,
        signedBytes: publicDeliveryPolicySigningBytes(grant.policy),
      }) === true && this.#proofVerifier.verify({
        key: authority.buyerKey,
        proof: grant.consent.signature,
        signedBytes: publicDisclosureConsentSigningBytes(grant.consent),
      }) === true;
    } catch {
      return false;
    }
  }
}

export function publicDeliveryPolicySigningBytes(input: unknown): string {
  const policy = normalizePolicy(withoutOptionalSignature(input), false);
  return `${PUBLIC_DELIVERY_POLICY_DOMAIN}${canonicalize(unsignedPolicy(policy))}`;
}

export function publicDisclosureConsentSigningBytes(input: unknown): string {
  const consent = normalizeConsent(withoutOptionalSignature(input), false);
  return `${PUBLIC_DISCLOSURE_CONSENT_DOMAIN}${canonicalize(unsignedConsent(consent))}`;
}

export function createPublicArtifactHttpHandler(
  options: PublicArtifactHttpOptions,
): (request: Request) => Promise<Response> {
  if (options?.authority === undefined || options.guards === undefined
    || typeof options.resolve !== "function" || !Number.isSafeInteger(options.maxArtifactBytes)
    || options.maxArtifactBytes < 1) {
    throw new TypeError("Public artifact HTTP requires bounded disclosure dependencies");
  }
  return async (request: Request): Promise<Response> => {
    if (request.url.length > MAX_REQUEST_URL_LENGTH || request.method !== "GET") {
      return terminalErrorResponse(request.method === "GET" ? 404 : 405,
        request.method === "GET" ? "not-found" : "method-not-allowed");
    }
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return terminalErrorResponse(404, "not-found");
    }
    if ((url.protocol !== "http:" && url.protocol !== "https:")
      || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
      return terminalErrorResponse(404, "not-found");
    }
    const match = PUBLIC_ARTIFACT_PATH.exec(url.pathname);
    if (match === null) return terminalErrorResponse(404, "not-found");
    return options.guards.run(PUBLIC_ARTIFACT_ROUTE, request, async () => {
      try {
        const resolved = await options.resolve({ contentHash: match[1]! });
        if (resolved?.disposition !== "resolved") {
          return terminalErrorResponse(404, "not-found");
        }
        const artifact = options.authority.authorizeRead(resolved.grant, resolved.artifact);
        if (artifact === null || artifact.contentHash !== match[1]) {
          return terminalErrorResponse(404, "not-found");
        }
        const bytes = new TextEncoder().encode(artifact.canonicalJson);
        return boundedArtifactResponse({
          source: new ReadableStream<Uint8Array>({
            start(controller): void {
              controller.enqueue(bytes);
              controller.close();
            },
          }),
          declaredLength: artifact.byteLength,
          verifiedStoredLength: bytes.byteLength,
          maxBytes: options.maxArtifactBytes,
          contentType: "application/json; charset=utf-8",
          ...(options.onMismatch === undefined ? {} : { onMismatch: options.onMismatch }),
        });
      } catch {
        return terminalErrorResponse(404, "not-found");
      }
    });
  };
}

function normalizeGrant(input: unknown): PublicArtifactDisclosureGrant {
  const value = record(input, ["consent", "delivery", "policy"]);
  const delivery = normalizeDelivery(value["delivery"]);
  const policy = normalizePolicy(value["policy"], true);
  const consent = normalizeConsent(value["consent"], true);
  return Object.freeze({ delivery, policy, consent });
}

function normalizeDelivery(input: unknown): PublicArtifactDisclosureGrant["delivery"] {
  const delivery = normalizeVerifiedDelivery(input);
  if (delivery.accessModel !== "public") {
    throw new TypeError("Anonymous disclosure requires verified public delivery evidence");
  }
  return Object.freeze({ ...delivery, accessModel: "public" as const });
}

function normalizeVerifiedDelivery(input: unknown): VerifiedPublicDelivery {
  const value = record(input, [
    "accessModel", "agreementHash", "artifactHash", "artifactRef", "audience",
    "disposition", "instanceId", "jobId",
  ]);
  if (value["disposition"] !== "verified"
    || !["public", "buyer-only", "encrypt-to-buyer"].includes(value["accessModel"] as string)) {
    throw new TypeError("Verified delivery evidence is invalid");
  }
  return Object.freeze({
    disposition: "verified" as const,
    accessModel: value["accessModel"] as VerifiedPublicDelivery["accessModel"],
    ...binding(value),
  });
}

function normalizePolicy(input: unknown, requireSignature: boolean): SignedPublicDeliveryPolicy {
  const keys = [
    "accessModel", "agreementHash", "artifactHash", "artifactRef", "audience", "expiresAtMs",
    "instanceId", "jobId", "policyVersion", "sellerKey",
    ...(requireSignature ? ["signature"] : []),
  ];
  const value = record(input, keys);
  if (value["policyVersion"] !== "1" || value["accessModel"] !== "public") {
    throw new TypeError("Public delivery policy is invalid");
  }
  return Object.freeze({
    policyVersion: "1" as const,
    accessModel: "public" as const,
    ...binding(value),
    expiresAtMs: timestamp(value["expiresAtMs"], "policy expiresAtMs"),
    sellerKey: field("sellerKey", value["sellerKey"]),
    signature: requireSignature ? field("policy signature", value["signature"]) : "",
  });
}

function normalizeConsent(input: unknown, requireSignature: boolean): SignedPublicDisclosureConsent {
  const keys = [
    "agreementHash", "artifactHash", "artifactRef", "audience", "buyerKey", "consentVersion",
    "expiresAtMs", "instanceId", "jobId", ...(requireSignature ? ["signature"] : []),
  ];
  const value = record(input, keys);
  if (value["consentVersion"] !== "1") throw new TypeError("Buyer disclosure consent is invalid");
  return Object.freeze({
    consentVersion: "1" as const,
    ...binding(value),
    expiresAtMs: timestamp(value["expiresAtMs"], "consent expiresAtMs"),
    buyerKey: field("buyerKey", value["buyerKey"]),
    signature: requireSignature ? field("consent signature", value["signature"]) : "",
  });
}

function normalizeArtifact(input: unknown): PublicArtifactRecord {
  const value = record(input, ["artifactRef", "byteLength", "canonicalJson", "contentHash"]);
  const byteLength = value["byteLength"];
  if (!Number.isSafeInteger(byteLength) || (byteLength as number) < 0) {
    throw new TypeError("Public artifact byte length is invalid");
  }
  return Object.freeze({
    artifactRef: field("artifactRef", value["artifactRef"]),
    contentHash: hash("contentHash", value["contentHash"]),
    canonicalJson: field("canonicalJson", value["canonicalJson"]),
    byteLength: byteLength as number,
  });
}

function normalizeAuthorityResolution(input: unknown): AgreementDisclosureAuthorityResolution {
  const value = snapshotRecord(input);
  if (value["disposition"] === "unavailable") {
    exactRecord(value, ["disposition"]);
    return Object.freeze({ disposition: "unavailable" });
  }
  exactRecord(value, ["agreementHash", "buyerKey", "disposition", "sellerKey"]);
  if (value["disposition"] !== "current") {
    throw new TypeError("Agreement disclosure authority is invalid");
  }
  const buyerKey = field("authority buyerKey", value["buyerKey"]);
  const sellerKey = field("authority sellerKey", value["sellerKey"]);
  if (buyerKey === sellerKey) throw new TypeError("Agreement disclosure parties must be distinct");
  return Object.freeze({
    disposition: "current" as const,
    agreementHash: hash("authority agreementHash", value["agreementHash"]),
    buyerKey,
    sellerKey,
  });
}

function normalizeDeliveryResolution(input: unknown): PublicDeliveryEvidenceResolution {
  const value = snapshotRecord(input);
  if (value["disposition"] === "unavailable") {
    exactRecord(value, ["disposition"]);
    return Object.freeze({ disposition: "unavailable" });
  }
  return normalizeVerifiedDelivery(value);
}

function binding(value: Record<string, unknown>) {
  return {
    instanceId: field("instanceId", value["instanceId"]),
    audience: field("audience", value["audience"]),
    jobId: field("jobId", value["jobId"]),
    agreementHash: hash("agreementHash", value["agreementHash"]),
    artifactRef: field("artifactRef", value["artifactRef"]),
    artifactHash: hash("artifactHash", value["artifactHash"]),
  };
}

function sameBinding(
  left: VerifiedPublicDelivery,
  right: SignedPublicDeliveryPolicy | SignedPublicDisclosureConsent,
): boolean {
  return left.instanceId === right.instanceId && left.audience === right.audience
    && left.jobId === right.jobId && left.agreementHash === right.agreementHash
    && left.artifactRef === right.artifactRef && left.artifactHash === right.artifactHash;
}

function sameDeliveryBinding(left: VerifiedPublicDelivery, right: VerifiedPublicDelivery): boolean {
  return left.disposition === right.disposition && left.accessModel === right.accessModel
    && left.instanceId === right.instanceId && left.audience === right.audience
    && left.jobId === right.jobId && left.agreementHash === right.agreementHash
    && left.artifactRef === right.artifactRef && left.artifactHash === right.artifactHash;
}

function unsignedPolicy(policy: SignedPublicDeliveryPolicy) {
  const { signature: _signature, ...unsigned } = policy;
  return unsigned;
}

function unsignedConsent(consent: SignedPublicDisclosureConsent) {
  const { signature: _signature, ...unsigned } = consent;
  return unsigned;
}

function record(input: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  return exactRecord(snapshotRecord(input), expectedKeys);
}

function snapshotRecord(input: unknown): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Disclosure record is invalid");
  }
  const value = input as Record<string, unknown>;
  const actual = Object.keys(value).sort();
  return Object.fromEntries(actual.map((key) => [key, value[key]]));
}

function exactRecord(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length
    || !actual.every((key, index) => key === expected[index])) {
    throw new TypeError("Disclosure record fields are invalid");
  }
  return value;
}

function withoutOptionalSignature(input: unknown): unknown {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return input;
  const value = { ...(input as Record<string, unknown>) };
  delete value["signature"];
  return value;
}

function field(name: string, value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_LENGTH) {
    throw new TypeError(`Disclosure ${name} is invalid`);
  }
  return value;
}

function hash(name: string, value: unknown): string {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new TypeError(`Disclosure ${name} must be lowercase SHA-256`);
  }
  return value;
}

function timestamp(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`Disclosure ${name} is invalid`);
  }
  return value as number;
}

function safeNow(now: () => number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Disclosure clock is invalid");
  return value;
}

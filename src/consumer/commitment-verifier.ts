import { createHash, createPublicKey, verify as verifyBytes } from "node:crypto";
import {
  ComponentSignatureEncodingError,
  decodeComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import {
  canonicalizeClaimReference,
  canonicalizeGenericClaimReference,
  isRegisteredClaimScheme,
} from "../protocol/claim-reference.ts";
import { consumerCanonicalize } from "./canonical-json.ts";

const COMMITMENT_DOMAIN = "dacs-commitment:v1:";
const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const DIRECT_KEY = /^key:([0-9a-f]{64})$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const DEFAULT_MAX_COMMITMENT_BYTES = 1_048_576;
const AGREEMENT_DOMAIN = "dacs-agreement:v1:";
const PAYEE_BOUND_AGREEMENT_DOMAIN = "dacs-payee-bound-agreement:v1:";

export type CommitmentVerificationResult =
  | {
    readonly disposition: "verified";
    readonly agreementHash: string;
    readonly commitmentHash: string;
    readonly committedAt: number;
    readonly jobId: string;
    readonly orchestrator: string;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported";
    readonly stage: "canonical-form" | "shape" | "binding" | "signature";
    readonly reason: string;
    readonly commitmentHash?: string;
  };

export interface CommitmentVerificationOptions {
  readonly expectedAgreementHash?: string;
  readonly expectedJobId?: string;
  readonly expectedOrchestrator: string;
  readonly maxArtifactBytes?: number;
}

export type CommittedAgreementCryptographyResult =
  | {
    readonly disposition: "verified";
    readonly agreementHash: string;
    readonly signingParties: readonly string[];
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported";
    readonly reason: string;
  };

export interface CommittedAgreementCryptographyOptions {
  readonly maxArtifactBytes?: number;
}

export function verifyCommittedAgreementCryptography(
  canonicalJson: string,
  expectedAgreementHash: string,
  options: CommittedAgreementCryptographyOptions = {},
): CommittedAgreementCryptographyResult {
  const maxArtifactBytes = options.maxArtifactBytes ?? DEFAULT_MAX_COMMITMENT_BYTES;
  if (!Number.isSafeInteger(maxArtifactBytes) || maxArtifactBytes < 1) {
    return Object.freeze({ disposition: "refused-unsupported", reason: "Configured agreement byte limit is invalid" });
  }
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > maxArtifactBytes) {
    return Object.freeze({
      disposition: "refused-unsupported",
      reason: `Agreement exceeds implementation input limit of ${maxArtifactBytes} bytes`,
    });
  }
  if (typeof expectedAgreementHash !== "string" || !HASH.test(expectedAgreementHash)) {
    return Object.freeze({ disposition: "rejected", reason: "Expected agreement hash is invalid" });
  }
  let agreement: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
      || consumerCanonicalize(parsed) !== canonicalJson) {
      return Object.freeze({ disposition: "rejected", reason: "Agreement is not a canonical JSON object" });
    }
    agreement = parsed as Record<string, unknown>;
  } catch (error) {
    return Object.freeze({ disposition: "rejected", reason: message(error) });
  }
  const legacy = agreement["agreementVersion"] === "1";
  const payeeBound = agreement["payeeBoundAgreementVersion"] === "1";
  const partyValues = agreement["parties"];
  const signatureValues = agreement["signatures"];
  if (legacy === payeeBound || !Array.isArray(partyValues)
    || !partyValues.every((party) => object(party) !== null)
    || !Array.isArray(signatureValues)
    || !signatureValues.every((signature) => object(signature) !== null)) {
    return Object.freeze({ disposition: "rejected", reason: "Agreement artifact or signature shape is invalid" });
  }
  const unsigned = { ...agreement };
  delete unsigned["signatures"];
  const agreementHash = hash(consumerCanonicalize(unsigned));
  if (agreementHash !== expectedAgreementHash) {
    return Object.freeze({ disposition: "rejected", reason: "Agreement hash does not match the commitment" });
  }
  const parties = partyValues as Record<string, unknown>[];
  const required = ["buyer", "seller"].map((role) =>
    parties.filter((party) => party["role"] === role));
  if (required.some((matches) => matches.length !== 1 || typeof matches[0]?.["primaryClaim"] !== "string")) {
    return Object.freeze({ disposition: "rejected", reason: "Agreement lacks unique buyer and seller parties" });
  }
  const requiredClaims = required.map((matches) => matches[0]!["primaryClaim"] as string);
  const allowedIdentities = new Set<string>();
  try {
    for (const party of parties) {
      if (typeof party["primaryClaim"] !== "string") throw new TypeError("Agreement party claim is invalid");
      const canonical = canonicalAgreementClaim(party["primaryClaim"]);
      const identity = agreementClaimIdentity(canonical);
      if (canonical !== party["primaryClaim"] || allowedIdentities.has(identity)) {
        throw new TypeError("Agreement party claims are non-canonical or duplicated");
      }
      allowedIdentities.add(identity);
    }
  } catch (error) {
    return Object.freeze({ disposition: "rejected", reason: message(error) });
  }
  const signatures = signatureValues as Record<string, unknown>[];
  const seenIdentities = new Set<string>();
  const signingParties: string[] = [];
  const domain = payeeBound ? PAYEE_BOUND_AGREEMENT_DOMAIN : AGREEMENT_DOMAIN;
  for (const signature of signatures) {
    if (typeof signature["party"] !== "string" || signature["algorithm"] !== "ed25519"
      || typeof signature["value"] !== "string") {
      return Object.freeze({
        disposition: signature["algorithm"] === "ed25519" ? "rejected" : "refused-unsupported",
        reason: "Agreement signature envelope is invalid or unsupported",
      });
    }
    let party: string;
    let identity: string;
    let key: Buffer | null;
    try {
      party = canonicalAgreementClaim(signature["party"]);
      identity = agreementClaimIdentity(party);
      key = directAgreementKey(party);
    } catch (error) {
      return Object.freeze({ disposition: "rejected", reason: message(error) });
    }
    if (party !== signature["party"] || !allowedIdentities.has(identity) || seenIdentities.has(identity)) {
      return Object.freeze({ disposition: "rejected", reason: "Agreement signature party binding is invalid" });
    }
    if (key === null) {
      return Object.freeze({ disposition: "refused-unsupported", reason: "Indirect agreement signer resolution is unavailable" });
    }
    let rawSignature: Uint8Array;
    try {
      rawSignature = decodeComponentSignatureValue(signature["value"], 64);
    } catch (error) {
      return Object.freeze({ disposition: "rejected", reason: message(error) });
    }
    try {
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, key]),
        format: "der",
        type: "spki",
      });
      if (!verifyBytes(
        null,
        Buffer.from(`${domain}${agreementHash}`, "utf8"),
        publicKey,
        rawSignature,
      )) return Object.freeze({ disposition: "rejected", reason: "Agreement signature is invalid" });
    } catch {
      return Object.freeze({ disposition: "rejected", reason: "Agreement signer key is invalid" });
    }
    seenIdentities.add(identity);
    signingParties.push(party);
  }
  if (requiredClaims.some((claim) => !seenIdentities.has(agreementClaimIdentity(claim)))) {
    return Object.freeze({ disposition: "rejected", reason: "Agreement requires buyer and seller signatures" });
  }
  return Object.freeze({ disposition: "verified", agreementHash, signingParties: Object.freeze(signingParties) });
}

function canonicalAgreementClaim(value: string): string {
  const generic = canonicalizeGenericClaimReference(value);
  const claim = isRegisteredClaimScheme(generic.scheme) ? canonicalizeClaimReference(value) : generic;
  return claim.canonicalReference;
}

function agreementClaimIdentity(value: string): string {
  const generic = canonicalizeGenericClaimReference(value);
  const claim = isRegisteredClaimScheme(generic.scheme) ? canonicalizeClaimReference(value) : generic;
  return JSON.stringify([claim.scheme, claim.identifier]);
}

function directAgreementKey(value: string): Buffer | null {
  const generic = canonicalizeGenericClaimReference(value);
  if (generic.scheme !== "key") return null;
  const claim = canonicalizeClaimReference(value);
  return /^[0-9a-f]{64}$/.test(claim.identifier) ? Buffer.from(claim.identifier, "hex") : null;
}

export function verifyCanonicalCommitmentJson(
  canonicalJson: string,
  options: CommitmentVerificationOptions,
): CommitmentVerificationResult {
  const expectedOrchestrator = options?.expectedOrchestrator;
  if (typeof expectedOrchestrator !== "string") {
    return rejected("binding", "Authenticated expected orchestrator binding is required");
  }
  try {
    if (canonicalizeClaimReference(expectedOrchestrator).canonicalReference !== expectedOrchestrator) {
      return rejected("binding", "Expected orchestrator binding is not canonical");
    }
  } catch (error) {
    return rejected("binding", `Expected orchestrator binding is invalid: ${message(error)}`);
  }
  const maxArtifactBytes = options.maxArtifactBytes ?? DEFAULT_MAX_COMMITMENT_BYTES;
  if (!Number.isSafeInteger(maxArtifactBytes) || maxArtifactBytes < 1) {
    return unsupported("canonical-form", "Configured commitment byte limit is invalid");
  }
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > maxArtifactBytes) {
    return unsupported("canonical-form", `Commitment exceeds implementation input limit of ${maxArtifactBytes} bytes`);
  }
  let record: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return rejected("shape", "Commitment must be a JSON object");
    }
    record = parsed as Record<string, unknown>;
    if (consumerCanonicalize(record) !== canonicalJson) {
      return rejected("canonical-form", "Commitment is not canonical JSON");
    }
  } catch (error) {
    return rejected("canonical-form", message(error));
  }

  const signature = object(record["signature"]);
  const listingRef = object(record["listingRef"]);
  if (record["dacsVersion"] !== "1" || typeof record["jobId"] !== "string"
    || !ULID.test(record["jobId"])
    || typeof record["agreementHash"] !== "string" || !HASH.test(record["agreementHash"])
    || listingRef === null || typeof listingRef["listingId"] !== "string"
    || listingRef["listingId"].length === 0
    || !Number.isSafeInteger(listingRef["version"]) || (listingRef["version"] as number) < 1
    || typeof listingRef["contentHash"] !== "string" || !HASH.test(listingRef["contentHash"])
    || !new Set(["fixed-price", "rfq", "sealed-envelope"]).has(record["pattern"] as string)
    || !Number.isSafeInteger(record["committedAt"]) || (record["committedAt"] as number) < 0
    || signature === null) {
    return rejected("shape", "Commitment record shape is invalid");
  }
  if (!Array.isArray(record["parties"]) || record["parties"].length < 2) {
    return rejected("shape", "Commitment requires at least two signing parties");
  }
  const parties = record["parties"] as unknown[];
  try {
    const canonicalParties = parties.map((party) => {
      if (typeof party !== "string") throw new TypeError("Commitment party is not a string");
      const canonical = canonicalizeClaimReference(party).canonicalReference;
      if (canonical !== party) throw new TypeError("Commitment party is not canonical");
      return canonical;
    });
    if (new Set(canonicalParties).size !== canonicalParties.length) {
      return rejected("shape", "Commitment parties must be unique");
    }
  } catch (error) {
    return rejected("shape", message(error));
  }

  const signedScope = { ...record };
  delete signedScope["signature"];
  let commitmentHash: string;
  try {
    commitmentHash = hash(consumerCanonicalize(signedScope));
  } catch (error) {
    return rejected("canonical-form", message(error));
  }
  const agreementHash = record["agreementHash"] as string;
  const jobId = record["jobId"] as string;
  if ((options.expectedAgreementHash !== undefined && options.expectedAgreementHash !== agreementHash)
    || (options.expectedJobId !== undefined && options.expectedJobId !== jobId)) {
    return rejected("binding", "Commitment does not match the expected agreement or job", commitmentHash);
  }
  if (signature["algorithm"] !== "ed25519") {
    return unsupported("signature", `Unsupported commitment signature algorithm: ${String(signature["algorithm"])}`, commitmentHash);
  }
  if (typeof signature["signer"] !== "string" || typeof signature["value"] !== "string") {
    return rejected("signature", "Commitment signature envelope is invalid", commitmentHash);
  }
  let orchestrator: string;
  try {
    orchestrator = canonicalizeClaimReference(signature["signer"]).canonicalReference;
  } catch (error) {
    return rejected("signature", message(error), commitmentHash);
  }
  const keyMatch = DIRECT_KEY.exec(orchestrator);
  if (keyMatch === null || orchestrator !== signature["signer"]) {
    return unsupported("signature", "Indirect commitment signer resolution is unavailable", commitmentHash);
  }
  if (expectedOrchestrator !== orchestrator) {
    return rejected("binding", "Commitment signer is not the expected session orchestrator", commitmentHash);
  }
  let rawSignature: Uint8Array;
  try {
    rawSignature = decodeComponentSignatureValue(signature["value"], 64);
  } catch (error) {
    return rejected(
      "signature",
      error instanceof ComponentSignatureEncodingError ? error.message : "Invalid commitment signature encoding",
      commitmentHash,
    );
  }
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyMatch[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    if (!verifyBytes(
      null,
      Buffer.from(`${COMMITMENT_DOMAIN}${commitmentHash}`, "utf8"),
      publicKey,
      rawSignature,
    )) return rejected("signature", "Commitment signature is invalid", commitmentHash);
  } catch {
    return rejected("signature", "Commitment signer key is invalid", commitmentHash);
  }
  return Object.freeze({
    disposition: "verified",
    agreementHash,
    commitmentHash,
    committedAt: record["committedAt"] as number,
    jobId,
    orchestrator,
  });
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function rejected(
  stage: "canonical-form" | "shape" | "binding" | "signature",
  reason: string,
  commitmentHash?: string,
): CommitmentVerificationResult {
  return Object.freeze({ disposition: "rejected", stage, reason, ...(commitmentHash === undefined ? {} : { commitmentHash }) });
}

function unsupported(
  stage: "canonical-form" | "signature",
  reason: string,
  commitmentHash?: string,
): CommitmentVerificationResult {
  return Object.freeze({ disposition: "refused-unsupported", stage, reason, ...(commitmentHash === undefined ? {} : { commitmentHash }) });
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

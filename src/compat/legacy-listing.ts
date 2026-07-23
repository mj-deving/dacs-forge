import { createHash, createPublicKey, verify as verifyBytes } from "node:crypto";
import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";

const LISTING_DOMAIN = "dacs-listing:v1:";
const MAX_ENVELOPE_BYTES = 32_768;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const DEMOS_AGENT = /^did:demos:agent:([0-9a-f]{64})$/;
const DEMOS_OWNER = /^0x([0-9a-f]{64})$/;
const STORAGE_ADDRESS = /^stor-[0-9a-f]{40}$/;
const LISTING_ID = /^[A-Za-z0-9._~-]{1,128}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const LEGACY_SCOPE_FIELDS = new Set([
  "name",
  "agentId",
  "serviceId",
  "signature",
  "description",
  "claimRequirements",
  "supportedDelivery",
  "supportedNegotiation",
  "supportedPaymentRails",
]);
const verifiedListings = new WeakSet<object>();

export interface LegacySdkListingScope extends Record<string, unknown> {
  readonly name: string;
  readonly agentId: string;
  readonly serviceId: string;
  readonly description: string;
  readonly claimRequirements: readonly string[];
  readonly supportedDelivery: readonly string[];
  readonly supportedNegotiation: readonly string[];
  readonly supportedPaymentRails: readonly string[];
}

export interface VerifiedLegacySdkListing {
  readonly artifactProfile: "legacy-sdk-v0.1";
  readonly sourceEnvelope: Readonly<Record<string, unknown>>;
  readonly scope: Readonly<LegacySdkListingScope>;
  readonly contentHash: string;
  readonly signer: string;
  readonly storageAddress: string;
  readonly sourceEnvelopeSha256: string;
}

export interface LegacySdkListingProvenance {
  readonly expectedEnvelopeSha256: string;
  readonly expectedOwner: string;
  readonly expectedStorageAddress: string;
}

export function readPinnedLegacySdkListingEnvelopeJson(
  rawJson: string,
  provenance: LegacySdkListingProvenance,
): VerifiedLegacySdkListing {
  if (typeof rawJson !== "string" || Buffer.byteLength(rawJson, "utf8") > MAX_ENVELOPE_BYTES) {
    throw new TypeError(`Legacy Listing envelope must be JSON no larger than ${MAX_ENVELOPE_BYTES} bytes`);
  }
  validateProvenance(provenance);
  const sourceEnvelopeSha256 = createHash("sha256").update(rawJson).digest("hex");
  if (sourceEnvelopeSha256 !== provenance.expectedEnvelopeSha256) {
    throw new TypeError("Legacy Listing envelope does not match its immutable source pin");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson) as unknown;
  } catch {
    throw new TypeError("Legacy Listing envelope is not valid JSON");
  }
  if (!isRecord(parsed)) throw new TypeError("Legacy Listing envelope must be an object");
  const envelope = parsed;
  if (envelope["success"] !== true || !isRecord(envelope["data"])) {
    throw new TypeError("Legacy Listing envelope must contain successful object data");
  }
  const storageAddress = requireString(envelope["storageAddress"], "storageAddress");
  if (!STORAGE_ADDRESS.test(storageAddress)) throw new TypeError("Legacy Listing storageAddress is invalid");
  const owner = requireString(envelope["owner"], "owner");
  const ownerMatch = DEMOS_OWNER.exec(owner);
  if (ownerMatch === null) throw new TypeError("Legacy Listing owner is invalid");
  if (storageAddress !== provenance.expectedStorageAddress || owner !== provenance.expectedOwner) {
    throw new TypeError("Legacy Listing envelope differs from its trusted storage provenance");
  }

  const data = envelope["data"];
  rejectUnsupportedLegacyFields(data);
  const signature = requireString(data["signature"], "data.signature");
  if (!/^[0-9a-f]{128}$/.test(signature)) {
    throw new TypeError("Legacy Listing signature must be a lowercase Ed25519 hex value");
  }
  const scopeRecord = withoutFields(data, "signature");
  validateLegacyScope(scopeRecord);
  const agentMatch = DEMOS_AGENT.exec(scopeRecord["agentId"] as string);
  const publicKeyHex = agentMatch?.[1];
  if (publicKeyHex === undefined || publicKeyHex !== ownerMatch[1]) {
    throw new TypeError("Legacy Listing agentId does not match the substrate owner");
  }
  const canonicalScope = canonicalize(scopeRecord);
  const contentHash = sha256Hex(canonicalScope);
  if (!verifyLegacySignature(publicKeyHex, signature, `${LISTING_DOMAIN}${contentHash}`)) {
    throw new TypeError("Legacy Listing signature is invalid");
  }

  const frozenEnvelope = deepFreezeJson(JSON.parse(JSON.stringify(envelope)) as Record<string, unknown>);
  const frozenScope = deepFreezeJson(JSON.parse(canonicalScope) as LegacySdkListingScope);
  const result: VerifiedLegacySdkListing = Object.freeze({
    artifactProfile: "legacy-sdk-v0.1" as const,
    sourceEnvelope: frozenEnvelope,
    scope: frozenScope,
    contentHash,
    signer: scopeRecord["agentId"] as string,
    storageAddress,
    sourceEnvelopeSha256,
  });
  verifiedListings.add(result);
  return result;
}

export function assertVerifiedLegacySdkListing(
  value: unknown,
): asserts value is VerifiedLegacySdkListing {
  if (value === null || typeof value !== "object" || !verifiedListings.has(value)) {
    throw new TypeError("Directory compatibility requires a verified legacy Listing read result");
  }
}

function rejectUnsupportedLegacyFields(data: Record<string, unknown>): void {
  for (const field of Object.keys(data)) {
    if (!LEGACY_SCOPE_FIELDS.has(field)) {
      throw new TypeError(`Legacy Listing contains unsupported profile field ${field}`);
    }
  }
}

function validateProvenance(provenance: LegacySdkListingProvenance): void {
  if (provenance === null || typeof provenance !== "object"
    || typeof provenance.expectedEnvelopeSha256 !== "string"
    || typeof provenance.expectedOwner !== "string"
    || typeof provenance.expectedStorageAddress !== "string"
    || !SHA256.test(provenance.expectedEnvelopeSha256)
    || !DEMOS_OWNER.test(provenance.expectedOwner)
    || !STORAGE_ADDRESS.test(provenance.expectedStorageAddress)) {
    throw new TypeError("Legacy Listing source provenance is invalid");
  }
}

function validateLegacyScope(scope: Record<string, unknown>): asserts scope is LegacySdkListingScope {
  if (!boundedString(scope["name"], 200)) throw new TypeError("Legacy Listing name is invalid");
  if (typeof scope["agentId"] !== "string" || DEMOS_AGENT.exec(scope["agentId"]) === null) {
    throw new TypeError("Legacy Listing agentId is invalid");
  }
  if (typeof scope["serviceId"] !== "string" || !LISTING_ID.test(scope["serviceId"])) {
    throw new TypeError("Legacy Listing serviceId is invalid");
  }
  if (!boundedString(scope["description"], 2_000)) {
    throw new TypeError("Legacy Listing description is invalid");
  }
  requireStringArray(scope["claimRequirements"], "claimRequirements", 64);
  requireStringArray(scope["supportedDelivery"], "supportedDelivery", 64);
  requireStringArray(scope["supportedNegotiation"], "supportedNegotiation", 64);
  requireStringArray(scope["supportedPaymentRails"], "supportedPaymentRails", 64);
}

function requireStringArray(value: unknown, field: string, maximum: number): asserts value is readonly string[] {
  if (!Array.isArray(value) || value.length > maximum
    || value.some((entry) => !boundedString(entry, 128))
    || new Set(value).size !== value.length) {
    throw new TypeError(`Legacy Listing ${field} is invalid`);
  }
}

function verifyLegacySignature(publicKeyHex: string, signatureHex: string, payload: string): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]),
      format: "der",
      type: "spki",
    });
    return verifyBytes(null, Buffer.from(payload, "utf8"), key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`Legacy Listing ${field} is invalid`);
  return value;
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

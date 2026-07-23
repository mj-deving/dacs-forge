import { types as utilTypes } from "node:util";
import {
  verifyDeliveryAttestation,
  type DeliveryAttestationAnchorContext,
  type DeliveryAttestationVerificationResult,
} from "../consumer/delivery-attestation-verifier.ts";
import { consumerCanonicalize } from "../consumer/canonical-json.ts";
import { canonicalizeGenericClaimReference } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";

export const STORAGE_PROGRAM_INLINE_LIMIT_BYTES = 128 * 1024;
export const DEFAULT_EXTERNAL_PAYLOAD_LIMIT_BYTES = 16 * 1024 * 1024;

const MAX_ATTESTED_PAYLOAD_BYTES = 1_048_576;
const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const ACCESS_MODELS = new Set(["public", "buyer-only", "encrypt-to-buyer"]);
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  "byteLength",
)?.get;

export interface ListingSelectedAttestedPayload {
  readonly kind: "attested-payload";
  readonly payloadFormat: string;
  readonly verificationMethod: Readonly<Record<string, unknown>>;
  readonly expectedSizeBytes?: number;
}

export interface ListingSelectedAttestationInput {
  readonly agreementHash: string;
  readonly anchorContext: DeliveryAttestationAnchorContext;
  readonly assertionCanonicalJson: string;
  readonly jobId: string;
  readonly listingDeliverable: ListingSelectedAttestedPayload;
  readonly payloadCanonicalJson: string;
  readonly phaseIndex: number;
  readonly sessionBindingHash: string;
  readonly signer: string;
  readonly verifyResultCanonicalJson: string;
}

export interface StorageProgramDeliverableSpec {
  readonly kind: "storage-program";
  readonly accessModel?: StorageProgramAccessModel;
  readonly expectedSizeBytes?: number;
  readonly schemaUrl?: string;
}

export type StorageProgramAccessModel = "public" | "buyer-only" | "encrypt-to-buyer";

export interface AgreementBoundBuyer {
  readonly primaryClaim: string;
  readonly address?: string;
  readonly encryptionKey?: string;
}

export interface StorageProgramReaderIdentity {
  readonly primaryClaim: string;
  readonly address?: string;
  readonly encryptionKey?: string;
}

export type StorageProgramAccess =
  | { readonly model: "public" }
  | {
    readonly model: "buyer-only";
    readonly allowed: readonly string[];
    readonly blacklist?: readonly string[];
  }
  | { readonly model: "encrypt-to-buyer"; readonly sealedTo: string };

export type StorageProgramRead =
  | { readonly status: "resolved"; readonly access: StorageProgramAccess; readonly value: Uint8Array }
  | { readonly status: "denied" | "absent" | "rejected" | "indeterminate" };

export type ExternalPayloadRead =
  | { readonly status: "resolved"; readonly value: Uint8Array }
  | { readonly status: "absent" | "rejected" | "indeterminate" };

export interface StorageProgramDeliveryEvidence {
  readonly deliverableAnchor: Readonly<{ readonly kind: "storage-program"; readonly locator: string }>;
  readonly deliverableContentHash: string;
}

export interface StorageProgramCompatibilityInput {
  readonly agreementBuyer: AgreementBoundBuyer;
  readonly evidence: StorageProgramDeliveryEvidence;
  readonly expectedPointerContentHash?: string;
  readonly externalRead?: (url: string, maxBytes: number) => ExternalPayloadRead;
  readonly jobId: string;
  readonly listingDeliverable: StorageProgramDeliverableSpec;
  readonly maxExternalPayloadBytes?: number;
  readonly reader: StorageProgramReaderIdentity;
  readonly storageRead: (address: string, reader: StorageProgramReaderIdentity) => StorageProgramRead;
}

export type StorageProgramCompatibilityResult =
  | {
    readonly disposition: "verified";
    readonly accessModel: StorageProgramAccessModel;
    readonly address: string;
    readonly deliverableContentHash: string;
    readonly payloadBytes: number;
    readonly pointerContentHash?: string;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported" | "indeterminate";
    readonly stage: "configuration" | "attestation" | "storage-read" | "access" | "pointer" | "payload";
    readonly reason: string;
  };

export function verifyListingSelectedDeliveryAttestation(
  input: ListingSelectedAttestationInput,
): DeliveryAttestationVerificationResult {
  try {
    const rawInput = input as unknown;
    if (!plainObject(rawInput)) {
      return attestationFailure("rejected", "Delivery attestation input is malformed");
    }
    const rawDeliverable = rawInput["listingDeliverable"];
    const agreementHash = rawInput["agreementHash"];
    const anchorContext = snapshotAnchorContext(rawInput["anchorContext"]);
    const assertionCanonicalJson = rawInput["assertionCanonicalJson"];
    const jobId = rawInput["jobId"];
    const payloadCanonicalJson = rawInput["payloadCanonicalJson"];
    const phaseIndex = rawInput["phaseIndex"];
    const sessionBindingHash = rawInput["sessionBindingHash"];
    const signer = rawInput["signer"];
    const verifyResultCanonicalJson = rawInput["verifyResultCanonicalJson"];
    if (!plainObject(rawDeliverable) || typeof payloadCanonicalJson !== "string"
      || anchorContext === null) {
      return attestationFailure("rejected", "Delivery attestation input is malformed");
    }
    const kind = rawDeliverable["kind"];
    const payloadFormat = rawDeliverable["payloadFormat"];
    const rawVerificationMethod = rawDeliverable["verificationMethod"];
    const expectedSizeBytes = rawDeliverable["expectedSizeBytes"];
    const verificationMethodKind = plainObject(rawVerificationMethod)
      ? rawVerificationMethod["kind"] : undefined;
    if (!exactKeys(
      rawDeliverable,
      ["kind", "payloadFormat", "verificationMethod", "expectedSizeBytes"],
      true,
    ) || kind !== "attested-payload"
      || !boundedString(payloadFormat, 256)
      || !plainObject(rawVerificationMethod)
      || !exactKeys(rawVerificationMethod, ["kind"])
      || verificationMethodKind !== "self-signed") {
      return attestationFailure(
        "refused-unsupported",
        "Listing-selected delivery verification method is unsupported",
      );
    }
    if (expectedSizeBytes !== undefined
      && (!Number.isSafeInteger(expectedSizeBytes) || (expectedSizeBytes as number) < 0)) {
      return attestationFailure("rejected", "Listing delivery size expectation is malformed");
    }
    if (payloadCanonicalJson.length > MAX_ATTESTED_PAYLOAD_BYTES) {
      return attestationFailure("refused-unsupported", "Delivered result exceeds the input limit");
    }
    const payloadBytes = Buffer.byteLength(payloadCanonicalJson, "utf8");
    if (payloadBytes > MAX_ATTESTED_PAYLOAD_BYTES) {
      return attestationFailure("refused-unsupported", "Delivered result exceeds the input limit");
    }
    if (expectedSizeBytes !== undefined && payloadBytes !== expectedSizeBytes) {
      return attestationFailure("rejected", "Delivered result size does not match the Listing");
    }
    const payload = JSON.parse(payloadCanonicalJson) as unknown;
    if (consumerCanonicalize(payload) !== payloadCanonicalJson) {
      return attestationFailure("rejected", "Delivered result is not canonical JSON");
    }
    const verification = verifyDeliveryAttestation(
      assertionCanonicalJson as string,
      verifyResultCanonicalJson as string,
      {
        agreementHash: agreementHash as string,
        anchorContext,
        deliverableContentHash: sha256Hex(payloadCanonicalJson),
        jobId: jobId as string,
        payloadFormat,
        phaseIndex: phaseIndex as number,
        sessionBindingHash: sessionBindingHash as string,
        signer: signer as string,
      },
    );
    if (verification.disposition !== "provisionally-verified"
      && verification.disposition !== "verified") return verification;
    const verifyResult = JSON.parse(verifyResultCanonicalJson as string) as Record<string, unknown>;
    if (verifyResult["method"] !== verificationMethodKind) {
      return attestationFailure("rejected", "Delivery attestation method does not match the Listing");
    }
    return verification;
  } catch {
    return attestationFailure("rejected", "Delivery attestation input is malformed");
  }
}

export function storageProgramDeliverableAddress(jobId: string): string {
  if (typeof jobId !== "string" || !ULID.test(jobId)) {
    throw new TypeError("Storage Program delivery jobId is invalid");
  }
  return `dacs4:deliverable:${jobId}`;
}

export function verifyStorageProgramCompatibility(
  input: StorageProgramCompatibilityInput,
): StorageProgramCompatibilityResult {
  let snapshot: StorageProgramCompatibilityInput;
  try {
    const result = snapshotStorageProgramInput(input);
    if (result === null) {
      return refused("configuration", "Storage Program compatibility expectation is malformed");
    }
    snapshot = result;
  } catch {
    return refused("configuration", "Storage Program compatibility expectation is malformed");
  }
  return verifyStorageProgramCompatibilitySnapshot(snapshot);
}

function verifyStorageProgramCompatibilitySnapshot(
  input: StorageProgramCompatibilityInput,
): StorageProgramCompatibilityResult {
  const deliverable = input.listingDeliverable;
  const declaredAccess = deliverable.accessModel ?? "public";
  const address = storageProgramDeliverableAddress(input.jobId);
  if (input.evidence.deliverableAnchor.kind !== "storage-program"
    || input.evidence.deliverableAnchor.locator !== address) {
    return rejected("configuration", "Delivery evidence does not bind the canonical Storage Program address");
  }
  const preAuthorization = authorizeReader(declaredAccess, input.agreementBuyer, input.reader);
  if (preAuthorization !== null) return preAuthorization;

  const storageRead = callStorageReader(input.storageRead, address, input.reader);
  if ("disposition" in storageRead) return storageRead;
  const deliveredAccess = storageRead.access.model;
  if (declaredAccess !== deliveredAccess) {
    if (declaredAccess !== "public" && deliveredAccess === "public") {
      return indeterminate("access", "Declared private delivery resolved as public");
    }
    if (declaredAccess !== "public") {
      return rejected("access", "Delivered access model does not match the Listing");
    }
  }
  const resolvedAuthorization = authorizeResolvedAccess(
    storageRead.access,
    input.agreementBuyer,
    input.reader,
  );
  if (resolvedAuthorization !== null) return resolvedAuthorization;

  const storedSnapshot = snapshotBytes(storageRead.value, STORAGE_PROGRAM_INLINE_LIMIT_BYTES);
  if (storedSnapshot.status === "invalid") {
    return indeterminate("storage-read", "Storage Program reader returned malformed bytes");
  }
  if (storedSnapshot.status === "oversized") {
    return rejected("storage-read", "Storage Program value exceeds the inline size limit");
  }
  const storedValue = storedSnapshot.value;
  const pointerRequired = deliverable.expectedSizeBytes !== undefined
    && deliverable.expectedSizeBytes > STORAGE_PROGRAM_INLINE_LIMIT_BYTES;
  if (pointerRequired || input.expectedPointerContentHash !== undefined) {
    return verifyExtendedPointer(input, declaredAccess, address, storedValue);
  }
  if (deliverable.expectedSizeBytes !== undefined && deliverable.expectedSizeBytes !== storedValue.byteLength) {
    return rejected("payload", "Inline payload size does not match the Listing");
  }
  const payloadHash = sha256Hex(storedValue);
  if (payloadHash !== input.evidence.deliverableContentHash) {
    return rejected("payload", "Inline payload hash does not match delivery evidence");
  }
  return Object.freeze({
    disposition: "verified",
    accessModel: declaredAccess,
    address,
    deliverableContentHash: payloadHash,
    payloadBytes: storedValue.byteLength,
  });
}

function verifyExtendedPointer(
  input: StorageProgramCompatibilityInput,
  accessModel: StorageProgramAccessModel,
  address: string,
  storedValue: Uint8Array,
): StorageProgramCompatibilityResult {
  if (input.expectedPointerContentHash === undefined || !HASH.test(input.expectedPointerContentHash)) {
    return refused("pointer", "Extended pointer expectation is not pinned");
  }
  const pointerHash = sha256Hex(storedValue);
  if (pointerHash !== input.expectedPointerContentHash) {
    return rejected("pointer", "Extended pointer content does not match the pinned fixture");
  }
  const pointer = parsePointer(storedValue);
  if ("disposition" in pointer) return pointer;
  if (input.externalRead === undefined) {
    return refused("pointer", "Extended payload reader is unavailable");
  }
  const maxBytes = input.maxExternalPayloadBytes ?? DEFAULT_EXTERNAL_PAYLOAD_LIMIT_BYTES;
  if (input.listingDeliverable.expectedSizeBytes !== undefined
    && input.listingDeliverable.expectedSizeBytes <= STORAGE_PROGRAM_INLINE_LIMIT_BYTES) {
    return refused("payload", "Listing expected payload size is incompatible with an extended pointer");
  }
  if (input.listingDeliverable.expectedSizeBytes !== undefined
    && input.listingDeliverable.expectedSizeBytes > maxBytes) {
    return refused("payload", "Listing expected payload size exceeds the configured size limit");
  }
  const externalRead = callExternalReader(input.externalRead, pointer.externalUrl, maxBytes);
  if ("disposition" in externalRead) return externalRead;
  const payloadSnapshot = snapshotBytes(externalRead.value, maxBytes);
  if (payloadSnapshot.status === "invalid") {
    return indeterminate("payload", "External payload reader returned malformed bytes");
  }
  if (payloadSnapshot.status === "oversized") {
    return rejected("payload", "External payload exceeds the configured size limit");
  }
  const payload = payloadSnapshot.value;
  if (input.listingDeliverable.expectedSizeBytes !== undefined
    && payload.byteLength !== input.listingDeliverable.expectedSizeBytes) {
    return rejected("payload", "External payload size does not match the Listing");
  }
  if (payload.byteLength <= STORAGE_PROGRAM_INLINE_LIMIT_BYTES) {
    return rejected("payload", "Extended pointer payload does not exceed the inline size limit");
  }
  const payloadHash = sha256Hex(payload);
  if (payloadHash !== pointer.externalContentHash
    || payloadHash !== input.evidence.deliverableContentHash) {
    return rejected("payload", "External payload hash does not match pointer and delivery evidence");
  }
  return Object.freeze({
    disposition: "verified",
    accessModel,
    address,
    deliverableContentHash: payloadHash,
    payloadBytes: payload.byteLength,
    pointerContentHash: pointerHash,
  });
}

function parsePointer(
  bytes: Uint8Array,
): Readonly<{ externalUrl: string; externalContentHash: string }> | StorageProgramCompatibilityResult {
  let canonicalJson: string;
  let value: unknown;
  try {
    canonicalJson = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    value = JSON.parse(canonicalJson) as unknown;
    if (consumerCanonicalize(value) !== canonicalJson) {
      return rejected("pointer", "Extended pointer is not canonical JSON");
    }
  } catch {
    return rejected("pointer", "Extended pointer is not valid canonical UTF-8 JSON");
  }
  if (!plainObject(value) || !exactKeys(value, ["externalContentHash", "externalUrl", "segmentRefs"], true)
    || !boundedString(value["externalUrl"], 2_048)
    || typeof value["externalContentHash"] !== "string" || !HASH.test(value["externalContentHash"])
    || !externalUrl(value["externalUrl"] as string)
    || (value["segmentRefs"] !== undefined && (!Array.isArray(value["segmentRefs"])
      || !value["segmentRefs"].every(attestationRef)))) {
    return rejected("pointer", "Extended pointer shape is invalid");
  }
  return Object.freeze({
    externalUrl: value["externalUrl"] as string,
    externalContentHash: value["externalContentHash"] as string,
  });
}

function snapshotStorageProgramInput(input: unknown): StorageProgramCompatibilityInput | null {
  if (!plainObject(input)) return null;
  const rawListing = input["listingDeliverable"];
  const rawEvidence = input["evidence"];
  const rawBuyer = input["agreementBuyer"];
  const rawReader = input["reader"];
  const jobId = input["jobId"];
  const expectedPointerContentHash = input["expectedPointerContentHash"];
  const externalRead = input["externalRead"];
  const maxExternalPayloadBytes = input["maxExternalPayloadBytes"];
  const storageRead = input["storageRead"];
  const rawAnchor = plainObject(rawEvidence) ? rawEvidence["deliverableAnchor"] : undefined;
  if (!plainObject(rawListing) || !plainObject(rawEvidence)
    || !plainObject(rawAnchor) || !plainObject(rawBuyer)
    || !plainObject(rawReader) || typeof jobId !== "string" || !ULID.test(jobId)
    || typeof storageRead !== "function"
    || (externalRead !== undefined && typeof externalRead !== "function")
    || (expectedPointerContentHash !== undefined && typeof expectedPointerContentHash !== "string")) {
    return null;
  }
  const kind = rawListing["kind"];
  const accessModel = rawListing["accessModel"];
  const expectedSizeBytes = rawListing["expectedSizeBytes"];
  const schemaUrl = rawListing["schemaUrl"];
  const evidenceHash = rawEvidence["deliverableContentHash"];
  const anchorKind = rawAnchor["kind"];
  const anchorLocator = rawAnchor["locator"];
  const maxBytes = maxExternalPayloadBytes === undefined
    ? DEFAULT_EXTERNAL_PAYLOAD_LIMIT_BYTES : maxExternalPayloadBytes;
  if (kind !== "storage-program"
    || (accessModel !== undefined && !ACCESS_MODELS.has(accessModel as string))
    || (expectedSizeBytes !== undefined
      && (!Number.isSafeInteger(expectedSizeBytes) || (expectedSizeBytes as number) < 0))
    || (schemaUrl !== undefined && !boundedString(schemaUrl, 2_048))
    || typeof evidenceHash !== "string" || !HASH.test(evidenceHash)
    || anchorKind !== "storage-program" || !boundedString(anchorLocator, 2_048)
    || !Number.isSafeInteger(maxBytes) || (maxBytes as number) <= STORAGE_PROGRAM_INLINE_LIMIT_BYTES) {
    return null;
  }
  const buyer = snapshotIdentity(rawBuyer);
  const reader = snapshotIdentity(rawReader);
  if (buyer === null || reader === null) return null;
  const listingDeliverable = Object.freeze({
    kind: "storage-program" as const,
    ...(accessModel === undefined ? {} : { accessModel: accessModel as StorageProgramAccessModel }),
    ...(expectedSizeBytes === undefined ? {} : { expectedSizeBytes: expectedSizeBytes as number }),
    ...(schemaUrl === undefined ? {} : { schemaUrl: schemaUrl as string }),
  });
  return Object.freeze({
    agreementBuyer: buyer,
    evidence: Object.freeze({
      deliverableAnchor: Object.freeze({ kind: "storage-program" as const, locator: anchorLocator }),
      deliverableContentHash: evidenceHash,
    }),
    ...(expectedPointerContentHash === undefined ? {} : { expectedPointerContentHash }),
    ...(externalRead === undefined ? {} : {
      externalRead: externalRead as NonNullable<StorageProgramCompatibilityInput["externalRead"]>,
    }),
    jobId,
    listingDeliverable,
    maxExternalPayloadBytes: maxBytes as number,
    reader,
    storageRead: storageRead as StorageProgramCompatibilityInput["storageRead"],
  });
}

function snapshotIdentity(value: Record<string, unknown>): AgreementBoundBuyer | null {
  const primaryClaim = value["primaryClaim"];
  const address = value["address"];
  const encryptionKey = value["encryptionKey"];
  const snapshot = Object.freeze({
    primaryClaim: primaryClaim as string,
    ...(address === undefined ? {} : { address: address as string }),
    ...(encryptionKey === undefined ? {} : { encryptionKey: encryptionKey as string }),
  });
  return validIdentity(snapshot) ? snapshot : null;
}

function snapshotAnchorContext(value: unknown): DeliveryAttestationAnchorContext | null {
  if (!plainObject(value)) return null;
  const mode = value["mode"];
  const read = value["read"];
  if (mode === "pre-anchor" && exactKeys(value, ["mode"])) {
    return Object.freeze({ mode: "pre-anchor" });
  }
  if (mode === "post-anchor" && typeof read === "function" && exactKeys(value, ["mode", "read"])) {
    return Object.freeze({ mode: "post-anchor", read: read as (address: string) => never });
  }
  return null;
}

function authorizeReader(
  accessModel: StorageProgramAccessModel,
  buyer: AgreementBoundBuyer,
  reader: StorageProgramReaderIdentity,
): StorageProgramCompatibilityResult | null {
  if (accessModel === "public") return null;
  if (reader.primaryClaim !== buyer.primaryClaim) {
    return rejected("access", "Reader is not the agreement-bound buyer");
  }
  if (accessModel === "buyer-only" && (buyer.address === undefined || reader.address !== buyer.address)) {
    return rejected("access", "Reader address is not the agreement-bound buyer address");
  }
  if (accessModel === "encrypt-to-buyer"
    && (buyer.encryptionKey === undefined || reader.encryptionKey !== buyer.encryptionKey)) {
    return rejected("access", "Reader key is not the agreement-bound buyer encryption key");
  }
  return null;
}

function authorizeResolvedAccess(
  access: StorageProgramAccess,
  buyer: AgreementBoundBuyer,
  reader: StorageProgramReaderIdentity,
): StorageProgramCompatibilityResult | null {
  if (access.model === "public") return null;
  if (access.model === "buyer-only") {
    if (reader.primaryClaim !== buyer.primaryClaim
      || buyer.address === undefined || reader.address !== buyer.address
      || access.allowed.length !== 1 || access.allowed[0] !== buyer.address
      || access.blacklist?.includes(buyer.address) === true) {
      return rejected("access", "Storage Program ACL does not authorize the agreement-bound buyer");
    }
    return null;
  }
  return reader.primaryClaim === buyer.primaryClaim
    && buyer.encryptionKey !== undefined
    && reader.encryptionKey === buyer.encryptionKey
    && access.sealedTo === buyer.encryptionKey
    ? null : rejected("access", "Storage Program is not sealed to the agreement-bound buyer key");
}

function callStorageReader(
  reader: StorageProgramCompatibilityInput["storageRead"],
  address: string,
  identity: StorageProgramReaderIdentity,
): Extract<StorageProgramRead, { status: "resolved" }> | StorageProgramCompatibilityResult {
  let result: StorageProgramRead;
  try {
    result = reader(address, Object.freeze({ ...identity }));
    if (!plainObject(result)) {
      return indeterminate("storage-read", "Storage Program reader returned a malformed result");
    }
    const status = result.status;
    if (status === "denied") return rejected("access", "Storage Program reader denied access");
    if (status === "absent") return rejected("storage-read", "Storage Program is authoritatively absent");
    if (status === "rejected") return rejected("storage-read", "Storage Program read was rejected");
    if (status === "indeterminate") return indeterminate("storage-read", "Storage Program read is indeterminate");
    if (status !== "resolved") {
      return indeterminate("storage-read", "Storage Program reader returned a malformed result");
    }
    const access = snapshotAccess(result.access);
    const value = result.value;
    if (access === null) {
      return indeterminate("storage-read", "Storage Program reader returned a malformed result");
    }
    return Object.freeze({
      status: "resolved",
      access,
      value,
    });
  } catch {
    return indeterminate("storage-read", "Storage Program read failed");
  }
}

function callExternalReader(
  reader: NonNullable<StorageProgramCompatibilityInput["externalRead"]>,
  url: string,
  maxBytes: number,
): Extract<ExternalPayloadRead, { status: "resolved" }> | StorageProgramCompatibilityResult {
  let result: ExternalPayloadRead;
  try {
    result = reader(url, maxBytes);
    if (!plainObject(result)) {
      return indeterminate("payload", "External payload reader returned a malformed result");
    }
    const status = result.status;
    if (status === "absent") return rejected("payload", "External payload is authoritatively absent");
    if (status === "rejected") return rejected("payload", "External payload read was rejected");
    if (status === "indeterminate") return indeterminate("payload", "External payload read is indeterminate");
    if (status !== "resolved") {
      return indeterminate("payload", "External payload reader returned a malformed result");
    }
    const value = result.value;
    return Object.freeze({ status: "resolved", value });
  } catch {
    return indeterminate("payload", "External payload read failed");
  }
}

function snapshotAccess(value: unknown): StorageProgramAccess | null {
  if (!plainObject(value)) return null;
  const model = value["model"];
  if (model === "public" && exactKeys(value, ["model"])) {
    return Object.freeze({ model: "public" });
  }
  if (model === "encrypt-to-buyer") {
    const sealedTo = value["sealedTo"];
    if (!exactKeys(value, ["model", "sealedTo"]) || !boundedString(sealedTo, 4_096)) return null;
    return Object.freeze({ model: "encrypt-to-buyer", sealedTo });
  }
  if (model !== "buyer-only") return null;
  const allowed = snapshotStringArray(value["allowed"], 2_048);
  const rawBlacklist = value["blacklist"];
  const blacklist = rawBlacklist === undefined ? undefined : snapshotStringArray(rawBlacklist, 2_048);
  if (!exactKeys(value, ["model", "allowed", "blacklist"], true)
    || allowed === null || blacklist === null) return null;
  return Object.freeze({
    model: "buyer-only",
    allowed,
    ...(blacklist === undefined ? {} : { blacklist }),
  });
}

function validIdentity(value: AgreementBoundBuyer | StorageProgramReaderIdentity): boolean {
  if (!plainObject(value) || !boundedString(value.primaryClaim, 2_048)
    || (value.address !== undefined && !boundedString(value.address, 2_048))
    || (value.encryptionKey !== undefined && !boundedString(value.encryptionKey, 4_096))) return false;
  try {
    return canonicalizeGenericClaimReference(value.primaryClaim).canonicalReference === value.primaryClaim;
  } catch {
    return false;
  }
}

function attestationRef(value: unknown): boolean {
  if (!plainObject(value) || !exactKeys(value, ["anchor", "contentHash", "signer"], true)
    || !plainObject(value["anchor"]) || !exactKeys(value["anchor"], ["kind", "locator"])
    || !["storage-program", "ipfs", "https"].includes(value["anchor"]["kind"] as string)
    || !boundedString(value["anchor"]["locator"], 2_048)
    || typeof value["contentHash"] !== "string" || !HASH.test(value["contentHash"])
    || (value["signer"] !== undefined && !boundedString(value["signer"], 2_048))) return false;
  if (typeof value["signer"] === "string") {
    try {
      if (canonicalizeGenericClaimReference(value["signer"]).canonicalReference !== value["signer"]) {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function externalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "ipfs:")
      && url.username === "" && url.password === "" && url.hash === "";
  } catch {
    return false;
  }
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  optionalLast = false,
): boolean {
  const keys = Object.keys(value);
  const required = optionalLast ? allowed.slice(0, -1) : allowed;
  return required.every((key) => keys.includes(key)) && keys.every((key) => allowed.includes(key));
}

function plainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function boundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function snapshotStringArray(value: unknown, maxLength: number): readonly string[] | null {
  if (!Array.isArray(value)) return null;
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0 || length > 256) return null;
  const snapshot: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const entry = value[index];
    if (!boundedString(entry, maxLength)) return null;
    snapshot.push(entry);
  }
  return Object.freeze(snapshot);
}

function realUint8Array(value: unknown): value is Uint8Array {
  try {
    return utilTypes.isUint8Array(value);
  } catch {
    return false;
  }
}

function snapshotBytes(
  value: unknown,
  maxBytes: number,
): Readonly<{ status: "resolved"; value: Uint8Array }>
  | Readonly<{ status: "invalid" }>
  | Readonly<{ status: "oversized" }> {
  if (!realUint8Array(value)) return Object.freeze({ status: "invalid" });
  try {
    if (TYPED_ARRAY_BYTE_LENGTH_GETTER === undefined) return Object.freeze({ status: "invalid" });
    const intrinsicByteLength = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH_GETTER, value, []) as number;
    if (!Number.isSafeInteger(intrinsicByteLength) || intrinsicByteLength < 0) {
      return Object.freeze({ status: "invalid" });
    }
    if (intrinsicByteLength > maxBytes) return Object.freeze({ status: "oversized" });
    const snapshot = new Uint8Array(intrinsicByteLength);
    snapshot.set(value);
    return Object.freeze({ status: "resolved", value: snapshot });
  } catch {
    return Object.freeze({ status: "invalid" });
  }
}

function attestationFailure(
  disposition: "rejected" | "refused-unsupported",
  reason: string,
): DeliveryAttestationVerificationResult {
  return Object.freeze({ disposition, stage: "binding", reason });
}

function rejected(
  stage: Extract<StorageProgramCompatibilityResult, { reason: string }>["stage"],
  reason: string,
): StorageProgramCompatibilityResult {
  return Object.freeze({ disposition: "rejected", stage, reason });
}

function refused(
  stage: Extract<StorageProgramCompatibilityResult, { reason: string }>["stage"],
  reason: string,
): StorageProgramCompatibilityResult {
  return Object.freeze({ disposition: "refused-unsupported", stage, reason });
}

function indeterminate(
  stage: Extract<StorageProgramCompatibilityResult, { reason: string }>["stage"],
  reason: string,
): StorageProgramCompatibilityResult {
  return Object.freeze({ disposition: "indeterminate", stage, reason });
}

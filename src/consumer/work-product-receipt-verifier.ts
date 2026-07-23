import {
  createPublicKey,
  createHash,
  verify as verifyBytes,
} from "node:crypto";
import { consumerCanonicalize } from "./canonical-json.ts";
import {
  decodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";

const DOMAINS = Object.freeze({
  "1": "dacs-template:work-product-receipt:v1:",
  "2": "dacs-template:work-product-receipt:v2:",
});
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HASH = /^[0-9a-f]{64}$/;
const KEY_CLAIM = /^key:([0-9a-f]{64})$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const MAX_RECEIPT_BYTES = 16_384;
const MAX_INPUT_BYTES = 262_144;
const MAX_OUTPUT_BYTES = 262_144;

export type WorkProductReceiptVerificationResult =
  | {
    readonly disposition: "verified";
    readonly receiptContentHash: string;
    readonly outputContentHash: string;
    readonly seller: string;
  }
  | {
    readonly disposition: "rejected";
    readonly stage: "canonical-form" | "shape" | "binding" | "signature";
    readonly reason: string;
  };

export interface WorkProductReceiptExpectations {
  readonly inputSchemaJson?: string;
  readonly inputSchemaVersion?: string;
  readonly jobId?: string;
  readonly outputKind?: string;
  readonly outputSchemaJson?: string;
  readonly outputSchemaVersion?: string;
  readonly requestHash?: string;
  readonly seller?: string;
  readonly serviceId?: string;
  readonly serviceVersion?: string;
}

export function verifyWorkProductReceiptJson(
  receiptJson: string,
  inputJson: string,
  outputJson: string,
  expected: WorkProductReceiptExpectations = {},
): WorkProductReceiptVerificationResult {
  let receipt: Record<string, unknown>;
  let output: unknown;
  try {
    assertByteLimit("Receipt", receiptJson, MAX_RECEIPT_BYTES);
    assertByteLimit("Input", inputJson, MAX_INPUT_BYTES);
    assertByteLimit("Output", outputJson, MAX_OUTPUT_BYTES);
    receipt = parseCanonicalObject(receiptJson);
    parseCanonical(inputJson);
    output = parseCanonical(outputJson);
  } catch (error) {
    return rejected("canonical-form", errorMessage(error));
  }
  const shapeError = validateReceiptShape(receipt);
  if (shapeError !== null) return rejected("shape", shapeError);

  const jobId = receipt["jobId"] as string;
  const requestHash = receipt["requestHash"] as string;
  const seller = receipt["seller"] as string;
  const service = receipt["service"] as Record<string, unknown>;
  const inputReference = receipt["input"] as Record<string, unknown>;
  const outputReference = receipt["output"] as Record<string, unknown>;
  const signature = receipt["signature"] as Record<string, unknown>;
  const receiptVersion = receipt["receiptVersion"] as "1" | "2";
  if (
    inputReference["contentHash"] !== hash(inputJson)
    || outputReference["contentHash"] !== hash(outputJson)
  ) return rejected("binding", "Receipt input/output content hash mismatch");
  if (
    (expected.jobId !== undefined && expected.jobId !== jobId)
    || (expected.requestHash !== undefined && expected.requestHash !== requestHash)
    || (expected.seller !== undefined && expected.seller !== seller)
    || (expected.serviceId !== undefined && expected.serviceId !== service["id"])
    || (expected.serviceVersion !== undefined && expected.serviceVersion !== service["version"])
  ) return rejected("binding", "Receipt does not match expected session or service bindings");
  const inputSchema = inputReference["schema"] as Record<string, unknown>;
  const outputSchema = outputReference["schema"] as Record<string, unknown>;
  try {
    if (!matchesSchemaExpectation(
      inputSchema,
      expected.inputSchemaJson,
      expected.inputSchemaVersion,
    ) || !matchesSchemaExpectation(
      outputSchema,
      expected.outputSchemaJson,
      expected.outputSchemaVersion,
    ) || (expected.outputKind !== undefined && outputReference["kind"] !== expected.outputKind)) {
      return rejected("binding", "Receipt schema or deliverable binding mismatch");
    }
  } catch (error) {
    return rejected("canonical-form", errorMessage(error));
  }

  const keyMatch = KEY_CLAIM.exec(seller);
  if (keyMatch === null || signature["signer"] !== seller) {
    return rejected("binding", "Receipt seller and signature signer must be the same key claim");
  }
  const rawPublicKey = Buffer.from(keyMatch[1] ?? "", "hex");
  const value = signature["value"] as string;
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = receiptVersion === "1"
      ? importLegacyComponentSignatureValue(value, "standard-base64-padded", 64)
      : decodeComponentSignatureValue(value, 64);
  } catch {
    return rejected(
      "signature",
      receiptVersion === "1"
        ? "Legacy v1 receipt signature is not canonical standard Base64"
        : "Receipt signature is not canonical Ed25519 base64url",
    );
  }
  const scope = {
    ...receipt,
    signature: { algorithm: signature["algorithm"], signer: signature["signer"] },
  };
  const signedHash = hash(consumerCanonicalize(scope));
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
      format: "der",
      type: "spki",
    });
    if (!verifyBytes(
      null,
      Buffer.from(`${DOMAINS[receiptVersion]}${signedHash}`, "utf8"),
      publicKey,
      signatureBytes,
    )) return rejected("signature", "Receipt seller signature is invalid");
  } catch {
    return rejected("signature", "Receipt seller key could not verify the signature");
  }

  return Object.freeze({
    disposition: "verified",
    receiptContentHash: hash(receiptJson),
    outputContentHash: hash(consumerCanonicalize(output)),
    seller,
  });
}

function validateReceiptShape(receipt: Record<string, unknown>): string | null {
  if (!exactKeys(receipt, [
    "evidenceMode", "input", "jobId", "output", "producedAt", "receiptVersion", "requestHash",
    "seller", "service", "signature",
  ])) return "Receipt has missing or unknown fields";
  if (
    (receipt["receiptVersion"] !== "1" && receipt["receiptVersion"] !== "2")
    || receipt["evidenceMode"] !== "fixture"
  ) {
    return "Receipt version or evidence mode is unsupported";
  }
  if (typeof receipt["jobId"] !== "string" || !ULID.test(receipt["jobId"])) {
    return "Receipt jobId is invalid";
  }
  if (typeof receipt["requestHash"] !== "string" || !HASH.test(receipt["requestHash"])) {
    return "Receipt requestHash is invalid";
  }
  if (typeof receipt["seller"] !== "string" || KEY_CLAIM.exec(receipt["seller"]) === null) {
    return "Receipt seller must be a canonical key claim";
  }
  if (!isCanonicalTimestamp(receipt["producedAt"])) return "Receipt producedAt is invalid";
  const service = object(receipt["service"]);
  if (
    service === null
    || !exactKeys(service, ["id", "version"])
    || typeof service["id"] !== "string"
    || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(service["id"])
    || typeof service["version"] !== "string"
    || !/^\d+\.\d+\.\d+$/.test(service["version"])
  ) return "Receipt service identity is invalid";
  const inputError = validateArtifactReference(receipt["input"], false);
  if (inputError !== null) return `Receipt input ${inputError}`;
  const outputError = validateArtifactReference(receipt["output"], true);
  if (outputError !== null) return `Receipt output ${outputError}`;
  const signature = object(receipt["signature"]);
  if (
    signature === null
    || !exactKeys(signature, ["algorithm", "signer", "value"])
    || signature["algorithm"] !== "ed25519"
    || typeof signature["signer"] !== "string"
    || typeof signature["value"] !== "string"
  ) return "Receipt signature shape is invalid";
  return null;
}

function validateArtifactReference(value: unknown, hasKind: boolean): string | null {
  const reference = object(value);
  const keys = hasKind ? ["contentHash", "kind", "schema"] : ["contentHash", "schema"];
  if (reference === null || !exactKeys(reference, keys)) return "reference shape is invalid";
  if (typeof reference["contentHash"] !== "string" || !HASH.test(reference["contentHash"])) {
    return "content hash is invalid";
  }
  if (hasKind && (typeof reference["kind"] !== "string" || reference["kind"].length === 0)) {
    return "kind is invalid";
  }
  const schema = object(reference["schema"]);
  if (
    schema === null
    || !exactKeys(schema, ["contentHash", "id", "version"])
    || typeof schema["contentHash"] !== "string"
    || !HASH.test(schema["contentHash"])
    || typeof schema["id"] !== "string"
    || schema["id"].length === 0
    || typeof schema["version"] !== "string"
    || schema["version"].length === 0
  ) return "schema reference is invalid";
  return null;
}

function parseCanonicalObject(value: string): Record<string, unknown> {
  const parsed = parseCanonical(value);
  const record = object(parsed);
  if (record === null) throw new TypeError("Receipt must be a JSON object");
  return record;
}

function parseCanonical(value: string): unknown {
  const parsed = JSON.parse(value) as unknown;
  if (consumerCanonicalize(parsed) !== value) throw new TypeError("JSON is not canonical");
  return parsed;
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((entry, index) => entry === [...expected].sort()[index]);
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function matchesSchemaExpectation(
  reference: Record<string, unknown>,
  schemaJson: string | undefined,
  version: string | undefined,
): boolean {
  if (schemaJson === undefined && version === undefined) return true;
  if (schemaJson === undefined || version === undefined) {
    throw new TypeError("Expected schema JSON and version must be supplied together");
  }
  const schema = parseCanonicalObject(schemaJson);
  return typeof schema["$id"] === "string"
    && schema["$id"] === reference["id"]
    && hash(schemaJson) === reference["contentHash"]
    && version === reference["version"];
}

function assertByteLimit(label: string, value: string, limit: number): void {
  if (typeof value !== "string") throw new TypeError(`${label} JSON must be a string`);
  if (Buffer.byteLength(value, "utf8") > limit) {
    throw new TypeError(`${label} JSON exceeds ${limit} bytes`);
  }
}

function rejected(
  stage: "canonical-form" | "shape" | "binding" | "signature",
  reason: string,
): WorkProductReceiptVerificationResult {
  return Object.freeze({ disposition: "rejected", stage, reason });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Canonical JSON parsing failed";
}

import type { EvidenceMode } from "../core/evidence-mode.ts";
import { assertArtifactSizeLimit } from "../core/artifact-size.ts";
import { canonicalize, deepFreezeJson } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const WORK_PRODUCT_RECEIPT_DOMAIN = "dacs-template:work-product-receipt:v2:";
const MAX_RECEIPT_BYTES = 16_384;

export interface ReceiptArtifactReference {
  readonly contentHash: string;
  readonly schema: {
    readonly id: string;
    readonly version: string;
    readonly contentHash: string;
  };
}

export interface UnsignedWorkProductReceipt {
  readonly receiptVersion: "2";
  readonly jobId: string;
  readonly requestHash: string;
  readonly service: { readonly id: string; readonly version: string };
  readonly evidenceMode: EvidenceMode;
  readonly input: ReceiptArtifactReference;
  readonly output: ReceiptArtifactReference & { readonly kind: string };
  readonly producedAt: string;
  readonly seller: string;
}

export interface WorkProductReceipt extends Omit<UnsignedWorkProductReceipt, "receiptVersion"> {
  readonly receiptVersion: "1" | "2";
  readonly signature: {
    readonly algorithm: "ed25519";
    readonly signer: string;
    readonly value: string;
  };
}

export interface SignedWorkProductReceipt {
  readonly receipt: WorkProductReceipt;
  readonly canonicalJson: string;
  readonly contentHash: string;
}

export function signWorkProductReceipt(
  input: UnsignedWorkProductReceipt,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedWorkProductReceipt {
  assertFixtureSigningAuthority(signer, context);
  const normalized = normalizeUnsignedReceipt(input, signer.signer);
  const scope = {
    ...normalized,
    signature: { algorithm: signer.algorithm, signer: signer.signer },
  };
  const scopeHash = sha256Hex(canonicalize(scope));
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${WORK_PRODUCT_RECEIPT_DOMAIN}${scopeHash}`), context),
    "standard-base64-padded",
    64,
  ));
  const receipt = deepFreezeJson({
    ...normalized,
    signature: { algorithm: signer.algorithm, signer: signer.signer, value: signature },
  });
  const canonicalJson = canonicalize(receipt);
  assertArtifactSizeLimit("Work-product receipt", canonicalJson, MAX_RECEIPT_BYTES);
  return Object.freeze({
    receipt,
    canonicalJson,
    contentHash: sha256Hex(canonicalJson),
  });
}

function normalizeUnsignedReceipt(
  input: UnsignedWorkProductReceipt,
  signer: string,
): UnsignedWorkProductReceipt {
  assertExactKeys(input, [
    "evidenceMode",
    "input",
    "jobId",
    "output",
    "producedAt",
    "receiptVersion",
    "requestHash",
    "seller",
    "service",
  ], "receipt");
  if (input.receiptVersion !== "2") throw new TypeError("Receipt version must be 2");
  if (!/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(input.jobId)) {
    throw new TypeError("Receipt jobId must be a canonical ULID");
  }
  if (!isHash(input.requestHash)) throw new TypeError("Receipt requestHash must be lowercase SHA-256");
  if (input.evidenceMode !== "fixture") {
    throw new TypeError("This receipt producer supports fixture evidence only");
  }
  if (input.seller !== signer) throw new TypeError("Receipt seller must be the signing claim");
  validateTimestamp(input.producedAt);
  validateService(input.service);
  validateReference("input", input.input);
  validateReference("output", input.output);
  if (input.output.kind.length === 0 || input.output.kind.length > 256) {
    throw new TypeError("Receipt output kind must be bounded and non-empty");
  }
  return deepFreezeJson({
    receiptVersion: input.receiptVersion,
    jobId: input.jobId,
    requestHash: input.requestHash,
    service: { id: input.service.id, version: input.service.version },
    evidenceMode: input.evidenceMode,
    input: {
      contentHash: input.input.contentHash,
      schema: {
        id: input.input.schema.id,
        version: input.input.schema.version,
        contentHash: input.input.schema.contentHash,
      },
    },
    output: {
      kind: input.output.kind,
      contentHash: input.output.contentHash,
      schema: {
        id: input.output.schema.id,
        version: input.output.schema.version,
        contentHash: input.output.schema.contentHash,
      },
    },
    producedAt: input.producedAt,
    seller: input.seller,
  });
}

function validateService(service: UnsignedWorkProductReceipt["service"]): void {
  assertExactKeys(service, ["id", "version"], "service");
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(service.id)) {
    throw new TypeError("Receipt service id is invalid");
  }
  if (!/^\d+\.\d+\.\d+$/.test(service.version)) {
    throw new TypeError("Receipt service version is invalid");
  }
}

function validateReference(label: string, reference: ReceiptArtifactReference): void {
  assertExactKeys(
    reference,
    label === "output" ? ["contentHash", "kind", "schema"] : ["contentHash", "schema"],
    label,
  );
  assertExactKeys(reference.schema, ["contentHash", "id", "version"], `${label} schema`);
  if (!isHash(reference.contentHash) || !isHash(reference.schema.contentHash)) {
    throw new TypeError(`Receipt ${label} hashes must be lowercase SHA-256`);
  }
  if (reference.schema.id.length === 0 || reference.schema.version.length === 0) {
    throw new TypeError(`Receipt ${label} schema identity is required`);
  }
}

function assertExactKeys(value: unknown, expected: readonly string[], label: string): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`Receipt ${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new TypeError(`Receipt ${label} must contain exactly ${required.join(", ")}`);
  }
}

function validateTimestamp(value: string): void {
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    throw new TypeError("Receipt producedAt must be a canonical ISO timestamp");
  }
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

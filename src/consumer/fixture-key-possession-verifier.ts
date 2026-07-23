import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import { FIXTURE_KEY_POSSESSION_DOMAIN, fixtureKeyPossessionLogicalAddress } from "../producer/fixture-key-possession.ts";
import { consumerCanonicalize } from "./canonical-json.ts";

const HASH = /^[0-9a-f]{64}$/;
const KEY = /^key:([0-9a-f]{64})$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_BYTES = 16_384;
const ASSERTION_FIELDS = new Set([
  "assertionVersion", "method", "jobId", "evaluatedParty", "bundleHash",
  "possessionVerified", "observedAt", "evidenceMode", "signature",
]);
const SIGNATURE_FIELDS = new Set(["algorithm", "signer", "value"]);

export interface FixtureKeyPossessionExpectation {
  readonly bundleHash: string;
  readonly evaluatedParty: string;
  readonly jobId: string;
}

export type FixtureKeyPossessionVerification =
  | {
      readonly disposition: "verified";
      readonly contentHash: string;
      readonly logicalAddress: string;
      readonly observedAt: number;
    }
  | {
    readonly disposition: "rejected" | "refused-unsupported";
    readonly stage: "canonical-form" | "shape" | "binding" | "signature";
    readonly reason: string;
  };

export function verifyFixtureKeyPossessionJson(
  canonicalJson: string,
  expectation: FixtureKeyPossessionExpectation,
): FixtureKeyPossessionVerification {
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > MAX_BYTES) {
    return rejected("canonical-form", `Fixture key-possession assertion exceeds ${MAX_BYTES} bytes`);
  }
  let value: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
      || consumerCanonicalize(parsed) !== canonicalJson) {
      return rejected("canonical-form", "Fixture key-possession assertion is not canonical JSON");
    }
    value = parsed as Record<string, unknown>;
  } catch {
    return rejected("canonical-form", "Fixture key-possession assertion JSON is invalid");
  }
  const signature = object(value["signature"]);
  if (Object.keys(value).some((key) => !ASSERTION_FIELDS.has(key))
    || value["assertionVersion"] !== "1" || value["method"] !== "self-signed"
    || typeof value["jobId"] !== "string" || !ULID.test(value["jobId"])
    || typeof value["evaluatedParty"] !== "string" || typeof value["bundleHash"] !== "string"
    || !HASH.test(value["bundleHash"]) || value["possessionVerified"] !== true
    || !Number.isSafeInteger(value["observedAt"]) || (value["observedAt"] as number) < 0
    || value["evidenceMode"] !== "fixture" || signature === null
    || Object.keys(signature).some((key) => !SIGNATURE_FIELDS.has(key))
    || signature["algorithm"] !== "ed25519" || typeof signature["signer"] !== "string"
    || typeof signature["value"] !== "string") {
    return rejected("shape", "Fixture key-possession assertion shape is invalid");
  }
  try {
    if (canonicalizeClaimReference(value["evaluatedParty"]).canonicalReference !== value["evaluatedParty"]) {
      return rejected("binding", "Fixture key-possession party is non-canonical");
    }
  } catch {
    return rejected("binding", "Fixture key-possession party is invalid");
  }
  if (value["jobId"] !== expectation.jobId || value["evaluatedParty"] !== expectation.evaluatedParty
    || value["bundleHash"] !== expectation.bundleHash || signature["signer"] !== expectation.evaluatedParty) {
    return rejected("binding", "Fixture key-possession assertion does not match its evaluated bundle");
  }
  const key = KEY.exec(expectation.evaluatedParty);
  if (key === null) return refused("signature", "Indirect fixture key-possession signer is unsupported");
  const unsigned = { ...value };
  delete unsigned["signature"];
  const semanticHash = sha256(consumerCanonicalize(unsigned));
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    const bytes = decodeComponentSignatureValue(signature["value"] as string, 64);
    if (!verifyBytes(
      null,
      Buffer.from(`${FIXTURE_KEY_POSSESSION_DOMAIN}${semanticHash}`, "utf8"),
      publicKey,
      bytes,
    )) return rejected("signature", "Fixture key-possession signature is invalid");
  } catch {
    return rejected("signature", "Fixture key-possession signature cannot be verified");
  }
  return Object.freeze({
    disposition: "verified",
    contentHash: sha256(canonicalJson),
    logicalAddress: fixtureKeyPossessionLogicalAddress(expectation.jobId, expectation.evaluatedParty),
    observedAt: value["observedAt"] as number,
  });
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

type Stage = "canonical-form" | "shape" | "binding" | "signature";

function rejected(stage: Stage, reason: string) {
  return Object.freeze({ disposition: "rejected" as const, stage, reason });
}

function refused(stage: Stage, reason: string) {
  return Object.freeze({ disposition: "refused-unsupported" as const, stage, reason });
}

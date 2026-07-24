import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { canonicalize } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";

const BINDING_DOMAIN = "dacs-fixture-binding:v1:";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

export interface FixtureBindingScope {
  readonly logicalAddress: string;
  readonly nativeAddress: string;
  readonly contentHash: string;
  readonly createdByTx: string;
}

export interface FixtureBindingProof extends FixtureBindingScope {
  readonly signer: string;
  readonly signature: string;
}

export interface DereferencedFixtureRecord {
  readonly canonicalJson: string;
  readonly createdByTx: string;
}

export interface FixtureBindingAuthority {
  readonly dereference: (nativeAddress: string) => DereferencedFixtureRecord | null;
  readonly verifyNativeWrite: (input: FixtureBindingScope & {
    readonly signer: string;
  }) => boolean;
}

export type FixtureBindingResult =
  | { readonly disposition: "verified"; readonly canonicalJson: string; readonly proof: FixtureBindingProof }
  | { readonly disposition: "rejected"; readonly reason: string };

export function fixtureBindingSigningBytes(input: FixtureBindingScope): string {
  validateScope(input);
  return `${BINDING_DOMAIN}${sha256Hex(canonicalize(bindingScope(input)))}`;
}

export function verifyFixtureBinding(
  proof: FixtureBindingProof,
  authority: FixtureBindingAuthority,
): FixtureBindingResult {
  try {
    validateProof(proof);
    const resolved = authority.dereference(proof.nativeAddress);
    if (resolved === null) return rejected("native address did not dereference");
    if (typeof resolved.canonicalJson !== "string" || typeof resolved.createdByTx !== "string") {
      return rejected("dereference result is malformed");
    }
    let artifact: unknown;
    try { artifact = JSON.parse(resolved.canonicalJson) as unknown; }
    catch { return rejected("dereferenced content is not JSON"); }
    if (canonicalize(artifact) !== resolved.canonicalJson) {
      return rejected("dereferenced content is not canonical JSON");
    }
    if (sha256Hex(resolved.canonicalJson) !== proof.contentHash) {
      return rejected("dereferenced content hash does not match binding");
    }
    if (resolved.createdByTx !== proof.createdByTx) {
      return rejected("dereferenced native-write provenance does not match binding");
    }
    if (!verifyDirectEd25519(proof.signer, proof.signature, fixtureBindingSigningBytes(proof))) {
      return rejected("binding signature is invalid");
    }
    const scope = bindingScope(proof);
    if (authority.verifyNativeWrite({ ...scope, signer: proof.signer }) !== true) {
      return rejected("native-write provenance is not independently verified");
    }
    return Object.freeze({ disposition: "verified", canonicalJson: resolved.canonicalJson, proof: Object.freeze({ ...proof }) });
  } catch (error) {
    return rejected(error instanceof Error ? error.message : "binding proof is invalid");
  }
}

function bindingScope(input: FixtureBindingScope): FixtureBindingScope {
  return Object.freeze({
    logicalAddress: input.logicalAddress,
    nativeAddress: input.nativeAddress,
    contentHash: input.contentHash,
    createdByTx: input.createdByTx,
  });
}

function validateProof(proof: FixtureBindingProof): void {
  if (proof === null || typeof proof !== "object" || Array.isArray(proof)
    || Object.keys(proof).sort().join(",") !== "contentHash,createdByTx,logicalAddress,nativeAddress,signature,signer") {
    throw new TypeError("Fixture binding proof must contain exactly the declared fields");
  }
  validateScope(proof);
  const signer = canonicalizeClaimReference(proof.signer);
  if (signer.canonicalReference !== proof.signer || signer.scheme !== "key"
    || !LOWER_HEX_64.test(signer.identifier)) {
    throw new TypeError("Fixture binding signer must be a canonical direct Ed25519 key claim");
  }
  if (!canonicalBase64Signature(proof.signature)) {
    throw new TypeError("Fixture binding signature must be canonical Ed25519 Base64");
  }
}

function validateScope(input: FixtureBindingScope): void {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Fixture binding scope must be an object");
  }
  for (const field of ["logicalAddress", "nativeAddress", "createdByTx"] as const) {
    const value = input[field];
    if (typeof value !== "string" || value.length === 0 || value.length > 4096
      || value !== value.normalize("NFC")) {
      throw new TypeError(`Fixture binding ${field} must be a bounded NFC string`);
    }
  }
  if (!LOWER_HEX_64.test(input.contentHash)) {
    throw new TypeError("Fixture binding contentHash must be lowercase SHA-256");
  }
}

function verifyDirectEd25519(claim: string, signature: string, payload: string): boolean {
  try {
    const parsed = canonicalizeClaimReference(claim);
    if (parsed.scheme !== "key" || !LOWER_HEX_64.test(parsed.identifier)) return false;
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(parsed.identifier, "hex")]),
      format: "der",
      type: "spki",
    });
    return verifyBytes(null, Buffer.from(payload), key, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

function canonicalBase64Signature(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const bytes = Buffer.from(value, "base64");
  return bytes.byteLength === 64 && bytes.toString("base64") === value;
}

function rejected(reason: string): FixtureBindingResult {
  return Object.freeze({ disposition: "rejected", reason });
}

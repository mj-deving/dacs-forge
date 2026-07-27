import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  assertArtifactSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

const BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface UnsignedIdentityBundle extends Record<string, unknown> {
  readonly bundleVersion: "1";
  readonly presentedBy: string;
  readonly presentedAt: number;
  readonly sessionNonce?: string;
  readonly claims: readonly Record<string, unknown>[];
}

export interface SignedIdentityBundleResult {
  readonly bundle: Readonly<Record<string, unknown>>;
  readonly bundleHash: string;
  readonly canonicalJson: string;
}

export function signPerClaimIdentityBundle(
  input: UnsignedIdentityBundle,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedIdentityBundleResult {
  assertArtifactSigningAuthority(signer, context);
  if (Object.hasOwn(input, "presentation")) {
    throw new TypeError("Unsigned IdentityBundle must not contain presentation");
  }
  const signerClaim = canonicalizeClaimReference(signer.signer).canonicalReference;
  const normalized = JSON.parse(canonicalize(input)) as Record<string, unknown>;
  validateBundleProducerShape(normalized, signerClaim);
  const presentedBy = normalized["presentedBy"] as string;
  const signedScope = canonicalize(withoutFields(normalized, "presentation"));
  const bundleHash = sha256Hex(signedScope);
  const signature = signer.sign(new TextEncoder().encode(`${BUNDLE_DOMAIN}${bundleHash}`), context);
  assertBase64Signature(signature);
  const bundle = {
    ...normalized,
    presentation: {
      kind: "per-claim",
      signatures: [{ ref: presentedBy, signature }],
    },
  };
  const canonicalJson = canonicalize(bundle);
  return Object.freeze({
    bundle: deepFreezeJson(JSON.parse(canonicalJson) as Record<string, unknown>),
    bundleHash,
    canonicalJson,
  });
}

function validateBundleProducerShape(bundle: Record<string, unknown>, signer: string): void {
  if (bundle["bundleVersion"] !== "1") throw new TypeError("IdentityBundle version must be 1");
  if (!Number.isSafeInteger(bundle["presentedAt"]) || (bundle["presentedAt"] as number) < 0) {
    throw new TypeError("IdentityBundle presentedAt must be a non-negative safe integer");
  }
  if (bundle["sessionNonce"] !== undefined
    && (typeof bundle["sessionNonce"] !== "string"
      || !/^[0-9a-f]{32,}$/.test(bundle["sessionNonce"]))) {
    throw new TypeError("IdentityBundle sessionNonce must be at least 32 lowercase hex characters");
  }
  const presentedBy = canonicalizeClaimReference(String(bundle["presentedBy"])).canonicalReference;
  if (presentedBy !== bundle["presentedBy"]) {
    throw new TypeError("IdentityBundle presentedBy must already be canonical");
  }
  const claims = bundle["claims"];
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new TypeError("IdentityBundle claims must be non-empty");
  }
  const references = claims.map((claim) => {
    if (claim === null || typeof claim !== "object" || Array.isArray(claim)) {
      throw new TypeError("IdentityBundle claim must be an object");
    }
    const reference = canonicalizeClaimReference(String((claim as Record<string, unknown>)["ref"]))
      .canonicalReference;
    if (reference !== (claim as Record<string, unknown>)["ref"]) {
      throw new TypeError("IdentityBundle claim ref must already be canonical");
    }
    assertBundleClaimFields(claim as Record<string, unknown>);
    return reference;
  });
  if (new Set(references.map(claimIdentityKey)).size !== references.length) {
    throw new TypeError("IdentityBundle claims must not contain duplicates");
  }
  if (!references.some((reference) => sameClaimIdentity(reference, presentedBy))
    || !references.some((reference) => sameClaimIdentity(reference, signer))
    || !sameClaimIdentity(presentedBy, signer)) {
    throw new TypeError("IdentityBundle must contain presentedBy and signer claims");
  }
}

export function assertPerClaimIdentityBundleForPublication(bundle: Record<string, unknown>): void {
  const presentedBy = bundle["presentedBy"];
  if (bundle["bundleVersion"] !== "1" || typeof presentedBy !== "string"
    || !Number.isSafeInteger(bundle["presentedAt"]) || (bundle["presentedAt"] as number) < 0) {
    throw new TypeError("Published IdentityBundle header is invalid");
  }
  if (canonicalizeClaimReference(presentedBy).canonicalReference !== presentedBy) {
    throw new TypeError("Published IdentityBundle presentedBy must be canonical");
  }
  if (bundle["sessionNonce"] !== undefined
    && (typeof bundle["sessionNonce"] !== "string"
      || !/^[0-9a-f]{32,}$/.test(bundle["sessionNonce"]))) {
    throw new TypeError("Published IdentityBundle sessionNonce is invalid");
  }
  const claims = bundle["claims"];
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new TypeError("Published IdentityBundle claims must be non-empty");
  }
  const references = claims.map((claim) => {
    if (claim === null || typeof claim !== "object" || Array.isArray(claim)
      || typeof (claim as Record<string, unknown>)["ref"] !== "string") {
      throw new TypeError("Published IdentityBundle claim is invalid");
    }
    const claimRecord = claim as Record<string, unknown>;
    const reference = claimRecord["ref"] as string;
    if (canonicalizeClaimReference(reference).canonicalReference !== reference) {
      throw new TypeError("Published IdentityBundle claim ref must be canonical");
    }
    assertBundleClaimFields(claimRecord);
    return reference;
  });
  const identities = references.map(claimIdentityKey);
  if (new Set(identities).size !== identities.length
    || !references.some((reference) => sameClaimIdentity(reference, presentedBy))) {
    throw new TypeError("Published IdentityBundle claims are ambiguous or omit presentedBy");
  }
  const presentation = bundle["presentation"];
  if (presentation === null || typeof presentation !== "object" || Array.isArray(presentation)
    || (presentation as Record<string, unknown>)["kind"] !== "per-claim") {
    throw new TypeError("Publisher supports only per-claim IdentityBundle presentations");
  }
  const signatures = (presentation as Record<string, unknown>)["signatures"];
  if (!Array.isArray(signatures) || signatures.length === 0) {
    throw new TypeError("Published IdentityBundle presentation must be non-empty");
  }
  const unsigned = { ...bundle };
  delete unsigned["presentation"];
  const bundleHash = sha256Hex(canonicalize(unsigned));
  const seen = new Set<string>();
  let presentedByVerified = false;
  for (const entry of signatures) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError("Published IdentityBundle signature entry is invalid");
    }
    const ref = (entry as Record<string, unknown>)["ref"];
    const signature = (entry as Record<string, unknown>)["signature"];
    if (typeof ref !== "string" || typeof signature !== "string"
      || canonicalizeClaimReference(ref).canonicalReference !== ref
      || seen.has(claimIdentityKey(ref))
      || !references.some((reference) => sameClaimIdentity(reference, ref))
      || !verifyEd25519(ref, signature, `${BUNDLE_DOMAIN}${bundleHash}`)) {
      throw new TypeError("Published IdentityBundle signature is invalid");
    }
    seen.add(claimIdentityKey(ref));
    if (sameClaimIdentity(ref, presentedBy)) presentedByVerified = true;
  }
  if (!presentedByVerified) throw new TypeError("Published IdentityBundle does not prove presentedBy control");
}

function verifyEd25519(claim: string, signature: string, payload: string): boolean {
  let publicKeyHex: string;
  try {
    const parsed = canonicalizeClaimReference(claim);
    if (parsed.scheme !== "key" || !/^[0-9a-f]{64}$/.test(parsed.identifier)) return false;
    publicKeyHex = parsed.identifier;
  } catch {
    return false;
  }
  const bytes = Buffer.from(signature, "base64");
  if (bytes.byteLength !== 64 || bytes.toString("base64") !== signature) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]),
      format: "der",
      type: "spki",
    });
    return verifyBytes(null, Buffer.from(payload), key, bytes);
  } catch {
    return false;
  }
}

function claimIdentityKey(reference: string): string {
  const claim = canonicalizeClaimReference(reference);
  return `${claim.scheme.length}:${claim.scheme}${claim.identifier}`;
}

function verifyResultRef(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const ref = value as Record<string, unknown>;
  const anchor = ref["anchor"];
  return anchor !== null && typeof anchor === "object" && !Array.isArray(anchor)
    && ["storage-program", "ipfs", "https"].includes(String((anchor as Record<string, unknown>)["kind"]))
    && typeof (anchor as Record<string, unknown>)["locator"] === "string"
    && ((anchor as Record<string, unknown>)["locator"] as string).length > 0
    && typeof ref["contentHash"] === "string" && /^[0-9a-f]{64}$/.test(ref["contentHash"])
    && Number.isSafeInteger(ref["recipeVersion"]) && (ref["recipeVersion"] as number) >= 1;
}

function assertBundleClaimFields(claim: Record<string, unknown>): void {
  if ((claim["verifiedBy"] !== undefined && !verifyResultRef(claim["verifiedBy"]))
    || (claim["issuedAt"] !== undefined
      && (!Number.isSafeInteger(claim["issuedAt"]) || (claim["issuedAt"] as number) < 0))
    || (claim["expiresAt"] !== undefined
      && (!Number.isSafeInteger(claim["expiresAt"]) || (claim["expiresAt"] as number) < 0))
    || (claim["metadata"] !== undefined
      && (claim["metadata"] === null || typeof claim["metadata"] !== "object"
        || Array.isArray(claim["metadata"])))) {
    throw new TypeError("IdentityBundle claim metadata is invalid");
  }
}

function assertBase64Signature(value: string): void {
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength !== 64 || decoded.toString("base64") !== value) {
    throw new Error("Signer returned a non-canonical Ed25519 signature");
  }
}

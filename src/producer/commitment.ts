import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const COMMITMENT_DOMAIN = "dacs-commitment:v1:";

const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

export interface CommitmentListingReference extends Record<string, unknown> {
  readonly listingId: string;
  readonly version: number;
  readonly contentHash: string;
}

export interface UnsignedCommitmentRecord extends Record<string, unknown> {
  readonly dacsVersion: "1";
  readonly jobId: string;
  readonly agreementHash: string;
  readonly listingRef: CommitmentListingReference;
  readonly parties: readonly string[];
  readonly pattern: "fixed-price" | "rfq" | "sealed-envelope";
  readonly committedAt: number;
}

export interface CommitmentSignature extends Record<string, unknown> {
  readonly algorithm: "ed25519";
  readonly signer: string;
  readonly value: string;
}

export interface CommitmentRecord extends UnsignedCommitmentRecord {
  readonly signature: CommitmentSignature;
}

export interface SignedCommitmentResult {
  readonly commitment: Readonly<CommitmentRecord>;
  readonly commitmentHash: string;
  readonly canonicalJson: string;
  readonly signedScopeCanonicalJson: string;
}

export function signCommitmentRecord(
  input: UnsignedCommitmentRecord,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedCommitmentResult {
  assertFixtureSigningAuthority(signer, context);
  if (Object.hasOwn(input, "signature")) {
    throw new TypeError("Unsigned commitment must not contain a signature");
  }
  const normalized = normalizeCommitment(input);
  const orchestrator = canonicalizeClaimReference(signer.signer).canonicalReference;
  if (orchestrator !== signer.signer || !/^key:[0-9a-f]{64}$/.test(orchestrator)) {
    throw new TypeError("Commitment signer must be a canonical direct Ed25519 key ClaimReference");
  }
  const signedScopeCanonicalJson = canonicalize(withoutFields(normalized, "signature"));
  const commitmentHash = sha256Hex(signedScopeCanonicalJson);
  const signatureBytes = importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${COMMITMENT_DOMAIN}${commitmentHash}`), context),
    "standard-base64-padded",
    64,
  );
  const commitment = {
    ...normalized,
    signature: {
      algorithm: signer.algorithm,
      signer: orchestrator,
      value: encodeComponentSignatureValue(signatureBytes),
    },
  } as CommitmentRecord;
  const canonicalJson = canonicalize(commitment);
  return Object.freeze({
    commitment: deepFreezeJson(JSON.parse(canonicalJson) as CommitmentRecord),
    commitmentHash,
    canonicalJson,
    signedScopeCanonicalJson,
  });
}

export function commitmentLogicalAddress(jobId: string): string {
  if (typeof jobId !== "string" || !ULID.test(jobId)) {
    throw new TypeError("Commitment jobId must be a canonical ULID");
  }
  return `dacs3:commit:${jobId}`;
}

function normalizeCommitment(input: UnsignedCommitmentRecord): UnsignedCommitmentRecord {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Commitment record must be an object");
  }
  if (input.dacsVersion !== "1" || typeof input.jobId !== "string" || !ULID.test(input.jobId)
    || typeof input.agreementHash !== "string" || !HASH.test(input.agreementHash)) {
    throw new TypeError("Commitment version, jobId, or agreementHash is invalid");
  }
  const listingRef = input.listingRef;
  if (listingRef === null || typeof listingRef !== "object" || Array.isArray(listingRef)
    || typeof listingRef.listingId !== "string" || listingRef.listingId.length === 0
    || !Number.isSafeInteger(listingRef.version) || listingRef.version < 1
    || typeof listingRef.contentHash !== "string" || !HASH.test(listingRef.contentHash)) {
    throw new TypeError("Commitment listingRef is invalid");
  }
  if (!Array.isArray(input.parties) || input.parties.length < 2) {
    throw new TypeError("Commitment requires at least two signing parties");
  }
  const parties = input.parties.map((party) => {
    if (typeof party !== "string") {
      throw new TypeError("Commitment parties must be canonical ClaimReferences");
    }
    const canonical = canonicalizeClaimReference(party).canonicalReference;
    if (canonical !== party) throw new TypeError("Commitment parties must be canonical ClaimReferences");
    return canonical;
  });
  if (new Set(parties).size !== parties.length) {
    throw new TypeError("Commitment parties must be unique");
  }
  if (!new Set(["fixed-price", "rfq", "sealed-envelope"]).has(input.pattern)
    || !Number.isSafeInteger(input.committedAt) || input.committedAt < 0) {
    throw new TypeError("Commitment pattern or committedAt is invalid");
  }
  return JSON.parse(canonicalize({ ...input, parties })) as UnsignedCommitmentRecord;
}

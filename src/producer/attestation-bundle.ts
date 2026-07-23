import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { canonicalizeClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { verifyCanonicalAttestationBundleJson } from "../consumer/attestation-bundle-verifier.ts";
import type {
  AttestationBundleVerificationOptions,
  AttestationReferenceCheck,
} from "../consumer/attestation-bundle-verifier.ts";
import type { AttestationReferenceContext } from "../consumer/attestation-bundle-verifier.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const ATTESTATION_BUNDLE_DOMAIN = "dacs-bundle:v1:";
export const MAX_ATTESTATION_BUNDLE_BYTES = 128 * 1024;

export type BundleRole = "buyer" | "seller" | "orchestrator";
export type BundleOutcome =
  | "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate"
  | "aborted-by-self" | "aborted-by-other";

export interface BundleParty extends Record<string, unknown> {
  readonly role: BundleRole;
  readonly bundleHash: string;
  readonly primaryClaim: string;
}

export interface UnsignedAttestationBundle extends Record<string, unknown> {
  readonly bundleVersion: "1";
  readonly jobId: string;
  readonly outcome: BundleOutcome;
  readonly listingRef: Readonly<Record<string, unknown>>;
  readonly agreementRef?: Readonly<Record<string, unknown>>;
  readonly parties: readonly BundleParty[];
  readonly phaseSummary: readonly Readonly<Record<string, unknown>>[];
  readonly vetRecords: readonly Readonly<Record<string, unknown>>[];
  readonly settlementEvidence: readonly Readonly<Record<string, unknown>>[];
  readonly recipeRegistryVersion: number;
  readonly railRegistryVersion: number;
  readonly finalisedAt: number;
}

export interface BundlePartySigner {
  readonly role: BundleRole;
  readonly signer: ArtifactSigner;
}

export interface SignedAttestationBundleCopy {
  readonly anchoredByRole: BundleRole;
  readonly artifact: Readonly<Record<string, unknown>>;
  readonly canonicalJson: string;
  readonly artifactContentHash: string;
  readonly logicalAddress: string;
}

export interface SignedAttestationBundleResult {
  readonly bundleHash: string;
  readonly signedScopeCanonicalJson: string;
  readonly copies: readonly SignedAttestationBundleCopy[];
}

export function bundleLogicalAddress(jobId: string, role: BundleRole): string {
  if (typeof jobId !== "string" || jobId.length === 0) throw new TypeError("Bundle jobId is required");
  return `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`;
}

export function signAttestationBundle(
  input: UnsignedAttestationBundle,
  partySigners: readonly BundlePartySigner[],
  anchorRoles: readonly BundleRole[],
  context: FixtureSigningContext,
  resolveAttestationRef: (
    ref: Readonly<Record<string, unknown>>,
    context: AttestationReferenceContext,
  ) => AttestationReferenceCheck,
  authorityResolvers: Pick<
    AttestationBundleVerificationOptions,
    "resolveListingRef" | "resolvePartyIdentity" | "resolveExecutedPhasePlan"
  >,
): SignedAttestationBundleResult {
  if (Object.hasOwn(input, "signatures") || Object.hasOwn(input, "anchoredByRole")) {
    throw new TypeError("Unsigned bundle must not contain copy-local or signature fields");
  }
  const normalized = JSON.parse(canonicalize(input)) as Record<string, unknown>;
  const parties = normalized["parties"];
  if (!Array.isArray(parties)) throw new TypeError("Bundle parties are required");
  const claims = requiredPartyClaims(parties);
  const requiredRoles = new Set<BundleRole>(["buyer", "seller"]);
  if (claims.has("orchestrator")) requiredRoles.add("orchestrator");
  const isAbort = normalized["outcome"] === "aborted-by-self" || normalized["outcome"] === "aborted-by-other";
  const isSingleSignedAbort = isAbort && partySigners.length === 1;
  if (!isSingleSignedAbort && partySigners.length !== requiredRoles.size) {
    throw new TypeError("Bundle requires every party signer, except for a valid single-signed abort");
  }
  const seen = new Set<BundleRole>();
  for (const entry of partySigners) {
    assertFixtureSigningAuthority(entry.signer, context);
    const claim = claims.get(entry.role);
    if (claim === undefined || seen.has(entry.role)
      || !sameClaimIdentity(claim, entry.signer.signer)) {
      throw new TypeError("Bundle signer must uniquely match its required party role");
    }
    seen.add(entry.role);
  }
  if (isSingleSignedAbort && !seen.has("buyer") && !seen.has("seller")) {
    throw new TypeError("Single-signed abort must be signed by buyer or seller");
  }
  if (!isSingleSignedAbort) {
    for (const role of requiredRoles) {
      if (!seen.has(role)) throw new TypeError(`Bundle lacks required ${role} signature`);
    }
  }
  if (anchorRoles.length === 0 || new Set(anchorRoles).size !== anchorRoles.length
    || anchorRoles.some((role) => !claims.has(role))) {
    throw new TypeError("Bundle anchor roles must be distinct session party roles");
  }
  if (isSingleSignedAbort) {
    const signerRole = [...seen][0]!;
    if (anchorRoles.length !== 1 || anchorRoles[0] !== signerRole) {
      throw new TypeError("Single-signed abort requires only its signer role-local anchor");
    }
  } else if (anchorRoles.length !== requiredRoles.size
    || [...requiredRoles].some((role) => !anchorRoles.includes(role))) {
    throw new TypeError("Bundle requires one role-local anchor for every required party");
  }

  const signedScopeCanonicalJson = canonicalize(withoutFields(normalized, "signatures", "anchoredByRole"));
  const bundleHash = sha256Hex(signedScopeCanonicalJson);
  const payload = new TextEncoder().encode(`${ATTESTATION_BUNDLE_DOMAIN}${bundleHash}`);
  const signatures = [...partySigners]
    .sort((left, right) => left.role < right.role ? -1 : left.role > right.role ? 1 : 0)
    .map(({ role, signer }) => ({
      party: claims.get(role)!,
      algorithm: signer.algorithm,
      value: encodeComponentSignatureValue(importLegacyComponentSignatureValue(
        signer.sign(payload, context), "standard-base64-padded", 64,
      )),
    }));
  const copies = anchorRoles.map((anchoredByRole) => {
    const artifact = { ...normalized, anchoredByRole, signatures };
    const canonicalJson = canonicalize(artifact);
    if (Buffer.byteLength(canonicalJson, "utf8") > MAX_ATTESTATION_BUNDLE_BYTES) {
      throw new TypeError(`AttestationBundle exceeds ${MAX_ATTESTATION_BUNDLE_BYTES} bytes`);
    }
    const logicalAddress = bundleLogicalAddress(input.jobId, anchoredByRole);
    const verified = verifyCanonicalAttestationBundleJson(canonicalJson, {
      expectedAddress: logicalAddress,
      resolveAttestationRef,
      ...authorityResolvers,
    });
    if (verified.disposition !== "verified" || verified.bundleHash !== bundleHash) {
      const reason = verified.disposition === "verified" ? "bundle hash mismatch" : verified.reason;
      throw new TypeError(`Bundle failed independent conformance: ${reason}`);
    }
    return Object.freeze({
      anchoredByRole,
      artifact: deepFreezeJson(JSON.parse(canonicalJson) as Record<string, unknown>),
      canonicalJson,
      artifactContentHash: sha256Hex(canonicalJson),
      logicalAddress,
    });
  });
  return Object.freeze({ bundleHash, signedScopeCanonicalJson, copies: Object.freeze(copies) });
}

function requiredPartyClaims(parties: readonly unknown[]): Map<BundleRole, string> {
  const claims = new Map<BundleRole, string>();
  for (const party of parties) {
    if (party === null || typeof party !== "object" || Array.isArray(party)) {
      throw new TypeError("Bundle party must be an object");
    }
    const role = (party as Record<string, unknown>)["role"];
    const primaryClaim = (party as Record<string, unknown>)["primaryClaim"];
    if ((role !== "buyer" && role !== "seller" && role !== "orchestrator")
      || typeof primaryClaim !== "string" || claims.has(role)) {
      throw new TypeError("Bundle party roles and primary claims must be unique and complete");
    }
    const canonical = canonicalizeClaimReference(primaryClaim).canonicalReference;
    if (canonical !== primaryClaim) throw new TypeError("Bundle party claim is not canonical");
    claims.set(role, canonical);
  }
  if (!claims.has("buyer") || !claims.has("seller")) {
    throw new TypeError("Bundle requires buyer and seller parties");
  }
  const values = [...claims.values()];
  if (values.some((claim, index) => values.some((other, otherIndex) =>
    index !== otherIndex && sameClaimIdentity(claim, other)))) {
    throw new TypeError("Bundle party identities must be distinct");
  }
  return claims;
}

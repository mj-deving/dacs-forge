import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { canonicalizeClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  verifyCanonicalAgreementJson,
  type AgreementVerificationOptions,
  type AgreementTemporalContext,
} from "../consumer/agreement-verifier.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const AGREEMENT_DOMAIN = "dacs-agreement:v1:";
export const PAYEE_BOUND_AGREEMENT_DOMAIN = "dacs-payee-bound-agreement:v1:";

export interface AgreementParty extends Record<string, unknown> {
  readonly role: "buyer" | "seller" | "bidder-non-winning";
  readonly bundleHash: string;
  readonly primaryClaim: string;
  readonly vetRecordRef: Readonly<Record<string, unknown>>;
}

export interface PayoutBinding extends Record<string, unknown> {
  readonly railId: string;
  readonly phaseIndex: number;
  readonly payeeAddress: string;
}

export interface UnsignedAgreementArtifact extends Record<string, unknown> {
  readonly jobId: string;
  readonly listingRef: Readonly<{ listingId: string; version: number; contentHash: string }>;
  readonly parties: readonly AgreementParty[];
  readonly terms: Readonly<Record<string, unknown>>;
  readonly derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope";
  readonly generatedAt: number;
  readonly agreementVersion?: "1";
  readonly payeeBoundAgreementVersion?: "1";
}

export interface AgreementPartySigner {
  readonly party: string;
  readonly signer: ArtifactSigner;
}

export interface SignedAgreementResult {
  readonly agreement: Readonly<Record<string, unknown>>;
  readonly agreementHash: string;
  readonly canonicalJson: string;
  readonly signedScopeCanonicalJson: string;
}

export type AgreementSigningOptions = FixtureSigningContext
  & Omit<AgreementVerificationOptions, "temporalContext">
  & { readonly temporalContext: Extract<AgreementTemporalContext, { readonly mode: "pre-anchor" }> };

export function signAgreementArtifact(
  input: UnsignedAgreementArtifact,
  partySigners: readonly AgreementPartySigner[],
  options: AgreementSigningOptions,
): SignedAgreementResult {
  if (options.temporalContext.mode !== "pre-anchor") {
    throw new TypeError("Agreement signing requires pre-anchor temporal verification");
  }
  if (Object.hasOwn(input, "signatures")) {
    throw new TypeError("Unsigned agreement must not contain signatures");
  }
  const hasLegacy = input.agreementVersion === "1";
  const hasPayeeBound = input.payeeBoundAgreementVersion === "1";
  if (hasLegacy === hasPayeeBound) {
    throw new TypeError("Agreement must carry exactly one supported version discriminator");
  }
  if (hasLegacy && Object.hasOwn(input.terms, "payoutBindings")) {
    throw new TypeError("Legacy AgreementDocument forbids payoutBindings");
  }
  if (hasPayeeBound && !Array.isArray(input.terms["payoutBindings"])) {
    throw new TypeError("PayeeBoundAgreementDocument requires payoutBindings");
  }
  const normalized = JSON.parse(canonicalize(input)) as Record<string, unknown>;
  const parties = normalized["parties"] as Record<string, unknown>[];
  const required = new Map<string, string>();
  for (const role of ["buyer", "seller"] as const) {
    const matches = parties.filter((party) => party["role"] === role);
    if (matches.length !== 1 || typeof matches[0]?.["primaryClaim"] !== "string") {
      throw new TypeError(`Agreement requires exactly one ${role} party`);
    }
    const claim = canonicalizeClaimReference(matches[0]["primaryClaim"] as string).canonicalReference;
    if (claim !== matches[0]["primaryClaim"]) throw new TypeError(`${role} party claim is not canonical`);
    required.set(claim, role);
  }
  const requiredClaims = [...required.keys()];
  if (requiredClaims.length !== 2) {
    throw new TypeError("Agreement buyer and seller must have distinct canonical identities");
  }
  if (sameClaimIdentity(requiredClaims[0]!, requiredClaims[1]!)) {
    throw new TypeError("Agreement buyer and seller must have distinct canonical identities");
  }
  if (partySigners.length !== required.size) {
    throw new TypeError("Agreement requires exactly the buyer and seller signers");
  }
  const signerClaims = new Set<string>();
  for (const entry of partySigners) {
    assertFixtureSigningAuthority(entry.signer, options);
    const partyClaim = canonicalizeClaimReference(entry.party);
    const signerClaim = canonicalizeClaimReference(entry.signer.signer);
    const party = partyClaim.canonicalReference;
    const signer = signerClaim.canonicalReference;
    const identity = JSON.stringify([partyClaim.scheme, partyClaim.identifier]);
    if (party !== entry.party || signer !== entry.signer.signer
      || !sameClaimIdentity(signer, party)
      || !requiredClaims.some((requiredClaim) => sameClaimIdentity(requiredClaim, party))
      || signerClaims.has(identity)) {
      throw new TypeError("Agreement signer must uniquely match a required party primary claim");
    }
    signerClaims.add(identity);
  }
  const signedScopeCanonicalJson = canonicalize(withoutFields(normalized, "signatures"));
  const agreementHash = sha256Hex(signedScopeCanonicalJson);
  const domain = hasPayeeBound ? PAYEE_BOUND_AGREEMENT_DOMAIN : AGREEMENT_DOMAIN;
  const payload = new TextEncoder().encode(`${domain}${agreementHash}`);
  const signatures = [...partySigners]
    .sort((a, b) => a.party < b.party ? -1 : a.party > b.party ? 1 : 0)
    .map(({ party, signer }) => {
      const raw = importLegacyComponentSignatureValue(
        signer.sign(payload, options),
        "standard-base64-padded",
        64,
      );
      return { party, algorithm: signer.algorithm, value: encodeComponentSignatureValue(raw) };
    });
  const agreement = { ...normalized, signatures };
  const canonicalJson = canonicalize(agreement);
  const verification = verifyCanonicalAgreementJson(canonicalJson, options);
  if (verification.disposition === "verified") {
    throw new TypeError("Agreement producer received an unexpected post-anchor verdict");
  }
  if (verification.disposition !== "provisionally-verified") {
    throw new TypeError(`Agreement failed independent conformance: ${verification.stage}: ${verification.reason}`);
  }
  if (verification.agreementHash !== agreementHash) throw new Error("Agreement verifier returned a mismatched hash");
  return Object.freeze({
    agreement: deepFreezeJson(JSON.parse(canonicalJson) as Record<string, unknown>),
    agreementHash,
    canonicalJson,
    signedScopeCanonicalJson,
  });
}

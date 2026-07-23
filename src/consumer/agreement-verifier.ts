import { createHash, createPublicKey, verify as verifyBytes } from "node:crypto";
import {
  decodeComponentSignatureValue,
  ComponentSignatureEncodingError,
} from "../protocol/component-signature-codec.ts";
import {
  compareCanonicalDecimals,
  isCanonicalNonNegativeDecimal,
  isCanonicalPositiveDecimal,
  multiplyCanonicalDecimalByInteger,
  negotiableBoundsHalfUp,
} from "../protocol/decimal.ts";
import {
  canonicalizeClaimReference,
  canonicalizeGenericClaimReference,
  isRegisteredClaimScheme,
} from "../protocol/claim-reference.ts";
import { consumerCanonicalize } from "./canonical-json.ts";
import type { ListingVerificationResult } from "./listing-verifier.ts";

const HASH = /^[0-9a-f]{64}$/;
const QUANTITY = /^(?:0|[1-9]\d*)$/;
const DEFAULT_MAX_AGREEMENT_BYTES = 1_048_576;
const DEFAULT_MAX_AGREEMENT_PARTIES = 4_096;
const DEFAULT_MAX_AGREEMENT_SIGNATURES = 256;
const MAX_SIGNATURE_VALUE_CHARS = 16_384;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIGNATURE_ALGORITHMS = new Set(["ed25519", "ecdsa-secp256k1", "sr1-aggregate"]);
const AGREEMENT_DOMAIN = "dacs-agreement:v1:";
const PAYEE_BOUND_AGREEMENT_DOMAIN = "dacs-payee-bound-agreement:v1:";

export type AgreementVerificationStage =
  | "canonical-form" | "artifact-type" | "shape" | "listing-ref" | "signature"
  | "job-binding" | "commitment-binding" | "party-binding"
  | "currency" | "pricing" | "rail" | "deliverable" | "deadline" | "validity"
  | "pattern" | "seller-binding" | "sealed-roles" | "sealed-selection" | "payout-bindings";

export type AgreementVerificationResult =
  | {
    readonly disposition: "verified";
    readonly agreementHash: string;
    readonly artifactType: "agreement" | "payee-bound-agreement";
    readonly buyer: string;
    readonly seller: string;
  }
  | {
    readonly disposition: "provisionally-verified";
    readonly agreementHash: string;
    readonly artifactType: "agreement" | "payee-bound-agreement";
    readonly buyer: string;
    readonly seller: string;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported" | "indeterminate";
    readonly stage: AgreementVerificationStage;
    readonly reason: string;
    readonly agreementHash?: string;
  };

export interface AgreementVerificationOptions {
  readonly temporalContext: AgreementTemporalContext;
  readonly maxArtifactBytes?: number;
  readonly maxParties?: number;
  readonly maxSignatures?: number;
  readonly expectedCommitPhase: "commit-agreement" | "commit-payee-bound-agreement";
  readonly expectedJobId: string;
  readonly listingCanonicalJson: string;
  readonly listingVerification: Extract<ListingVerificationResult, { readonly disposition: "accepted" }>;
  readonly vettedPartyCheck: (party: VettedAgreementPartyBinding) => "verified" | "rejected" | "indeterminate";
  readonly sealedEnvelopeResult?: VerifiedSealedEnvelopeResult;
}

export type AgreementTemporalContext =
  | { readonly mode: "pre-anchor"; readonly nowMs: number }
  | { readonly mode: "post-anchor"; readonly committedAt: number; readonly agreementHash: string };

export interface VerifiedSealedEnvelopeResult {
  readonly phaseKind: "negotiate-sealed-envelope" | "negotiate-sealed-envelope-procurement";
  readonly agreementHash: string;
  readonly winningBidderClaim: string;
}

export interface VettedAgreementPartyBinding {
  readonly role: "buyer" | "seller" | "bidder-non-winning";
  readonly primaryClaim: string;
  readonly bundleHash: string;
  readonly vetRecordRefCanonicalJson: string;
}

export function verifyCanonicalAgreementJson(
  canonicalJson: string,
  options: AgreementVerificationOptions,
): AgreementVerificationResult {
  const maxArtifactBytes = options.maxArtifactBytes ?? DEFAULT_MAX_AGREEMENT_BYTES;
  if (!Number.isSafeInteger(maxArtifactBytes) || maxArtifactBytes < 1) {
    return unsupported("canonical-form", "Configured AgreementArtifact byte limit is invalid");
  }
  if (Buffer.byteLength(canonicalJson, "utf8") > maxArtifactBytes) {
    return unsupported(
      "canonical-form",
      `AgreementArtifact exceeds implementation input limit of ${maxArtifactBytes} bytes`,
    );
  }
  let agreement: Record<string, unknown>;
  let listing: Record<string, unknown>;
  try {
    agreement = parseCanonicalObject(canonicalJson, "AgreementArtifact");
    const collectionLimit = agreementCollectionLimitReason(agreement, options);
    if (collectionLimit !== null) return unsupported(collectionLimit.stage, collectionLimit.reason);
    if (hasOversizedSignatureValue(agreement)) {
      return unsupported("signature", "Agreement signature value exceeds implementation input limit");
    }
    listing = parseCanonicalObject(options.listingCanonicalJson, "Listing");
  } catch (error) {
    return rejected("canonical-form", message(error));
  }

  const listingCommitPhase = selectedCommitPhase(listing);
  if (listingCommitPhase === null || listingCommitPhase !== options.expectedCommitPhase) {
    return rejected("artifact-type", "Commitment phase does not match the pinned Listing pipeline");
  }
  const artifact = selectArtifact(agreement, listingCommitPhase);
  if (typeof artifact === "string") return rejected("artifact-type", artifact);
  const shapeError = validateBaseShape(agreement, artifact.type);
  if (shapeError !== null) return rejected("shape", shapeError);
  if (agreement["jobId"] !== options.expectedJobId) {
    return rejected("job-binding", "Agreement jobId does not match the commitment session");
  }

  const listingRef = agreement["listingRef"] as Record<string, unknown>;
  let listingHash: string;
  try {
    listingHash = hash(consumerCanonicalize(omitField(listing, "signature")));
  } catch (error) {
    return rejected("listing-ref", `Pinned Listing cannot be hashed: ${message(error)}`);
  }
  if (listingRef["listingId"] !== listing["listingId"]
    || listingRef["version"] !== listing["listingVersion"]
    || listingRef["contentHash"] !== listingHash
    || options.listingVerification.listingId !== listing["listingId"]
    || options.listingVerification.listingVersion !== listing["listingVersion"]
    || options.listingVerification.contentHash !== listingHash) {
    return rejected("listing-ref", "Agreement listingRef does not bind the pinned Listing");
  }

  const signedScope = consumerCanonicalize(omitField(agreement, "signatures"));
  const agreementHash = hash(signedScope);
  if (options.temporalContext.mode === "post-anchor"
    && options.temporalContext.agreementHash !== agreementHash) {
    return rejected("commitment-binding", "Agreement hash differs from the anchored commitment record", agreementHash);
  }
  const parties = agreement["parties"] as Record<string, unknown>[];
  const buyer = uniquePartyClaim(parties, "buyer");
  const seller = uniquePartyClaim(parties, "seller");
  if (buyer === null || seller === null || canonicalIdentityEquals(buyer, seller)) {
    return rejected("shape", "Agreement requires distinct, unique buyer and seller parties", agreementHash);
  }
  if (hasDuplicatePartyIdentity(parties)) {
    return rejected("shape", "Agreement parties contain a duplicate canonical identity", agreementHash);
  }
  if (object(listing["terms"])?.["acceptanceModel"] === "auto-accept") {
    return unsupported("signature", "Auto-accept commitment signature verification is unavailable", agreementHash);
  }
  const signatureResult = verifyRequiredSignatures(
    agreement["signatures"] as Record<string, unknown>[],
    [buyer, seller],
    parties.map((party) => party["primaryClaim"] as string),
    `${artifact.domain}${agreementHash}`,
  );
  if (signatureResult !== null) return signatureResult(agreementHash);

  const terms = agreement["terms"] as Record<string, unknown>;
  const price = terms["price"] as Record<string, unknown>;
  const pricing = object(listing["pricing"]);
  if (pricing === null || typeof pricing["kind"] !== "string") {
    return rejected("pricing", "Pinned Listing pricing is malformed", agreementHash);
  }
  const pricingKind = pricing["kind"];
  const listingCurrency = priceCurrency(pricing, price);
  let deferredCurrency: AgreementVerificationResult | null = null;
  if (listingCurrency === null) {
    if (pricingKind === "auction" && pricing["reservePrice"] === undefined) {
      deferredCurrency = indeterminate(
        "currency",
        "Reserve-free auction Listing does not declare an authoritative currency",
      );
    } else {
      return pricingKind === "fixed" || pricingKind === "negotiable" || pricingKind === "metered" || pricingKind === "auction"
        ? rejected("pricing", "Pinned Listing pricing fields are malformed", agreementHash)
        : unsupported("pricing", "unrecognized-pricing-kind", agreementHash);
    }
  }
  if (listingCurrency !== null && price["currency"] !== listingCurrency) {
    return rejected("currency", "Agreement currency differs from pinned Listing", agreementHash);
  }
  const priceError = validatePrice(price, terms, pricing, agreement["derivedFromPattern"] as string);
  if (priceError !== null) {
    return priceError.unsupported
      ? unsupported("pricing", priceError.reason, agreementHash)
      : rejected("pricing", priceError.reason, agreementHash);
  }

  const pipeline = listing["pipeline"];
  if (!Array.isArray(pipeline) || !pipeline.every((entry) => object(entry) !== null)) {
    return rejected("pattern", "Pinned Listing pipeline is malformed", agreementHash);
  }
  const steps = pipeline as Record<string, unknown>[];
  const paySteps = steps.flatMap((step, phaseIndex) =>
    typeof step["kind"] === "string" && (step["kind"] as string).startsWith("pay-")
      ? [{ step, phaseIndex }] : []);
  const railError = validateRail(terms["rail"], listing["acceptedRails"], paySteps);
  if (railError !== null) return rejected("rail", railError, agreementHash);

  const deliverableError = validateDeliverable(terms["deliverable"], listing);
  if (deliverableError !== null) return rejected("deliverable", deliverableError, agreementHash);
  const privateDeliveryError = validatePrivateDeliveryBinding(parties, listing);
  if (privateDeliveryError !== null) return rejected("deliverable", privateDeliveryError, agreementHash);

  const listingTerms = object(listing["terms"]);
  const deadlineSec = listingTerms?.["deadlineSecAfterCommit"];
  if (!Number.isSafeInteger(deadlineSec) || (deadlineSec as number) < 0) {
    return rejected("deadline", "Pinned Listing lacks a valid deadlineSecAfterCommit", agreementHash);
  }
  const patternResult = validatePatternAndRoles(agreement, listing, steps, buyer, seller);
  const payoutError = validatePayoutBindings(artifact.type, terms, paySteps);
  if (patternResult !== null) return rejected(patternResult.stage, patternResult.reason, agreementHash);
  if (payoutError !== null) return rejected("payout-bindings", payoutError, agreementHash);

  const temporalInstant = agreementTemporalInstant(options.temporalContext);
  const deferredTemporal = temporalInstant === null
    ? indeterminate("deadline", "Agreement temporal context is unavailable")
    : null;
  if (temporalInstant !== null) {
    if ((terms["deadline"] as number) > temporalInstant + (deadlineSec as number) * 1_000) {
      return rejected(
        "deadline",
        options.temporalContext.mode === "post-anchor"
          ? "Agreement deadline exceeds anchored commitment allowance"
          : "Agreement deadline exceeds provisional commitment allowance",
        agreementHash,
      );
    }
    const validity = object(listing["validity"]);
    if (validity === null || (validity["notAfter"] !== undefined
      && (!Number.isSafeInteger(validity["notAfter"]) || (validity["notAfter"] as number) < temporalInstant))) {
      return rejected(
        "validity",
        options.temporalContext.mode === "post-anchor"
          ? "Pinned Listing expired before agreement commitment"
          : "Pinned Listing is expired at provisional commitment verification",
        agreementHash,
      );
    }
  }

  const partyBinding = verifyVettedPartyBindings(parties, options.vettedPartyCheck);
  if (partyBinding?.disposition === "rejected") return partyBinding;
  const sealedSelectionResult = validateSealedEnvelopeSelection(
    agreement,
    steps,
    buyer,
    seller,
    agreementHash,
    options.sealedEnvelopeResult,
  );
  if (sealedSelectionResult?.disposition === "rejected") return sealedSelectionResult;
  const deferred = deferredCurrency ?? partyBinding ?? sealedSelectionResult ?? deferredTemporal;
  if (deferred !== null) return deferred;

  return Object.freeze({
    disposition: options.temporalContext.mode === "post-anchor" ? "verified" : "provisionally-verified",
    agreementHash,
    artifactType: artifact.type,
    buyer,
    seller,
  });
}

function agreementTemporalInstant(context: AgreementTemporalContext): number | null {
  const value = context.mode === "post-anchor" ? context.committedAt : context.nowMs;
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function hasOversizedSignatureValue(agreement: Record<string, unknown>): boolean {
  return Array.isArray(agreement["signatures"])
    && agreement["signatures"].some((entry) => {
      const signature = object(entry);
      return typeof signature?.["value"] === "string"
        && signature["value"].length > MAX_SIGNATURE_VALUE_CHARS;
    });
}

function agreementCollectionLimitReason(
  agreement: Record<string, unknown>,
  options: AgreementVerificationOptions,
): { readonly stage: "shape" | "signature"; readonly reason: string } | null {
  const maxParties = options.maxParties ?? DEFAULT_MAX_AGREEMENT_PARTIES;
  const maxSignatures = options.maxSignatures ?? DEFAULT_MAX_AGREEMENT_SIGNATURES;
  if (!Number.isSafeInteger(maxParties) || maxParties < 2
    || !Number.isSafeInteger(maxSignatures) || maxSignatures < 2) {
    return { stage: "shape", reason: "Configured AgreementArtifact collection limit is invalid" };
  }
  if (Array.isArray(agreement["parties"]) && agreement["parties"].length > maxParties) {
    return { stage: "shape", reason: `Agreement parties exceed implementation limit of ${maxParties}` };
  }
  if (Array.isArray(agreement["signatures"]) && agreement["signatures"].length > maxSignatures) {
    return { stage: "signature", reason: `Agreement signatures exceed implementation limit of ${maxSignatures}` };
  }
  return null;
}

function selectArtifact(
  agreement: Record<string, unknown>,
  expected: AgreementVerificationOptions["expectedCommitPhase"],
): { readonly type: "agreement" | "payee-bound-agreement"; readonly domain: string } | string {
  const legacy = agreement["agreementVersion"] === "1";
  const payeeBound = agreement["payeeBoundAgreementVersion"] === "1";
  if (legacy === payeeBound) return "Artifact must carry exactly one supported version discriminator";
  if (Object.hasOwn(agreement, legacy ? "payeeBoundAgreementVersion" : "agreementVersion")) {
    return "Artifact carries an invalid competing version discriminator";
  }
  if ((expected === "commit-agreement") !== legacy) {
    return "Agreement artifact type does not match the commitment phase (CA-5)";
  }
  return legacy
    ? { type: "agreement", domain: AGREEMENT_DOMAIN }
    : { type: "payee-bound-agreement", domain: PAYEE_BOUND_AGREEMENT_DOMAIN };
}

function validateBaseShape(
  agreement: Record<string, unknown>,
  type: "agreement" | "payee-bound-agreement",
): string | null {
  if (typeof agreement["jobId"] !== "string" || agreement["jobId"].length === 0
    || !Number.isSafeInteger(agreement["generatedAt"]) || (agreement["generatedAt"] as number) < 0
    || !new Set(["fixed-price", "rfq", "sealed-envelope"]).has(agreement["derivedFromPattern"] as string)) {
    return "Agreement identity, timestamp, or pattern is invalid";
  }
  const channel = agreement["derivedFromChannel"] === undefined
    ? undefined : object(agreement["derivedFromChannel"]);
  if (channel === null || (channel !== undefined
    && (typeof channel["subnet"] !== "string" || channel["subnet"].length === 0
      || typeof channel["lastMessageHash"] !== "string" || !HASH.test(channel["lastMessageHash"])))) {
    return "Agreement derivedFromChannel is invalid";
  }
  const ref = object(agreement["listingRef"]);
  if (ref === null
    || typeof ref["listingId"] !== "string" || ref["listingId"].length === 0
    || !Number.isSafeInteger(ref["version"]) || (ref["version"] as number) < 1
    || typeof ref["contentHash"] !== "string" || !HASH.test(ref["contentHash"])) {
    return "Agreement listingRef is invalid";
  }
  if (!Array.isArray(agreement["parties"]) || agreement["parties"].length < 2
    || !(agreement["parties"] as unknown[]).every(validateParty)) return "Agreement parties are invalid";
  const terms = object(agreement["terms"]);
  if (terms === null || !validatePriceTerm(terms["price"])
    || !Number.isSafeInteger(terms["deadline"]) || (terms["deadline"] as number) < 0
    || object(terms["deliverable"]) === null
    || (terms["additionalTerms"] !== undefined && object(terms["additionalTerms"]) === null)) {
    return "Agreement terms are invalid";
  }
  if (terms["priceAnchor"] !== undefined && !validatePriceAnchor(terms["priceAnchor"])) {
    return "Agreement priceAnchor is invalid";
  }
  if (terms["feeSchedule"] !== undefined
    && !validateFeeSchedule(terms["feeSchedule"], terms["price"] as Record<string, unknown>)) {
    return "Agreement feeSchedule is invalid";
  }
  if (type === "agreement" && Object.hasOwn(terms, "payoutBindings")) return "Legacy agreement forbids payoutBindings";
  if (type === "payee-bound-agreement" && !Array.isArray(terms["payoutBindings"])) {
    return "Payee-bound agreement requires payoutBindings";
  }
  if (!Array.isArray(agreement["signatures"]) || agreement["signatures"].length < 2
    || !(agreement["signatures"] as unknown[]).every((entry) => {
      const signature = object(entry);
      return signature !== null
        && typeof signature["algorithm"] === "string" && SIGNATURE_ALGORITHMS.has(signature["algorithm"])
        && typeof signature["party"] === "string" && canonicalClaimReference(signature["party"])
        && typeof signature["value"] === "string";
    })) return "Agreement signatures are invalid";
  return null;
}

function validateParty(value: unknown): boolean {
  const party = object(value);
  if (party === null || !new Set(["buyer", "seller", "bidder-non-winning"]).has(party["role"] as string)
    || typeof party["primaryClaim"] !== "string" || !canonicalClaimReference(party["primaryClaim"])
    || typeof party["bundleHash"] !== "string" || !HASH.test(party["bundleHash"])
    || (party["encryptionKey"] !== undefined && (typeof party["encryptionKey"] !== "string"
      || party["encryptionKey"].length === 0 || party["encryptionKey"].length > 8_192
      || party["encryptionKey"].trim() !== party["encryptionKey"]))) return false;
  const ref = object(party["vetRecordRef"]);
  return ref !== null && validAttestationRef(ref);
}

function verifyRequiredSignatures(
  signatures: readonly Record<string, unknown>[],
  required: readonly string[],
  allowed: readonly string[],
  payload: string,
): ((agreementHash: string) => AgreementVerificationResult) | null {
  const seen = new Set<string>();
  const allowedIdentities = new Set(allowed.map(canonicalIdentityKey));
  const requiredIdentities = new Set(required.map(canonicalIdentityKey));
  for (const signature of signatures) {
    const party = signature["party"] as string;
    const identity = canonicalIdentityKey(party);
    if (identity === null) return (hashValue) => rejected("signature", "Agreement signature party is invalid", hashValue);
    if (seen.has(identity)) return (hashValue) => rejected("signature", "Duplicate agreement signature party", hashValue);
    if (!allowedIdentities.has(identity)) {
      return (hashValue) => rejected("signature", "Agreement signature party is not in parties", hashValue);
    }
    seen.add(identity);
    if (signature["algorithm"] !== "ed25519") {
      return (hashValue) => unsupported("signature", `Unsupported agreement signature algorithm: ${String(signature["algorithm"])}`, hashValue);
    }
    const key = directEd25519Key(party);
    if (key === null) return (hashValue) => unsupported("signature", "Indirect agreement signer resolution is unavailable", hashValue);
    let rawSignature: Uint8Array;
    try {
      rawSignature = decodeComponentSignatureValue(signature["value"] as string, 64);
    } catch (error) {
      const reason = error instanceof ComponentSignatureEncodingError ? error.message : "Invalid signature encoding";
      return (hashValue) => rejected("signature", reason, hashValue);
    }
    try {
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, key]),
        format: "der",
        type: "spki",
      });
      if (!verifyBytes(null, Buffer.from(payload, "utf8"), publicKey, rawSignature)) {
        return (hashValue) => rejected("signature", "Agreement signature is invalid", hashValue);
      }
    } catch {
      return (hashValue) => rejected("signature", "Agreement signer key is invalid", hashValue);
    }
  }
  if ([...requiredIdentities].some((identity) => identity === null || !seen.has(identity))) {
    return (hashValue) => rejected("signature", "Agreement requires buyer and seller signatures", hashValue);
  }
  return null;
}

function validatePrice(
  price: Record<string, unknown>,
  terms: Record<string, unknown>,
  pricing: Record<string, unknown>,
  pattern: string,
): { readonly reason: string; readonly unsupported?: true } | null {
  const amount = price["amount"] as string;
  if (pricing["kind"] !== "metered" && Object.hasOwn(terms, "meteredQuantity")) {
    return { reason: "meteredQuantity is forbidden for non-metered pricing" };
  }
  switch (pricing["kind"]) {
    case "fixed": {
      const listed = object(pricing["price"]);
      return listed !== null
        && listed["amount"] === price["amount"]
        && listed["currency"] === price["currency"]
        && sameOptionalUnit(price, listed)
        ? null : { reason: "Agreement PriceTerm differs from fixed Listing price" };
    }
    case "negotiable": {
      const center = object(pricing["bandCenter"]);
      const minPct = pricing["minPct"];
      const maxPct = pricing["maxPct"];
      if (center === null || !isCanonicalPositiveDecimal(center["amount"])
        || typeof minPct !== "number" || typeof maxPct !== "number") return { reason: "Negotiable Listing pricing is malformed" };
      if (!sameOptionalUnit(price, center)) return { reason: "Agreement price unit differs from negotiable Listing price" };
      try {
        const bounds = negotiableBoundsHalfUp(center["amount"], minPct as number, maxPct as number);
        if (compareCanonicalDecimals(bounds.lower, "0") <= 0) return { reason: "Negotiable lower bound is not positive" };
        if (pattern === "fixed-price") {
          return amount === center["amount"] ? null : { reason: "PS-3 fixed-price agreement must equal bandCenter" };
        }
        return compareCanonicalDecimals(amount, bounds.lower) >= 0 && compareCanonicalDecimals(amount, bounds.upper) <= 0
          ? null : { reason: "Agreement price is outside the rounded negotiable band" };
      } catch {
        return { reason: "Negotiable Listing pricing is malformed" };
      }
    }
    case "metered": {
      const unitPrice = object(pricing["unitPrice"]);
      const minTotal = pricing["minTotal"] === undefined ? null : object(pricing["minTotal"]);
      const quantity = object(terms["meteredQuantity"]);
      if (unitPrice === null || !isCanonicalPositiveDecimal(unitPrice["amount"])
        || typeof pricing["unit"] !== "string" || pricing["unit"].length === 0
        || (minTotal !== null && (minTotal["currency"] !== unitPrice["currency"]
          || !isCanonicalPositiveDecimal(minTotal["amount"])))) return { reason: "Metered Listing violates MTR-2 or MTR-3" };
      if (quantity === null
        || typeof quantity["quantity"] !== "string" || !QUANTITY.test(quantity["quantity"])
        || quantity["unit"] !== pricing["unit"]) return { reason: "Agreement metered quantity violates MTR-4" };
      const computed = multiplyCanonicalDecimalByInteger(unitPrice["amount"], quantity["quantity"]);
      const minimumWins = minTotal !== null && compareCanonicalDecimals(minTotal["amount"] as string, computed) > 0;
      const total = minimumWins ? minTotal?.["amount"] as string : computed;
      return amount === total && sameOptionalUnit(price, unitPrice)
        ? null : { reason: "Agreement metered total or unit violates MTR-4" };
    }
    case "auction": {
      if (pattern !== "sealed-envelope") return { reason: "Auction pricing requires sealed-envelope agreement" };
      const reserve = pricing["reservePrice"] === undefined ? null : object(pricing["reservePrice"]);
      if (reserve === null && pricing["reservePrice"] !== undefined) return { reason: "Auction reservePrice is malformed" };
      if (reserve === null) return null;
      if (!isCanonicalPositiveDecimal(reserve["amount"]) || reserve["currency"] !== price["currency"]) {
        return { reason: "Auction reservePrice is malformed" };
      }
      if (!sameOptionalUnit(price, reserve)) return { reason: "Agreement price unit differs from auction reserve" };
      const comparison = compareCanonicalDecimals(amount, reserve["amount"]);
      return pricing["selectionRule"] === "lowest-price"
        ? comparison <= 0 ? null : { reason: "Auction price exceeds reserve ceiling" }
        : comparison >= 0 ? null : { reason: "Auction price is below reserve floor" };
    }
    default:
      return { reason: "unrecognized-pricing-kind", unsupported: true };
  }
}

function validateRail(
  railValue: unknown,
  acceptedValue: unknown,
  paySteps: readonly { readonly step: Record<string, unknown>; readonly phaseIndex: number }[],
): string | null {
  if (paySteps.length === 0) return railValue === undefined ? null : "Zero-pay Listing forbids terms.rail";
  const rail = object(railValue);
  if (rail === null || typeof rail["railId"] !== "string") return "Pay Listing requires terms.rail";
  if (!Array.isArray(acceptedValue)) return "Pay Listing lacks acceptedRails";
  const canonicalRail = consumerCanonicalize(rail);
  const accepted = acceptedValue
    .map(object)
    .filter((entry): entry is Record<string, unknown> => entry !== null)
    .some((entry) => consumerCanonicalize(entry) === canonicalRail);
  return accepted ? null : "Agreement rail is not accepted by the pinned Listing";
}

function validateDeliverable(value: unknown, listing: Record<string, unknown>): string | null {
  const deliverable = object(value);
  const offering = object(listing["offering"]);
  const spec = object(offering?.["deliverable"]);
  if (deliverable === null || spec === null || typeof spec["kind"] !== "string"
    || deliverable["deliverableType"] !== spec["kind"]
    || typeof deliverable["hash"] !== "string" || deliverable["hash"] !== hash(consumerCanonicalize(spec))) {
    return "Agreement deliverable does not bind the pinned Listing specification";
  }
  return deliverable["schemaUrl"] === spec["schemaUrl"]
    && (Object.hasOwn(deliverable, "schemaUrl") === Object.hasOwn(spec, "schemaUrl"))
    ? null : "Agreement deliverable schemaUrl differs from the pinned Listing";
}

function validatePatternAndRoles(
  agreement: Record<string, unknown>,
  listing: Record<string, unknown>,
  pipeline: readonly Record<string, unknown>[],
  buyer: string,
  seller: string,
): { readonly stage: "pattern" | "seller-binding" | "sealed-roles"; readonly reason: string } | null {
  const negotiations = pipeline.filter((step) => typeof step["kind"] === "string"
    && (step["kind"] as string).startsWith("negotiate-"));
  if (negotiations.length !== 1) return { stage: "pattern", reason: "Pinned Listing must contain one negotiation phase" };
  const kind = negotiations[0]?.["kind"];
  const parameters = object(negotiations[0]?.["parameters"]);
  const expected = kind === "negotiate-fixed-price" ? ["fixed-price"]
    : kind === "negotiate-rfq" ? parameters?.["fixedPriceFallback"] === true
      ? ["rfq", "fixed-price"] : ["rfq"]
      : kind === "negotiate-sealed-envelope" || kind === "negotiate-sealed-envelope-procurement"
        ? ["sealed-envelope"] : null;
  if (expected === null || !expected.includes(agreement["derivedFromPattern"] as string)) {
    return { stage: "pattern", reason: "Agreement pattern differs from pinned Listing pipeline" };
  }
  const listingSeller = object(object(listing["seller"])?.["identity"])?.["presentedBy"];
  if (typeof listingSeller !== "string") {
    return { stage: "seller-binding", reason: "Pinned Listing publisher claim is unavailable" };
  }
  if (!expected.includes("sealed-envelope")) {
    return canonicalIdentityEquals(seller, listingSeller)
      ? null
      : { stage: "seller-binding", reason: "Agreement seller differs from pinned Listing publisher" };
  }
  const procurement = kind === "negotiate-sealed-envelope-procurement";
  if (parameters === null || (procurement && parameters["auctionMode"] !== "procurement")
    || (!procurement && parameters["auctionMode"] !== undefined && parameters["auctionMode"] !== "demand")) {
    return { stage: "sealed-roles", reason: "unresolvable-auctionMode" };
  }
  if (procurement
    ? !canonicalIdentityEquals(buyer, listingSeller)
    : !canonicalIdentityEquals(seller, listingSeller)) {
    return { stage: "sealed-roles", reason: "Agreement roles are inverted for sealed-envelope mode" };
  }
  return null;
}

function validatePayoutBindings(
  artifactType: "agreement" | "payee-bound-agreement",
  terms: Record<string, unknown>,
  paySteps: readonly { readonly step: Record<string, unknown>; readonly phaseIndex: number }[],
): string | null {
  if (artifactType === "agreement") return null;
  const bindings = terms["payoutBindings"] as unknown[];
  if (bindings.length !== paySteps.length) return "Payout bindings must exactly cover every pay phase";
  const seen = new Set<string>();
  for (const value of bindings) {
    const binding = object(value);
    if (binding === null
      || typeof binding["railId"] !== "string" || !Number.isSafeInteger(binding["phaseIndex"])
      || typeof binding["payeeAddress"] !== "string" || binding["payeeAddress"].length === 0) {
      return "Payout binding shape is invalid";
    }
    const key = `${binding["railId"]}\u0000${binding["phaseIndex"]}`;
    if (seen.has(key)) return "Payout binding key is duplicated";
    seen.add(key);
    const expected = paySteps.find(({ phaseIndex }) => phaseIndex === binding["phaseIndex"]);
    if (expected === undefined || object(expected.step["parameters"])?.["rail"] !== binding["railId"]) {
      return "Payout binding does not match its pay phase rail and index";
    }
  }
  return null;
}

function validateSealedEnvelopeSelection(
  agreement: Record<string, unknown>,
  pipeline: readonly Record<string, unknown>[],
  buyer: string,
  seller: string,
  agreementHash: string,
  authority: VerifiedSealedEnvelopeResult | undefined,
): AgreementVerificationResult | null {
  if (agreement["derivedFromPattern"] !== "sealed-envelope") return null;
  if (authority === undefined) {
    return indeterminate("sealed-selection", "Authoritative sealed-envelope result is unavailable");
  }
  const phase = pipeline.find((step) => step["kind"] === "negotiate-sealed-envelope"
    || step["kind"] === "negotiate-sealed-envelope-procurement");
  const phaseKind = phase?.["kind"];
  const winningClaim = phaseKind === "negotiate-sealed-envelope-procurement" ? seller : buyer;
  if (authority.phaseKind !== phaseKind || authority.agreementHash !== agreementHash
    || !canonicalClaimReference(authority.winningBidderClaim)
    || !canonicalIdentityEquals(authority.winningBidderClaim, winningClaim)) {
    return rejected(
      "sealed-selection",
      "Agreement does not match the authoritative sealed-envelope selection result",
      agreementHash,
    );
  }
  return null;
}

function priceCurrency(
  pricing: Record<string, unknown>,
  _agreementPrice: Record<string, unknown>,
): string | null {
  const price = pricing["kind"] === "fixed" ? object(pricing["price"])
    : pricing["kind"] === "negotiable" ? object(pricing["bandCenter"])
      : pricing["kind"] === "metered" ? object(pricing["unitPrice"])
        : pricing["kind"] === "auction" ? object(pricing["reservePrice"])
          : null;
  return price !== null && typeof price["currency"] === "string" ? price["currency"] : null;
}

function validatePriceTerm(value: unknown): value is Record<string, unknown> {
  const price = object(value);
  return price !== null && isCanonicalPositiveDecimal(price["amount"])
    && typeof price["currency"] === "string" && price["currency"].length > 0
    && (price["unit"] === undefined || (typeof price["unit"] === "string" && price["unit"].length > 0));
}

function validatePriceAnchor(value: unknown): boolean {
  const anchor = object(value);
  return anchor !== null
    && typeof anchor["asset"] === "string" && anchor["asset"].length > 0
    && typeof anchor["quoteCurrency"] === "string" && anchor["quoteCurrency"].length > 0
    && isCanonicalNonNegativeDecimal(anchor["price"])
    && validAttestationRef(anchor["attestationRef"])
    && Number.isSafeInteger(anchor["observedAt"]) && (anchor["observedAt"] as number) >= 0
    && typeof anchor["sourceUrl"] === "string" && validUrl(anchor["sourceUrl"]);
}

function validateFeeSchedule(value: unknown, agreementPrice: Record<string, unknown>): boolean {
  const schedule = object(value);
  if (schedule === null || (schedule["priceBasis"] !== "inclusive" && schedule["priceBasis"] !== "exclusive")
    || !Array.isArray(schedule["items"]) || !validatePriceTerm(schedule["oneOffTotal"])
    || (schedule["oneOffTotal"] as Record<string, unknown>)["currency"] !== agreementPrice["currency"]
    || (schedule["minimumTermSeconds"] !== undefined
      && (!Number.isSafeInteger(schedule["minimumTermSeconds"]) || (schedule["minimumTermSeconds"] as number) < 0))
    || (schedule["disclosureNote"] !== undefined
      && (typeof schedule["disclosureNote"] !== "string" || schedule["disclosureNote"].length === 0))) return false;
  const items = schedule["items"] as unknown[];
  if (!items.every(validateFeeItem)) return false;
  const hasRecurring = items.some((item) => object(item)?.["recurrence"] !== undefined);
  if (hasRecurring !== Object.hasOwn(schedule, "recurringTotal")) return false;
  if (schedule["recurringTotal"] !== undefined
    && (!validatePriceTerm(schedule["recurringTotal"])
      || (schedule["recurringTotal"] as Record<string, unknown>)["currency"] !== agreementPrice["currency"])) return false;
  return schedule["earlyTerminationFee"] === undefined || validateFeeItem(schedule["earlyTerminationFee"]);
}

function validateFeeItem(value: unknown): boolean {
  const item = object(value);
  if (item === null || !new Set(["network", "platform", "processing", "spread", "subscription", "other"])
    .has(item["kind"] as string)
    || !(item["collector"] === "substrate" || canonicalClaimReference(item["collector"]))
    || (item["label"] !== undefined && (typeof item["label"] !== "string" || item["label"].length === 0))) return false;
  const hasFixed = Object.hasOwn(item, "fixed");
  const hasRate = Object.hasOwn(item, "rateBps");
  if (hasFixed === hasRate || (hasFixed && !validatePriceTerm(item["fixed"]))
    || (hasRate && (!Number.isSafeInteger(item["rateBps"]) || (item["rateBps"] as number) < 0))) return false;
  if (item["toleranceBps"] !== undefined && (item["kind"] !== "network"
    || !Number.isSafeInteger(item["toleranceBps"]) || (item["toleranceBps"] as number) < 0)) return false;
  return item["recurrence"] === undefined || validateRecurrence(item["recurrence"]);
}

function validateRecurrence(value: unknown): boolean {
  const recurrence = object(value);
  if (recurrence === null) return false;
  const period = recurrence["period"];
  const periodObject = object(period);
  const validPeriod = new Set(["daily", "weekly", "monthly", "quarterly", "annual"]).has(period as string)
    || (periodObject !== null
      && Number.isSafeInteger(periodObject["everySeconds"])
      && (periodObject["everySeconds"] as number) > 0);
  if (!validPeriod || (recurrence["count"] !== undefined
    && (!Number.isSafeInteger(recurrence["count"]) || (recurrence["count"] as number) < 1))
    || (recurrence["until"] !== undefined
      && (!Number.isSafeInteger(recurrence["until"]) || (recurrence["until"] as number) < 0))) return false;
  return !(recurrence["count"] !== undefined && recurrence["until"] !== undefined);
}

function validatePrivateDeliveryBinding(
  parties: readonly Record<string, unknown>[],
  listing: Record<string, unknown>,
): string | null {
  const deliverable = object(object(listing["offering"])?.["deliverable"]);
  if (deliverable?.["kind"] !== "storage-program" || deliverable["accessModel"] !== "encrypt-to-buyer") return null;
  const buyer = parties.find((party) => party["role"] === "buyer");
  return buyer !== undefined && typeof buyer["encryptionKey"] === "string" && buyer["encryptionKey"].length > 0
    ? null : "encrypt-to-buyer delivery requires the agreement-bound buyer encryptionKey";
}

function verifyVettedPartyBindings(
  parties: readonly Record<string, unknown>[],
  check: AgreementVerificationOptions["vettedPartyCheck"],
): AgreementVerificationResult | null {
  if (typeof check !== "function") return indeterminate("party-binding", "Vetted party resolver is unavailable");
  let unresolved = false;
  for (const party of parties) {
    const binding = Object.freeze({
      role: party["role"] as VettedAgreementPartyBinding["role"],
      primaryClaim: party["primaryClaim"] as string,
      bundleHash: party["bundleHash"] as string,
      vetRecordRefCanonicalJson: consumerCanonicalize(party["vetRecordRef"]),
    });
    let disposition: unknown;
    try {
      disposition = check(binding);
    } catch {
      unresolved = true;
      continue;
    }
    if (disposition === "rejected") return rejected("party-binding", "Agreement party does not match the vetted session");
    if (disposition !== "verified") unresolved = true;
  }
  return unresolved ? indeterminate("party-binding", "Agreement party vet binding is indeterminate") : null;
}

function hasDuplicatePartyIdentity(parties: readonly Record<string, unknown>[]): boolean {
  const identities = new Set<string>();
  for (const party of parties) {
    const identity = canonicalIdentityKey(party["primaryClaim"]);
    if (identity === null || identities.has(identity)) return true;
    identities.add(identity);
  }
  return false;
}

function canonicalIdentityEquals(left: unknown, right: unknown): boolean {
  const leftKey = canonicalIdentityKey(left);
  const rightKey = canonicalIdentityKey(right);
  return leftKey !== null && leftKey === rightKey;
}

function canonicalIdentityKey(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const generic = canonicalizeGenericClaimReference(value);
    const claim = isRegisteredClaimScheme(generic.scheme) ? canonicalizeClaimReference(value) : generic;
    return JSON.stringify([claim.scheme, claim.identifier]);
  } catch {
    return null;
  }
}

function sameOptionalUnit(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  return left["unit"] === right["unit"] && Object.hasOwn(left, "unit") === Object.hasOwn(right, "unit");
}

function canonicalClaimReference(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    const generic = canonicalizeGenericClaimReference(value);
    return generic.canonicalReference === value && (!isRegisteredClaimScheme(generic.scheme)
      || canonicalizeClaimReference(value).canonicalReference === value);
  } catch {
    return false;
  }
}

function directEd25519Key(claim: string): Buffer | null {
  try {
    const parsed = canonicalizeClaimReference(claim);
    return parsed.scheme === "key" && /^[0-9a-f]{64}$/.test(parsed.identifier)
      ? Buffer.from(parsed.identifier, "hex") : null;
  } catch {
    return null;
  }
}

function validAttestationRef(value: unknown): boolean {
  const ref = object(value);
  const anchor = object(ref?.["anchor"]);
  return ref !== null && typeof ref["contentHash"] === "string" && HASH.test(ref["contentHash"])
    && anchor !== null && new Set(["storage-program", "ipfs", "https"]).has(anchor["kind"] as string)
    && typeof anchor["locator"] === "string" && anchor["locator"].length > 0
    && (ref["signer"] === undefined || canonicalClaimReference(ref["signer"]));
}

function validUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.username === "" && parsed.password === "";
  } catch {
    return false;
  }
}

function uniquePartyClaim(parties: readonly Record<string, unknown>[], role: string): string | null {
  const matches = parties.filter((party) => party["role"] === role);
  return matches.length === 1 && typeof matches[0]?.["primaryClaim"] === "string"
    ? matches[0]["primaryClaim"] as string : null;
}

function selectedCommitPhase(
  listing: Record<string, unknown>,
): AgreementVerificationOptions["expectedCommitPhase"] | null {
  const pipeline = listing["pipeline"];
  if (!Array.isArray(pipeline)) return null;
  const phases = pipeline.flatMap((entry) => {
    const step = object(entry);
    return step?.["kind"] === "commit-agreement" || step?.["kind"] === "commit-payee-bound-agreement"
      ? [step["kind"] as AgreementVerificationOptions["expectedCommitPhase"]] : [];
  });
  return phases.length === 1 ? phases[0] as AgreementVerificationOptions["expectedCommitPhase"] : null;
}

function parseCanonicalObject(value: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  const record = object(parsed);
  if (record === null) throw new TypeError(`${label} must be an object`);
  if (consumerCanonicalize(record) !== value) throw new TypeError(`${label} is not canonical JSON`);
  return record;
}

function omitField(value: Record<string, unknown>, field: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function rejected(
  stage: AgreementVerificationStage,
  reason: string,
  agreementHash?: string,
): AgreementVerificationResult {
  return Object.freeze({ disposition: "rejected", stage, reason, ...(agreementHash === undefined ? {} : { agreementHash }) });
}

function unsupported(
  stage: AgreementVerificationStage,
  reason: string,
  agreementHash?: string,
): AgreementVerificationResult {
  return Object.freeze({ disposition: "refused-unsupported", stage, reason, ...(agreementHash === undefined ? {} : { agreementHash }) });
}

function indeterminate(stage: AgreementVerificationStage, reason: string): AgreementVerificationResult {
  return Object.freeze({ disposition: "indeterminate", stage, reason });
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown verification error";
}

import {
  canonicalizeClaimReference,
  canonicalizeGenericClaimReference,
  isRegisteredClaimScheme,
} from "./claim-reference.ts";
import { compareCanonicalDecimals, negotiableBoundsHalfUp } from "./decimal.ts";

const LISTING_ID = /^[A-Za-z0-9._~-]{1,128}$/;
const SCHEME = /^[a-z][a-z0-9-]*$/;
const CATEGORY = /^[^.\s]+(?:\.[^.\s]+)*$/u;
const HASH_256 = /^[0-9a-f]{64}$/;
const POSITIVE_DECIMAL = /^(?:0\.\d*[1-9]|[1-9]\d*(?:\.\d*[1-9])?)$/;
const CAPABILITIES = new Set(["SR-1", "SR-2", "SR-3", "SR-4", "SR-5"]);
const PRESENTATIONS = new Set(["siwd", "sr1-root", "per-claim", "session-key", "any"]);
const CANCELLATION_POLICIES = new Set(["none", "pre-commit", "with-fee"]);
const DISCLOSURE_POLICIES = new Set([
  "none", "encrypted-anchored-recommended", "encrypted-anchored-required",
]);
const ACCESS_MODELS = new Set(["public", "buyer-only", "encrypt-to-buyer"]);
const SELECTION_RULES = new Set(["lowest-price", "highest-price", "first-acceptable"]);
const SIGNATURE_ALGORITHMS = new Set(["ed25519", "ecdsa-secp256k1", "sr1-aggregate"]);
const CURRENT_DELIVERABLE_KINDS = new Set([
  "storage-program", "entitlement", "attested-payload", "external",
]);
const CURRENT_PRICING_KINDS = new Set(["fixed", "negotiable", "auction", "metered"]);
const CURRENT_VERIFICATION_METHOD_KINDS = new Set([
  "verifiable-credential", "tlsnotary", "zktls", "consensus-backed-proxy",
  "oauth-attested", "evm-rpc", "domain-tls-control", "self-signed",
]);

export const CURRENT_PHASES = new Set([
  "vet-credentials",
  "negotiate-fixed-price", "negotiate-rfq", "negotiate-sealed-envelope",
  "negotiate-sealed-envelope-procurement", "commit-agreement",
  "commit-payee-bound-agreement", "pay-evm-erc20", "pay-solana-spl",
  "pay-cross-chain-htlc", "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402",
  "pay-dem", "deliver-storage-program", "deliver-entitlement", "deliver-attested-payload", "rate",
]);

const NO_PARAMETER_PHASES = new Set([
  "vet-credentials", "negotiate-fixed-price", "commit-agreement",
  "commit-payee-bound-agreement", "deliver-storage-program", "deliver-entitlement",
  "deliver-attested-payload",
]);

export type PipelineValidation =
  | { readonly status: "valid" }
  | { readonly status: "unsupported"; readonly index: number }
  | { readonly status: "invalid"; readonly reason: string };

export function validateListingSchema(
  listing: Record<string, unknown>,
  signatureRequired: boolean,
): string | null {
  if (typeof listing["dacsVersion"] !== "string") return "dacsVersion must be a string";
  if (!positiveSafeInteger(listing["listingVersion"])) return "listingVersion must be positive";
  if (typeof listing["listingId"] !== "string" || !LISTING_ID.test(listing["listingId"])) {
    return "listingId must be 1-128 URL-safe ASCII characters";
  }
  if (listing["requiredCapabilities"] !== undefined) {
    const capabilities = listing["requiredCapabilities"];
    if (!uniqueStringArray(capabilities, CAPABILITIES)) return "requiredCapabilities is invalid";
  }

  const seller = listing["seller"];
  if (!isObject(seller) || !isObject(seller["identity"])) return "seller.identity is required";
  const identity = seller["identity"];
  if (!canonicalAnyClaimReference(identity["presentedBy"]) || !Array.isArray(identity["claims"])
    || !isObject(identity["presentation"])) return "seller.identity shape is invalid";
  if (!boundedString(seller["displayName"], 200)) return "seller.displayName is invalid";
  if (seller["publicEndpoint"] !== undefined && !httpsUrl(seller["publicEndpoint"])) {
    return "seller.publicEndpoint must be HTTPS";
  }

  const offering = listing["offering"];
  if (!isObject(offering)) return "offering is required";
  if (!boundedString(offering["title"], 200) || !boundedString(offering["description"], 2_000)) {
    return "offering title or description is invalid";
  }
  if (typeof offering["category"] !== "string" || !CATEGORY.test(offering["category"])) {
    return "offering category must be dot-delimited";
  }
  if (!Array.isArray(offering["tags"]) || offering["tags"].length > 16
    || !offering["tags"].every((tag) => boundedString(tag, 32))) return "offering tags are invalid";
  const deliverableError = validateDeliverable(offering["deliverable"]);
  if (deliverableError !== null) return deliverableError;
  if ((offering["extendedDescriptionUrl"] === undefined)
    !== (offering["extendedDescriptionHash"] === undefined)) {
    return "extended description URL and hash must appear together";
  }
  if (offering["extendedDescriptionUrl"] !== undefined
    && (!url(offering["extendedDescriptionUrl"])
      || typeof offering["extendedDescriptionHash"] !== "string"
      || !HASH_256.test(offering["extendedDescriptionHash"]))) {
    return "extended description binding is invalid";
  }

  const requirementError = validateBundleRequirement(listing["buyerRequirement"]);
  if (requirementError !== null) return requirementError;
  if (!Array.isArray(listing["pipeline"]) || listing["pipeline"].length === 0
    || !listing["pipeline"].every((step) => isObject(step) && boundedString(step["kind"], 100)
      && (step["parameters"] === undefined || isObject(step["parameters"])))) {
    return "pipeline is invalid";
  }
  const pricingError = validatePricing(listing["pricing"]);
  if (pricingError !== null) return pricingError;
  const railError = validateRailArray(listing["acceptedRails"]);
  if (railError !== null) return railError;
  const termsError = validateTerms(listing["terms"]);
  if (termsError !== null) return termsError;

  const validity = listing["validity"];
  if (!isObject(validity) || !nonNegativeSafeInteger(validity["notBefore"])
    || (validity["notAfter"] !== undefined && !nonNegativeSafeInteger(validity["notAfter"]))) {
    return "validity is invalid";
  }
  if (validity["notAfter"] !== undefined
    && (validity["notAfter"] as number) < (validity["notBefore"] as number)) {
    return "validity window is inverted";
  }

  const signature = listing["signature"];
  if (!signatureRequired) {
    return signature === undefined ? null : "unsigned Listing must not contain signature";
  }
  if (!isObject(signature) || typeof signature["algorithm"] !== "string"
    || !SIGNATURE_ALGORITHMS.has(signature["algorithm"])
    || !boundedString(signature["signer"], 2_048) || !boundedString(signature["value"], 4_096)) {
    return "signature is invalid";
  }
  return null;
}

export function findUnsupportedListingType(listing: Record<string, unknown>): string | null {
  const offering = listing["offering"];
  if (!isObject(offering)) return null;
  const deliverable = offering["deliverable"];
  if (!isObject(deliverable)) return null;
  const deliverableKind = deliverable["kind"];
  if (boundedString(deliverableKind, 100) && !CURRENT_DELIVERABLE_KINDS.has(deliverableKind)) {
    return `Unsupported deliverable kind: ${deliverableKind}`;
  }
  const verificationMethod = deliverable["verificationMethod"];
  if (CURRENT_DELIVERABLE_KINDS.has(deliverableKind as string) && isObject(verificationMethod)) {
    const methodKind = verificationMethod["kind"];
    if (boundedString(methodKind, 100) && !CURRENT_VERIFICATION_METHOD_KINDS.has(methodKind)) {
      return `Unsupported verificationMethod kind: ${methodKind}`;
    }
  }
  const pricing = listing["pricing"];
  if (!isObject(pricing)) return null;
  const pricingKind = pricing["kind"];
  return boundedString(pricingKind, 100) && !CURRENT_PRICING_KINDS.has(pricingKind)
    ? `Unsupported pricing kind: ${pricingKind}`
    : null;
}

export function validateCurrentPipeline(
  listing: Record<string, unknown>,
  nowMs: number,
): PipelineValidation {
  if (!nonNegativeSafeInteger(nowMs)) {
    throw new TypeError("Pipeline validation clock must be a non-negative safe integer");
  }
  const pipeline = listing["pipeline"] as Record<string, unknown>[];
  const unsupported = pipeline.findIndex((step) => !CURRENT_PHASES.has(step["kind"] as string));
  if (unsupported !== -1) return { status: "unsupported", index: unsupported };

  for (let index = 0; index < pipeline.length; index += 1) {
    const step = pipeline[index] as Record<string, unknown>;
    const kind = step["kind"] as string;
    const parameters = step["parameters"];
    const error = validatePhaseParameters(kind, parameters);
    if (error !== null) return { status: "invalid", reason: `pipeline[${index}]: ${error}` };
    if ((kind === "negotiate-sealed-envelope"
      || kind === "negotiate-sealed-envelope-procurement")
      && ((parameters as Record<string, unknown>)["commitDeadline"] as number) - nowMs < 60_000) {
      return {
        status: "invalid",
        reason: `pipeline[${index}]: commitDeadline must be at least 60 seconds in the future`,
      };
    }
  }

  const negotiateIndexes = pipeline.flatMap((step, index) =>
    (step["kind"] as string).startsWith("negotiate-") ? [index] : []);
  if (!pipeline.some((step) => (step["kind"] as string).startsWith("deliver-"))) {
    return { status: "invalid", reason: "pipeline must contain at least one delivery phase" };
  }
  if (negotiateIndexes.length !== 1) {
    return { status: "invalid", reason: "pipeline must contain exactly one negotiate phase" };
  }
  const commitIndexes = pipeline.flatMap((step, index) =>
    step["kind"] === "commit-agreement" || step["kind"] === "commit-payee-bound-agreement"
      ? [index] : []);
  if (commitIndexes.length !== 1 || commitIndexes[0] !== (negotiateIndexes[0] as number) + 1) {
    return { status: "invalid", reason: "one agreement commitment must immediately follow negotiation" };
  }
  for (let index = 1; index < pipeline.length; index += 1) {
    const previousStage = pipelineStage(pipeline[index - 1]?.["kind"] as string);
    const currentStage = pipelineStage(pipeline[index]?.["kind"] as string);
    if (currentStage < previousStage) {
      return {
        status: "invalid",
        reason: `pipeline[${index}]: phase stages must follow vet, negotiate, commit, settle, rate order`,
      };
    }
  }

  const pricing = listing["pricing"] as Record<string, unknown>;
  const pricingKind = pricing["kind"] as string;
  const negotiateKind = pipeline[negotiateIndexes[0] as number]?.["kind"] as string;
  const compatible = negotiateKind === "negotiate-fixed-price"
    ? new Set(["fixed", "negotiable", "metered"]).has(pricingKind)
    : negotiateKind === "negotiate-rfq"
      ? new Set(["negotiable", "metered"]).has(pricingKind)
      : pricingKind === "auction";
  if (!compatible) {
    return { status: "invalid", reason: `${negotiateKind} is incompatible with ${pricingKind} pricing` };
  }
  if ((negotiateKind === "negotiate-sealed-envelope"
      || negotiateKind === "negotiate-sealed-envelope-procurement")
    && (pipeline[negotiateIndexes[0] as number]?.["parameters"] as Record<string, unknown>)["selectionRule"]
      !== pricing["selectionRule"]) {
    return { status: "invalid", reason: "auction selectionRule must match the negotiation phase" };
  }
  return { status: "valid" };
}

export function validatePayRailBindings(listing: Record<string, unknown>): string | null {
  const pipeline = listing["pipeline"] as Record<string, unknown>[];
  const paySteps = pipeline.filter((step) => (step["kind"] as string).startsWith("pay-"));
  if (paySteps.length === 0) return null;
  const rails = listing["acceptedRails"];
  if (!Array.isArray(rails) || rails.length === 0) return "Pay phases require acceptedRails";
  const accepted = new Set((rails as Record<string, unknown>[]).map((rail) => rail["railId"] as string));
  for (const step of paySteps) {
    const rail = (step["parameters"] as Record<string, unknown>)["rail"] as string;
    if (!accepted.has(rail)) return `Pay phase references unaccepted rail: ${rail}`;
  }
  return null;
}

function validateBundleRequirement(value: unknown): string | null {
  if (!isObject(value) || value["requirementVersion"] !== "1" || !Array.isArray(value["required"])) {
    return "buyerRequirement is invalid";
  }
  if (!value["required"].every(validateClaimRequirement)) return "buyerRequirement.required is invalid";
  if (value["oneOf"] !== undefined && (!Array.isArray(value["oneOf"])
    || !value["oneOf"].every((group) => Array.isArray(group) && group.length > 0
      && group.every(validateClaimRequirement)))) return "buyerRequirement.oneOf is invalid";
  if (value["preferredPresentation"] !== undefined
    && (typeof value["preferredPresentation"] !== "string"
      || !PRESENTATIONS.has(value["preferredPresentation"]))) {
    return "buyerRequirement.preferredPresentation is invalid";
  }
  if (value["primaryClaimSelector"] !== undefined
    && (typeof value["primaryClaimSelector"] !== "string"
      || !SCHEME.test(value["primaryClaimSelector"]))) {
    return "buyerRequirement.primaryClaimSelector is invalid";
  }
  return null;
}

function validateClaimRequirement(value: unknown): boolean {
  return isObject(value) && typeof value["scheme"] === "string" && SCHEME.test(value["scheme"])
    && typeof value["verificationRequired"] === "boolean"
    && (value["maxAge"] === undefined || nonNegativeSafeInteger(value["maxAge"]))
    && (value["recipeVersion"] === undefined || positiveSafeInteger(value["recipeVersion"]))
    && (value["parameters"] === undefined || isObject(value["parameters"]));
}

function validateDeliverable(value: unknown): string | null {
  if (!isObject(value) || !boundedString(value["kind"], 100)) return "offering.deliverable is invalid";
  if (value["expectedSizeBytes"] !== undefined && !nonNegativeSafeInteger(value["expectedSizeBytes"])) {
    return "deliverable expectedSizeBytes is invalid";
  }
  if (value["verificationMethod"] !== undefined && !isObject(value["verificationMethod"])) {
    return "deliverable verificationMethod is invalid";
  }
  if (value["verificationMethod"] !== undefined) {
    const methodError = validateVerificationMethod(value["verificationMethod"]);
    if (methodError !== null) return methodError;
  }
  switch (value["kind"]) {
    case "storage-program":
      if (value["schemaUrl"] !== undefined && !url(value["schemaUrl"])) return "deliverable schemaUrl is invalid";
      return value["accessModel"] === undefined || (typeof value["accessModel"] === "string"
        && ACCESS_MODELS.has(value["accessModel"]))
        ? null : "deliverable accessModel is invalid";
    case "entitlement":
      return positiveSafeInteger(value["durationSec"]) && typeof value["renewable"] === "boolean"
        ? null : "entitlement deliverable is invalid";
    case "attested-payload":
      return boundedString(value["payloadFormat"], 256) ? null : "attested-payload deliverable is invalid";
    case "external":
      return boundedString(value["description"], 2_000) ? null : "external deliverable is invalid";
    default:
      return "deliverable kind is unsupported";
  }
}

function validatePricing(value: unknown): string | null {
  if (!isObject(value) || !boundedString(value["kind"], 100)) return "pricing is invalid";
  switch (value["kind"]) {
    case "fixed":
      return validatePriceTerm(value["price"]) ? null : "fixed pricing is invalid";
    case "negotiable":
      return validatePriceTerm(value["bandCenter"])
        && nonNegativeSafeNumber(value["minPct"]) && (value["minPct"] as number) < 100
        && nonNegativeSafeNumber(value["maxPct"])
        && roundedNegotiableLowerBoundIsPositive(
          (value["bandCenter"] as Record<string, unknown>)["amount"] as string,
          value["minPct"] as number,
        )
        ? null : "negotiable pricing is invalid";
    case "auction":
      return (value["reservePrice"] === undefined || validatePriceTerm(value["reservePrice"]))
        && selectionRule(value["selectionRule"])
        ? null : "auction pricing is invalid";
    case "metered": {
      if (!validatePriceTerm(value["unitPrice"]) || !boundedString(value["unit"], 128)
        || (value["minTotal"] !== undefined && !validatePriceTerm(value["minTotal"]))) {
        return "metered pricing is invalid";
      }
      const unitPrice = value["unitPrice"] as Record<string, unknown>;
      if (unitPrice["unit"] !== undefined && unitPrice["unit"] !== value["unit"]) {
        return "metered pricing unit is inconsistent";
      }
      if (value["minTotal"] !== undefined
        && (value["minTotal"] as Record<string, unknown>)["currency"] !== unitPrice["currency"]) {
        return "metered pricing currencies differ";
      }
      return null;
    }
    default:
      return "pricing kind is unsupported";
  }
}

function validatePriceTerm(value: unknown): value is Record<string, unknown> {
  return isObject(value) && typeof value["amount"] === "string" && POSITIVE_DECIMAL.test(value["amount"])
    && boundedString(value["currency"], 128)
    && (value["unit"] === undefined || boundedString(value["unit"], 128));
}

function roundedNegotiableLowerBoundIsPositive(amount: string, minPct: number): boolean {
  try {
    return compareCanonicalDecimals(negotiableBoundsHalfUp(amount, minPct, 0).lower, "0") > 0;
  } catch {
    return false;
  }
}

function validateVerificationMethod(value: unknown): string | null {
  if (!isObject(value) || !boundedString(value["kind"], 100)) {
    return "deliverable verificationMethod is invalid";
  }
  switch (value["kind"]) {
    case "verifiable-credential":
      if (value["issuerAllowList"] !== undefined && (!Array.isArray(value["issuerAllowList"])
        || !value["issuerAllowList"].every(canonicalClaimReference))) {
        return "verifiable-credential issuerAllowList is invalid";
      }
      return value["schemaUrl"] === undefined || url(value["schemaUrl"])
        ? null : "verifiable-credential schemaUrl is invalid";
    case "tlsnotary":
      return boundedString(value["endpoint"], 2_048)
        && (value["sessionTemplate"] === undefined || boundedString(value["sessionTemplate"], 4_096))
        ? null : "tlsnotary verification method is invalid";
    case "zktls":
      return boundedString(value["provider"], 128) && boundedString(value["programId"], 512)
        ? null : "zktls verification method is invalid";
    case "consensus-backed-proxy": {
      const endpoint = value["endpoint"];
      if (!isObject(endpoint) || (endpoint["method"] !== "GET" && endpoint["method"] !== "POST")
        || !boundedString(endpoint["urlTemplate"], 2_048)
        || (endpoint["body"] !== undefined && typeof endpoint["body"] !== "string")
        || (endpoint["headers"] !== undefined && (!isObject(endpoint["headers"])
          || !Object.values(endpoint["headers"]).every((header) => typeof header === "string")))) {
        return "consensus-backed-proxy verification method is invalid";
      }
      return null;
    }
    case "oauth-attested":
      return boundedString(value["provider"], 128) && Array.isArray(value["scopes"])
        && value["scopes"].every((scope) => boundedString(scope, 256))
        && nonNegativeSafeInteger(value["maxTokenAgeSec"])
        ? null : "oauth-attested verification method is invalid";
    case "evm-rpc":
      return positiveSafeInteger(value["chainId"]) && boundedString(value["contract"], 256)
        && boundedString(value["method"], 256)
        && (value["args"] === undefined || Array.isArray(value["args"]))
        ? null : "evm-rpc verification method is invalid";
    case "domain-tls-control":
      return value["challengeType"] === "http-01" || value["challengeType"] === "dns-01"
        || value["challengeType"] === "tls-alpn-01"
        ? null : "domain-tls-control verification method is invalid";
    case "self-signed":
      return null;
    default:
      return "deliverable verificationMethod kind is unsupported";
  }
}

function canonicalClaimReference(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    return canonicalizeClaimReference(value).canonicalReference === value;
  } catch {
    return false;
  }
}

function canonicalAnyClaimReference(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    const generic = canonicalizeGenericClaimReference(value);
    if (generic.canonicalReference !== value) return false;
    return !isRegisteredClaimScheme(generic.scheme)
      || canonicalizeClaimReference(value).canonicalReference === value;
  } catch {
    return false;
  }
}

function validateRailArray(value: unknown): string | null {
  if (value === undefined) return null;
  if (!Array.isArray(value)) return "acceptedRails must be an array";
  const keys = new Set<string>();
  for (const rail of value) {
    if (!isObject(rail) || !boundedString(rail["railId"], 64)
      || !/^[a-z0-9]+(?:[.:_-][A-Za-z0-9]+)*$/.test(rail["railId"] as string)
      || (rail["railVersion"] !== undefined && !positiveSafeInteger(rail["railVersion"]))
      || (rail["parameters"] !== undefined && !isObject(rail["parameters"]))) {
      return "acceptedRails is invalid";
    }
    const key = rail["railId"] as string;
    if (keys.has(key)) return "acceptedRails contains a duplicate rail reference";
    keys.add(key);
  }
  return null;
}

function validateTerms(value: unknown): string | null {
  if (!isObject(value)) return "terms is required";
  if (value["termsOfServiceUrl"] !== undefined && !url(value["termsOfServiceUrl"])) {
    return "termsOfServiceUrl is invalid";
  }
  if (value["termsOfServiceHash"] !== undefined
    && (typeof value["termsOfServiceHash"] !== "string" || !HASH_256.test(value["termsOfServiceHash"]))) {
    return "termsOfServiceHash is invalid";
  }
  if (value["jurisdictions"] !== undefined && (!Array.isArray(value["jurisdictions"])
    || !value["jurisdictions"].every((code) => typeof code === "string" && /^[A-Z]{2}$/.test(code)))) {
    return "terms jurisdictions are invalid";
  }
  if (value["conflictOfLawsRule"] !== undefined
    && value["conflictOfLawsRule"] !== "buyer-jurisdiction"
    && value["conflictOfLawsRule"] !== "seller-jurisdiction"
    && !(typeof value["conflictOfLawsRule"] === "string"
      && value["conflictOfLawsRule"].startsWith("rule-ref:")
      && url(value["conflictOfLawsRule"].slice("rule-ref:".length)))) {
    return "conflictOfLawsRule is invalid";
  }
  if (value["deadlineSecAfterCommit"] !== undefined
    && !nonNegativeSafeInteger(value["deadlineSecAfterCommit"])) return "deadlineSecAfterCommit is invalid";
  if (value["acceptanceModel"] !== undefined && value["acceptanceModel"] !== "auto-accept") {
    return "acceptanceModel is invalid";
  }
  if (value["cancellationPolicy"] !== undefined
    && (typeof value["cancellationPolicy"] !== "string"
      || !CANCELLATION_POLICIES.has(value["cancellationPolicy"]))) {
    return "cancellationPolicy is invalid";
  }
  if (value["retentionYears"] !== undefined && !nonNegativeSafeInteger(value["retentionYears"])) {
    return "retentionYears is invalid";
  }
  if (value["transcriptDisclosurePolicy"] !== undefined
    && (typeof value["transcriptDisclosurePolicy"] !== "string"
      || !DISCLOSURE_POLICIES.has(value["transcriptDisclosurePolicy"]))) {
    return "transcriptDisclosurePolicy is invalid";
  }
  return null;
}

function validatePhaseParameters(kind: string, value: unknown): string | null {
  if (NO_PARAMETER_PHASES.has(kind)) return value === undefined ? null : `${kind} forbids parameters`;
  if (kind.startsWith("pay-")) {
    return isObject(value) && boundedString(value["rail"], 256) ? null : `${kind} requires a rail parameter`;
  }
  if (kind === "negotiate-rfq") {
    return isObject(value) && Number.isSafeInteger(value["maxTurns"]) && (value["maxTurns"] as number) >= 2
      && positiveSafeInteger(value["timeoutSec"])
      && (value["channelSubnet"] === undefined || boundedString(value["channelSubnet"], 512))
      && (value["rfqInitiator"] === undefined || value["rfqInitiator"] === "buyer"
        || value["rfqInitiator"] === "seller")
      && (value["fixedPriceFallback"] === undefined || value["fixedPriceFallback"] === true)
      ? null : "negotiate-rfq parameters are invalid";
  }
  if (kind === "negotiate-sealed-envelope" || kind === "negotiate-sealed-envelope-procurement") {
    if (!isObject(value) || !nonNegativeSafeInteger(value["commitDeadline"])
      || !Number.isSafeInteger(value["revealWindow"]) || (value["revealWindow"] as number) < 60
      || !selectionRule(value["selectionRule"])
      || (value["channelSubnet"] !== undefined && !boundedString(value["channelSubnet"], 512))) {
      return `${kind} parameters are invalid`;
    }
    if (kind === "negotiate-sealed-envelope-procurement") {
      return value["auctionMode"] === "procurement" ? null : "procurement auctionMode is required";
    }
    return value["auctionMode"] === undefined || value["auctionMode"] === "demand"
      ? null : "demand auctionMode is invalid";
  }
  if (kind === "rate") {
    return value === undefined || (isObject(value)
      && (value["required"] === undefined || typeof value["required"] === "boolean"))
      ? null : "rate parameters are invalid";
  }
  return null;
}

function selectionRule(value: unknown): boolean {
  if (typeof value !== "string") return false;
  if (SELECTION_RULES.has(value)) return true;
  const external = /^rule-ref:([0-9a-f]{64}):(.+)$/u.exec(value);
  return external !== null && httpsUrl(external[2]);
}

function pipelineStage(kind: string): number {
  if (kind === "vet-credentials") return 0;
  if (kind.startsWith("negotiate-")) return 1;
  if (kind === "commit-agreement" || kind === "commit-payee-bound-agreement") return 2;
  if (kind.startsWith("pay-") || kind.startsWith("deliver-")) return 3;
  return 4;
}

function uniqueStringArray(value: unknown, allowed: ReadonlySet<string>): boolean {
  if (!Array.isArray(value)) return false;
  const items = value as unknown[];
  return items.every((item) => typeof item === "string" && allowed.has(item))
    && new Set(items).size === items.length;
}

function url(value: unknown): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) return false;
  try {
    const parsed = new URL(value);
    return parsed.username === "" && parsed.password === "";
  } catch {
    return false;
  }
}

function httpsUrl(value: unknown): boolean {
  if (!url(value)) return false;
  return new URL(value as string).protocol === "https:";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && [...value].length <= max;
}

function nonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function nonNegativeSafeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value)
    && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
}

function positiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 1;
}

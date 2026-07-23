import { canonicalizeClaimReference } from "./claim-reference.ts";
import { canonicalize } from "./canonical-json.ts";
import { encodeCf4Segment } from "./logical-address.ts";

export const VERIFY_RESULT_DOMAIN = "dacs-verifyresult:v1:";
export const COMPOSITE_VERIFICATION_DOMAIN = "dacs-composite:v1:";

export const VET_DECISIONS = Object.freeze([
  "pass", "fail", "indeterminate", "error",
] as const);
export type VetDecision = typeof VET_DECISIONS[number];

export const RECIPE_AVAILABILITIES = Object.freeze([
  "live", "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed",
] as const);
export type RecipeAvailability = typeof RECIPE_AVAILABILITIES[number];

export interface VetClaimRequirement {
  readonly scheme: string;
  readonly verificationRequired?: boolean;
  readonly maxAge?: number;
  readonly recipeVersion?: number;
  readonly parameters?: Readonly<Record<string, unknown>>;
}

export interface VetBundleRequirement {
  readonly requirementVersion?: "1";
  readonly required: readonly VetClaimRequirement[];
  readonly oneOf?: readonly (readonly VetClaimRequirement[])[];
  readonly preferredPresentation?: "siwd" | "sr1-root" | "per-claim" | "session-key" | "any";
  readonly primaryClaimSelector?: string;
}

export interface VetResultSummary {
  readonly scheme: string;
  readonly decision: VetDecision;
  readonly availability: RecipeAvailability;
  readonly recipeVersion?: number;
  readonly verifiedAt?: number;
  readonly verificationPerformed?: boolean;
  readonly data?: Readonly<Record<string, unknown>>;
}

export interface VetAggregationResult {
  readonly decision: VetDecision;
  readonly reasons: readonly string[];
}

const SCHEME = /^[A-Za-z][A-Za-z0-9-]*$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

export function verifyResultLogicalAddress(
  jobId: string,
  scheme: string,
  identifier: string,
  recipeVersion: number,
): string {
  assertJobId(jobId);
  if (!SCHEME.test(scheme) || scheme !== scheme.toLowerCase()) {
    throw new TypeError("Vet scheme must be canonical lowercase ASCII");
  }
  if (typeof identifier !== "string" || identifier.length === 0) {
    throw new TypeError("Vet identifier must be non-empty");
  }
  if (!Number.isSafeInteger(recipeVersion) || recipeVersion < 1) {
    throw new TypeError("Vet recipeVersion must be a positive safe integer");
  }
  return `dacs2:${jobId}:${scheme}:${encodeCf4Segment(identifier.normalize("NFC"))}:v${recipeVersion}`;
}

export function compositeVerificationLogicalAddress(jobId: string, evaluatedParty: string): string {
  assertJobId(jobId);
  const party = canonicalizeClaimReference(evaluatedParty).canonicalReference;
  if (party !== evaluatedParty) throw new TypeError("Evaluated party must be canonical");
  return `dacs2:composite:${jobId}:${encodeCf4Segment(party)}`;
}

export function effectiveVetDecision(
  decision: VetDecision,
  availability: RecipeAvailability,
): VetDecision {
  return availability === "mocked" || availability === "disabled" || availability === "failed"
    ? "error" : decision;
}

export function aggregateVetResults(
  results: readonly VetResultSummary[],
  requirement: VetBundleRequirement,
  evaluatedAt?: number,
): VetAggregationResult {
  validateRequirement(requirement);
  if (evaluatedAt !== undefined && (!Number.isSafeInteger(evaluatedAt) || evaluatedAt < 0)) {
    throw new TypeError("Vet aggregation evaluation time is invalid");
  }
  const normalized = results.map((result) => {
    if (!SCHEME.test(result.scheme) || result.scheme !== result.scheme.toLowerCase()
      || !VET_DECISIONS.includes(result.decision)
      || !RECIPE_AVAILABILITIES.includes(result.availability)
      || (result.recipeVersion !== undefined
        && (!Number.isSafeInteger(result.recipeVersion) || result.recipeVersion < 1))
      || (result.verifiedAt !== undefined
        && (!Number.isSafeInteger(result.verifiedAt) || result.verifiedAt < 0))
      || (result.verificationPerformed !== undefined && typeof result.verificationPerformed !== "boolean")
      || (result.data !== undefined
        && (result.data === null || typeof result.data !== "object" || Array.isArray(result.data)))) {
      throw new TypeError("Vet result summary is invalid");
    }
    return { ...result, decision: effectiveVetDecision(result.decision, result.availability) };
  });
  const failures: string[] = [];
  const errors: string[] = [];
  const indeterminates: string[] = [];

  for (const claim of requirement.required) {
    classifyRequired(normalized, claim, evaluatedAt, failures, errors, indeterminates);
  }
  for (const group of requirement.oneOf ?? []) {
    const groupResults = group.flatMap((claim) => matchingResults(normalized, claim, evaluatedAt));
    if (groupResults.some((result) => result.decision === "pass")) continue;
    if (groupResults.some((result) => result.decision === "error")) {
      errors.push("oneOf group: at least one claim errored");
    } else if (groupResults.some((result) => result.decision === "indeterminate")) {
      indeterminates.push("oneOf group: at least one claim indeterminate");
    } else {
      failures.push("oneOf group: no claim satisfied");
    }
  }
  return Object.freeze(failures.length > 0
    ? { decision: "fail" as const, reasons: Object.freeze(failures) }
    : errors.length > 0
      ? { decision: "error" as const, reasons: Object.freeze(errors) }
      : indeterminates.length > 0
        ? { decision: "indeterminate" as const, reasons: Object.freeze(indeterminates) }
        : { decision: "pass" as const, reasons: Object.freeze([]) });
}

function classifyRequired(
  results: readonly VetResultSummary[],
  claim: VetClaimRequirement,
  evaluatedAt: number | undefined,
  failures: string[],
  errors: string[],
  indeterminates: string[],
): void {
  const sameScheme = results.filter((result) => result.scheme === claim.scheme);
  const matches = matchingResults(sameScheme, claim, evaluatedAt);
  if (matches.length === 0) {
    return void failures.push(sameScheme.length === 0
      ? `required not present: ${claim.scheme}`
      : `required constraints not satisfied: ${claim.scheme}`);
  }
  // DACS-2 §7.7.1 deliberately treats any same-scheme pass as satisfying the claim.
  if (matches.some((result) => result.decision === "pass")) return;
  if (matches.some((result) => result.decision === "fail")) return void failures.push(`required failing: ${claim.scheme}`);
  if (matches.some((result) => result.decision === "error")) return void errors.push(`required errored: ${claim.scheme}`);
  indeterminates.push(`required indeterminate: ${claim.scheme}`);
}

function matchingResults(
  results: readonly VetResultSummary[],
  claim: VetClaimRequirement,
  evaluatedAt: number | undefined,
): VetResultSummary[] {
  return results.filter((result) => {
    if (result.scheme !== claim.scheme) return false;
    if (claim.recipeVersion !== undefined && result.recipeVersion !== claim.recipeVersion) return false;
    if (claim.maxAge !== undefined) {
      if (evaluatedAt === undefined || result.verifiedAt === undefined) return false;
      const expiresAt = result.verifiedAt + claim.maxAge * 1_000;
      if (!Number.isSafeInteger(expiresAt) || evaluatedAt > expiresAt) return false;
    }
    if (claim.parameters !== undefined) {
      if (result.data === undefined) return false;
      for (const [key, expected] of Object.entries(claim.parameters)) {
        if (!Object.hasOwn(result.data, key) || !jsonEqual(result.data[key], expected)) return false;
      }
    }
    return claim.verificationRequired !== true || result.verificationPerformed === true;
  });
}

function jsonEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function validateRequirement(requirement: VetBundleRequirement): void {
  if (requirement === null || typeof requirement !== "object" || !Array.isArray(requirement.required)
    || Object.keys(requirement).some((key) => ![
      "requirementVersion", "required", "oneOf", "preferredPresentation", "primaryClaimSelector",
    ].includes(key))
    || (requirement.requirementVersion !== undefined && requirement.requirementVersion !== "1")
    || (requirement.preferredPresentation !== undefined && ![
      "siwd", "sr1-root", "per-claim", "session-key", "any",
    ].includes(requirement.preferredPresentation))
    || (requirement.primaryClaimSelector !== undefined
      && (!SCHEME.test(requirement.primaryClaimSelector)
        || requirement.primaryClaimSelector !== requirement.primaryClaimSelector.toLowerCase()))
    || requirement.required.some((claim) => !validClaimRequirement(claim))
    || (requirement.oneOf !== undefined && (!Array.isArray(requirement.oneOf)
      || requirement.oneOf.some((group) => !Array.isArray(group) || group.length === 0
        || group.some((claim) => !validClaimRequirement(claim)))))) {
    throw new TypeError("Vet bundle requirement is invalid");
  }
}

function validClaimRequirement(value: unknown): value is VetClaimRequirement {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const claim = value as VetClaimRequirement;
  return !Object.keys(value).some((key) => ![
    "scheme", "verificationRequired", "maxAge", "recipeVersion", "parameters",
  ].includes(key))
    && typeof claim.scheme === "string" && SCHEME.test(claim.scheme)
    && claim.scheme === claim.scheme.toLowerCase()
    && (claim.verificationRequired === undefined || typeof claim.verificationRequired === "boolean")
    && (claim.maxAge === undefined || (Number.isSafeInteger(claim.maxAge) && claim.maxAge >= 0))
    && (claim.recipeVersion === undefined
      || (Number.isSafeInteger(claim.recipeVersion) && claim.recipeVersion > 0))
    && (claim.parameters === undefined || (claim.parameters !== null
      && typeof claim.parameters === "object" && !Array.isArray(claim.parameters)));
}

function assertJobId(jobId: string): void {
  if (!ULID.test(jobId)) throw new TypeError("Vet jobId must be a canonical ULID");
}

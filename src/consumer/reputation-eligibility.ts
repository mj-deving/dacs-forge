export type ProtocolReputationEligibility =
  | "eligible"
  | "excluded"
  | "indeterminate"
  | "not-applicable";

export interface ReputationOutputCandidate {
  readonly artifact: unknown;
  readonly protocolEligibility: ProtocolReputationEligibility;
  readonly provenance: unknown;
}

export type ReputationOutputGateResult =
  | {
    readonly disposition: "excluded";
    readonly stage: "provenance" | "protocol-eligibility";
    readonly reason: string;
  }
  | {
    readonly disposition: "blocked";
    readonly stage: "live-authority";
    readonly reason: string;
  };

/**
 * The only boundary from protocol-level eligibility into a live reputation output.
 * Provenance is checked before the opaque artifact reaches a parser or writer.
 */
export function gateReputationOutputCandidate(
  candidate: ReputationOutputCandidate,
): ReputationOutputGateResult {
  if (!hasLiveValueProvenance(candidate.provenance)) {
    return excluded("provenance", "Reputation output requires independently verified live-value provenance");
  }
  if (candidate.protocolEligibility !== "eligible") {
    return excluded("protocol-eligibility", "Protocol result is not reputation eligible");
  }
  return Object.freeze({
    disposition: "blocked",
    stage: "live-authority",
    reason: "No trusted artifact-bound live reputation authority is implemented",
  });
}

function hasLiveValueProvenance(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return dataValue(descriptors, "evidenceMode") === "live"
      && dataValue(descriptors, "economicMode") === "live-value"
      && dataValue(descriptors, "authority") === "independently-verified";
  } catch {
    return false;
  }
}

function dataValue(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
  key: string,
): unknown {
  const descriptor = descriptors[key];
  return descriptor !== undefined && Object.hasOwn(descriptor, "value")
    ? descriptor.value
    : undefined;
}

function excluded(
  stage: "provenance" | "protocol-eligibility",
  reason: string,
): ReputationOutputGateResult {
  return Object.freeze({ disposition: "excluded", stage, reason });
}

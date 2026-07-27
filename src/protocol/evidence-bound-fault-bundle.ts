export const EVIDENCE_BOUND_FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN =
  "dacs-evidence-bound-fault-bundle:v1:";
export const EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN =
  "dacs-evidence-bound-fault-bundle-pointer:v1:";

export type EvidenceBoundSettlementReasonCode =
  | "ok"
  | "raw-multiplicity"
  | "exact-cardinality"
  | "exact-phase-mapping"
  | "exact-bijection"
  | "pointer-agreement"
  | "st8-raw-admissibility"
  | "unrelated-authority-indeterminate";

export interface EvidenceBoundSettlementSetInput {
  readonly expectedPhaseKeys: readonly string[];
  readonly topLevelRefs: readonly string[];
  readonly resolvedReferencePhaseKeys: Readonly<Record<string, string>>;
  readonly pointerMap: Readonly<Record<string, string>>;
  readonly recordClassByRef?: Readonly<Record<string,
    "ordinary-terminal" | "st8-resolved-success" | "st8-expired-interim-failure">>;
  readonly supersedesEdges: Readonly<Record<string, string>>;
  readonly unrelatedAuthorityDisposition: "verified" | "indeterminate";
}

export type EvidenceBoundSettlementSetResult = Readonly<{
  readonly disposition: "verified" | "rejected" | "indeterminate";
  readonly reasonCode: EvidenceBoundSettlementReasonCode;
}>;

/** DACS-5 v0.4 draft PR #290, SEB-1..SEB-6 pure exact-set decision. */
export function evaluateEvidenceBoundSettlementSet(
  input: EvidenceBoundSettlementSetInput,
): EvidenceBoundSettlementSetResult {
  const expected = input.expectedPhaseKeys;
  const refs = input.topLevelRefs;
  const resolved = input.resolvedReferencePhaseKeys;
  const pointers = input.pointerMap;

  if (refs.length !== new Set(refs).size) return rejected("raw-multiplicity");

  for (const [successor, interim] of Object.entries(input.supersedesEdges)) {
    if (refs.includes(interim) || !refs.includes(successor)) {
      return rejected("st8-raw-admissibility");
    }
  }
  for (const ref of refs) {
    if (input.recordClassByRef?.[ref] === "st8-resolved-success"
      && input.supersedesEdges[ref] === undefined) {
      return rejected("st8-raw-admissibility");
    }
  }

  if (refs.some((ref) => resolved[ref] === undefined || !expected.includes(resolved[ref]))) {
    return rejected("exact-phase-mapping");
  }
  if (refs.length !== expected.length) return rejected("exact-cardinality");

  const mapped = refs.map((ref) => resolved[ref]!);
  if (new Set(mapped).size !== mapped.length || !sameSet(mapped, expected)) {
    return rejected("exact-bijection");
  }

  const pointerRefs = Object.values(pointers);
  if (new Set(pointerRefs).size !== pointerRefs.length) return rejected("pointer-agreement");
  for (const [phaseKey, ref] of Object.entries(pointers)) {
    if (!refs.includes(ref) || resolved[ref] !== phaseKey) return rejected("pointer-agreement");
  }

  return input.unrelatedAuthorityDisposition === "indeterminate"
    ? Object.freeze({ disposition: "indeterminate", reasonCode: "unrelated-authority-indeterminate" })
    : Object.freeze({ disposition: "verified", reasonCode: "ok" });
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  const leftSet = new Set(left);
  return leftSet.size === new Set(right).size && right.every((value) => leftSet.has(value));
}

function rejected(reasonCode: EvidenceBoundSettlementReasonCode): EvidenceBoundSettlementSetResult {
  return Object.freeze({ disposition: "rejected", reasonCode });
}

import type { EvidenceMode } from "../core/evidence-mode.ts";

export interface BindingReadiness {
  readonly status: "not-applicable" | "blocked";
  readonly protocolDisposition?: "indeterminate";
  readonly resolverConfigured: false;
  readonly deterministicInferenceUsed: false;
  readonly reason: string;
}

export function bindingReadiness(evidenceMode: EvidenceMode): BindingReadiness {
  return evidenceMode === "fixture"
    ? Object.freeze({
      status: "not-applicable",
      resolverConfigured: false,
      deterministicInferenceUsed: false,
      reason: "Live logical/native binding is outside fixture execution",
    })
    : Object.freeze({
      status: "blocked",
      protocolDisposition: "indeterminate",
      resolverConfigured: false,
      deterministicInferenceUsed: false,
      reason: "No authoritative live logical/native binding resolver is configured",
    });
}

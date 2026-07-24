import { describe, expect, test } from "bun:test";
import { bindingReadiness } from "../../src/readiness/binding-readiness.ts";

describe("binding readiness", () => {
  test("keeps fixture separate and local/live honestly blocked without address inference", () => {
    expect(bindingReadiness("fixture")).toEqual({
      status: "not-applicable",
      resolverConfigured: false,
      deterministicInferenceUsed: false,
      reason: "Live logical/native binding is outside fixture execution",
    });
    for (const mode of ["local-chain", "live"] as const) {
      expect(bindingReadiness(mode)).toEqual({
        status: "blocked",
        protocolDisposition: "indeterminate",
        resolverConfigured: false,
        deterministicInferenceUsed: false,
        reason: "No authoritative live logical/native binding resolver is configured",
      });
    }
  });
});

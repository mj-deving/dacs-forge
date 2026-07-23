import { describe, expect, test } from "bun:test";
import vector from "../../vectors/dacs-standard-bundle-convergence-ad48d16.json";

describe("pinned DACS-5 bundle convergence contract", () => {
  test("pins exact upstream spec and fixture bytes without promoting stale fixture shape", () => {
    expect(vector.upstreamCommit).toBe("ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4");
    expect(vector.specSha256).toBe("bf8b84b00dc22f4e91c60df8af34ab98465a4463fcd3d71a0a67fa637dac95bd");
    expect(vector.fixtureSources).toEqual([
      {
        path: "conformance/fixtures/session-bundles-presence.json",
        sha256: "bb3f9e0534b53eb8c049d85a927e9fbdcc1ad1076d6d6f5102233362a543480e",
        usedFor: ["phase-presence-divergence", "advisory-skew"],
      },
      {
        path: "conformance/fixtures/session-bundle-one-sided.json",
        sha256: "02e6a20a59a3f8baa4f2a5e0e8bbd3abb9ca065c35a5e615d9e73268cbf62235",
        usedFor: ["single-signed-abort"],
      },
      {
        path: "conformance/fixtures/attestation-bundle-0004.json",
        sha256: "aa12856c1356fd58c3ff23518db679a98985eeb791d0cd097d0c826081eb9ff7",
        usedFor: ["full-signature-envelope", "role-local-copy"],
      },
    ]);
    expect(vector.knownUpstreamDrift.authority).toBe("spec");
    expect(vector.knownUpstreamDrift.implementationPosture).toContain("external-rig qualification open");
  });

  test("pins all contradiction fields and fail-closed reputation disposition", () => {
    expect(vector.rules.signedScopeExcludes).toEqual(["anchoredByRole", "signatures"]);
    expect(vector.rules.lookupDispositions).toEqual([
      "absent", "indeterminate", "one-sided", "unified", "divergent",
    ]);
    expect(vector.rules.divergenceFields).toEqual([
      "outcome", "phaseSummary[].presence", "phaseSummary[].kind",
      "phaseSummary[].outcome", "phaseSummary[].errorClass",
    ]);
    expect(vector.rules.reputationOnDivergence).toBe("exclude-all-metrics");
  });
});

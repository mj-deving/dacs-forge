import { describe, expect, test } from "bun:test";
import projection from "../../vectors/dacs-standard-settlement-finalization-ad48d16.json";

describe("pinned DACS settlement finalization propagation vectors", () => {
  test("pins the exact upstream source and complete six-case decision corpus", () => {
    expect(projection.upstreamCommit).toBe("ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4");
    expect(projection.upstreamSha256).toBe("98c6356157b180d62e1049201143ab5681d9db2e71eb6f9aef6fdf20f787c555");
    expect(projection.hash).toBe("f7ac3446cb19766933b1bc60c3bca3841429291744efcf6041a343e2219a7282");
    expect(projection.vectors).toHaveLength(projection.count);
    expect(new Set(projection.vectors.map(({ name }) => name)).size).toBe(6);
  });

  test("classifies complete propagation, stale propagation, missing resigning, and semantic drift", () => {
    const required = new Set(projection.requiredChangedPaths);
    const allowed = new Set(projection.allowedChangedPaths);
    const byName = new Map(projection.vectors.map((vector) => [vector.name, vector]));
    const complete = byName.get("final-source-propagates-through-evidence-and-bundle")!;
    expect(complete.expected).toBe("pass");
    expect(new Set(complete.changedPaths)).toEqual(required);
    expect(complete.changedPaths.every((path) => allowed.has(path))).toBe(true);

    for (const name of [
      "evidence-rebuilt-but-bundle-reference-stays-stale",
      "bundle-reference-updated-but-phase-txref-stays-placeholder",
      "hashes-updated-without-required-resigning",
    ]) {
      const vector = byName.get(name)!;
      expect(vector.expected).toBe("fail");
      expect(projection.requiredChangedPaths.some((path) => !vector.changedPaths.includes(path))).toBe(true);
    }

    const unrelated = byName.get("unrelated-agreement-change-is-outside-propagation-closure")!;
    expect(unrelated.expected).toBe("fail");
    expect(unrelated.changedPaths.some((path) => !allowed.has(path))).toBe(true);
    expect(byName.get("signed-anchored-placeholder-is-never-valid-evidence")!.draftDisposition)
      .toBe("signed-anchored-success");
  });
});

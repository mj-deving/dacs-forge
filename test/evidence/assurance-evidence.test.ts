import { expect, test } from "bun:test";
import { runAssuranceEvidence } from "../../tools/run-assurance-evidence.ts";

test("reproduces the frozen three-slice assurance evidence", async () => {
  const observed = await runAssuranceEvidence();
  const frozen = await Bun.file(
    `${import.meta.dir}/../../evidence/assurance/results.json`,
  ).json();
  expect(observed).toEqual(frozen);

  for (const slice of frozen.slices) {
    expect(slice.cases.length).toBeGreaterThan(0);
    for (const testCase of slice.cases) {
      if (!("mutation" in testCase)) continue;
      expect(testCase.mutation.killed).toBe(true);
      expect(testCase.mutation.expectedGreen).not.toBe(testCase.mutation.observedRed);
    }
  }

  const bijection = frozen.slices.find((slice: { id: string }) => slice.id === "FORGE-ASSURANCE-003");
  expect(bijection).toBeDefined();
  if (bijection === undefined) throw new Error("FORGE-ASSURANCE-003 slice missing");
  type FrozenCase = { caseId: string; observed: unknown };
  const cases = new Map<string, FrozenCase>(
    (bijection.cases as FrozenCase[]).map((testCase) => [testCase.caseId, testCase]),
  );
  expect(cases.get("st8-missing-terminal-projection-reject")?.observed).toEqual({ disposition: "rejected", reasonCode: "st8-raw-admissibility" });
  expect(cases.get("st8-resolved-only-pass")?.observed).toEqual({ disposition: "verified", reasonCode: "ok" });
  expect(cases.get("st8-expired-interim-only-pass")?.observed).toEqual({ disposition: "verified", reasonCode: "ok" });
  expect(cases.get("st8-resolved-success-suppressed-reject")?.observed).toEqual({ disposition: "rejected", reasonCode: "st8-raw-admissibility" });
  expect(cases.get("st8-interim-plus-resolved-reject")?.observed).toEqual({ disposition: "rejected", reasonCode: "st8-raw-admissibility" });
});

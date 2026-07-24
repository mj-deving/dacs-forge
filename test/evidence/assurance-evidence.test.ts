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
});

import { expect, test } from "bun:test";
import {
  assertCalibrationCatalog,
  assertCommandEquivalence,
  CALIBRATION_SOURCE_SHA256,
  type MutationRecord,
  type MutationReport,
} from "../../tools/mutation/report.ts";

test("rejects mutation assertions that differ from the release command", () => {
  expect(() => assertCommandEquivalence(
    "bun test --timeout 10000",
    "bun test test/mutation/calibration.test.ts",
    ["test/mutation/calibration.test.ts"],
  )).toThrow(/differ from the release command/);
});

test("rejects a calibration report that skipped a known mutant", () => {
  const source = Bun.file("test/mutation/calibration-target.ts");
  expect(sha256(new Uint8Array())).not.toBe(CALIBRATION_SOURCE_SHA256);
  return source.arrayBuffer().then((bytes) => {
    const report: MutationReport = {
      schemaVersion: "1.0",
      files: {
        "test/mutation/calibration-target.ts": {
          mutants: [fakeMutant()],
        },
      },
    };
    expect(() => assertCalibrationCatalog(report, new Uint8Array(bytes)))
      .toThrow(/catalog size mismatch/);
  });
});

function fakeMutant(): MutationRecord {
  return {
    id: "0",
    location: {
      start: { line: 1, column: 0 },
      end: { line: 1, column: 1 },
    },
    mutatorName: "ArithmeticOperator",
    replacement: "left - right",
    status: "Killed",
  };
}

function sha256(bytes: Uint8Array): string {
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

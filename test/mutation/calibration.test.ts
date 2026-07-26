import { describe, expect, test } from "bun:test";
import {
  classifyCalibrationValue,
  combineCalibrationValues,
} from "./calibration-target.ts";

describe("mutation-runner calibration catalog", () => {
  test("distinguishes disabled, low, boundary, and high values", () => {
    expect(classifyCalibrationValue(11, false)).toBe("disabled");
    expect(classifyCalibrationValue(9, true)).toBe("low");
    expect(classifyCalibrationValue(10, true)).toBe("boundary");
    expect(classifyCalibrationValue(11, true)).toBe("high");
  });

  test("detects arithmetic replacement", () => {
    expect(combineCalibrationValues(4, 3)).toBe(7);
  });
});

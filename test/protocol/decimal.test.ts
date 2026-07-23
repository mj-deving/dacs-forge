import { describe, expect, test } from "bun:test";
import {
  compareCanonicalDecimals,
  isCanonicalNonNegativeDecimal,
  multiplyCanonicalDecimalByInteger,
  negotiableBoundsHalfUp,
} from "../../src/protocol/decimal.ts";

describe("DACS CD-1 arithmetic", () => {
  test.each(["0", "1", "0.01", "10.25"])("accepts canonical %s", (value) => {
    expect(isCanonicalNonNegativeDecimal(value)).toBeTrue();
  });

  test.each(["", "00", "01", ".1", "1.0", "1e2", "+1", "-1"])("rejects non-canonical %s", (value) => {
    expect(isCanonicalNonNegativeDecimal(value)).toBeFalse();
  });

  test("compares and multiplies without floating point", () => {
    expect(compareCanonicalDecimals("1.01", "1.001")).toBe(1);
    expect(multiplyCanonicalDecimalByInteger("0.0000001", "10000000")).toBe("1");
    expect(multiplyCanonicalDecimalByInteger("1.25", "0")).toBe("0");
  });

  test("rounds negotiable bounds half-up at bandCenter precision", () => {
    expect(negotiableBoundsHalfUp("1.25", 10, 10)).toEqual({ lower: "1.13", upper: "1.38" });
    expect(negotiableBoundsHalfUp("1.25", 2.5, 2.5)).toEqual({ lower: "1.22", upper: "1.28" });
    expect(negotiableBoundsHalfUp("10", 0.125, 0.125))
      .toEqual({ lower: "10", upper: "10" });
    expect(negotiableBoundsHalfUp("1", 50, 50)).toEqual({ lower: "1", upper: "2" });
    expect(negotiableBoundsHalfUp("100", 0, Number.MAX_SAFE_INTEGER).upper)
      .toBe("9007199254741091");
  });

  test.each([Number.NaN, Number.POSITIVE_INFINITY, -0.1, Number.MAX_SAFE_INTEGER + 1])(
    "rejects unsupported percentage %s",
    (percentage) => {
      expect(() => negotiableBoundsHalfUp("1", percentage, 1)).toThrow("percentages are invalid");
    },
  );
});

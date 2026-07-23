import { describe, expect, test } from "bun:test";
import vectors from "../../vectors/dacs-standard-canonicalize-db9f9c0.json";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";

describe("pinned DACS canonicalization vectors", () => {
  for (const vector of vectors.cases) {
    test(vector.id, () => {
      switch (vector.operation) {
        case "canonicalize":
          expect(canonicalize(vector.input)).toBe(vector.want);
          break;
        case "throws":
          expect(() => canonicalize(vector.input)).toThrow();
          break;
        case "without-signature":
          expect(canonicalize(withoutFields(
            vector.input as Record<string, unknown>,
            "signature",
          ))).toBe(vector.want);
          break;
        default:
          throw new Error(`Unknown vector operation: ${vector.operation}`);
      }
    });
  }
});

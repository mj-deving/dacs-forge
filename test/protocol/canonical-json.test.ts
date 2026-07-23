import { describe, expect, test } from "bun:test";
import {
  CanonicalizationError,
  canonicalize,
  deepFreezeJson,
  withoutFields,
} from "../../src/protocol/canonical-json.ts";

describe("DACS canonical JSON", () => {
  test("sorts keys and preserves array order", () => {
    expect(canonicalize({ z: [3, 1, 2], a: { y: 1, x: 2 }, A: true }))
      .toBe('{"A":true,"a":{"x":2,"y":1},"z":[3,1,2]}');
  });

  test("does not dispatch through an input-controlled array map method", () => {
    const value = [1, 2] as number[] & { map: () => never };
    value.map = () => { throw new Error("must not run"); };
    expect(canonicalize(value)).toBe("[1,2]");
  });

  test("normalizes every string value to NFC", () => {
    expect(canonicalize({ value: "e\u0301" })).toBe('{"value":"é"}');
  });

  test("normalizes keys and rejects NFC collisions", () => {
    expect(canonicalize({ "e\u0301": 1 })).toBe('{"é":1}');
    expect(() => canonicalize({ "e\u0301": 1, "é": 2 }))
      .toThrow(/NFC key collision/);
  });

  test("uses only required JSON escapes", () => {
    expect(canonicalize('a"b\\c\n\t/a')).toBe('"a\\"b\\\\c\\n\\t/a"');
    expect(canonicalize(String.fromCharCode(1))).toBe('"\\u0001"');
  });

  test("accepts finite numbers in range and canonicalizes them with RFC 8785", () => {
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(canonicalize(1.5)).toBe("1.5");
    expect(canonicalize(1e-7)).toBe("1e-7");
    expect(canonicalize(-0)).toBe("0");
  });

  test("rejects out-of-range and non-finite numbers", () => {
    expect(() => canonicalize(Number.MAX_SAFE_INTEGER + 2)).toThrow(/exceeds/);
    expect(() => canonicalize(Infinity)).toThrow(/non-finite/);
  });

  test("rejects lone surrogates", () => {
    expect(() => canonicalize("\ud800")).toThrow(/lone high surrogate/);
    expect(() => canonicalize("\udc00")).toThrow(/lone low surrogate/);
  });

  test("rejects sparse arrays and undefined array values", () => {
    const sparse = Array(1) as unknown[];
    expect(() => canonicalize(sparse)).toThrow(/sparse array/);
    Object.setPrototypeOf(sparse, { 0: "inherited" });
    expect(() => canonicalize(sparse)).toThrow(/sparse array/);
    expect(() => canonicalize([undefined])).toThrow(CanonicalizationError);
  });

  test("rejects cyclic and non-plain objects", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    expect(() => canonicalize(cyclic)).toThrow(/cyclic/);
    expect(() => canonicalize(new Date())).toThrow(/plain JSON objects/);
  });

  test("accepts 64 nesting levels and rejects deeper input with the typed error", () => {
    expect(() => canonicalize(nestedArrays(64))).not.toThrow();
    expect(() => canonicalize(nestedArrays(65)))
      .toThrow(CanonicalizationError);
    expect(() => canonicalize(nestedArrays(200_000)))
      .toThrow(/nesting depth exceeds 64/);
  });

  test("omits undefined object fields and removes signed-scope fields", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(withoutFields({ a: 1, signature: "x" }, "signature")).toEqual({ a: 1 });
  });

  test("deep-freezes descendants beneath an already frozen parent", () => {
    const child = { value: 1 };
    const root = Object.freeze({ child });
    deepFreezeJson(root);
    expect(Object.isFrozen(child)).toBe(true);
  });
});

function nestedArrays(depth: number): unknown {
  let value: unknown = null;
  for (let index = 0; index < depth; index += 1) value = [value];
  return value;
}

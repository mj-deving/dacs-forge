import { describe, expect, test } from "bun:test";
import {
  CanonicalizationError,
  canonicalize,
  deepFreezeJson,
} from "../../src/protocol/canonical-json.ts";
import {
  ComponentSignatureEncodingError,
  decodeComponentSignatureValue,
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";
import {
  compareCanonicalDecimals,
  isCanonicalNonNegativeDecimal,
  isCanonicalPositiveDecimal,
  multiplyCanonicalDecimalByInteger,
  negotiableBoundsHalfUp,
} from "../../src/protocol/decimal.ts";
import {
  encodeCf4Segment,
  listingLogicalAddress,
  parseListingLogicalAddress,
} from "../../src/protocol/logical-address.ts";
import { paymentEvidenceLogicalAddress } from "../../src/protocol/settlement-address.ts";

describe("canonical JSON mutation boundaries", () => {
  test("preserves primitives and recursively freezes arrays and objects", () => {
    expect(deepFreezeJson(null)).toBeNull();
    expect(deepFreezeJson("value")).toBe("value");
    const child = { value: 1 };
    const array = [child];
    const root = { array };
    expect(deepFreezeJson(root)).toBe(root);
    expect(Object.isFrozen(root)).toBeTrue();
    expect(Object.isFrozen(array)).toBeTrue();
    expect(Object.isFrozen(child)).toBeTrue();
  });

  test("serializes every primitive and special control escape exactly", () => {
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
    expect(canonicalize("\b\f\r")).toBe('"\\b\\f\\r"');
    expect(canonicalize("\u001f ")).toBe('"\\u001f "');
  });

  test("uses the typed error and exact unsupported-type boundary", () => {
    const error = new CanonicalizationError("bad");
    expect(error.name).toBe("CanonicalizationError");
    expect(() => canonicalize(undefined)).toThrow('JCS: unsupported value type "undefined"');
    expect(() => canonicalize(Symbol("x"))).toThrow('JCS: unsupported value type "symbol"');
  });

  test("accepts valid surrogate boundaries and rejects malformed pairs", () => {
    expect(canonicalize("\ud800\udc00")).toBe('"𐀀"');
    expect(canonicalize("\udbff\udfff")).toBe('"􏿿"');
    expect(() => canonicalize("\ud800x")).toThrow("JCS: lone high surrogate");
    expect(() => canonicalize("\udbff\udbff")).toThrow("JCS: lone high surrogate");
    expect(() => canonicalize("\udc00")).toThrow("JCS: lone low surrogate");
    expect(() => canonicalize("\udfff")).toThrow("JCS: lone low surrogate");
  });

  test("clears cycle state after each completed branch", () => {
    const shared = { value: 1 };
    expect(canonicalize([shared, shared])).toBe('[{"value":1},{"value":1}]');
  });
});

describe("signature codec mutation boundaries", () => {
  test("keeps the typed error identity and input guards", () => {
    expect(new ComponentSignatureEncodingError("bad").name)
      .toBe("ComponentSignatureEncodingError");
    expect(() => encodeComponentSignatureValue(new Uint8Array()))
      .toThrow("Signature bytes must be non-empty");
    expect(() => encodeComponentSignatureValue([] as unknown as Uint8Array))
      .toThrow("Signature bytes must be non-empty");
    expect(() => decodeComponentSignatureValue(""))
      .toThrow("Signature value must be a non-empty string");
    expect(() => decodeComponentSignatureValue(null as unknown as string))
      .toThrow("Signature value must be a non-empty string");
  });

  test.each(["!AA", "AA!", " AA", "AA "])("rejects base64url junk %s", (value) => {
    expect(() => decodeComponentSignatureValue(value))
      .toThrow("Signature must use the unpadded base64url alphabet");
  });

  test("rejects impossible length and accepts exact expected length", () => {
    expect(() => decodeComponentSignatureValue("A"))
      .toThrow("Signature has an impossible base64url length");
    expect(decodeComponentSignatureValue("AA", 1)).toEqual(Uint8Array.of(0));
  });

  test("guards legacy encodings and their canonical spelling", () => {
    expect(() => importLegacyComponentSignatureValue("", "lowercase-hex"))
      .toThrow("Legacy signature value must be a non-empty string");
    expect(() => importLegacyComponentSignatureValue(null as unknown as string, "lowercase-hex"))
      .toThrow("Legacy signature value must be a non-empty string");
    for (const value of ["!+/8A", "+/8A!", "A===", "AAAAA"] as const) {
      expect(() => importLegacyComponentSignatureValue(value, "standard-base64-padded"))
        .toThrow("Legacy signature is not canonical standard base64");
    }
    for (const value of ["!00", "00!", "A0", "0", "000"] as const) {
      expect(() => importLegacyComponentSignatureValue(value, "lowercase-hex"))
        .toThrow("Legacy signature is not canonical lowercase hex");
    }
    expect(importLegacyComponentSignatureValue("00", "lowercase-hex", 1))
      .toEqual(Uint8Array.of(0));
    expect(() => importLegacyComponentSignatureValue("00", "unknown" as "lowercase-hex"))
      .toThrow("Legacy signature source encoding is unsupported");
  });
});

describe("decimal mutation boundaries", () => {
  test("distinguishes non-negative and positive canonical values", () => {
    expect(isCanonicalNonNegativeDecimal(1)).toBeFalse();
    expect(isCanonicalPositiveDecimal("0")).toBeFalse();
    expect(isCanonicalPositiveDecimal("0.01")).toBeTrue();
    expect(isCanonicalPositiveDecimal("01")).toBeFalse();
  });

  test("covers less-than, equal, and differently scaled comparisons", () => {
    expect(compareCanonicalDecimals("1", "1")).toBe(0);
    expect(compareCanonicalDecimals("1.001", "1.01")).toBe(-1);
    expect(compareCanonicalDecimals("2.01", "2.001")).toBe(1);
  });

  test.each(["", "00", "1x", "x1", "-1"])("rejects multiplier %s", (multiplier) => {
    expect(() => multiplyCanonicalDecimalByInteger("1", multiplier))
      .toThrow("Multiplier must be a canonical non-negative integer string");
  });

  test("formats zero and fractional products canonically", () => {
    expect(multiplyCanonicalDecimalByInteger("0.0001", "0")).toBe("0");
    expect(multiplyCanonicalDecimalByInteger("0.0001", "10")).toBe("0.001");
    expect(() => multiplyCanonicalDecimalByInteger("1.0", "1"))
      .toThrow("Value is not a CD-1 canonical non-negative decimal");
  });

  test("covers percentage boundaries and exponential ratios", () => {
    expect(() => negotiableBoundsHalfUp("1", 100, 1))
      .toThrow("Negotiable percentages are invalid");
    expect(() => negotiableBoundsHalfUp("1", 1, Number.MAX_SAFE_INTEGER + 1))
      .toThrow("Negotiable percentages are invalid");
    expect(negotiableBoundsHalfUp("1.00000001", 1e-7, 1e-7))
      .toEqual({ lower: "1.00000001", upper: "1.00000001" });
    expect(negotiableBoundsHalfUp("1", 0, 1e3).upper).toBe("11");
  });
});

describe("logical-address mutation boundaries", () => {
  const claim = `cci-xm:evm:mainnet:0x${"12".repeat(20)}`;

  test("rejects listing id and version boundaries with exact errors", () => {
    expect(() => listingLogicalAddress(claim, "", 1))
      .toThrow("listingId must be 1-128 URL-safe ASCII characters");
    expect(() => listingLogicalAddress(claim, "x".repeat(129), 1))
      .toThrow("listingId must be 1-128 URL-safe ASCII characters");
    expect(() => listingLogicalAddress(claim, "ok", 1.5))
      .toThrow("listingVersion must be a positive safe integer");
    expect(() => listingLogicalAddress(claim, "ok", Number.MAX_SAFE_INTEGER + 1))
      .toThrow("listingVersion must be a positive safe integer");
  });

  test("encodes each reserved character and rejects address junk", () => {
    expect(encodeCf4Segment(":?&=%")).toBe("%3A%3F%26%3D%25");
    const valid = listingLogicalAddress(claim, "listing", 1);
    expect(() => parseListingLogicalAddress(`junk${valid}`)).toThrow("canonical CF-4");
    expect(() => parseListingLogicalAddress(`${valid}junk`)).toThrow("canonical CF-4");
    expect(() => parseListingLogicalAddress(valid.replace(":v1", ":v9007199254740992")))
      .toThrow("version exceeds the safe integer range");
  });
});

describe("settlement-address mutation boundaries", () => {
  const jobId = "01J8ME0SXKQ4T9V2RC5HJ6WX7D";

  test("accepts zero phase and the maximum rail length", () => {
    const rail = `a${"b".repeat(63)}`;
    expect(paymentEvidenceLogicalAddress(jobId, rail, 0))
      .toBe(`dacs4:payment:${jobId}:${rail}:0`);
  });

  test("rejects anchored input and length violations with exact errors", () => {
    expect(() => paymentEvidenceLogicalAddress(`x${jobId}`, "rail", 0))
      .toThrow("Payment evidence jobId must be a canonical ULID");
    expect(() => paymentEvidenceLogicalAddress(`${jobId}x`, "rail", 0))
      .toThrow("Payment evidence jobId must be a canonical ULID");
    expect(() => paymentEvidenceLogicalAddress(jobId, `a${"b".repeat(64)}`, 0))
      .toThrow("Payment evidence railId is invalid");
    expect(() => paymentEvidenceLogicalAddress(jobId, "rail!", 0))
      .toThrow("Payment evidence railId is invalid");
    expect(() => paymentEvidenceLogicalAddress(jobId, "rail", -1))
      .toThrow("Payment evidence phaseIndex must be a non-negative safe integer");
  });
});

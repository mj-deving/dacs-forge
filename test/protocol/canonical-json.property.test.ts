import { expect, test } from "bun:test";
import fc from "fast-check";
import { consumerCanonicalize } from "../../src/consumer/canonical-json.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";

const PROPERTY_SEED = 0x5da5c001;

test("10,000 generated DACS JSON values are canonicalization-idempotent", () => {
  fc.assert(
    fc.property(fc.jsonValue(), (generated) => {
      const value = toDacsJson(generated);
      const canonical = canonicalize(value);
      const reparsed = JSON.parse(canonical) as unknown;
      expect(canonicalize(reparsed)).toBe(canonical);
      expect(sha256Hex(canonicalize(reparsed))).toBe(sha256Hex(canonical));
    }),
    { numRuns: 10_000, seed: PROPERTY_SEED },
  );
});

test("generated object insertion order does not change canonical bytes", () => {
  fc.assert(
    fc.property(fc.dictionary(fc.string(), fc.integer()), (generated) => {
      const entries = Object.entries(generated);
      const forward = Object.fromEntries(entries);
      const reverse = Object.fromEntries(entries.reverse());
      expect(canonicalize(forward)).toBe(canonicalize(reverse));
    }),
    { numRuns: 2_000, seed: PROPERTY_SEED + 1 },
  );
});

test("10,000 values match the independently implemented consumer canonicalizer", () => {
  fc.assert(
    fc.property(fc.jsonValue(), (generated) => {
      const value = toDacsJson(generated);
      let producer: string | Error;
      let consumer: string | Error;
      try {
        producer = canonicalize(value);
      } catch (error) {
        producer = error as Error;
      }
      try {
        consumer = consumerCanonicalize(value);
      } catch (error) {
        consumer = error as Error;
      }
      expect(producer instanceof Error).toBe(consumer instanceof Error);
      if (typeof producer === "string" && typeof consumer === "string") {
        expect(consumer).toBe(producer);
      }
    }),
    { numRuns: 10_000, seed: PROPERTY_SEED + 2 },
  );
});

function toDacsJson(value: unknown): unknown {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    return Math.max(
      Number.MIN_SAFE_INTEGER,
      Math.min(Number.MAX_SAFE_INTEGER, value),
    );
  }
  if (typeof value === "string") return value.normalize("NFC");
  if (Array.isArray(value)) return value.map(toDacsJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key.normalize("NFC"),
        toDacsJson(entry),
      ]),
    );
  }
  return value;
}

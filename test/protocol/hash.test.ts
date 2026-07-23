import { expect, test } from "bun:test";
import { contentHash, sha256Hex } from "../../src/protocol/hash.ts";

test("sha256Hex emits lowercase SHA-256", () => {
  expect(sha256Hex("abc"))
    .toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("contentHash uses canonical NFC bytes", () => {
  expect(contentHash({ b: "e\u0301", a: 1 }))
    .toBe(contentHash({ a: 1, b: "é" }));
});

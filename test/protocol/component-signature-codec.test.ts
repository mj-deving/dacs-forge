import { describe, expect, test } from "bun:test";
import {
  ComponentSignatureEncodingError,
  decodeComponentSignatureValue,
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";

describe("DACS CORE SIG-6 signature value codec", () => {
  test("producer emits canonical unpadded base64url with distinguishing alphabet", () => {
    const raw = Uint8Array.from([0xfb, 0xff, 0xfe, 0x00]);
    const encoded = encodeComponentSignatureValue(raw);
    expect(encoded).toBe("-__-AA");
    expect(decodeComponentSignatureValue(encoded)).toEqual(raw);
  });

  test("conforming consumer rejects padded standard base64", () => {
    const raw = Uint8Array.from([0xfb, 0xff, 0xfe, 0x00]);
    expect(() => decodeComponentSignatureValue(Buffer.from(raw).toString("base64")))
      .toThrow(ComponentSignatureEncodingError);
  });

  test("conforming consumer rejects standard base64 even without padding", () => {
    const raw = Uint8Array.from([0xfb, 0xff, 0x00]);
    expect(Buffer.from(raw).toString("base64")).toBe("+/8A");
    expect(() => decodeComponentSignatureValue("+/8A")).toThrow(ComponentSignatureEncodingError);
  });

  test("declared legacy imports preserve bytes and re-emit canonical SIG-6", () => {
    const raw = Uint8Array.from([0xfb, 0xff, 0xfe, 0x00]);
    const fromBase64 = importLegacyComponentSignatureValue(
      Buffer.from(raw).toString("base64"),
      "standard-base64-padded",
    );
    const fromHex = importLegacyComponentSignatureValue(Buffer.from(raw).toString("hex"), "lowercase-hex");
    expect(fromBase64).toEqual(raw);
    expect(fromHex).toEqual(raw);
    expect(encodeComponentSignatureValue(fromBase64)).toBe("-__-AA");
  });

  test("accepts canonical legacy standard base64 when no padding characters are required", () => {
    const raw = Uint8Array.from([0xfb, 0xff, 0x00]);
    expect(importLegacyComponentSignatureValue(
      Buffer.from(raw).toString("base64"),
      "standard-base64-padded",
    )).toEqual(raw);
  });

  test.each([
    "-__-AA=",
    "+//+AA",
    "AB==",
    "A",
    "AB",
    "AA===",
    "AA A",
  ])("rejects non-canonical spelling %s", (value) => {
    expect(() => decodeComponentSignatureValue(value)).toThrow(ComponentSignatureEncodingError);
  });

  test("enforces the expected signature length", () => {
    expect(() => decodeComponentSignatureValue("AA", 64)).toThrow("64 bytes");
  });
});

import { describe, expect, test } from "bun:test";
import vectorSet from "../../vectors/dacs-standard-signature-value-encoding-c4ace08.json";
import {
  decodeComponentSignatureValue,
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
  type LegacySignatureValueEncoding,
} from "../../src/protocol/component-signature-codec.ts";

describe("pinned DACS CORE SIG-6 vectors", () => {
  for (const vector of vectorSet.vectors) {
    test(vector.name, () => {
      if (vector.mode === "conforming-verifier") {
        if (vector.expected === "accept") {
          const decoded = decodeComponentSignatureValue(vector.value, 64);
          expect(decoded.byteLength).toBe(vector.decodedLength ?? 64);
          expect(Buffer.from(decoded).toString("hex")).toBe(vectorSet.signatureBytesHex);
          expect(encodeComponentSignatureValue(decoded)).toBe(vectorSet.canonicalValue);
        } else {
          expect(() => decodeComponentSignatureValue(vector.value, 64)).toThrow();
        }
        return;
      }

      if (vector.expected === "accept") {
        const decoded = importLegacyComponentSignatureValue(
          vector.value,
          vector.declaredEncoding as LegacySignatureValueEncoding,
          64,
        );
        expect(Buffer.from(decoded).toString("hex")).toBe(vectorSet.signatureBytesHex);
        expect(encodeComponentSignatureValue(decoded)).toBe(vectorSet.canonicalValue);
      } else {
        expect(() => decodeComponentSignatureValue(vector.value, 64)).toThrow();
      }
    });
  }
});

import { describe, expect, test } from "bun:test";
import { withProductionKeyLifecycle } from "../fixtures/production-key-provider.ts";

describe("post-revocation signature admission", () => {
  test("rejects old-key signatures for new sessions after revocation", async () => {
    await withProductionKeyLifecycle(({ lifecycle, provider, resolver }) => {
      const first = provider.claim("primary-v1");
      const second = provider.claim("primary-v2");
      resolver.current(first);
      lifecycle.activateInitialKey("primary-v1", 10);
      resolver.current(second);
      lifecycle.rotate("primary-v2", 100);
      expect(() => lifecycle.assertSignatureForNewSession({
        keyClaim: first, signedAt: 101, checkedAt: 101,
      })).toThrow(/current production key/i);
      lifecycle.assertSignatureForNewSession({
        keyClaim: second, signedAt: 101, checkedAt: 101,
      });
      expect(() => lifecycle.assertSignatureForNewSession({
        keyClaim: second, signedAt: 99, checkedAt: 101,
      })).toThrow(/validity interval/i);
      expect(() => lifecycle.assertSignatureForNewSession({
        keyClaim: second, signedAt: 102, checkedAt: 101,
      })).toThrow(/validity interval/i);
    });
  });
});

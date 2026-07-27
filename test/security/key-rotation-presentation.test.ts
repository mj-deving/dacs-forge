import { describe, expect, test } from "bun:test";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import { withProductionKeyLifecycle } from "../fixtures/production-key-provider.ts";

describe("production key rotation presentation", () => {
  test("new IdentityBundle presentations use the replacement current key", async () => {
    await withProductionKeyLifecycle(({ lifecycle, provider, resolver }) => {
      resolver.current(provider.claim("primary-v1"));
      lifecycle.activateInitialKey("primary-v1", 10);
      const replacement = provider.claim("primary-v2");
      resolver.current(replacement);
      lifecycle.rotate("primary-v2", 100);
      const signer = lifecycle.currentSigner();
      const signed = signPerClaimIdentityBundle({
        bundleVersion: "1",
        presentedBy: replacement,
        presentedAt: 101,
        claims: [{ ref: replacement }],
      }, signer, { deploymentMode: "local-chain", requestMode: "local-chain" });
      expect(signed.bundle["presentedBy"]).toBe(replacement);
      expect((signed.bundle["presentation"] as Record<string, unknown>)["signatures"])
        .toEqual([expect.objectContaining({ ref: replacement })]);
    });
  });
});

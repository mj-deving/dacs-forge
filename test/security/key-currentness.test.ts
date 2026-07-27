import { describe, expect, test } from "bun:test";
import { ProductionKeyLifecycle } from "../../src/substrate/keys/production-key-lifecycle.ts";
import { withProductionKeyLifecycle } from "../fixtures/production-key-provider.ts";

describe("DACS-2 key currentness", () => {
  test("admits only the recipe-resolved current production key", async () => {
    await withProductionKeyLifecycle(({ lifecycle, provider, resolver }) => {
      const first = provider.claim("primary-v1");
      const second = provider.claim("primary-v2");
      resolver.current(first);
      lifecycle.activateInitialKey("primary-v1", 10);
      lifecycle.assertCurrentForNewSession({ keyClaim: first, checkedAt: 20 });
      resolver.current(second);
      expect(() => lifecycle.assertCurrentForNewSession({ keyClaim: first, checkedAt: 21 }))
        .toThrow(/currentness authority/i);
      expect(() => lifecycle.assertCurrentForNewSession({ keyClaim: second, checkedAt: 21 }))
        .toThrow(/persisted current/i);
      lifecycle.rotate("primary-v2", 21);
      lifecycle.assertCurrentForNewSession({ keyClaim: second, checkedAt: 22 });
    });
  });

  test("refuses rotation through a provider that does not own the persisted key", async () => {
    await withProductionKeyLifecycle(({ database, lifecycle, provider, resolver }) => {
      resolver.current(provider.claim("primary-v1"));
      lifecycle.activateInitialKey("primary-v1", 10);
      resolver.current(provider.claim("primary-v2"));
      const wrongProvider = {
        providerId: "wrong-provider",
        publicKey: (handle: string) => provider.publicKey(handle),
        sign: (handle: string, payload: Uint8Array) => provider.sign(handle, payload),
      };
      const wrongLifecycle = new ProductionKeyLifecycle(database, {
        deploymentMode: "local-chain",
        provider: wrongProvider,
        resolver,
      });
      expect(() => wrongLifecycle.rotate("primary-v2", 20)).toThrow(/different signer provider/i);
      expect(lifecycle.currentSigner().signer).toBe(provider.claim("primary-v1"));
    });
  });

  test("does not pin a session before the persisted key activation", async () => {
    await withProductionKeyLifecycle(({ lifecycle, provider, resolver }) => {
      const claim = provider.claim("primary-v1");
      resolver.current(claim);
      lifecycle.activateInitialKey("primary-v1", 100);
      expect(() => lifecycle.pinCommittedSession({
        jobId: "01J00000000000000000000000",
        agreementHash: "a".repeat(64),
        keyClaim: claim,
        committedAt: 90,
      })).toThrow(/precedes key activation/i);
    });
  });
});

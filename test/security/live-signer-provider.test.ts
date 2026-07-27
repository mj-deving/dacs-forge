import { describe, expect, test } from "bun:test";
import {
  initializeProductionSigning,
  ProductionKeyLifecycle,
} from "../../src/substrate/keys/production-key-lifecycle.ts";
import { withProductionKeyLifecycle } from "../fixtures/production-key-provider.ts";

describe("provider-backed production signer", () => {
  test("exposes only a non-exporting handle-backed signing capability", async () => {
    await withProductionKeyLifecycle(({ database, lifecycle, provider, resolver }) => {
      resolver.current(provider.claim("primary-v1"));
      const signer = lifecycle.activateInitialKey("primary-v1", 10);
      expect(Object.keys(signer).sort()).toEqual(["algorithm", "sign", "signer"]);
      expect(signer.sign(new TextEncoder().encode("payload"), {
        deploymentMode: "local-chain",
        requestMode: "local-chain",
      })).toMatch(/^[A-Za-z0-9+/]{86}==$/);
      expect(() => signer.sign(new Uint8Array(), {
        deploymentMode: "fixture",
        requestMode: "fixture",
      })).toThrow(/production signing authority/i);
      expect(() => initializeProductionSigning({
        deploymentMode: "local-chain",
        keyHandle: "primary-v1",
        provider,
        initializeActionProvider: () => ({}),
        privateKey: "forbidden-raw-key",
      } as never)).toThrow(/exactly/i);
      const stored = database.query<Record<string, unknown>, []>(`
        SELECT * FROM production_signing_keys
      `).get();
      expect(Object.values(stored ?? {}).map(String)).not.toContain("forbidden-raw-key");
      expect(stored).toMatchObject({ provider_id: provider.providerId, key_handle: "primary-v1" });

      let signingTransactionObserved = false;
      const observingLifecycle = new ProductionKeyLifecycle(database, {
          deploymentMode: "local-chain",
          resolver,
          provider: {
            providerId: provider.providerId,
            publicKey: (handle: string) => provider.publicKey(handle),
            sign: (handle: string, payload: Uint8Array) => {
              signingTransactionObserved = database.inTransaction;
              return provider.sign(handle, payload);
            },
          },
      });
      observingLifecycle.currentSigner().sign(new TextEncoder().encode("serialized"), {
        deploymentMode: "local-chain",
        requestMode: "local-chain",
      });
      expect(signingTransactionObserved).toBe(true);
      expect(() => database.transaction(() => signer.sign(
        new TextEncoder().encode("caller-owned-transaction"),
        { deploymentMode: "local-chain", requestMode: "local-chain" },
      )).deferred()).toThrow(/caller-owned database transaction/i);

      resolver.current(provider.claim("primary-v2"));
      lifecycle.rotate("primary-v2", 20);
      expect(() => signer.sign(new TextEncoder().encode("stale"), {
        deploymentMode: "local-chain",
        requestMode: "local-chain",
      })).toThrow(/persisted current key/i);
    });
  });
});

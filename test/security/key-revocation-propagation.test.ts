import { describe, expect, test } from "bun:test";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import { signListing } from "../../src/producer/listing.ts";
import {
  FIXTURE_NOW_MS,
  fixtureUnsignedListing,
} from "../fixtures/reference-listing.ts";
import { withProductionKeyLifecycle } from "../fixtures/production-key-provider.ts";

const PRODUCTION_CONTEXT = Object.freeze({
  deploymentMode: "local-chain" as const,
  requestMode: "local-chain" as const,
  nowMs: FIXTURE_NOW_MS,
});

describe("production key revocation propagation", () => {
  test("retains one signed revocation binding for every old-key Listing version", async () => {
    await withProductionKeyLifecycle(({ lifecycle, provider, resolver }) => {
      const first = provider.claim("primary-v1");
      const second = provider.claim("primary-v2");
      resolver.current(first);
      const signer = lifecycle.activateInitialKey("primary-v1", 10);
      const base = fixtureUnsignedListing();
      const identity = signPerClaimIdentityBundle({
        bundleVersion: "1",
        presentedBy: first,
        presentedAt: FIXTURE_NOW_MS,
        claims: [{ ref: first }],
      }, signer, PRODUCTION_CONTEXT).bundle;
      const seller = { ...(base["seller"] as Record<string, unknown>), identity };
      const signVersion = (listingVersion: number, description?: string) => signListing({
        ...base,
        listingId: "alpha",
        listingVersion,
        seller,
        ...(description === undefined ? {} : {
          offering: {
            ...(base["offering"] as Record<string, unknown>),
            description,
          },
        }),
      }, signer, PRODUCTION_CONTEXT);
      signVersion(1);
      signVersion(2);
      expect(() => signVersion(2, "Mutated retained Listing content"))
        .toThrow(/cannot change content hash/i);
      resolver.current(second);
      const created = lifecycle.rotate("primary-v2", 100);
      expect(created).toHaveLength(2);
      expect(lifecycle.revocationsForKey(first).map((item) => ({
        listingId: item.listingId,
        listingVersion: item.listingVersion,
        replacement: item.replacementKeyClaim,
      }))).toEqual([
        { listingId: "alpha", listingVersion: 1, replacement: second },
        { listingId: "alpha", listingVersion: 2, replacement: second },
      ]);
      for (const item of created) {
        const marker = JSON.parse(item.canonicalJson) as Record<string, unknown>;
        expect(marker["keyClaim"]).toBe(first);
        expect(marker["replacementKeyClaim"]).toBe(second);
        expect(marker["signature"]).toMatchObject({ algorithm: "ed25519", signer: first });
      }
    });
  });
});

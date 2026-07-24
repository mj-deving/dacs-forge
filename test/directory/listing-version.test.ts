import { describe, expect, test } from "bun:test";
import {
  publishFixtureVersion,
  withListingLifecycle,
} from "../fixtures/identity-listing/lifecycle.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";

describe("Listing version monotonicity", () => {
  test("accepts exactly the next version and rejects skips and reuse", async () => {
    await withListingLifecycle(({ lifecycle }) => {
      const first = publishFixtureVersion(lifecycle, 1);
      expect(first.listingVersion).toBe(1);
      expect(() => publishFixtureVersion(lifecycle, 3)).toThrow(/exactly to 2/i);
      const second = publishFixtureVersion(lifecycle, 2);
      expect(second.listingVersion).toBe(2);
      expect(() => publishFixtureVersion(lifecycle, 2)).toThrow(/exactly to 3/i);
    });
  });

  test("namespaces version and discovery ownership by seller claim", async () => {
    await withListingLifecycle(({ lifecycle, store }) => {
      const first = publishFixtureVersion(lifecycle, 1);
      const otherSeller = `key:${"b".repeat(64)}`;
      const other = store.publish({
        sellerPrimaryClaim: otherSeller,
        listingId: first.listingId,
        listingVersion: 1,
        contentHash: sha256Hex("other-seller-listing"),
        canonicalJson: "{}",
        logicalAddress: `dacs1:${encodeURIComponent(otherSeller)}:${first.listingId}:v1`,
        nativeAddress: `stor-${"c".repeat(40)}`,
        anchorTx: "d".repeat(64),
        anchorVerifiedAt: 1,
        createdAt: "2026-07-24T00:00:00.000Z",
      });
      expect(store.current(first.sellerPrimaryClaim, first.listingId)).toEqual(first);
      expect(store.current(otherSeller, first.listingId)).toEqual(other);
    });
  });
});

import { describe, expect, test } from "bun:test";
import {
  publishFixtureVersion,
  withListingLifecycle,
} from "../fixtures/identity-listing/lifecycle.ts";

describe("Listing version retention", () => {
  test("keeps prior anchored bytes independently readable after an update", async () => {
    await withListingLifecycle(({ lifecycle, store }) => {
      const first = publishFixtureVersion(lifecycle, 1);
      const retainedBefore = store.get(
        first.sellerPrimaryClaim,
        first.listingId,
        first.listingVersion,
      );
      publishFixtureVersion(lifecycle, 2);
      expect(store.get(first.sellerPrimaryClaim, first.listingId, first.listingVersion))
        .toEqual(retainedBefore);
      expect(store.get(first.sellerPrimaryClaim, first.listingId, 2)?.canonicalJson)
        .not.toBe(retainedBefore?.canonicalJson);
    });
  });
});

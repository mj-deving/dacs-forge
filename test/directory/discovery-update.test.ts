import { describe, expect, test } from "bun:test";
import {
  publishFixtureVersion,
  withListingLifecycle,
} from "../fixtures/identity-listing/lifecycle.ts";

describe("Listing discovery update", () => {
  test("moves discovery without mutating the prior immutable anchor", async () => {
    await withListingLifecycle(({ lifecycle, store }) => {
      const first = publishFixtureVersion(lifecycle, 1);
      const oldAnchor = store.get(first.sellerPrimaryClaim, first.listingId, 1)?.nativeAddress;
      const second = publishFixtureVersion(lifecycle, 2);
      expect(store.current(first.sellerPrimaryClaim, first.listingId)).toEqual(second);
      expect(store.get(first.sellerPrimaryClaim, first.listingId, 1)?.nativeAddress).toBe(oldAnchor);
      expect(store.get(first.sellerPrimaryClaim, first.listingId, 2)?.nativeAddress).not.toBe(oldAnchor);
    });
  });
});

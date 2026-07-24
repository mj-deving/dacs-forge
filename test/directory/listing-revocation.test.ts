import { describe, expect, test } from "bun:test";
import {
  createSignedListingRevocation,
  listingRevocationLogicalAddress,
} from "../../src/directory/listing-lifecycle.ts";
import { fixtureSigner, FIXTURE_NOW_MS, FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";
import {
  CREATED_AT,
  fixtureBinding,
  publishFixtureVersion,
  withListingLifecycle,
} from "../fixtures/identity-listing/lifecycle.ts";

describe("Listing withdrawal", () => {
  test("anchors a signed retained revocation before removing discovery", async () => {
    await withListingLifecycle(({ database, lifecycle, store }) => {
      const listing = publishFixtureVersion(lifecycle, 1);
      const signer = fixtureSigner();
      const revocation = createSignedListingRevocation({
        listing,
        revokedAt: FIXTURE_NOW_MS + 1,
        reason: "withdrawn-by-fixture-owner",
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
      });
      const logical = listingRevocationLogicalAddress(signer.signer, listing.listingId, listing.listingVersion);
      const binding = fixtureBinding(revocation.canonicalJson, logical, "listing-revocation");
      lifecycle.withdraw({
        listing,
        revokedAt: FIXTURE_NOW_MS + 1,
        reason: "withdrawn-by-fixture-owner",
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
        bindingProof: binding.proof,
        bindingAuthority: binding.authority,
        verifiedAt: FIXTURE_NOW_MS + 1,
        createdAt: CREATED_AT,
      });
      expect(store.current(listing.sellerPrimaryClaim, listing.listingId)).toBeNull();
      expect(store.get(listing.sellerPrimaryClaim, listing.listingId, listing.listingVersion)).not.toBeNull();
      expect(store.revocation(
        listing.sellerPrimaryClaim,
        listing.listingId,
        listing.listingVersion,
      )?.canonicalJson)
        .toBe(revocation.canonicalJson);
      expect(database.query<{ contentHash: string }, { nativeAddress: string }>(`
        SELECT content_hash AS contentHash FROM fixture_listing_anchor_registry
        WHERE native_address = $nativeAddress
      `).get({ nativeAddress: binding.proof.nativeAddress })?.contentHash)
        .toBe(binding.proof.contentHash);
    });
  });

  test("rejects native-address reuse across retained Listings and revocations", async () => {
    await withListingLifecycle(({ lifecycle, store }) => {
      const listing = publishFixtureVersion(lifecycle, 1);
      const retained = store.get(
        listing.sellerPrimaryClaim,
        listing.listingId,
        listing.listingVersion,
      )!;
      const signer = fixtureSigner();
      const revocation = createSignedListingRevocation({
        listing,
        revokedAt: FIXTURE_NOW_MS + 1,
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
      });
      const logical = listingRevocationLogicalAddress(signer.signer, listing.listingId, listing.listingVersion);
      const binding = fixtureBinding(revocation.canonicalJson, logical, "reused-native", {
        nativeAddress: retained.nativeAddress,
      });
      expect(() => lifecycle.withdraw({
        listing,
        revokedAt: FIXTURE_NOW_MS + 1,
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
        bindingProof: binding.proof,
        bindingAuthority: binding.authority,
        verifiedAt: FIXTURE_NOW_MS + 1,
        createdAt: CREATED_AT,
      })).toThrow(/unique|constraint/i);
      expect(store.current(listing.sellerPrimaryClaim, listing.listingId)).toEqual(listing);
    });
  });

  test("rejects malformed, pre-anchor, and future-effective revocation times", async () => {
    await withListingLifecycle(({ lifecycle }) => {
      const listing = publishFixtureVersion(lifecycle, 1);
      const signer = fixtureSigner();
      const attempt = (revokedAt: number, verifiedAt: number) => lifecycle.withdraw({
        listing,
        revokedAt,
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
        bindingProof: fixtureBinding("{}", "unused", `invalid-${revokedAt}`).proof,
        bindingAuthority: fixtureBinding("{}", "unused", `invalid-${revokedAt}`).authority,
        verifiedAt,
        createdAt: CREATED_AT,
      });
      expect(() => attempt(-1, FIXTURE_NOW_MS)).toThrow(/Revocation time/i);
      expect(() => attempt(FIXTURE_NOW_MS - 1, FIXTURE_NOW_MS)).toThrow(/Revocation time/i);
      expect(() => attempt(FIXTURE_NOW_MS + 1, FIXTURE_NOW_MS)).toThrow(/Revocation time/i);
      expect(() => attempt(1.5, FIXTURE_NOW_MS)).toThrow(/Revocation time/i);
    });
  });
});

import { describe, expect, test } from "bun:test";
import { listingLogicalAddress } from "../../src/directory/listing-lifecycle.ts";
import { fixtureSigner, FIXTURE_NOW_MS } from "../fixtures/reference-listing.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import {
  CREATED_AT,
  fixtureBinding,
  signedListingVersion,
  withListingLifecycle,
} from "../fixtures/identity-listing/lifecycle.ts";

describe("Listing publication order", () => {
  test("does not expose discovery until dereference, hash, signature, and native-write provenance pass", async () => {
    await withListingLifecycle(({ lifecycle, store }) => {
      const listing = signedListingVersion(1);
      const logical = listingLogicalAddress(fixtureSigner().signer, "reference-json-transform", 1);
      const binding = fixtureBinding(listing.canonicalJson, logical, "publication-order");
      const refusedAuthority = {
        ...binding.authority,
        verifyNativeWrite: () => false,
      };
      expect(() => lifecycle.publish({
        canonicalJson: listing.canonicalJson,
        bindingProof: binding.proof,
        bindingAuthority: refusedAuthority,
        verifiedAt: FIXTURE_NOW_MS,
        createdAt: CREATED_AT,
      })).toThrow(/native-write provenance/i);
      expect(store.current(fixtureSigner().signer, "reference-json-transform")).toBeNull();

      const attacker = createFixtureEd25519Signer(Buffer.alloc(32, 23), {
        deploymentMode: "fixture",
        authorityMode: "fixture",
      });
      const attackerBinding = fixtureBinding(
        listing.canonicalJson,
        logical,
        "attacker-publication",
        { signer: attacker },
      );
      expect(() => lifecycle.publish({
        canonicalJson: listing.canonicalJson,
        bindingProof: attackerBinding.proof,
        bindingAuthority: attackerBinding.authority,
        verifiedAt: FIXTURE_NOW_MS,
        createdAt: CREATED_AT,
      })).toThrow(/authenticated seller authority/i);
      expect(store.current(fixtureSigner().signer, "reference-json-transform")).toBeNull();

      const published = lifecycle.publish({
        canonicalJson: listing.canonicalJson,
        bindingProof: binding.proof,
        bindingAuthority: binding.authority,
        verifiedAt: FIXTURE_NOW_MS,
        createdAt: CREATED_AT,
      });
      expect(store.current(published.sellerPrimaryClaim, published.listingId)).toEqual(published);
    });
  });
});

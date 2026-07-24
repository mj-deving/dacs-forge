import { describe, expect, test } from "bun:test";
import { verifyFixtureBinding } from "../../src/consumer/binding-verifier.ts";
import { fixtureBinding, signedListingVersion } from "../fixtures/identity-listing/lifecycle.ts";

describe("fixture logical/native binding verification", () => {
  test("requires dereference, content hash, signature, and native-write provenance independently", () => {
    const listing = signedListingVersion(1);
    const fixture = fixtureBinding(listing.canonicalJson, "dacs1:key%3Afixture:listing:v1", "binding-pass");
    expect(verifyFixtureBinding(fixture.proof, fixture.authority)).toMatchObject({
      disposition: "verified",
      canonicalJson: listing.canonicalJson,
    });

    expect(verifyFixtureBinding({ ...fixture.proof, contentHash: "0".repeat(64) }, fixture.authority))
      .toMatchObject({ disposition: "rejected" });
    expect(verifyFixtureBinding({ ...fixture.proof, nativeAddress: `${fixture.proof.nativeAddress}-derived` }, fixture.authority))
      .toMatchObject({ disposition: "rejected", reason: expect.stringContaining("dereference") });
    expect(verifyFixtureBinding({ ...fixture.proof, signature: "A".repeat(88) }, fixture.authority))
      .toMatchObject({ disposition: "rejected", reason: expect.stringContaining("signature") });
    expect(verifyFixtureBinding(fixture.proof, {
      ...fixture.authority,
      verifyNativeWrite: () => false,
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("provenance") });
  });
});

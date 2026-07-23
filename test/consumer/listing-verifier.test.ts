import { describe, expect, test } from "bun:test";
import vector from "../../vectors/dacs-standard-listing-preserve-unknown-c4ace08.json";
import { consumerCanonicalize } from "../../src/consumer/canonical-json.ts";
import { verifyCanonicalListingJson } from "../../src/consumer/listing-verifier.ts";
import {
  createFixtureEd25519Signer,
  type ArtifactSigner,
} from "../../src/producer/fixture-ed25519.ts";
import {
  signPerClaimIdentityBundle as signIdentityBundleWithContext,
} from "../../src/producer/identity-bundle.ts";
import { signListing as signListingWithContext } from "../../src/producer/listing.ts";
import {
  FIXTURE_NOW_MS,
  FIXTURE_SIGNING_CONTEXT,
  fixtureSignedListing,
  fixtureSigner,
  fixtureUnsignedListing,
  signUncheckedFixtureIdentityBundle,
  signUncheckedFixtureListing,
} from "../fixtures/reference-listing.ts";

function signListing(
  input: Parameters<typeof signListingWithContext>[0],
  signer: ArtifactSigner,
) {
  return signListingWithContext(input, signer, FIXTURE_SIGNING_CONTEXT);
}

function signPerClaimIdentityBundle(
  input: Parameters<typeof signIdentityBundleWithContext>[0],
  signer: ArtifactSigner,
) {
  return signIdentityBundleWithContext(input, signer, FIXTURE_SIGNING_CONTEXT);
}

const options = {
  nowMs: FIXTURE_NOW_MS,
  revocationCheck: () => "absent" as const,
};

describe("independent DACS Listing consumer", () => {
  test("accepts the producer output without importing producer helpers", () => {
    const produced = fixtureSignedListing();
    expect(verifyCanonicalListingJson(produced.canonicalJson, options)).toEqual({
      disposition: "accepted",
      listingId: "reference-json-transform",
      listingVersion: 1,
      contentHash: produced.contentHash,
    });
  });

  test("passes the pinned SIG-5 inert-extension vector", () => {
    const fixture = vector.fixtures["listing-with-inert-extension"];
    const result = verifyCanonicalListingJson(consumerCanonicalize(fixture.listing), options);
    expect(result).toEqual({
      disposition: "accepted",
      listingId: "sig5-extension-listing",
      listingVersion: 1,
      contentHash: fixture.artifactHash,
    });
  });

  test("preserves unknown signed fields and detects mutation or removal", () => {
    const fixture = vector.fixtures["listing-with-inert-extension"];
    const mutated = structuredClone(fixture.listing) as Record<string, unknown>;
    (mutated["futureOptionalMetadata"] as Record<string, unknown>)["displayTier"] = "red";
    expect(verifyCanonicalListingJson(consumerCanonicalize(mutated), options)).toMatchObject({
      disposition: "rejected",
      stage: "signature",
      signature: "invalid",
      contentHash: "27a2948ea53f43920e8ccb08a0d8e44a7e773164ef4f590040ab9305c7b22261",
    });

    const removed = structuredClone(fixture.listing) as Record<string, unknown>;
    delete removed["futureOptionalMetadata"];
    expect(verifyCanonicalListingJson(consumerCanonicalize(removed), options)).toMatchObject({
      disposition: "rejected",
      stage: "signature",
      signature: "invalid",
      contentHash: fixture.knownFieldProjectionHash,
    });
  });

  test("verifies before refusing an unknown action discriminator", () => {
    const fixture = vector.fixtures["listing-with-unknown-phase"];
    expect(verifyCanonicalListingJson(consumerCanonicalize(fixture.listing), options)).toEqual({
      disposition: "refused-unsupported",
      stage: "pipeline",
      reason: "Unsupported phase kind at pipeline[0]",
      contentHash: fixture.artifactHash,
      signature: "valid",
    });
  });

  test("structurally refuses later-minor schema types before signature verification", () => {
    const unsigned = fixtureUnsignedListing();
    const offering = unsigned["offering"] as Record<string, unknown>;
    const deliverable = offering["deliverable"] as Record<string, unknown>;
    const variants = [
      {
        listing: {
          ...unsigned,
          offering: {
            ...offering,
            deliverable: { kind: "future-deliverable", futureAction: "opaque" },
          },
        },
        reason: /Unsupported deliverable kind/,
      },
      {
        listing: { ...unsigned, pricing: { kind: "future-pricing", futureAction: "opaque" } },
        reason: /Unsupported pricing kind/,
      },
      {
        listing: {
          ...unsigned,
          offering: {
            ...offering,
            deliverable: {
              ...deliverable,
              verificationMethod: { kind: "future-proof", futureAction: "opaque" },
            },
          },
        },
        reason: /Unsupported verificationMethod kind/,
      },
    ];
    let revocationChecks = 0;
    for (const variant of variants) {
      const signed = signUncheckedFixtureListing(variant.listing);
      const result = verifyCanonicalListingJson(signed.canonicalJson, {
        nowMs: FIXTURE_NOW_MS,
        revocationCheck: () => {
          revocationChecks += 1;
          return "absent";
        },
      });
      expect(result).toMatchObject({
        disposition: "refused-unsupported",
        stage: "schema",
        signature: "not-checked",
      });
      if (result.disposition === "accepted") throw new Error("Expected unsupported Listing type refusal");
      expect(result.reason).toMatch(variant.reason);
    }
    expect(revocationChecks).toBe(0);

    const signed = signUncheckedFixtureListing(variants[0]!.listing);
    const tampered = structuredClone(signed.listing) as Record<string, unknown>;
    const tamperedOffering = tampered["offering"] as Record<string, unknown>;
    const tamperedDeliverable = tamperedOffering["deliverable"] as Record<string, unknown>;
    tamperedDeliverable["futureAction"] = "changed";
    expect(verifyCanonicalListingJson(consumerCanonicalize(tampered), options)).toMatchObject({
      disposition: "refused-unsupported",
      stage: "schema",
      signature: "not-checked",
    });
  });

  test("rejects non-canonical transport, tampering, revocation, and indeterminate reads", () => {
    const produced = fixtureSignedListing();
    expect(verifyCanonicalListingJson(JSON.stringify(produced.listing, null, 2), options))
      .toMatchObject({ disposition: "rejected", stage: "canonical-form" });

    const tampered = structuredClone(produced.listing) as Record<string, unknown>;
    ((tampered["offering"] as Record<string, unknown>)["title"] as string) = "Tampered";
    expect(verifyCanonicalListingJson(consumerCanonicalize(tampered), options))
      .toMatchObject({ disposition: "rejected", stage: "signature", signature: "invalid" });

    for (const revocation of ["revoked", "indeterminate"] as const) {
      expect(verifyCanonicalListingJson(produced.canonicalJson, {
        nowMs: FIXTURE_NOW_MS,
        revocationCheck: () => revocation,
      })).toMatchObject({
        disposition: "rejected",
        stage: "revocation",
        signature: "valid",
      });
    }
  });

  test("rejects malformed signatures and missing rails fail closed", () => {
    const produced = fixtureSignedListing();
    const malformed = structuredClone(produced.listing) as Record<string, unknown>;
    (malformed["signature"] as Record<string, unknown>)["value"] = "A".repeat(88);
    expect(verifyCanonicalListingJson(consumerCanonicalize(malformed), options))
      .toMatchObject({ disposition: "rejected", stage: "signature" });

    const payListing = signUncheckedFixtureListing({
      ...fixtureUnsignedListing(),
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:1" } },
        { kind: "deliver-attested-payload" },
      ],
    });
    expect(verifyCanonicalListingJson(payListing.canonicalJson, options))
      .toMatchObject({ disposition: "rejected", stage: "rails", signature: "valid" });
  });

  test("rejects domain confusion and refuses an unsupported signature algorithm", () => {
    const unsigned = fixtureUnsignedListing();
    const wrongDomain = signUncheckedFixtureListing(unsigned, { domain: "dacs-revocation:v1:" });
    expect(verifyCanonicalListingJson(wrongDomain.canonicalJson, options))
      .toMatchObject({ disposition: "rejected", stage: "signature", signature: "invalid" });

    const mislabeled = signUncheckedFixtureListing(unsigned, { algorithm: "ecdsa-secp256k1" });
    expect(verifyCanonicalListingJson(mislabeled.canonicalJson, options)).toMatchObject({
      disposition: "refused-unsupported",
      stage: "signature",
      signature: "not-checked",
    });

    const noncanonicalSigner = structuredClone(fixtureSignedListing().listing) as Record<string, unknown>;
    const signature = noncanonicalSigner["signature"] as Record<string, unknown>;
    signature["signer"] = (signature["signer"] as string).toUpperCase();
    expect(verifyCanonicalListingJson(consumerCanonicalize(noncanonicalSigner), options)).toMatchObject({
      disposition: "rejected",
      stage: "signature",
      signature: "not-checked",
    });
  });

  test("rejects a valid Listing signature from a key outside the publisher bundle", () => {
    const publisher = createFixtureEd25519Signer(Buffer.alloc(32, 9), {
      deploymentMode: "fixture",
      authorityMode: "fixture",
    });
    const identity = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: publisher.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: publisher.signer }],
    }, publisher).bundle;
    const unsigned = fixtureUnsignedListing();
    const seller = unsigned["seller"] as Record<string, unknown>;
    const signed = signUncheckedFixtureListing({ ...unsigned, seller: { ...seller, identity } });
    expect(verifyCanonicalListingJson(signed.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "signer",
      signature: "valid",
    });
  });

  test("rejects identity failures at their ordered schema or post-signature boundary", () => {
    const unsigned = fixtureUnsignedListing();
    const seller = unsigned["seller"] as Record<string, unknown>;
    const identity = structuredClone(seller["identity"]) as Record<string, unknown>;
    const claims = identity["claims"] as Record<string, unknown>[];
    claims[0] = { ...claims[0], issuedAt: "yesterday" };
    const signed = signUncheckedFixtureListing({ ...unsigned, seller: { ...seller, identity } });
    expect(verifyCanonicalListingJson(signed.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "identity",
      signature: "valid",
    });

    const invalidPrimary = structuredClone(seller["identity"]) as Record<string, unknown>;
    invalidPrimary["presentedBy"] = "not-a-claim";
    const invalidPrimaryListing = signUncheckedFixtureListing({
      ...unsigned,
      seller: { ...seller, identity: invalidPrimary },
    });
    let revocationChecks = 0;
    expect(verifyCanonicalListingJson(invalidPrimaryListing.canonicalJson, {
      nowMs: FIXTURE_NOW_MS,
      revocationCheck: () => {
        revocationChecks += 1;
        return "absent";
      },
    })).toMatchObject({ disposition: "rejected", stage: "schema" });
    expect(revocationChecks).toBe(0);
  });

  test("rejects signed short-window sealed bids and malformed session nonces after signature verification", () => {
    const unsigned = fixtureUnsignedListing();
    const staleAuction = signUncheckedFixtureListing({
      ...unsigned,
      pipeline: [
        {
          kind: "negotiate-sealed-envelope",
          parameters: {
            commitDeadline: FIXTURE_NOW_MS + 59_999,
            revealWindow: 60,
            selectionRule: "lowest-price",
          },
        },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      pricing: { kind: "auction", selectionRule: "lowest-price" },
    });
    expect(verifyCanonicalListingJson(staleAuction.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "pipeline",
      signature: "valid",
    });

    const hash = "ab".repeat(32);
    const unsafeRule = `rule-ref:${hash}:file:///etc/passwd`;
    const unsafeAuction = signUncheckedFixtureListing({
      ...unsigned,
      pipeline: [
        {
          kind: "negotiate-sealed-envelope",
          parameters: {
            commitDeadline: FIXTURE_NOW_MS + 60_000,
            revealWindow: 60,
            selectionRule: unsafeRule,
          },
        },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      pricing: { kind: "auction", selectionRule: unsafeRule },
    });
    expect(verifyCanonicalListingJson(unsafeAuction.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "schema",
    });

    const seller = unsigned["seller"] as Record<string, unknown>;
    const identity = signUncheckedFixtureIdentityBundle({
      bundleVersion: "1",
      presentedBy: fixtureSigner().signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: "A".repeat(32),
      claims: [{ ref: fixtureSigner().signer }],
    }).bundle;
    const malformedNonce = signUncheckedFixtureListing({
      ...unsigned,
      seller: { ...seller, identity },
    });
    expect(verifyCanonicalListingJson(malformedNonce.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "identity",
      signature: "valid",
    });
  });

  test("rejects signed settlement phases ordered before agreement commitment", () => {
    const unordered = signUncheckedFixtureListing({
      ...fixtureUnsignedListing(),
      pipeline: [
        { kind: "pay-x402", parameters: { rail: "x402:base:USDC" } },
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      acceptedRails: [{ railId: "x402:base:USDC" }],
    });
    let railChecks = 0;
    expect(verifyCanonicalListingJson(unordered.canonicalJson, {
      ...options,
      paymentRailCheck: () => {
        railChecks += 1;
        return { status: "resolved", phaseHandler: "pay-x402" };
      },
    })).toMatchObject({ disposition: "rejected", stage: "pipeline", signature: "valid" });
    expect(railChecks).toBe(0);
  });

  test("accepts VerifyResultRef objects and CF-3-equivalent claim parameters", () => {
    const signer = fixtureSigner();
    const presentedBy = `${signer.signer}?scope=`;
    const identity = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{
        ref: presentedBy,
        verifiedBy: {
          anchor: { kind: "storage-program", locator: "stor-fixture" },
          contentHash: "ab".repeat(32),
          recipeVersion: 1,
        },
      }],
    }, signer).bundle;
    const unsigned = fixtureUnsignedListing();
    const seller = unsigned["seller"] as Record<string, unknown>;
    const listing = signListing({ ...unsigned, seller: { ...seller, identity } }, signer);
    expect(verifyCanonicalListingJson(listing.canonicalJson, options).disposition).toBe("accepted");
  });

  test("preserves unknown supporting claims but rejects malformed presentation refs", () => {
    const signer = fixtureSigner();
    const identity = signUncheckedFixtureIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: signer.signer }, { ref: "x-future:opaque-subject?a=2&z=1" }],
    }).bundle;
    const unsigned = fixtureUnsignedListing();
    const seller = unsigned["seller"] as Record<string, unknown>;
    const listing = signUncheckedFixtureListing({ ...unsigned, seller: { ...seller, identity } });
    const accepted = verifyCanonicalListingJson(listing.canonicalJson, options);
    expect(accepted).toMatchObject({
      disposition: "accepted",
      unknownClaims: ["x-future:opaque-subject?a=2&z=1"],
    });
    if (accepted.disposition === "accepted" && accepted.unknownClaims !== undefined) {
      expect(Object.isFrozen(accepted.unknownClaims)).toBe(true);
    }

    const noncanonicalUnknown = signUncheckedFixtureIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: signer.signer }, { ref: "x-future:opaque-subject?z=1&a=2" }],
    }).bundle;
    const noncanonicalListing = signUncheckedFixtureListing({
      ...unsigned,
      seller: { ...seller, identity: noncanonicalUnknown },
    });
    expect(verifyCanonicalListingJson(noncanonicalListing.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "identity",
      signature: "valid",
    });

    const duplicateUnknownIdentity = signUncheckedFixtureIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [
        { ref: signer.signer },
        { ref: "x-future:opaque-subject?a=1" },
        { ref: "x-future:opaque-subject?a=2" },
      ],
    }).bundle;
    const duplicateUnknownListing = signUncheckedFixtureListing({
      ...unsigned,
      seller: { ...seller, identity: duplicateUnknownIdentity },
    });
    expect(verifyCanonicalListingJson(duplicateUnknownListing.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "identity",
      signature: "valid",
    });

    const unknownPrimaryIdentity = signUncheckedFixtureIdentityBundle({
      bundleVersion: "1",
      presentedBy: "x-future:opaque-subject",
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: "x-future:opaque-subject" }, { ref: signer.signer }],
    }).bundle;
    const unknownPrimaryListing = signUncheckedFixtureListing({
      ...unsigned,
      seller: { ...seller, identity: unknownPrimaryIdentity },
    });
    expect(() => verifyCanonicalListingJson(unknownPrimaryListing.canonicalJson, options)).not.toThrow();
    expect(verifyCanonicalListingJson(unknownPrimaryListing.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "identity",
      signature: "valid",
    });

    const malformedIdentity = structuredClone(identity) as Record<string, unknown>;
    const presentation = malformedIdentity["presentation"] as Record<string, unknown>;
    const signatures = presentation["signatures"] as Record<string, unknown>[];
    signatures[0] = { ...signatures[0], ref: signer.signer.toUpperCase() };
    const malformedListing = signUncheckedFixtureListing({
      ...unsigned,
      seller: { ...seller, identity: malformedIdentity },
    });
    expect(() => verifyCanonicalListingJson(malformedListing.canonicalJson, options)).not.toThrow();
    expect(verifyCanonicalListingJson(malformedListing.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "identity",
      signature: "valid",
    });
  });

  test("enforces inclusive validity boundaries and the final signed size cap", () => {
    const signed = fixtureSignedListing();
    expect(verifyCanonicalListingJson(signed.canonicalJson, {
      ...options,
      nowMs: FIXTURE_NOW_MS + 86_400_000,
    }).disposition).toBe("accepted");
    expect(verifyCanonicalListingJson(signed.canonicalJson, {
      ...options,
      nowMs: FIXTURE_NOW_MS + 86_400_001,
    })).toMatchObject({ disposition: "rejected", stage: "validity" });

    const oversized = signUncheckedFixtureListing({
      ...fixtureUnsignedListing(),
      futureInertField: "x".repeat(17_000),
    });
    expect(verifyCanonicalListingJson(oversized.canonicalJson, options)).toMatchObject({
      disposition: "rejected",
      stage: "canonical-form",
    });
  });

  test("treats revocation callbacks as synchronous infrastructure boundaries", () => {
    const signed = fixtureSignedListing();
    let checkedSigner = "";
    expect(verifyCanonicalListingJson(signed.canonicalJson, {
      nowMs: FIXTURE_NOW_MS,
      revocationCheck: (listing) => {
        checkedSigner = listing.listingSigner;
        expect(Object.isFrozen(listing)).toBe(true);
        return "absent";
      },
    }).disposition).toBe("accepted");
    expect(checkedSigner).toBe(fixtureSigner().signer);
    expect(() => verifyCanonicalListingJson(signed.canonicalJson, {
      nowMs: FIXTURE_NOW_MS,
      revocationCheck: () => Promise.resolve("absent") as unknown as "absent",
    })).toThrow(/invalid disposition/);
    expect(() => verifyCanonicalListingJson(signed.canonicalJson, {
      nowMs: FIXTURE_NOW_MS,
      revocationCheck: () => { throw new Error("revocation backend down"); },
    })).toThrow("revocation backend down");
  });

  test("resolves every accepted pay rail and rejects ambiguity or resolver failure", () => {
    const payListing = signListing({
      ...fixtureUnsignedListing(),
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:base:USDC" } },
        { kind: "deliver-attested-payload" },
      ],
      acceptedRails: [{ railId: "x402:base:USDC", railVersion: 1 }],
    }, fixtureSigner());
    let calls = 0;
    expect(verifyCanonicalListingJson(payListing.canonicalJson, {
      ...options,
      paymentRailCheck: (rail) => {
        calls += 1;
        expect(Object.isFrozen(rail)).toBe(true);
        expect(rail).toEqual({
          railId: "x402:base:USDC",
          railVersion: 1,
          canonicalJson: '{"railId":"x402:base:USDC","railVersion":1}',
          referencedByPhaseKinds: ["pay-x402"],
        });
        return { status: "resolved", phaseHandler: "pay-x402" };
      },
    }).disposition).toBe("accepted");
    expect(calls).toBe(1);
    expect(verifyCanonicalListingJson(payListing.canonicalJson, {
      ...options,
      paymentRailCheck: () => ({ status: "indeterminate" }),
    })).toMatchObject({ disposition: "rejected", stage: "rails", signature: "valid" });
    expect(() => verifyCanonicalListingJson(payListing.canonicalJson, {
      ...options,
      paymentRailCheck: () => Promise.resolve({
        status: "resolved",
        phaseHandler: "pay-x402",
      }) as unknown as { status: "resolved"; phaseHandler: string },
    })).toThrow(/invalid disposition/);
  });

  test("rejects a correctly signed payment-only pipeline before rail resolution", () => {
    const paymentOnly = signUncheckedFixtureListing({
      ...fixtureUnsignedListing(),
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:base:USDC" } },
      ],
      acceptedRails: [{ railId: "x402:base:USDC" }],
    });
    let railChecks = 0;
    expect(verifyCanonicalListingJson(paymentOnly.canonicalJson, {
      ...options,
      paymentRailCheck: () => {
        railChecks += 1;
        return { status: "resolved", phaseHandler: "pay-x402" };
      },
    })).toMatchObject({ disposition: "rejected", stage: "pipeline", signature: "valid" });
    expect(railChecks).toBe(0);
  });

  test("rejects a resolved rail bound to a different phase handler", () => {
    const payListing = signListing({
      ...fixtureUnsignedListing(),
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "evm-erc20:1:USDC" } },
        { kind: "deliver-attested-payload" },
      ],
      acceptedRails: [{ railId: "evm-erc20:1:USDC" }],
    }, fixtureSigner());
    expect(verifyCanonicalListingJson(payListing.canonicalJson, {
      ...options,
      paymentRailCheck: () => ({ status: "resolved", phaseHandler: "pay-evm-erc20" }),
    })).toMatchObject({ disposition: "rejected", stage: "rails", signature: "valid" });
  });

  test("resolves advertised rails even when no pay phase selects them", () => {
    const listing = signListing({
      ...fixtureUnsignedListing(),
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:base:USDC" } },
        { kind: "deliver-attested-payload" },
      ],
      acceptedRails: [
        { railId: "x402:base:USDC" },
        { railId: "evm-erc20:1:USDC" },
      ],
    }, fixtureSigner());
    const checked: string[] = [];
    expect(verifyCanonicalListingJson(listing.canonicalJson, {
      ...options,
      paymentRailCheck: (rail) => {
        checked.push(rail.railId);
        if (rail.railId === "evm-erc20:1:USDC") {
          expect(rail.referencedByPhaseKinds).toEqual([]);
          return { status: "unresolved" };
        }
        return { status: "resolved", phaseHandler: "pay-x402" };
      },
    })).toMatchObject({ disposition: "rejected", stage: "rails", signature: "valid" });
    expect(checked).toEqual(["x402:base:USDC", "evm-erc20:1:USDC"]);
  });
});

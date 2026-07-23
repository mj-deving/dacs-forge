import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
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
} from "../fixtures/reference-listing.ts";

function signListing(
  input: Parameters<typeof signListingWithContext>[0],
  signer: ArtifactSigner,
  options: { readonly nowMs?: number } = {},
) {
  return signListingWithContext(input, signer, { ...FIXTURE_SIGNING_CONTEXT, ...options });
}

function signPerClaimIdentityBundle(
  input: Parameters<typeof signIdentityBundleWithContext>[0],
  signer: ArtifactSigner,
) {
  return signIdentityBundleWithContext(input, signer, FIXTURE_SIGNING_CONTEXT);
}

describe("DACS Listing producer", () => {
  test("produces byte-identical deterministic Ed25519 listings", () => {
    const first = fixtureSignedListing();
    const second = fixtureSignedListing();
    expect(first).toEqual(second);
    expect(first.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(first.canonicalJson).toBe(JSON.stringify(first.listing));
    expect((first.listing["signature"] as Record<string, unknown>)["signer"])
      .toBe(fixtureSigner().signer);
    expect(Object.isFrozen(first.listing)).toBe(true);
    expect(Object.isFrozen(first.listing["seller"])).toBe(true);
    expect(Object.isFrozen((first.listing["seller"] as Record<string, unknown>)["identity"])).toBe(true);
  });

  test("fixture signer is mode-bound, seed-bound, and non-exporting", () => {
    const seed = createHash("sha256").update("seed-a").digest();
    const signer = createFixtureEd25519Signer(seed, {
      deploymentMode: "fixture",
      authorityMode: "fixture",
    });
    expect(signer.signer).toMatch(/^key:[0-9a-f]{64}$/);
    expect(Object.keys(signer).sort()).toEqual(["algorithm", "sign", "signer"]);
    expect(() => createFixtureEd25519Signer(seed, {
      deploymentMode: "live",
      authorityMode: "fixture",
    })).toThrow(/fixture authority/i);
    expect(() => createFixtureEd25519Signer(seed, {
      deploymentMode: "fixture",
      authorityMode: "live",
    })).toThrow(/fixture authority/i);
    expect(() => createFixtureEd25519Signer(seed.subarray(0, 31), {
      deploymentMode: "fixture",
      authorityMode: "fixture",
    }))
      .toThrow(/32 bytes/);
  });

  test("rechecks fixture authority and non-forgeable signer capability at every signing call", () => {
    const signer = fixtureSigner();
    const listing = fixtureUnsignedListing();
    const rawSign = signer.sign;
    expect(() => rawSign(new Uint8Array([1]), {
      deploymentMode: "live",
      requestMode: "fixture",
    })).toThrow(/fixture authority/i);
    expect(() => signListingWithContext(listing, signer, {
      deploymentMode: "live",
      requestMode: "fixture",
    })).toThrow(/fixture authority/i);
    expect(() => signIdentityBundleWithContext({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: signer.signer }],
    }, signer, {
      deploymentMode: "fixture",
      requestMode: "live",
    })).toThrow(/fixture authority/i);

    const forgedSigner: ArtifactSigner = {
      algorithm: signer.algorithm,
      signer: signer.signer,
      sign: signer.sign,
    };
    expect(() => signListingWithContext(listing, forgedSigner, FIXTURE_SIGNING_CONTEXT))
      .toThrow(/not a fixture-authority capability/i);
  });

  test("refuses signer substitution and pre-signed producer input", () => {
    const listing = fixtureUnsignedListing();
    const other = createFixtureEd25519Signer(Buffer.alloc(32, 7), {
      deploymentMode: "fixture",
      authorityMode: "fixture",
    });
    expect(() => signListing(listing, other)).toThrow(/signer.*claims/i);
    expect(() => signListing({ ...listing, signature: {} }, fixtureSigner()))
      .toThrow(/must not contain signature/);
  });

  test("re-verifies the embedded publisher IdentityBundle before signing", () => {
    const listing = fixtureUnsignedListing();
    const seller = listing["seller"] as Record<string, unknown>;
    const identity = structuredClone(seller["identity"]) as Record<string, unknown>;
    const presentation = identity["presentation"] as Record<string, unknown>;
    const signatures = presentation["signatures"] as Record<string, unknown>[];
    signatures[0] = { ...signatures[0], signature: "A".repeat(88) };
    expect(() => signListing({ ...listing, seller: { ...seller, identity } }, fixtureSigner()))
      .toThrow(/IdentityBundle signature is invalid/);

    const duplicateIdentity = structuredClone(seller["identity"]) as Record<string, unknown>;
    const duplicatePresentation = duplicateIdentity["presentation"] as Record<string, unknown>;
    const duplicateSignatures = duplicatePresentation["signatures"] as Record<string, unknown>[];
    duplicateSignatures.push({
      ...duplicateSignatures[0],
      ref: `${fixtureSigner().signer}?scope=duplicate`,
    });
    expect(() => signListing({
      ...listing,
      seller: { ...seller, identity: duplicateIdentity },
    }, fixtureSigner())).toThrow(/IdentityBundle signature is invalid/);
  });

  test("enforces the 16 KiB final canonical Listing cap", () => {
    const listing = fixtureUnsignedListing();
    const offering = listing["offering"] as Record<string, unknown>;
    expect(() => signListing({
      ...listing,
      offering: { ...offering, futureMetadata: "x".repeat(17_000) },
    }, fixtureSigner())).toThrow(/16384 bytes/);

    const emptyPadding = signListing({ ...listing, futurePadding: "" }, fixtureSigner());
    const exactPadding = 16_384 - new TextEncoder().encode(emptyPadding.canonicalJson).byteLength;
    const exact = signListing({ ...listing, futurePadding: "x".repeat(exactPadding) }, fixtureSigner());
    expect(new TextEncoder().encode(exact.canonicalJson).byteLength).toBe(16_384);
    expect(() => signListing({
      ...listing,
      futurePadding: "x".repeat(exactPadding + 1),
    }, fixtureSigner())).toThrow(/16384 bytes/);
  });

  test("signs only canonical identity bundles containing the signer", () => {
    const signer = fixtureSigner();
    const result = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: signer.signer }],
    }, signer);
    expect(result.bundleHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.canonicalJson).toBe(JSON.stringify(result.bundle));
    expect(Object.isFrozen(result.bundle["claims"])).toBe(true);
    expect(() => signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer.toUpperCase(),
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: signer.signer }],
    }, signer)).toThrow(/canonical/);
  });

  test("refuses non-conformant pipeline, pricing, and rail combinations", () => {
    const listing = fixtureUnsignedListing();
    expect(() => signListing({
      ...listing,
      pipeline: [{ kind: "negotiate-fixed-price" }, { kind: "deliver-attested-payload" }],
    }, fixtureSigner())).toThrow(/commitment.*follow/i);
    expect(() => signListing({
      ...listing,
      pipeline: [{ kind: "negotiate-rfq", parameters: { maxTurns: 2, timeoutSec: 30 } },
        { kind: "commit-agreement" }, { kind: "deliver-attested-payload" }],
    }, fixtureSigner())).toThrow(/incompatible.*fixed pricing/i);
    expect(() => signListing({
      ...listing,
      pipeline: [{ kind: "negotiate-fixed-price" }, { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:1" } },
        { kind: "deliver-attested-payload" }],
    }, fixtureSigner())).toThrow(/require acceptedRails/i);
    expect(() => signListing({
      ...listing,
      pricing: { kind: "fixed", price: { amount: "1.0", currency: "USDC" } },
    }, fixtureSigner())).toThrow(/fixed pricing is invalid/i);
    expect(() => signListing({
      ...listing,
      pipeline: [{ kind: "negotiate-fixed-price" }, { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:1" } }],
      acceptedRails: [{ railId: "x402:1" }],
    }, fixtureSigner())).toThrow(/delivery phase/i);
    expect(() => signListing({
      ...listing,
      pipeline: [
        { kind: "pay-x402", parameters: { rail: "x402:1" } },
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      acceptedRails: [{ railId: "x402:1" }],
    }, fixtureSigner())).toThrow(/phase stages must follow/i);
    expect(() => signListing({
      ...listing,
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "rate" },
        { kind: "deliver-attested-payload" },
      ],
    }, fixtureSigner())).toThrow(/phase stages must follow/i);
    expect(() => signListing({
      ...listing,
      pipeline: [
        {
          kind: "negotiate-rfq",
          parameters: { maxTurns: 2, timeoutSec: 30, fixedPriceFallback: "yes" },
        },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "1", currency: "USDC" },
        minPct: 0,
        maxPct: 10,
      },
    }, fixtureSigner())).toThrow(/negotiate-rfq parameters are invalid/i);
  });

  test("validates VerificationMethod and rounded negotiable lower bounds", () => {
    const listing = fixtureUnsignedListing();
    const offering = listing["offering"] as Record<string, unknown>;
    const deliverable = offering["deliverable"] as Record<string, unknown>;
    expect(() => signListing({
      ...listing,
      offering: { ...offering, deliverable: { ...deliverable, verificationMethod: {} } },
    }, fixtureSigner())).toThrow(/verificationMethod is invalid/i);
    expect(signListing({
      ...listing,
      offering: {
        ...offering,
        deliverable: { ...deliverable, verificationMethod: { kind: "self-signed" } },
      },
    }, fixtureSigner()).contentHash).toMatch(/^[0-9a-f]{64}$/);

    expect(() => signListing({
      ...listing,
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "0.01", currency: "USDC" },
        minPct: 99,
        maxPct: 0,
      },
    }, fixtureSigner())).toThrow(/negotiable pricing is invalid/i);
    expect(signListing({
      ...listing,
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "0.01", currency: "USDC" },
        minPct: 50,
        maxPct: 0,
      },
    }, fixtureSigner()).contentHash).toMatch(/^[0-9a-f]{64}$/);

    const terms = listing["terms"] as Record<string, unknown>;
    for (const invalidTerms of [
      { ...terms, cancellationPolicy: ["pre-commit"] },
      { ...terms, transcriptDisclosurePolicy: ["encrypted-anchored-required"] },
    ]) {
      expect(() => signListing({ ...listing, terms: invalidTerms }, fixtureSigner()))
        .toThrow(/Policy|cancellation/i);
    }
    expect(() => signListing({
      ...listing,
      offering: {
        ...offering,
        deliverable: { kind: "storage-program", accessModel: ["encrypt-to-buyer"] },
      },
    }, fixtureSigner())).toThrow(/accessModel is invalid/i);
    expect(() => signListing({
      ...listing,
      offering: { ...offering, deliverable: { kind: "future-deliverable" } },
    }, fixtureSigner())).toThrow(/deliverable kind is unsupported/i);
    expect(() => signListing({
      ...listing,
      pricing: { kind: "future-pricing" },
    }, fixtureSigner())).toThrow(/pricing kind is unsupported/i);
    expect(() => signListing({
      ...listing,
      offering: {
        ...offering,
        deliverable: {
          ...deliverable,
          verificationMethod: { kind: "future-proof" },
        },
      },
    }, fixtureSigner())).toThrow(/verificationMethod kind is unsupported/i);

    const hash = "ab".repeat(32);
    expect(() => signListing({
      ...listing,
      pipeline: [
        {
          kind: "negotiate-sealed-envelope",
          parameters: {
            commitDeadline: FIXTURE_NOW_MS + 60_000,
            revealWindow: 60,
            selectionRule: `rule-ref:${hash}:not-a-uri`,
          },
        },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      pricing: { kind: "auction", selectionRule: `rule-ref:${hash}:not-a-uri` },
    }, fixtureSigner())).toThrow(/auction pricing is invalid/i);
  });

  test("binds sealed-envelope deadlines and conflict rules to validated clocks and URLs", () => {
    const listing = fixtureUnsignedListing();
    const sealedListing = {
      ...listing,
      pipeline: [
        {
          kind: "negotiate-sealed-envelope",
          parameters: {
            commitDeadline: FIXTURE_NOW_MS + 60_000,
            revealWindow: 60,
            selectionRule: "lowest-price",
          },
        },
        { kind: "commit-agreement" },
        { kind: "deliver-attested-payload" },
      ],
      pricing: { kind: "auction", selectionRule: "lowest-price" },
    };
    expect(signListing(sealedListing, fixtureSigner(), { nowMs: FIXTURE_NOW_MS }).contentHash)
      .toMatch(/^[0-9a-f]{64}$/);
    expect(() => signListing(sealedListing, fixtureSigner(), {
      nowMs: FIXTURE_NOW_MS + 1,
    })).toThrow(/commitDeadline must be at least 60 seconds in the future/i);
    expect(() => signListing({
      ...listing,
      terms: { conflictOfLawsRule: "rule-ref:not-a-url" },
    }, fixtureSigner())).toThrow(/conflictOfLawsRule is invalid/i);

    const hash = "ab".repeat(32);
    for (const unsafeRule of [
      `rule-ref:${hash}:file:///etc/passwd`,
      `rule-ref:${hash}:http://rules.example/auction`,
    ]) {
      const pipeline = structuredClone(sealedListing.pipeline) as Record<string, unknown>[];
      (pipeline[0]?.["parameters"] as Record<string, unknown>)["selectionRule"] = unsafeRule;
      expect(() => signListing({
        ...sealedListing,
        pipeline,
        pricing: { kind: "auction", selectionRule: unsafeRule },
      }, fixtureSigner(), { nowMs: FIXTURE_NOW_MS })).toThrow(/auction pricing is invalid/i);
    }
    const httpsRule = `rule-ref:${hash}:https://rules.example/auction`;
    const httpsPipeline = structuredClone(sealedListing.pipeline) as Record<string, unknown>[];
    (httpsPipeline[0]?.["parameters"] as Record<string, unknown>)["selectionRule"] = httpsRule;
    expect(signListing({
      ...sealedListing,
      pipeline: httpsPipeline,
      pricing: { kind: "auction", selectionRule: httpsRule },
    }, fixtureSigner(), { nowMs: FIXTURE_NOW_MS }).contentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("requires its single emitted signature to control presentedBy", () => {
    const signer = fixtureSigner();
    const other = createFixtureEd25519Signer(Buffer.alloc(32, 11), {
      deploymentMode: "fixture",
      authorityMode: "fixture",
    });
    expect(() => signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: other.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: other.signer }, { ref: signer.signer }],
    }, signer)).toThrow(/presentedBy and signer/i);
    expect(() => signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: signer.signer, issuedAt: "yesterday" }],
    }, signer)).toThrow(/claim metadata is invalid/i);
    expect(() => signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: "",
      claims: [{ ref: signer.signer }],
    }, signer)).toThrow(/sessionNonce.*32 lowercase hex/i);
    expect(() => signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: "A".repeat(32),
      claims: [{ ref: signer.signer }],
    }, signer)).toThrow(/sessionNonce.*32 lowercase hex/i);
    expect(signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: "ab".repeat(16),
      claims: [{ ref: signer.signer }],
    }, signer).bundle["sessionNonce"]).toBe("ab".repeat(16));
  });

  test("allows an empty acceptedRails array only for a zero-pay pipeline", () => {
    expect(signListing({ ...fixtureUnsignedListing(), acceptedRails: [] }, fixtureSigner()).contentHash)
      .toMatch(/^[0-9a-f]{64}$/);
  });
});

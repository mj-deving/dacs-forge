import { createHash } from "node:crypto";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { signListing, type UnsignedListing } from "../../src/producer/listing.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";

export const FIXTURE_NOW_MS = 1_784_073_600_000;
export const FIXTURE_SIGNING_CONTEXT = Object.freeze({
  deploymentMode: "fixture" as const,
  requestMode: "fixture" as const,
});

export function fixtureSigner() {
  const seed = createHash("sha256").update("reference-dacs-template-listing-v1").digest();
  return createFixtureEd25519Signer(seed, {
    deploymentMode: "fixture",
    authorityMode: "fixture",
  });
}

export function fixtureUnsignedListing(): UnsignedListing {
  const signer = fixtureSigner();
  const identity = signPerClaimIdentityBundle({
    bundleVersion: "1",
    presentedBy: signer.signer,
    presentedAt: FIXTURE_NOW_MS,
    claims: [{ ref: signer.signer }],
  }, signer, FIXTURE_SIGNING_CONTEXT).bundle;
  return {
    dacsVersion: "1",
    listingVersion: 1,
    listingId: "reference-json-transform",
    requiredCapabilities: ["SR-2"],
    seller: {
      identity,
      displayName: "Reference JSON Transform",
      publicEndpoint: "https://service.example/v1",
    },
    offering: {
      title: "Deterministic JSON transform",
      description: "Produces one fixture-attested JSON work product.",
      category: "developer.data.transform",
      tags: ["fixture", "json"],
      deliverable: {
        kind: "attested-payload",
        payloadFormat: "application/json",
        verificationMethod: { kind: "self-signed" },
      },
    },
    buyerRequirement: {
      requirementVersion: "1",
      required: [{ scheme: "key", verificationRequired: false }],
    },
    pipeline: [
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      { kind: "deliver-attested-payload" },
    ],
    pricing: {
      kind: "fixed",
      price: { amount: "1", currency: "USDC", unit: "job" },
    },
    terms: { cancellationPolicy: "pre-commit" },
    validity: { notBefore: FIXTURE_NOW_MS, notAfter: FIXTURE_NOW_MS + 86_400_000 },
  };
}

export function fixtureSignedListing() {
  const signer = fixtureSigner();
  return signListing(fixtureUnsignedListing(), signer, FIXTURE_SIGNING_CONTEXT);
}

export function signUncheckedFixtureListing(
  input: Record<string, unknown>,
  options: { readonly domain?: string; readonly algorithm?: string } = {},
) {
  const signer = fixtureSigner();
  const signedScopeCanonicalJson = canonicalize(input);
  const contentHash = sha256Hex(signedScopeCanonicalJson);
  const value = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(
      new TextEncoder().encode(`${options.domain ?? "dacs-listing:v1:"}${contentHash}`),
      FIXTURE_SIGNING_CONTEXT,
    ),
    "standard-base64-padded",
    64,
  ));
  const listing = {
    ...JSON.parse(signedScopeCanonicalJson) as Record<string, unknown>,
    signature: { algorithm: options.algorithm ?? "ed25519", signer: signer.signer, value },
  };
  return { listing, canonicalJson: canonicalize(listing), contentHash };
}

export function signUncheckedFixtureIdentityBundle(input: Record<string, unknown>) {
  const signer = fixtureSigner();
  const signedScopeCanonicalJson = canonicalize(input);
  const bundleHash = sha256Hex(signedScopeCanonicalJson);
  const signature = signer.sign(
    new TextEncoder().encode(`dacs-bundle-presentation:v1:${bundleHash}`),
    FIXTURE_SIGNING_CONTEXT,
  );
  const bundle = {
    ...JSON.parse(signedScopeCanonicalJson) as Record<string, unknown>,
    presentation: {
      kind: "per-claim",
      signatures: [{ ref: signer.signer, signature }],
    },
  };
  return { bundle, canonicalJson: canonicalize(bundle), bundleHash };
}

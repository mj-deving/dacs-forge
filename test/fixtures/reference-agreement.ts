import { createHash } from "node:crypto";
import { verifyCanonicalListingJson } from "../../src/consumer/listing-verifier.ts";
import type {
  AgreementVerificationOptions,
  VerifiedSealedEnvelopeResult,
  VettedAgreementPartyBinding,
} from "../../src/consumer/agreement-verifier.ts";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  signAgreementArtifact,
  AGREEMENT_DOMAIN,
  PAYEE_BOUND_AGREEMENT_DOMAIN,
  type AgreementPartySigner,
  type AgreementSigningOptions,
  type UnsignedAgreementArtifact,
} from "../../src/producer/agreement.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { signListing, type UnsignedListing } from "../../src/producer/listing.ts";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import {
  FIXTURE_NOW_MS,
  FIXTURE_SIGNING_CONTEXT,
  fixtureSigner,
  fixtureUnsignedListing,
} from "./reference-listing.ts";

export const FIXTURE_COMMITTED_AT = FIXTURE_NOW_MS + 10_000;
export const FIXTURE_RAIL_ID = "x402:default";
export const FIXTURE_JOB_ID = "01J00000000000000000000000";

export function buyerFixtureSigner() {
  const seed = createHash("sha256").update("reference-dacs-template-buyer-v1").digest();
  return createFixtureEd25519Signer(seed, {
    deploymentMode: "fixture",
    authorityMode: "fixture",
  });
}

export function attackerFixtureSigner() {
  const seed = createHash("sha256").update("reference-dacs-template-attacker-v1").digest();
  return createFixtureEd25519Signer(seed, {
    deploymentMode: "fixture",
    authorityMode: "fixture",
  });
}

export function fixtureUnsignedPaidListing(
  overrides: Partial<UnsignedListing> = {},
): UnsignedListing {
  const base = fixtureUnsignedListing();
  return {
    ...base,
    listingId: "reference-json-transform-paid",
    pipeline: [
      { kind: "negotiate-fixed-price" },
      { kind: "commit-payee-bound-agreement" },
      { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
      { kind: "deliver-attested-payload" },
    ],
    acceptedRails: [{ railId: FIXTURE_RAIL_ID, railVersion: 1 }],
    terms: { cancellationPolicy: "pre-commit", deadlineSecAfterCommit: 300 },
    ...overrides,
  };
}

export function fixtureSignedPaidListing(overrides: Partial<UnsignedListing> = {}) {
  return signListing(
    fixtureUnsignedPaidListing(overrides),
    fixtureSigner(),
    { ...FIXTURE_SIGNING_CONTEXT, nowMs: FIXTURE_NOW_MS },
  );
}

export function acceptedPaidListing(
  canonicalJson: string,
  railIds: readonly string[] = [FIXTURE_RAIL_ID],
) {
  const listing = JSON.parse(canonicalJson) as Record<string, unknown>;
  const pipeline = listing["pipeline"] as Record<string, unknown>[];
  const paymentPhase = pipeline.find((phase) =>
    typeof phase["kind"] === "string" && phase["kind"].startsWith("pay-"));
  const result = verifyCanonicalListingJson(canonicalJson, {
    nowMs: FIXTURE_NOW_MS,
    revocationCheck: () => "absent",
    paymentRailCheck: ({ railId }) => {
      return railIds.includes(railId) && typeof paymentPhase?.["kind"] === "string"
        ? { status: "resolved", phaseHandler: paymentPhase["kind"] }
        : { status: "unresolved" };
    },
  });
  if (result.disposition !== "accepted") {
    throw new Error(`Fixture Listing failed verification: ${result.stage}: ${result.reason}`);
  }
  return result;
}

export function fixtureUnsignedPayeeBoundAgreement(
  listing = fixtureSignedPaidListing(),
): UnsignedAgreementArtifact {
  const listingObject = listing.listing as Record<string, unknown>;
  const deliverable = ((listingObject["offering"] as Record<string, unknown>)["deliverable"] as Record<string, unknown>);
  const pricing = listingObject["pricing"] as Record<string, unknown>;
  const pipeline = listingObject["pipeline"] as Record<string, unknown>[];
  const selectedPaymentPhaseIndex = pipeline.findIndex((phase) =>
    typeof phase["kind"] === "string" && phase["kind"].startsWith("pay-"));
  const paymentPhaseIndex = selectedPaymentPhaseIndex < 0 ? 2 : selectedPaymentPhaseIndex;
  const paymentPhase = selectedPaymentPhaseIndex < 0
    ? { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } }
    : pipeline[selectedPaymentPhaseIndex]!;
  const paymentParameters = paymentPhase["parameters"] as Record<string, unknown>;
  const railId = paymentParameters["rail"] as string;
  const listedPrice = pricing["kind"] === "fixed"
    ? pricing["price"] as Record<string, unknown>
    : pricing["kind"] === "metered"
      ? pricing["unitPrice"] as Record<string, unknown>
      : pricing["bandCenter"] as Record<string, unknown>;
  return {
    payeeBoundAgreementVersion: "1",
    jobId: FIXTURE_JOB_ID,
    listingRef: {
      listingId: listingObject["listingId"] as string,
      version: listingObject["listingVersion"] as number,
      contentHash: listing.contentHash,
    },
    parties: [
      fixtureParty("buyer", fixtureBuyerIdentity()),
      fixtureParty("seller", fixtureListingSellerIdentity(listing)),
    ],
    terms: {
      deliverable: {
        deliverableType: deliverable["kind"],
        hash: sha256Hex(canonicalize(deliverable)),
        ...(deliverable["schemaUrl"] === undefined ? {} : { schemaUrl: deliverable["schemaUrl"] }),
      },
      price: { ...listedPrice },
      rail: { railId, railVersion: 1 },
      deadline: FIXTURE_COMMITTED_AT + 120_000,
      payoutBindings: [{
        railId,
        phaseIndex: paymentPhaseIndex,
        payeeAddress: paymentPhase["kind"] === "pay-dem"
          ? `0x${"2".repeat(64)}` : "fixture:x402:payee",
      }],
    },
    derivedFromPattern: "fixed-price",
    generatedAt: FIXTURE_COMMITTED_AT - 1_000,
  };
}

export function fixtureAgreementSigners(): readonly AgreementPartySigner[] {
  const buyer = buyerFixtureSigner();
  const seller = fixtureSigner();
  return Object.freeze([
    { party: buyer.signer, signer: buyer },
    { party: seller.signer, signer: seller },
  ]);
}

export function signFixtureAgreement(input: UnsignedAgreementArtifact) {
  return signAgreementArtifact(input, fixtureAgreementSigners(), fixtureAgreementSigningOptions(input));
}

export function signFixtureAgreementForListing(
  input: UnsignedAgreementArtifact,
  listing: ReturnType<typeof fixtureSignedPaidListing>,
) {
  return signAgreementArtifact(input, fixtureAgreementSigners(), fixtureAgreementSigningOptions(input, listing));
}

export function fixtureAgreementSigningOptions(
  input: UnsignedAgreementArtifact = fixtureUnsignedPayeeBoundAgreement(),
  listing = fixtureSignedPaidListing(),
): AgreementSigningOptions {
  const sealedEnvelopeResult = fixtureSealedEnvelopeResult(input, listing);
  return {
    ...FIXTURE_SIGNING_CONTEXT,
    temporalContext: { mode: "pre-anchor", nowMs: FIXTURE_COMMITTED_AT - 1_000 },
    expectedCommitPhase: "commit-payee-bound-agreement",
    expectedJobId: input.jobId,
    listingCanonicalJson: listing.canonicalJson,
    listingVerification: acceptedPaidListing(
      listing.canonicalJson,
      [((input.terms as Record<string, unknown>)["rail"] as Record<string, unknown>)["railId"] as string],
    ),
    vettedPartyCheck: fixtureVettedPartyCheck(input),
    ...(sealedEnvelopeResult === undefined ? {} : { sealedEnvelopeResult }),
  };
}

export function fixtureAgreementVerificationOptions(
  input: UnsignedAgreementArtifact = fixtureUnsignedPayeeBoundAgreement(),
  listing = fixtureSignedPaidListing(),
  railIds: readonly string[] = [FIXTURE_RAIL_ID],
): AgreementVerificationOptions {
  const sealedEnvelopeResult = fixtureSealedEnvelopeResult(input, listing);
  return {
    temporalContext: {
      mode: "post-anchor",
      committedAt: FIXTURE_COMMITTED_AT,
      agreementHash: fixtureUnsignedAgreementHash(input),
    },
    expectedCommitPhase: "commit-payee-bound-agreement",
    expectedJobId: input.jobId,
    listingCanonicalJson: listing.canonicalJson,
    listingVerification: acceptedPaidListing(listing.canonicalJson, railIds),
    vettedPartyCheck: fixtureVettedPartyCheck(input),
    ...(sealedEnvelopeResult === undefined ? {} : { sealedEnvelopeResult }),
  };
}

export function fixtureUnsignedAgreementHash(input: UnsignedAgreementArtifact): string {
  return sha256Hex(canonicalize(withoutFields(input, "signatures")));
}

export function fixtureSealedEnvelopeResult(
  input: UnsignedAgreementArtifact,
  listing = fixtureSignedPaidListing(),
): VerifiedSealedEnvelopeResult | undefined {
  if (input.derivedFromPattern !== "sealed-envelope") return undefined;
  const phase = (listing.listing["pipeline"] as Record<string, unknown>[]).find((step) =>
    step["kind"] === "negotiate-sealed-envelope" || step["kind"] === "negotiate-sealed-envelope-procurement");
  if (phase === undefined) return undefined;
  const phaseKind = phase["kind"] as VerifiedSealedEnvelopeResult["phaseKind"];
  const winningRole = phaseKind === "negotiate-sealed-envelope-procurement" ? "seller" : "buyer";
  const winningParty = input.parties.find((party) => party.role === winningRole);
  if (winningParty === undefined) return undefined;
  return {
    phaseKind,
    agreementHash: fixtureUnsignedAgreementHash(input),
    winningBidderClaim: winningParty.primaryClaim,
  };
}

export function fixtureVettedPartyCheck(input: UnsignedAgreementArtifact = fixtureUnsignedPayeeBoundAgreement()) {
  const expected = new Set(input.parties.map((party) => canonicalize({
    role: party.role,
    primaryClaim: party.primaryClaim,
    bundleHash: party.bundleHash,
    vetRecordRefCanonicalJson: canonicalize(party.vetRecordRef),
  })));
  return (binding: VettedAgreementPartyBinding) => expected.has(canonicalize(binding))
    ? "verified" as const : "rejected" as const;
}

export function signUncheckedFixtureAgreement(
  input: UnsignedAgreementArtifact,
  partySigners: readonly AgreementPartySigner[] = fixtureAgreementSigners(),
) {
  const normalized = JSON.parse(canonicalize(input)) as Record<string, unknown>;
  const scope = canonicalize(withoutFields(normalized, "signatures"));
  const agreementHash = sha256Hex(scope);
  const domain = input.payeeBoundAgreementVersion === "1"
    ? PAYEE_BOUND_AGREEMENT_DOMAIN : AGREEMENT_DOMAIN;
  const payload = new TextEncoder().encode(`${domain}${agreementHash}`);
  const signatures = [...partySigners]
    .sort((left, right) => left.party < right.party ? -1 : left.party > right.party ? 1 : 0)
    .map(({ party, signer }) => ({
      party,
      algorithm: signer.algorithm,
      value: encodeComponentSignatureValue(importLegacyComponentSignatureValue(
        signer.sign(payload, FIXTURE_SIGNING_CONTEXT),
        "standard-base64-padded",
        64,
      )),
    }));
  const agreement = { ...normalized, signatures };
  return { agreement, agreementHash, canonicalJson: canonicalize(agreement), signedScopeCanonicalJson: scope };
}

export function fixtureBuyerIdentity() {
  const signer = buyerFixtureSigner();
  return signPerClaimIdentityBundle({
    bundleVersion: "1",
    presentedBy: signer.signer,
    presentedAt: FIXTURE_NOW_MS,
    claims: [{ ref: signer.signer }],
  }, signer, FIXTURE_SIGNING_CONTEXT);
}

export function fixtureListingSellerIdentity(listing = fixtureSignedPaidListing()) {
  const identity = (listing.listing["seller"] as Record<string, unknown>)["identity"] as Record<string, unknown>;
  const canonicalJson = canonicalize(identity);
  return Object.freeze({
    bundle: identity,
    bundleHash: sha256Hex(canonicalize(withoutFields(identity, "presentation"))),
    canonicalJson,
  });
}

function fixtureParty(
  role: "buyer" | "seller",
  identity: Readonly<{ bundleHash: string; bundle: Readonly<Record<string, unknown>> }>,
) {
  return {
    role,
    bundleHash: identity.bundleHash,
    primaryClaim: identity.bundle["presentedBy"] as string,
    vetRecordRef: {
      anchor: { kind: "https", locator: `https://fixture.example/vet/${role}` },
      contentHash: sha256Hex(`${role}-vet-record`),
    },
  };
}

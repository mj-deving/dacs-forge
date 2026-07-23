import { describe, expect, test } from "bun:test";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { signAgreementArtifact } from "../../src/producer/agreement.ts";
import { signListing } from "../../src/producer/listing.ts";
import {
  acceptedPaidListing,
  buyerFixtureSigner,
  FIXTURE_COMMITTED_AT,
  FIXTURE_JOB_ID,
  fixtureAgreementSigningOptions,
  fixtureAgreementSigners,
  fixtureSignedPaidListing,
  fixtureUnsignedPayeeBoundAgreement,
  fixtureVettedPartyCheck,
  signFixtureAgreement,
} from "../fixtures/reference-agreement.ts";
import {
  FIXTURE_SIGNING_CONTEXT,
  fixtureSigner,
  fixtureUnsignedListing,
} from "../fixtures/reference-listing.ts";

describe("AgreementArtifact producer", () => {
  test("emits deterministic dual-signed payee-bound agreement", () => {
    const input = fixtureUnsignedPayeeBoundAgreement();
    const first = signFixtureAgreement(input);
    const second = signFixtureAgreement(input);
    expect(first).toEqual(second);
    expect(first.canonicalJson).toBe(canonicalize(first.agreement));
    const signatures = first.agreement["signatures"] as Record<string, unknown>[];
    expect(signatures).toHaveLength(2);
    expect(signatures.every((signature) => /^[A-Za-z0-9_-]{86}$/.test(signature["value"] as string))).toBeTrue();
  });

  test("refuses discriminator ambiguity and legacy payout smuggling", () => {
    const base = fixtureUnsignedPayeeBoundAgreement();
    expect(() => signFixtureAgreement({ ...base, agreementVersion: "1" })).toThrow("exactly one");
    const { payeeBoundAgreementVersion: _, ...legacy } = base;
    expect(() => signFixtureAgreement({ ...legacy, agreementVersion: "1" })).toThrow("forbids payoutBindings");
  });

  test("requires exact signer-to-party binding", () => {
    const input = fixtureUnsignedPayeeBoundAgreement();
    const buyer = buyerFixtureSigner();
    expect(() => signAgreementArtifact(input, [
      { party: buyer.signer, signer: buyer },
      { party: buyer.signer, signer: buyer },
    ], fixtureAgreementSigningOptions())).toThrow("uniquely match");
    expect(() => signAgreementArtifact(input, fixtureAgreementSigners().slice(0, 1), fixtureAgreementSigningOptions())).toThrow("exactly");
  });

  test("refuses buyer and seller aliases of one CF-3 identity", () => {
    const input = structuredClone(fixtureUnsignedPayeeBoundAgreement());
    const buyer = buyerFixtureSigner();
    const parties = input.parties as unknown as Record<string, unknown>[];
    parties.find((party) => party["role"] === "buyer")!["primaryClaim"] = `${buyer.signer}?role=buyer`;
    parties.find((party) => party["role"] === "seller")!["primaryClaim"] = `${buyer.signer}?role=seller`;
    expect(() => signAgreementArtifact(input, fixtureAgreementSigners(), fixtureAgreementSigningOptions(input)))
      .toThrow("distinct canonical identities");
  });

  test("refuses byte-identical buyer and seller claims with a stable diagnostic", () => {
    const input = structuredClone(fixtureUnsignedPayeeBoundAgreement());
    const parties = input.parties as unknown as Record<string, unknown>[];
    const buyerClaim = parties.find((party) => party["role"] === "buyer")!["primaryClaim"];
    parties.find((party) => party["role"] === "seller")!["primaryClaim"] = buyerClaim;
    expect(() => signAgreementArtifact(input, fixtureAgreementSigners(), fixtureAgreementSigningOptions(input)))
      .toThrow("distinct canonical identities");
  });

  test("allows a signature ClaimReference alias of the required party identity", () => {
    const input = structuredClone(fixtureUnsignedPayeeBoundAgreement());
    const buyer = buyerFixtureSigner();
    const parties = input.parties as unknown as Record<string, unknown>[];
    parties.find((party) => party["role"] === "buyer")!["primaryClaim"] = `${buyer.signer}?context=session`;
    const sellerEntry = fixtureAgreementSigners().find((entry) => entry.party !== buyer.signer)!;
    const signed = signAgreementArtifact(input, [
      { party: buyer.signer, signer: buyer },
      sellerEntry,
    ], fixtureAgreementSigningOptions(input));
    expect(signed.agreementHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("does not apply the Listing-only 16 KiB cap to AgreementArtifact", () => {
    const base = fixtureUnsignedPayeeBoundAgreement();
    const signed = signFixtureAgreement({ ...base, padding: "x".repeat(17_000) });
    expect(Buffer.byteLength(signed.canonicalJson, "utf8")).toBeGreaterThan(16_384);
  });

  test("refuses to sign an agreement the independent consumer rejects", () => {
    const input = structuredClone(fixtureUnsignedPayeeBoundAgreement());
    ((input.terms["price"] as Record<string, unknown>))["amount"] = "2";
    expect(() => signFixtureAgreement(input)).toThrow("independent conformance: pricing");
  });

  test("runs the normative provisional time checks before an anchor exists", () => {
    const input = structuredClone(fixtureUnsignedPayeeBoundAgreement());
    (input.terms as Record<string, unknown>)["deadline"] = FIXTURE_COMMITTED_AT + 300_000;
    expect(() => signFixtureAgreement(input)).toThrow("provisional commitment allowance");
  });

  test("supports the distinct zero-pay legacy AgreementDocument contract", () => {
    const listing = signListing({
      ...fixtureUnsignedListing(),
      terms: { cancellationPolicy: "pre-commit", deadlineSecAfterCommit: 300 },
    }, fixtureSigner(), FIXTURE_SIGNING_CONTEXT);
    const base = structuredClone(fixtureUnsignedPayeeBoundAgreement(listing));
    const { payeeBoundAgreementVersion: _, ...withoutVersion } = base;
    const terms = structuredClone(withoutVersion.terms) as Record<string, unknown>;
    delete terms["rail"];
    delete terms["payoutBindings"];
    const input = { ...withoutVersion, agreementVersion: "1" as const, terms };
    const signed = signAgreementArtifact(input, fixtureAgreementSigners(), {
      ...FIXTURE_SIGNING_CONTEXT,
      temporalContext: { mode: "pre-anchor", nowMs: FIXTURE_COMMITTED_AT - 1_000 },
      expectedCommitPhase: "commit-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    });
    expect(signed.agreement["agreementVersion"]).toBe("1");
    expect(signed.agreement["payeeBoundAgreementVersion"]).toBeUndefined();
  });

  test("preserves valid paid legacy AgreementDocument compatibility", () => {
    const listing = fixtureSignedPaidListing({
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-agreement" },
        { kind: "pay-x402", parameters: { rail: "x402:default" } },
        { kind: "deliver-attested-payload" },
      ],
    });
    const base = structuredClone(fixtureUnsignedPayeeBoundAgreement(listing));
    const { payeeBoundAgreementVersion: _, ...withoutVersion } = base;
    const terms = structuredClone(withoutVersion.terms) as Record<string, unknown>;
    delete terms["payoutBindings"];
    const signed = signAgreementArtifact(
      { ...withoutVersion, agreementVersion: "1", terms },
      fixtureAgreementSigners(),
      {
        ...FIXTURE_SIGNING_CONTEXT,
        temporalContext: { mode: "pre-anchor", nowMs: FIXTURE_COMMITTED_AT - 1_000 },
        expectedCommitPhase: "commit-agreement",
        expectedJobId: FIXTURE_JOB_ID,
        listingCanonicalJson: listing.canonicalJson,
        listingVerification: acceptedPaidListing(listing.canonicalJson),
        vettedPartyCheck: fixtureVettedPartyCheck({ ...withoutVersion, agreementVersion: "1", terms }),
      },
    );
    expect(signed.agreement["agreementVersion"]).toBe("1");
  });
});

import { describe, expect, test } from "bun:test";
import { verifyCanonicalAgreementJson } from "../../src/consumer/agreement-verifier.ts";
import { verifyCanonicalListingJson } from "../../src/consumer/listing-verifier.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import { signListing } from "../../src/producer/listing.ts";
import type { UnsignedAgreementArtifact } from "../../src/producer/agreement.ts";
import {
  FIXTURE_COMMITTED_AT,
  FIXTURE_JOB_ID,
  FIXTURE_RAIL_ID,
  acceptedPaidListing,
  attackerFixtureSigner,
  buyerFixtureSigner,
  fixtureAgreementSigners,
  fixtureAgreementSigningOptions,
  fixtureAgreementVerificationOptions,
  fixtureSignedPaidListing,
  fixtureUnsignedPaidListing,
  fixtureUnsignedPayeeBoundAgreement,
  fixtureVettedPartyCheck,
  signFixtureAgreement,
  signFixtureAgreementForListing,
  signUncheckedFixtureAgreement,
} from "../fixtures/reference-agreement.ts";
import {
  FIXTURE_NOW_MS,
  FIXTURE_SIGNING_CONTEXT,
  fixtureSigner,
} from "../fixtures/reference-listing.ts";

describe("independent AgreementArtifact consumer", () => {
  test("verifies the paid fixture and rejects legacy wire encoding on the conforming path", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    const result = verify(signed.canonicalJson, listing);
    expect(result.disposition).toBe("verified");
    if (result.disposition !== "verified") {
      throw new Error("reason" in result ? result.reason : "Unexpected provisional verdict");
    }
    expect(result.agreementHash).toBe(signed.agreementHash);

    const padded = clone(signed.agreement);
    for (const signature of padded["signatures"] as Record<string, unknown>[]) {
      signature["value"] = Buffer.from(signature["value"] as string, "base64url").toString("base64");
    }
    expect(verify(canonicalize(padded), listing))
      .toMatchObject({ disposition: "rejected", stage: "signature" });
  });

  test("separates provisional pre-anchor verification from final post-anchor verification", () => {
    const listing = fixtureSignedPaidListing();
    const input = fixtureUnsignedPayeeBoundAgreement(listing);
    const signed = signFixtureAgreement(input);
    expect(verifyCanonicalAgreementJson(
      signed.canonicalJson,
      fixtureAgreementSigningOptions(input, listing),
    ).disposition).toBe("provisionally-verified");
    expect(verifyCanonicalAgreementJson(
      signed.canonicalJson,
      fixtureAgreementVerificationOptions(input, listing),
    ).disposition).toBe("verified");
  });

  test("binds final verification to the exact SR-2 committed agreement hash", () => {
    const listing = fixtureSignedPaidListing();
    const anchoredInput = fixtureUnsignedPayeeBoundAgreement(listing);
    const anchored = signFixtureAgreement(anchoredInput);
    const alternativeInput = {
      ...anchoredInput,
      terms: { ...anchoredInput.terms, additionalTerms: { revision: "unanchored" } },
    };
    const alternative = signFixtureAgreement(alternativeInput);
    const anchoredOptions = fixtureAgreementVerificationOptions(anchoredInput, listing);
    expect(verifyCanonicalAgreementJson(anchored.canonicalJson, anchoredOptions).disposition).toBe("verified");
    expect(verifyCanonicalAgreementJson(alternative.canonicalJson, anchoredOptions))
      .toMatchObject({ disposition: "rejected", stage: "commitment-binding" });
  });

  test("bounds untrusted agreement and signature bytes as implementation policy", () => {
    const listing = fixtureSignedPaidListing();
    const input = { ...fixtureUnsignedPayeeBoundAgreement(listing), padding: "x".repeat(1_100_000) };
    const signed = signUncheckedFixtureAgreement(input);
    const options = fixtureAgreementVerificationOptions(input, listing);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, options))
      .toMatchObject({ disposition: "refused-unsupported", stage: "canonical-form" });
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, { ...options, maxArtifactBytes: 2_000_000 }).disposition)
      .toBe("verified");

    const ordinary = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    const ordinaryOptions = fixtureAgreementVerificationOptions(fixtureUnsignedPayeeBoundAgreement(listing), listing);
    const oversizedSignature = clone(ordinary.agreement);
    (oversizedSignature["signatures"] as Record<string, unknown>[])[0]!["value"] = "A".repeat(16_385);
    expect(verifyCanonicalAgreementJson(canonicalize(oversizedSignature), ordinaryOptions))
      .toMatchObject({ disposition: "refused-unsupported", stage: "signature" });
    expect(verifyCanonicalAgreementJson(ordinary.canonicalJson, { ...ordinaryOptions, maxArtifactBytes: 0 }))
      .toMatchObject({ disposition: "refused-unsupported", stage: "canonical-form" });
    expect(verifyCanonicalAgreementJson(ordinary.canonicalJson, { ...ordinaryOptions, maxParties: 1 }))
      .toMatchObject({ disposition: "refused-unsupported", stage: "shape" });
    expect(verifyCanonicalAgreementJson(ordinary.canonicalJson, { ...ordinaryOptions, maxSignatures: 1 }))
      .toMatchObject({ disposition: "refused-unsupported", stage: "shape" });
    expect(verifyCanonicalAgreementJson(ordinary.canonicalJson, { ...ordinaryOptions, maxParties: 2 }).disposition)
      .toBe("verified");
  });

  test("rejects non-canonical JSON and signature encodings", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    expect(verify(` ${signed.canonicalJson}`, listing)).toMatchObject({ disposition: "rejected", stage: "canonical-form" });
    const malformed = clone(signed.agreement);
    (malformed["signatures"] as Record<string, unknown>[])[0]!["value"] += "=";
    expect(verify(canonicalize(malformed), listing)).toMatchObject({ disposition: "rejected", stage: "signature" });
    const tampered = clone(signed.agreement);
    const signature = (tampered["signatures"] as Record<string, unknown>[])[0]!;
    const value = signature["value"] as string;
    signature["value"] = `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
    expect(verify(canonicalize(tampered), listing)).toMatchObject({ disposition: "rejected", stage: "signature" });
  });

  test("retains unknown signed fields and detects their mutation", () => {
    const listing = fixtureSignedPaidListing();
    const input = { ...fixtureUnsignedPayeeBoundAgreement(listing), extension: { future: "retained" } };
    const signed = signFixtureAgreement(input);
    expect(verify(signed.canonicalJson, listing).disposition).toBe("verified");
    const tampered = clone(signed.agreement);
    (tampered["extension"] as Record<string, unknown>)["future"] = "mutated";
    expect(verify(canonicalize(tampered), listing)).toMatchObject({ disposition: "rejected", stage: "signature" });
  });

  test("preserves additive fields inside signed agreement objects", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    (input.listingRef as Record<string, unknown>)["extension"] = { retained: true };
    const terms = input.terms as Record<string, unknown>;
    (terms["price"] as Record<string, unknown>)["auditNote"] = "retained-but-not-interpreted";
    (terms["payoutBindings"] as Record<string, unknown>[])[0]!["extension"] = "retained";
    terms["feeSchedule"] = {
      priceBasis: "exclusive",
      items: [{
        kind: "subscription",
        collector: "substrate",
        fixed: { amount: "0.01", currency: "USDC" },
        recurrence: { period: { everySeconds: 60, extension: true } },
      }],
      oneOffTotal: { amount: "0.01", currency: "USDC" },
      recurringTotal: { amount: "0.01", currency: "USDC" },
    };
    const signed = signFixtureAgreement(input);
    expect(verify(signed.canonicalJson, listing).disposition).toBe("verified");

    const signatureExtension = clone(signed.agreement);
    (signatureExtension["signatures"] as Record<string, unknown>[])[0]!["extension"] = { retained: true };
    expect(verify(canonicalize(signatureExtension), listing).disposition).toBe("verified");
  });

  test("validates known optional agreement object fields", () => {
    const listing = fixtureSignedPaidListing();
    const base = fixtureUnsignedPayeeBoundAgreement(listing);
    const valid = {
      ...base,
      derivedFromChannel: { subnet: "fixture-private", lastMessageHash: "a".repeat(64), extension: true },
      terms: { ...base.terms, additionalTerms: { competitiveContext: { source: "fixture" } } },
    };
    expect(verify(signFixtureAgreement(valid).canonicalJson, listing).disposition).toBe("verified");
    for (const malformed of [
      { ...base, derivedFromChannel: 1 },
      { ...base, derivedFromChannel: { subnet: "fixture-private" } },
      { ...base, derivedFromChannel: { subnet: "", lastMessageHash: "a".repeat(64) } },
      { ...base, derivedFromChannel: { subnet: "fixture-private", lastMessageHash: "x" } },
      { ...base, terms: { ...base.terms, additionalTerms: "invalid" } },
      { ...base, terms: { ...base.terms, additionalTerms: [] } },
    ]) {
      const signed = signUncheckedFixtureAgreement(malformed as UnsignedAgreementArtifact);
      expect(verify(signed.canonicalJson, listing)).toMatchObject({ disposition: "rejected", stage: "shape" });
    }
  });

  test("enforces CA-5 before interpreting terms", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(),
    })).toMatchObject({ disposition: "rejected", stage: "artifact-type" });

    const legacyInput = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    delete (legacyInput as unknown as Record<string, unknown>)["payeeBoundAgreementVersion"];
    (legacyInput as unknown as Record<string, unknown>)["agreementVersion"] = "1";
    delete (legacyInput["terms"] as Record<string, unknown>)["payoutBindings"];
    const legacy = signUncheckedFixtureAgreement(legacyInput);
    expect(verifyCanonicalAgreementJson(legacy.canonicalJson, {
      temporalContext: postAnchor(legacy.agreementHash),
      expectedCommitPhase: "commit-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(),
    })).toMatchObject({ disposition: "rejected", stage: "artifact-type" });
  });

  test("binds agreement jobId to the commitment session", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: "01J00000000000000000000001",
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(),
    })).toMatchObject({ disposition: "rejected", stage: "job-binding" });
  });

  test("requires every party to resolve against the vetted session", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    const base = {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement" as const,
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
    } as const;
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...base,
      vettedPartyCheck: () => "rejected",
    })).toMatchObject({ disposition: "rejected", stage: "party-binding" });
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...base,
      vettedPartyCheck: () => "indeterminate",
    })).toMatchObject({ disposition: "indeterminate", stage: "party-binding" });

    const mixed = (binding: { readonly role: string }) => binding.role === "buyer"
      ? "indeterminate" as const : "rejected" as const;
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...base,
      vettedPartyCheck: mixed,
    })).toMatchObject({ disposition: "rejected", stage: "party-binding" });

    const originalInput = fixtureUnsignedPayeeBoundAgreement(listing);
    const reorderedInput = { ...originalInput, parties: [...originalInput.parties].reverse() };
    const reordered = signFixtureAgreement(reorderedInput);
    expect(verifyCanonicalAgreementJson(reordered.canonicalJson, {
      ...base,
      temporalContext: postAnchor(reordered.agreementHash),
      vettedPartyCheck: mixed,
    })).toMatchObject({ disposition: "rejected", stage: "party-binding" });

    const invalidInput = clone(originalInput);
    ((invalidInput["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["currency"] = "EUR";
    const invalid = signUncheckedFixtureAgreement(invalidInput);
    expect(verifyCanonicalAgreementJson(invalid.canonicalJson, {
      ...base,
      temporalContext: postAnchor(invalid.agreementHash),
      vettedPartyCheck: () => "indeterminate",
    })).toMatchObject({ disposition: "rejected", stage: "currency" });
  });

  test("authenticates signatures before invoking the vetted-party resolver", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    const tampered = clone(signed.agreement);
    const signature = (tampered["signatures"] as Record<string, unknown>[])[0]!;
    const value = signature["value"] as string;
    signature["value"] = `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
    let calls = 0;
    const result = verifyCanonicalAgreementJson(canonicalize(tampered), {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: () => {
        calls += 1;
        return "verified";
      },
    });
    expect(result).toMatchObject({ disposition: "rejected", stage: "signature" });
    expect(calls).toBe(0);
  });

  test("validates known priceAnchor fields without requiring audit resolution", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    (input["terms"] as Record<string, unknown>)["priceAnchor"] = {
      asset: "USDC",
      quoteCurrency: "USD",
      price: "1",
      attestationRef: {
        anchor: { kind: "https", locator: "https://fixture.example/price" },
        contentHash: "1".repeat(64),
      },
      observedAt: FIXTURE_COMMITTED_AT - 1_000,
      sourceUrl: "https://fixture.example/prices/{asset}",
    };
    expect(verify(signFixtureAgreement(input).canonicalJson, listing).disposition).toBe("verified");
    const zeroAnchor = clone(input);
    ((zeroAnchor["terms"] as Record<string, unknown>)["priceAnchor"] as Record<string, unknown>)["price"] = "0";
    expect(verify(signFixtureAgreement(zeroAnchor).canonicalJson, listing).disposition).toBe("verified");
    const malformed = clone(input);
    ((malformed["terms"] as Record<string, unknown>)["priceAnchor"] as Record<string, unknown>)["price"] = "1.0";
    expect(verify(signUncheckedFixtureAgreement(malformed).canonicalJson, listing))
      .toMatchObject({ disposition: "rejected", stage: "shape" });
  });

  test("validates fee disclosure structure without reconciling settlement fees", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const terms = input["terms"] as Record<string, unknown>;
    terms["feeSchedule"] = {
      priceBasis: "exclusive",
      items: [{ kind: "platform", collector: "substrate", rateBps: 25 }],
      oneOffTotal: { amount: "0.01", currency: "USDC" },
      disclosureNote: "Fixture disclosure only",
    };
    expect(verify(signFixtureAgreement(input).canonicalJson, listing).disposition).toBe("verified");
    const malformed = clone(input);
    const item = (((malformed["terms"] as Record<string, unknown>)["feeSchedule"] as Record<string, unknown>)["items"] as Record<string, unknown>[])[0]!;
    item["fixed"] = { amount: "0.01", currency: "USDC" };
    expect(verify(signUncheckedFixtureAgreement(malformed).canonicalJson, listing))
      .toMatchObject({ disposition: "rejected", stage: "shape" });
  });

  test("classifies current but unimplemented signer forms as unsupported", () => {
    const listing = fixtureSignedPaidListing();
    const signed = signFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    const algorithm = clone(signed.agreement);
    (algorithm["signatures"] as Record<string, unknown>[])[0]!["algorithm"] = "ecdsa-secp256k1";
    expect(verify(canonicalize(algorithm), listing))
      .toMatchObject({ disposition: "refused-unsupported", stage: "signature" });

    const indirect = clone(signed.agreement);
    const buyer = (indirect["parties"] as Record<string, unknown>[]).find((party) => party["role"] === "buyer")!;
    const oldBuyer = buyer["primaryClaim"];
    buyer["primaryClaim"] = "github:octocat";
    const buyerSignature = (indirect["signatures"] as Record<string, unknown>[])
      .find((signature) => signature["party"] === oldBuyer)!;
    buyerSignature["party"] = "github:octocat";
    const canonicalJson = canonicalize(indirect);
    expect(verifyCanonicalAgreementJson(canonicalJson, {
      temporalContext: postAnchor(agreementHashFromCanonical(canonicalJson)),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: () => "verified",
    })).toMatchObject({ disposition: "refused-unsupported", stage: "signature" });
  });

  test("verifies parameterized direct key claims by parsed key identity", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const buyer = buyerFixtureSigner();
    const parameterizedBuyer = `${buyer.signer}?context=fixture`;
    const buyerParty = (input["parties"] as unknown as Record<string, unknown>[])
      .find((party) => party["role"] === "buyer")!;
    buyerParty["primaryClaim"] = parameterizedBuyer;
    const sellerEntry = fixtureAgreementSigners().find((entry) => entry.party !== buyer.signer)!;
    const signed = signUncheckedFixtureAgreement(input, [
      { party: buyer.signer, signer: buyer },
      sellerEntry,
    ]);
    const options = {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    } as const;
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, options).disposition).toBe("verified");

    const duplicated = signUncheckedFixtureAgreement(input, [
      { party: buyer.signer, signer: buyer },
      { party: parameterizedBuyer, signer: buyer },
      sellerEntry,
    ]);
    expect(verifyCanonicalAgreementJson(duplicated.canonicalJson, options))
      .toMatchObject({ disposition: "rejected", stage: "signature", reason: "Duplicate agreement signature party" });
  });

  test("rejects parameter aliases that collapse buyer and seller to one CF-3 identity", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const sharedSigner = buyerFixtureSigner();
    const buyerClaim = `${sharedSigner.signer}?role=buyer`;
    const sellerClaim = `${sharedSigner.signer}?role=seller`;
    const parties = input.parties as unknown as Record<string, unknown>[];
    parties.find((party) => party["role"] === "buyer")!["primaryClaim"] = buyerClaim;
    parties.find((party) => party["role"] === "seller")!["primaryClaim"] = sellerClaim;
    const signed = signUncheckedFixtureAgreement(input, [
      { party: buyerClaim, signer: sharedSigner },
      { party: sellerClaim, signer: sharedSigner },
    ]);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...fixtureAgreementVerificationOptions(input, listing),
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    })).toMatchObject({ disposition: "rejected", stage: "shape" });
  });

  test("rejects duplicate CF-3 identities across non-winning parties", () => {
    const listing = fixtureSignedPaidListing();
    const base = fixtureUnsignedPayeeBoundAgreement(listing);
    const buyer = base.parties.find((party) => party.role === "buyer")!;
    const input = { ...base, parties: [...base.parties, {
      ...buyer,
      role: "bidder-non-winning" as const,
      primaryClaim: `${buyer.primaryClaim}?role=loser`,
    }] };
    const signed = signUncheckedFixtureAgreement(input);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, fixtureAgreementVerificationOptions(input, listing)))
      .toMatchObject({ disposition: "rejected", stage: "shape" });
  });

  test("refuses unsupported auto-accept instance-signature verification honestly", () => {
    const listing = fixtureSignedPaidListing({
      terms: {
        cancellationPolicy: "pre-commit",
        deadlineSecAfterCommit: 300,
        acceptanceModel: "auto-accept",
      },
    });
    const input = fixtureUnsignedPayeeBoundAgreement(listing);
    const signed = signUncheckedFixtureAgreement(input);
    expect(verify(signed.canonicalJson, listing))
      .toMatchObject({ disposition: "refused-unsupported", stage: "signature" });
  });

  test.each([
    ["listing-ref", (input: Record<string, unknown>) => {
      (input["listingRef"] as Record<string, unknown>)["contentHash"] = "0".repeat(64);
    }],
    ["currency", (input: Record<string, unknown>) => {
      ((input["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["currency"] = "EUR";
    }],
    ["pricing", (input: Record<string, unknown>) => {
      ((input["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["amount"] = "2";
    }],
    ["pricing", (input: Record<string, unknown>) => {
      delete ((input["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["unit"];
    }],
    ["pricing", (input: Record<string, unknown>) => {
      (input["terms"] as Record<string, unknown>)["meteredQuantity"] = { quantity: "1", unit: "job" };
    }],
    ["rail", (input: Record<string, unknown>) => {
      ((input["terms"] as Record<string, unknown>)["rail"] as Record<string, unknown>)["railId"] = "x402:other";
    }],
    ["rail", (input: Record<string, unknown>) => {
      delete ((input["terms"] as Record<string, unknown>)["rail"] as Record<string, unknown>)["railVersion"];
    }],
    ["deliverable", (input: Record<string, unknown>) => {
      ((input["terms"] as Record<string, unknown>)["deliverable"] as Record<string, unknown>)["hash"] = "0".repeat(64);
    }],
    ["deadline", (input: Record<string, unknown>) => {
      (input["terms"] as Record<string, unknown>)["deadline"] = FIXTURE_COMMITTED_AT + 301_000;
    }],
  ])("rejects signed %s mismatch", (stage, mutate) => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    mutate(input);
    const signed = signUncheckedFixtureAgreement(input as unknown as UnsignedAgreementArtifact);
    expect(verify(signed.canonicalJson, listing)).toMatchObject({ disposition: "rejected", stage });
  });

  test("rechecks listing expiry against anchored committedAt", () => {
    const listing = fixtureSignedPaidListing({
      validity: { notBefore: FIXTURE_COMMITTED_AT - 20_000, notAfter: FIXTURE_COMMITTED_AT - 1 },
    });
    const signed = signUncheckedFixtureAgreement(fixtureUnsignedPayeeBoundAgreement(listing));
    const listingVerification = acceptedPaidListing(listing.canonicalJson);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification,
      vettedPartyCheck: fixtureVettedPartyCheck(),
    })).toMatchObject({ disposition: "rejected", stage: "validity" });
  });

  test("does not invent a commitment-time notBefore check beyond pinned section 8.5.2", () => {
    const notBefore = FIXTURE_COMMITTED_AT + 1;
    const listing = signListing(fixtureUnsignedPaidListing({
      validity: { notBefore, notAfter: notBefore + 60_000 },
    }), fixtureSigner(), { ...FIXTURE_SIGNING_CONTEXT, nowMs: notBefore });
    const listingVerification = verifyCanonicalListingJson(listing.canonicalJson, {
      nowMs: notBefore,
      revocationCheck: () => "absent",
      paymentRailCheck: () => ({ status: "resolved", phaseHandler: "pay-x402" }),
    });
    expect(listingVerification.disposition).toBe("accepted");
    if (listingVerification.disposition !== "accepted") throw new Error(listingVerification.reason);
    const input = fixtureUnsignedPayeeBoundAgreement(listing);
    const signed = signUncheckedFixtureAgreement(input);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...fixtureAgreementVerificationOptions(input),
      listingCanonicalJson: listing.canonicalJson,
      listingVerification,
    }).disposition).toBe("verified");
  });

  test("does not let unavailable committedAt mask permanent failures", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const options = {
      temporalContext: { mode: "pre-anchor" as const, nowMs: Number.NaN },
      expectedCommitPhase: "commit-payee-bound-agreement" as const,
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    };
    expect(verifyCanonicalAgreementJson(signFixtureAgreement(input).canonicalJson, options))
      .toMatchObject({ disposition: "indeterminate", stage: "deadline" });
    ((input["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["currency"] = "EUR";
    expect(verifyCanonicalAgreementJson(signUncheckedFixtureAgreement(input).canonicalJson, options))
      .toMatchObject({ disposition: "rejected", stage: "currency" });
    ((input["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["currency"] = "USDC";
    ((input["terms"] as Record<string, unknown>)["payoutBindings"] as unknown[]).splice(0);
    expect(verifyCanonicalAgreementJson(signUncheckedFixtureAgreement(input).canonicalJson, options))
      .toMatchObject({ disposition: "rejected", stage: "payout-bindings" });
  });

  test("binds fixed-price seller to the pinned Listing publisher", () => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const attacker = attackerFixtureSigner();
    const buyer = buyerFixtureSigner();
    const seller = (input["parties"] as unknown as Record<string, unknown>[])
      .find((party) => party["role"] === "seller")!;
    seller["primaryClaim"] = attacker.signer;
    const signed = signUncheckedFixtureAgreement(input, [
      { party: buyer.signer, signer: buyer },
      { party: attacker.signer, signer: attacker },
    ]);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson: listing.canonicalJson,
      listingVerification: acceptedPaidListing(listing.canonicalJson),
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    }))
      .toMatchObject({ disposition: "rejected", stage: "seller-binding" });
  });

  test("matches Listing publisher and agreement seller by CF-3 identity", () => {
    const sellerSigner = fixtureSigner();
    const listingClaim = `${sellerSigner.signer}?context=listing`;
    const sessionClaim = `${sellerSigner.signer}?context=session`;
    const identity = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: listingClaim,
      presentedAt: FIXTURE_NOW_MS,
      claims: [{ ref: listingClaim }],
    }, sellerSigner, FIXTURE_SIGNING_CONTEXT).bundle;
    const listing = signListing({
      ...fixtureUnsignedPaidListing(),
      seller: {
        identity,
        displayName: "Reference JSON Transform",
        publicEndpoint: "https://service.example/v1",
      },
    }, sellerSigner, { ...FIXTURE_SIGNING_CONTEXT, nowMs: FIXTURE_NOW_MS });
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const sellerParty = (input.parties as unknown as Record<string, unknown>[])
      .find((party) => party["role"] === "seller")!;
    sellerParty["primaryClaim"] = sessionClaim;
    const buyerEntry = fixtureAgreementSigners().find((entry) => entry.party !== sellerSigner.signer)!;
    const signed = signUncheckedFixtureAgreement(input, [
      buyerEntry,
      { party: sessionClaim, signer: sellerSigner },
    ]);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...fixtureAgreementVerificationOptions(input, listing),
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    }).disposition).toBe("verified");
  });

  test("matches the complete selected PaymentRailRef", () => {
    const listing = fixtureSignedPaidListing({
      acceptedRails: [{
        railId: FIXTURE_RAIL_ID,
        railVersion: 1,
        parameters: { resource: "fixture-v1" },
      }],
    });
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const signed = signUncheckedFixtureAgreement(input);
    expect(verify(signed.canonicalJson, listing)).toMatchObject({ disposition: "rejected", stage: "rail" });
    ((input["terms"] as Record<string, unknown>)["rail"] as Record<string, unknown>)["parameters"] = {
      resource: "fixture-v1",
    };
    expect(verify(signFixtureAgreementForListing(input, listing).canonicalJson, listing).disposition).toBe("verified");
  });

  test("keeps agreement rail selection independent from per-phase payout rail bindings", () => {
    const secondaryRail = "x402:secondary";
    const listing = fixtureSignedPaidListing({
      acceptedRails: [
        { railId: FIXTURE_RAIL_ID, railVersion: 1 },
        { railId: secondaryRail, railVersion: 1 },
      ],
    });
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    (input.terms as Record<string, unknown>)["rail"] = { railId: secondaryRail, railVersion: 1 };
    const signed = signUncheckedFixtureAgreement(input);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...fixtureAgreementVerificationOptions(input, listing, [FIXTURE_RAIL_ID, secondaryRail]),
    }).disposition).toBe("verified");
  });

  test("requires the agreement-bound buyer key for encrypt-to-buyer delivery", () => {
    const base = fixtureUnsignedPaidListing();
    const listing = fixtureSignedPaidListing({
      offering: {
        ...(base["offering"] as Record<string, unknown>),
        deliverable: { kind: "storage-program", accessModel: "encrypt-to-buyer" },
      },
      pipeline: [
        { kind: "negotiate-fixed-price" },
        { kind: "commit-payee-bound-agreement" },
        { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
        { kind: "deliver-storage-program" },
      ],
    });
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    expect(verify(signUncheckedFixtureAgreement(input).canonicalJson, listing))
      .toMatchObject({ disposition: "rejected", stage: "deliverable" });
    const buyer = (input["parties"] as unknown as Record<string, unknown>[])
      .find((party) => party["role"] === "buyer")!;
    buyer["encryptionKey"] = "ml-kem-aes:fixture-public-key";
    expect(verify(signFixtureAgreementForListing(input, listing).canonicalJson, listing).disposition).toBe("verified");
  });

  test.each([
    ["missing", (bindings: Record<string, unknown>[]) => bindings.splice(0)],
    ["wrong-index", (bindings: Record<string, unknown>[]) => { bindings[0]!["phaseIndex"] = 3; }],
    ["wrong-rail", (bindings: Record<string, unknown>[]) => { bindings[0]!["railId"] = "x402:other"; }],
    ["duplicate", (bindings: Record<string, unknown>[]) => bindings.push({ ...bindings[0] })],
  ])("rejects %s payout binding coverage", (_name, mutate) => {
    const listing = fixtureSignedPaidListing();
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const bindings = (input["terms"] as Record<string, unknown>)["payoutBindings"] as Record<string, unknown>[];
    mutate(bindings);
    const signed = signUncheckedFixtureAgreement(input as unknown as UnsignedAgreementArtifact);
    expect(verify(signed.canonicalJson, listing)).toMatchObject({ disposition: "rejected", stage: "payout-bindings" });
  });

  test("enforces metered MTR-1..4 and exact integer arithmetic", () => {
    const listing = fixtureSignedPaidListing({
      pricing: {
        kind: "metered",
        unitPrice: { amount: "0.125", currency: "USDC", unit: "record" },
        unit: "record",
        minTotal: { amount: "1", currency: "USDC" },
      },
    });
    const valid = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    const terms = valid["terms"] as Record<string, unknown>;
    terms["price"] = { amount: "1.25", currency: "USDC", unit: "record" };
    terms["meteredQuantity"] = { quantity: "10", unit: "record" };
    expect(verify(signFixtureAgreementForListing(valid as unknown as UnsignedAgreementArtifact, listing).canonicalJson, listing).disposition).toBe("verified");

    for (const quantity of ["09", "1.5", "+10", "1e1"]) {
      const invalid = clone(valid);
      ((invalid["terms"] as Record<string, unknown>)["meteredQuantity"] as Record<string, unknown>)["quantity"] = quantity;
      expect(verify(signUncheckedFixtureAgreement(invalid as unknown as UnsignedAgreementArtifact).canonicalJson, listing))
        .toMatchObject({ disposition: "rejected", stage: "pricing" });
    }

    const minimumWins = clone(valid);
    const minimumTerms = minimumWins["terms"] as Record<string, unknown>;
    minimumTerms["price"] = { amount: "1", currency: "USDC", unit: "record" };
    minimumTerms["meteredQuantity"] = { quantity: "1", unit: "record" };
    expect(verify(signFixtureAgreementForListing(
      minimumWins as unknown as UnsignedAgreementArtifact,
      listing,
    ).canonicalJson, listing).disposition).toBe("verified");
    delete (minimumTerms["price"] as Record<string, unknown>)["unit"];
    expect(verify(signUncheckedFixtureAgreement(
      minimumWins as unknown as UnsignedAgreementArtifact,
    ).canonicalJson, listing)).toMatchObject({ disposition: "rejected", stage: "pricing" });
  });

  test("enforces PS-3 and rounded negotiable RFQ boundaries", () => {
    const fixedListing = fixtureSignedPaidListing({
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "1.25", currency: "USDC" },
        minPct: 10,
        maxPct: 10,
      },
    });
    const fixed = fixtureUnsignedPayeeBoundAgreement(fixedListing);
    expect(verify(signFixtureAgreementForListing(fixed, fixedListing).canonicalJson, fixedListing).disposition).toBe("verified");
    const offCenter = clone(fixed);
    ((offCenter["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["amount"] = "1.26";
    expect(verify(signUncheckedFixtureAgreement(offCenter).canonicalJson, fixedListing))
      .toMatchObject({ disposition: "rejected", stage: "pricing" });

    const rfqListing = fixtureSignedPaidListing({
      pipeline: [
        { kind: "negotiate-rfq", parameters: { maxTurns: 2, timeoutSec: 60 } },
        { kind: "commit-payee-bound-agreement" },
        { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
        { kind: "deliver-attested-payload" },
      ],
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "1.25", currency: "USDC" },
        minPct: 10,
        maxPct: 10,
      },
    });
    const lowerBoundary = clone(fixtureUnsignedPayeeBoundAgreement(rfqListing));
    (lowerBoundary as unknown as Record<string, unknown>)["derivedFromPattern"] = "rfq";
    ((lowerBoundary["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["amount"] = "1.13";
    expect(verify(signFixtureAgreementForListing(lowerBoundary, rfqListing).canonicalJson, rfqListing).disposition).toBe("verified");
    const below = clone(lowerBoundary);
    ((below["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["amount"] = "1.12";
    expect(verify(signUncheckedFixtureAgreement(below).canonicalJson, rfqListing))
      .toMatchObject({ disposition: "rejected", stage: "pricing" });

    const fractionalListing = fixtureSignedPaidListing({
      pipeline: [
        { kind: "negotiate-rfq", parameters: { maxTurns: 2, timeoutSec: 60 } },
        { kind: "commit-payee-bound-agreement" },
        { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
        { kind: "deliver-attested-payload" },
      ],
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "1.25", currency: "USDC" },
        minPct: 2.5,
        maxPct: 2.5,
      },
    });
    const fractionalBoundary = clone(fixtureUnsignedPayeeBoundAgreement(fractionalListing));
    (fractionalBoundary as unknown as Record<string, unknown>)["derivedFromPattern"] = "rfq";
    ((fractionalBoundary["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["amount"] = "1.22";
    expect(verify(signFixtureAgreementForListing(
      fractionalBoundary,
      fractionalListing,
    ).canonicalJson, fractionalListing).disposition).toBe("verified");
    const outsideFractionalBoundary = clone(fractionalBoundary);
    ((outsideFractionalBoundary["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["amount"] = "1.21";
    expect(verify(signUncheckedFixtureAgreement(outsideFractionalBoundary).canonicalJson, fractionalListing))
      .toMatchObject({ disposition: "rejected", stage: "pricing" });

    const fallbackListing = fixtureSignedPaidListing({
      pipeline: [
        {
          kind: "negotiate-rfq",
          parameters: { maxTurns: 2, timeoutSec: 60, fixedPriceFallback: true },
        },
        { kind: "commit-payee-bound-agreement" },
        { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
        { kind: "deliver-attested-payload" },
      ],
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "1.25", currency: "USDC" },
        minPct: 10,
        maxPct: 10,
      },
    });
    const fallback = fixtureUnsignedPayeeBoundAgreement(fallbackListing);
    expect(verify(signFixtureAgreementForListing(fallback, fallbackListing).canonicalJson, fallbackListing).disposition)
      .toBe("verified");

    const unitListing = fixtureSignedPaidListing({
      pricing: {
        kind: "negotiable",
        bandCenter: { amount: "1.25", currency: "USDC", unit: "hour" },
        minPct: 10,
        maxPct: 10,
      },
    });
    const unitAgreement = fixtureUnsignedPayeeBoundAgreement(unitListing);
    expect(verify(signFixtureAgreementForListing(unitAgreement, unitListing).canonicalJson, unitListing).disposition)
      .toBe("verified");
    const changedUnit = clone(unitAgreement);
    ((changedUnit["terms"] as Record<string, unknown>)["price"] as Record<string, unknown>)["unit"] = "call";
    expect(verify(signUncheckedFixtureAgreement(changedUnit).canonicalJson, unitListing))
      .toMatchObject({ disposition: "rejected", stage: "pricing" });
  });

  test("fails closed when a reserve-free auction has no authoritative currency", () => {
    const listing = fixtureSignedPaidListing({
      pipeline: [
        {
          kind: "negotiate-sealed-envelope",
          parameters: {
            commitDeadline: FIXTURE_COMMITTED_AT + 120_000,
            revealWindow: 60,
            selectionRule: "highest-price",
          },
        },
        { kind: "commit-payee-bound-agreement" },
        { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
        { kind: "deliver-attested-payload" },
      ],
      pricing: { kind: "auction", selectionRule: "highest-price" },
    });
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    (input as unknown as Record<string, unknown>)["derivedFromPattern"] = "sealed-envelope";
    (input["terms"] as Record<string, unknown>)["price"] = { amount: "2", currency: "USDC" };
    const signed = signUncheckedFixtureAgreement(input);
    const options = fixtureAgreementVerificationOptions(input, listing);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, options))
      .toMatchObject({ disposition: "indeterminate", stage: "currency" });

    const invalidPayout = clone(input);
    ((invalidPayout["terms"] as Record<string, unknown>)["payoutBindings"] as Record<string, unknown>[])[0]!["phaseIndex"] = 99;
    const invalidPayoutSigned = signUncheckedFixtureAgreement(invalidPayout as unknown as UnsignedAgreementArtifact);
    expect(verifyCanonicalAgreementJson(invalidPayoutSigned.canonicalJson, fixtureAgreementVerificationOptions(
      invalidPayout as unknown as UnsignedAgreementArtifact,
      listing,
    ))).toMatchObject({ disposition: "rejected", stage: "payout-bindings" });

    expect(() => signFixtureAgreementForListing(input, listing))
      .toThrow("Reserve-free auction Listing does not declare an authoritative currency");
  });

  test("verifies a sealed-envelope auction with reserve-declared currency and authoritative selection", () => {
    const listing = fixtureSignedPaidListing({
      pipeline: [
        {
          kind: "negotiate-sealed-envelope",
          parameters: {
            commitDeadline: FIXTURE_COMMITTED_AT + 120_000,
            revealWindow: 60,
            selectionRule: "highest-price",
          },
        },
        { kind: "commit-payee-bound-agreement" },
        { kind: "pay-x402", parameters: { rail: FIXTURE_RAIL_ID } },
        { kind: "deliver-attested-payload" },
      ],
      pricing: {
        kind: "auction",
        reservePrice: { amount: "1", currency: "USDC" },
        selectionRule: "highest-price",
      },
    });
    const input = clone(fixtureUnsignedPayeeBoundAgreement(listing));
    (input as unknown as Record<string, unknown>)["derivedFromPattern"] = "sealed-envelope";
    (input["terms"] as Record<string, unknown>)["price"] = { amount: "2", currency: "USDC" };
    const signed = signFixtureAgreementForListing(input, listing);
    const options = fixtureAgreementVerificationOptions(input, listing);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, options).disposition).toBe("verified");

    const { sealedEnvelopeResult: _, ...withoutAuthority } = options;
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, withoutAuthority))
      .toMatchObject({ disposition: "indeterminate", stage: "sealed-selection" });
    const invalidDeadline = clone(input);
    (invalidDeadline["terms"] as Record<string, unknown>)["deadline"] = FIXTURE_COMMITTED_AT + 300_001;
    const invalidDeadlineSigned = signUncheckedFixtureAgreement(invalidDeadline as unknown as UnsignedAgreementArtifact);
    const { sealedEnvelopeResult: _deadlineAuthority, ...withoutAuthorityForInvalidDeadline } = fixtureAgreementVerificationOptions(
      invalidDeadline as unknown as UnsignedAgreementArtifact,
      listing,
    );
    expect(verifyCanonicalAgreementJson(invalidDeadlineSigned.canonicalJson, withoutAuthorityForInvalidDeadline))
      .toMatchObject({ disposition: "rejected", stage: "deadline" });
    const invalidPayout = clone(input);
    ((invalidPayout["terms"] as Record<string, unknown>)["payoutBindings"] as Record<string, unknown>[])[0]!["phaseIndex"] = 99;
    const invalidPayoutSigned = signUncheckedFixtureAgreement(invalidPayout as unknown as UnsignedAgreementArtifact);
    const { sealedEnvelopeResult: _ignored, ...withoutAuthorityForInvalidPayout } = fixtureAgreementVerificationOptions(
      invalidPayout as unknown as UnsignedAgreementArtifact,
      listing,
    );
    expect(verifyCanonicalAgreementJson(invalidPayoutSigned.canonicalJson, withoutAuthorityForInvalidPayout))
      .toMatchObject({ disposition: "rejected", stage: "payout-bindings" });
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...options,
      sealedEnvelopeResult: { ...options.sealedEnvelopeResult!, agreementHash: "0".repeat(64) },
    })).toMatchObject({ disposition: "rejected", stage: "sealed-selection" });
    const seller = input.parties.find((party) => party.role === "seller")!;
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      ...options,
      sealedEnvelopeResult: { ...options.sealedEnvelopeResult!, winningBidderClaim: seller.primaryClaim },
    })).toMatchObject({ disposition: "rejected", stage: "sealed-selection" });
  });

  test("MTR-5 refuses an unrecognized pricing kind even with a claimed pinned Listing", () => {
    const source = fixtureSignedPaidListing();
    const listing = clone(source.listing) as Record<string, unknown>;
    listing["pricing"] = { kind: "future-pricing", currency: "USDC" };
    const listingCanonicalJson = canonicalize(listing);
    const listingHash = sha256Hex(canonicalize(omit(listing, "signature")));
    const input = clone(fixtureUnsignedPayeeBoundAgreement(source));
    (input["listingRef"] as Record<string, unknown>)["contentHash"] = listingHash;
    const signed = signUncheckedFixtureAgreement(input as unknown as UnsignedAgreementArtifact);
    expect(verifyCanonicalAgreementJson(signed.canonicalJson, {
      temporalContext: postAnchor(signed.agreementHash),
      expectedCommitPhase: "commit-payee-bound-agreement",
      expectedJobId: FIXTURE_JOB_ID,
      listingCanonicalJson,
      listingVerification: {
        disposition: "accepted",
        contentHash: listingHash,
        listingId: listing["listingId"] as string,
        listingVersion: listing["listingVersion"] as number,
      },
      vettedPartyCheck: fixtureVettedPartyCheck(input),
    })).toMatchObject({ disposition: "refused-unsupported", stage: "pricing", reason: "unrecognized-pricing-kind" });
  });
});

function verify(canonicalJson: string, listing: ReturnType<typeof fixtureSignedPaidListing>) {
  return verifyCanonicalAgreementJson(canonicalJson, {
    temporalContext: postAnchor(agreementHashFromCanonical(canonicalJson)),
    expectedCommitPhase: "commit-payee-bound-agreement",
    expectedJobId: FIXTURE_JOB_ID,
    listingCanonicalJson: listing.canonicalJson,
    listingVerification: acceptedPaidListing(listing.canonicalJson),
    vettedPartyCheck: fixtureVettedPartyCheck(),
  });
}

function postAnchor(agreementHash: string) {
  return { mode: "post-anchor" as const, committedAt: FIXTURE_COMMITTED_AT, agreementHash };
}

function agreementHashFromCanonical(canonicalJson: string): string {
  const agreement = JSON.parse(canonicalJson) as Record<string, unknown>;
  return sha256Hex(canonicalize(omit(agreement, "signatures")));
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function omit(value: Record<string, unknown>, field: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

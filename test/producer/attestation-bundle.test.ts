import { describe, expect, test } from "bun:test";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  bundleLogicalAddress,
  signAttestationBundle,
  signFaultAttestationBundleCopies,
} from "../../src/producer/attestation-bundle.ts";
import { verifyCanonicalAttestationBundleJson } from "../../src/consumer/attestation-bundle-verifier.ts";
import {
  attestationBundleHash,
  bundleSignatureDomain,
  impliedFaultSet,
  isFaultAttestationBundle,
  rosterRoles,
} from "../../src/protocol/fault-attestation-bundle.ts";
import {
  bundleCopiesDiverge,
  classifyBundlePair,
  scoredOutcome,
} from "../../src/consumer/bundle-consistency.ts";
import { FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";
import {
  fixtureBundleAuthorityOptions,
  fixtureBundleSigners,
  fixtureReferenceResolver,
  fixtureSignedBundle,
  fixtureUnsignedBundle,
  orchestratorFixtureSigner,
  signUncheckedBundle,
} from "../fixtures/reference-bundle.ts";

describe("AttestationBundle producer and independent verifier", () => {
  test("emits role-local buyer, seller, and optional orchestrator copies over one signed scope", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({
      parties: [
        ...fixtureUnsignedBundle().parties,
        { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
      ],
    });
    const signed = signAttestationBundle(
      input, fixtureBundleSigners(true), ["buyer", "seller", "orchestrator"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    );
    expect(signed.copies).toHaveLength(3);
    expect(new Set(signed.copies.map((copy) => copy.logicalAddress)).size).toBe(3);
    for (const copy of signed.copies) {
      const verified = verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
        expectedAddress: copy.logicalAddress,
        expectedJobId: input.jobId,
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      });
      expect(verified).toMatchObject({ disposition: "verified", bundleHash: signed.bundleHash });
      if (verified.disposition === "verified") {
        expect(verified.signedScopeCanonicalJson).toBe(signed.signedScopeCanonicalJson);
        expect(verified.signatureCount).toBe(3);
      }
    }
  });

  test("emits a FaultAttestationBundle perspective pair with one absolute faultedParty", () => {
    // An abort is attested over a strict prefix of the authenticated executed phase plan,
    // every retained phase having succeeded (§10.4.1 abort class).
    const full = fixtureUnsignedBundle();
    const base = fixtureUnsignedBundle({
      phaseSummary: full.phaseSummary.slice(0, 1),
      settlementEvidence: full.settlementEvidence.slice(0, 1),
    });
    const { bundleVersion, outcome, ...shared } = base;
    const signed = signFaultAttestationBundleCopies(
      { ...shared, faultBundleVersion: "1", faultedParty: "seller" } as any,
      "abort",
      fixtureBundleSigners(),
      ["buyer", "seller"],
      FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver,
      fixtureBundleAuthorityOptions,
    );

    expect(signed.copies).toHaveLength(2);
    expect(new Set(signed.copies.map((copy) => copy.logicalAddress)).size).toBe(2);

    const buyerCopy = signed.copies.find((copy) => copy.anchoredByRole === "buyer")!;
    const sellerCopy = signed.copies.find((copy) => copy.anchoredByRole === "seller")!;

    // The role-relative spellings differ; the absolute hashed attribution does not.
    expect(buyerCopy.outcome).toBe("aborted-by-other");
    expect(sellerCopy.outcome).toBe("aborted-by-self");
    expect(buyerCopy.artifact["faultedParty"]).toBe("seller");
    expect(sellerCopy.artifact["faultedParty"]).toBe("seller");
    expect(buyerCopy.bundleHash).not.toBe(sellerCopy.bundleHash);

    for (const copy of signed.copies) {
      expect(isFaultAttestationBundle(copy.artifact)).toBe(true);
      expect(copy.artifact["bundleVersion"]).toBeUndefined();
      // §10.4.1: each copy's signatures are over its OWN hash under the fault domain.
      expect(attestationBundleHash(copy.artifact)).toBe(copy.bundleHash);
      expect(bundleSignatureDomain(copy.artifact)).toBe("dacs-fault-bundle:v1:");
      const permitted = impliedFaultSet(
        copy.outcome, copy.anchoredByRole, rosterRoles(copy.artifact),
      );
      expect(permitted.has("seller")).toBe(true);
      // ISC-34: the independent verifier recomputes hash, signed scope, and signatures for
      // a FaultAttestationBundle exactly as it does for the legacy class.
      const verified = verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
        expectedAddress: copy.logicalAddress,
        expectedJobId: base.jobId,
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      });
      expect(verified).toMatchObject({ disposition: "verified", bundleHash: copy.bundleHash });
    }

    // §10.4.3: the pair converges on faultedParty and outcome class despite unequal forms.
    expect(bundleCopiesDiverge(buyerCopy.artifact, sellerCopy.artifact)).toBe(false);
    const pair = classifyBundlePair(buyerCopy.artifact, sellerCopy.artifact);
    expect(pair).toMatchObject({
      convergence: "unified",
      pairKind: "fault-pair",
      faultedParty: "seller",
    });
    expect(scoredOutcome(sellerCopy.artifact, "seller")).toBe("aborted-by-self");
    expect(scoredOutcome(sellerCopy.artifact, "buyer")).toBe("aborted-by-other");
  });

  test("emits a distinct orchestrator-anchored FaultAttestationBundle copy", () => {
    const orchestrator = orchestratorFixtureSigner();
    const successful = fixtureUnsignedBundle();
    const base = fixtureUnsignedBundle({
      parties: [
        ...fixtureUnsignedBundle().parties,
        { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
      ],
      phaseSummary: [
        successful.phaseSummary[0]!,
        { ...successful.phaseSummary[1]!, outcome: "fail", errorClass: "counterparty" },
      ],
    });
    const { bundleVersion, outcome, ...shared } = base;
    const signed = signFaultAttestationBundleCopies(
      { ...shared, faultBundleVersion: "1", faultedParty: "seller" } as any,
      "failure",
      fixtureBundleSigners(true),
      ["buyer", "seller", "orchestrator"],
      FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver,
      fixtureBundleAuthorityOptions,
    );

    expect(signed.copies).toHaveLength(3);
    const orchestratorCopy = signed.copies.find((c) => c.anchoredByRole === "orchestrator")!;
    // §10.4.2: anchoredByRole equals the role segment of the address it is bound to.
    expect(orchestratorCopy.logicalAddress)
      .toBe(bundleLogicalAddress(base.jobId, "orchestrator"));
    expect(orchestratorCopy.outcome).toBe("failed-counterparty");
    expect(orchestratorCopy.artifact["faultedParty"]).toBe("seller");
    expect((orchestratorCopy.artifact["signatures"] as unknown[])).toHaveLength(3);
    // An orchestrator-anchored copy follows the same permissible-set rule.
    expect(impliedFaultSet("failed-counterparty", "orchestrator", rosterRoles(orchestratorCopy.artifact))
      .has("seller")).toBe(true);
  });

  test("refuses to produce a FaultAttestationBundle copy outside the permissible fault set", () => {
    const base = fixtureUnsignedBundle();
    const { bundleVersion, outcome, ...shared } = base;
    // `completed` admits only faultedParty "none"; naming a party is a production error,
    // not something a consumer should have to reject downstream.
    expect(() => signFaultAttestationBundleCopies(
      { ...shared, faultBundleVersion: "1", faultedParty: "seller" } as any,
      "completed",
      fixtureBundleSigners(),
      ["buyer", "seller"],
      FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver,
      fixtureBundleAuthorityOptions,
    )).toThrow(/faultedParty "none"/);
  });

  test("retains unknown signed fields and rejects post-sign mutation", () => {
    const signed = fixtureSignedBundle({ extensionProof: { version: 1, value: "bound" } });
    expect(JSON.parse(signed.signedScopeCanonicalJson).extensionProof).toEqual({ version: 1, value: "bound" });
    const copy = JSON.parse(signed.copies[0]!.canonicalJson);
    copy.extensionProof.value = "mutated";
    const canonicalJson = canonicalize(copy);
    expect(verifyCanonicalAttestationBundleJson(canonicalJson, {
      expectedAddress: signed.copies[0]!.logicalAddress,
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: fixtureReferenceResolver,
    })).toMatchObject({ disposition: "rejected", stage: "signatures" });
  });

  test("rejects a valid artifact fetched from the wrong role address", () => {
    const signed = fixtureSignedBundle();
    expect(verifyCanonicalAttestationBundleJson(signed.copies[0]!.canonicalJson, {
      expectedAddress: bundleLogicalAddress(fixtureUnsignedBundle().jobId, "seller"),
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: fixtureReferenceResolver,
    })).toMatchObject({ disposition: "rejected", stage: "anchor-binding" });
  });

  test("rejects non-monotonic phase order before resolver uncertainty", () => {
    const input = fixtureUnsignedBundle();
    const reversed = { ...input, phaseSummary: [...input.phaseSummary].reverse() };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(reversed, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveExecutedPhasePlan: () => ({ status: "indeterminate" as const, reason: "phase plan unavailable" }),
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "rejected", stage: "shape" });
  });

  test("rejects missing required signer and undeclared anchor roles at production", () => {
    expect(() => signAttestationBundle(
      fixtureUnsignedBundle(), fixtureBundleSigners().slice(0, 1), ["buyer"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    )).toThrow("every party signer");
    expect(() => signAttestationBundle(
      fixtureUnsignedBundle(), fixtureBundleSigners(), ["orchestrator"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    )).toThrow("anchor roles");
    expect(() => signAttestationBundle(
      fixtureUnsignedBundle(), fixtureBundleSigners(), ["buyer"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    )).toThrow("one role-local anchor");
  });

  test("produces only the signer-local copy for a normative single-signed abort", () => {
    const complete = fixtureUnsignedBundle();
    const input = fixtureUnsignedBundle({
      outcome: "aborted-by-other",
      phaseSummary: complete.phaseSummary.slice(0, -1),
      settlementEvidence: complete.settlementEvidence.slice(0, -1),
    });
    const signed = signAttestationBundle(
      input, fixtureBundleSigners().slice(0, 1), ["buyer"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    );
    expect(signed.copies).toHaveLength(1);
    expect(signed.copies[0]).toMatchObject({ anchoredByRole: "buyer" });
    expect(verifyCanonicalAttestationBundleJson(signed.copies[0]!.canonicalJson, {
      expectedAddress: signed.copies[0]!.logicalAddress,
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: fixtureReferenceResolver,
    })).toMatchObject({ disposition: "verified", signatureCount: 1 });
    expect(() => signAttestationBundle(
      input, fixtureBundleSigners().slice(0, 1), ["seller"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    )).toThrow("signer role-local anchor");
  });

  test("rejects a completed outcome when any summarized phase failed", () => {
    const input = fixtureUnsignedBundle();
    const contradictory = {
      ...input,
      phaseSummary: [
        { ...input.phaseSummary[0]!, outcome: "fail", errorClass: "counterparty" },
        input.phaseSummary[1]!,
      ],
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(contradictory, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "rejected", stage: "outcome" });
  });

  test("binds failed outcomes to an authenticated matching phase error class", () => {
    const input = fixtureUnsignedBundle();
    const cases = [
      ["failed-perm", "permanent"],
      ["failed-perm", "transient"],
      ["failed-counterparty", "counterparty"],
      ["failed-counterparty", "settlement-atomicity"],
      ["failed-substrate", "substrate"],
    ] as const;
    for (const [outcome, errorClass] of cases) {
      const matching = {
        ...input,
        outcome,
        phaseSummary: [
          input.phaseSummary[0]!,
          { ...input.phaseSummary[1]!, outcome: "fail" as const, errorClass },
        ],
      };
      expect(verifyCanonicalAttestationBundleJson(
        signUncheckedBundle(matching, ["buyer", "seller"], "buyer"),
        {
          expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
          ...fixtureBundleAuthorityOptions,
          resolveAttestationRef: fixtureReferenceResolver,
        },
      )).toMatchObject({ disposition: "verified" });
      const allSuccessful = { ...matching, phaseSummary: input.phaseSummary };
      expect(verifyCanonicalAttestationBundleJson(
        signUncheckedBundle(allSuccessful, ["buyer", "seller"], "buyer"),
        {
          expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
          ...fixtureBundleAuthorityOptions,
          resolveAttestationRef: fixtureReferenceResolver,
        },
      )).toMatchObject({ disposition: "rejected", stage: "outcome" });
    }
  });

  test("rejects non-terminal failures and full-plan aborts against the authenticated plan", () => {
    const input = fixtureUnsignedBundle();
    const earlierFailure = {
      ...input,
      outcome: "failed-perm" as const,
      phaseSummary: input.phaseSummary.map((phase) => ({
        ...phase,
        outcome: "fail" as const,
        errorClass: "permanent" as const,
      })),
    };
    const fullPlanAbort = { ...input, outcome: "aborted-by-other" as const };
    for (const [candidate, roles] of [
      [earlierFailure, ["buyer", "seller"]],
      [fullPlanAbort, ["buyer"]],
    ] as const) {
      expect(verifyCanonicalAttestationBundleJson(
        signUncheckedBundle(candidate, roles, "buyer"),
        {
          expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
          ...fixtureBundleAuthorityOptions,
          resolveAttestationRef: fixtureReferenceResolver,
        },
      )).toMatchObject({ disposition: "rejected", stage: "phase-plan" });
    }
  });

  test("requires independently matching Listing and IdentityBundle authority", () => {
    const input = fixtureUnsignedBundle();
    const copy = signUncheckedBundle(input, ["buyer", "seller"], "buyer");
    const base = {
      expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
      resolveAttestationRef: fixtureReferenceResolver,
      ...fixtureBundleAuthorityOptions,
    };
    expect(verifyCanonicalAttestationBundleJson(copy, {
      ...base,
      resolveListingRef: (ref) => ({
        ...fixtureBundleAuthorityOptions.resolveListingRef(ref),
        contentHash: "0".repeat(64),
      }),
      resolveExecutedPhasePlan: fixtureBundleAuthorityOptions.resolveExecutedPhasePlan,
    })).toMatchObject({ disposition: "rejected", stage: "listing" });
    expect(verifyCanonicalAttestationBundleJson(copy, {
      ...base,
      resolveListingRef: () => ({ status: "absent" }),
      resolveExecutedPhasePlan: fixtureBundleAuthorityOptions.resolveExecutedPhasePlan,
    })).toMatchObject({ disposition: "rejected", stage: "listing" });
    expect(verifyCanonicalAttestationBundleJson(copy, {
      ...base,
      resolvePartyIdentity: (party) => ({
        ...fixtureBundleAuthorityOptions.resolvePartyIdentity(party) as Extract<
          ReturnType<typeof fixtureBundleAuthorityOptions.resolvePartyIdentity>, { status: "verified" }
        >,
        bundleHash: "0".repeat(64),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "parties" });
    expect(verifyCanonicalAttestationBundleJson(copy, {
      ...base,
      resolvePartyIdentity: () => ({ status: "indeterminate", reason: "identity store unavailable" }),
    })).toMatchObject({ disposition: "indeterminate" });

    expect(verifyCanonicalAttestationBundleJson(copy, {
      ...base,
      resolveAttestationRef: (ref, context) => ({
        ...fixtureReferenceResolver(ref, context),
        ...(context.usage === "agreement" ? {
          agreementListingRef: { ...input.listingRef, contentHash: "f".repeat(64) },
        } : {}),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "agreement-binding" });
  });

  test("requires authenticated recipe and rail registry versions", () => {
    const input = fixtureUnsignedBundle({ recipeRegistryVersion: 2, railRegistryVersion: 3 });
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "rejected", stage: "registry-binding" });

    const withoutAgreement = { ...fixtureUnsignedBundle() } as Record<string, unknown>;
    delete withoutAgreement["agreementRef"];
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(withoutAgreement as unknown as ReturnType<typeof fixtureUnsignedBundle>, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "rejected", stage: "agreement-binding" });
  });

  test("binds ok phases to successful evidence without treating vet signers as orchestrators", () => {
    const input = fixtureUnsignedBundle();
    const externalAuthority = `key:${"a".repeat(64)}`;
    const vetted = {
      ...input,
      vetRecords: [{
        anchor: { kind: "storage-program", locator: `dacs5:vet:${input.jobId}` },
        contentHash: "a".repeat(64),
        signer: externalAuthority,
      }],
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(vetted, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "verified" });

    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: (ref, context) => ({
          ...fixtureReferenceResolver(ref, context),
          ...(context.usage === "phase" || context.usage === "settlement"
            ? { evidenceOutcome: "failure" as const } : {}),
        }),
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
  });

  test("requires authenticated phase-evidence signers but permits omitted per-phase pointers", () => {
    const input = fixtureUnsignedBundle();
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: (ref, context) => {
          const resolved = fixtureReferenceResolver(ref, context);
          if (context.usage !== "settlement") return resolved;
          const { signer: _signer, ...withoutSigner } = resolved;
          return withoutSigner;
        },
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });

    const withoutPhasePointers = {
      ...input,
      phaseSummary: input.phaseSummary.map(({ attestationRef: _attestationRef, ...phase }) => phase),
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(withoutPhasePointers, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "verified" });
  });

  test("gives an authoritative rejected reference precedence over earlier uncertainty", () => {
    const input = fixtureUnsignedBundle();
    const withAgreement = {
      ...input,
      agreementRef: {
        anchor: { kind: "storage-program", locator: `dacs3:agreement:${input.jobId}` },
        contentHash: "2".repeat(64),
      },
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(withAgreement, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: (_ref, context) => context.usage === "agreement"
          ? { status: "indeterminate" as const, reason: "agreement read timeout" }
          : { status: "rejected" as const, reason: "known corrupt phase evidence" },
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
  });

  test("does not let reference uncertainty mask an invalid bundle signature", () => {
    const input = fixtureUnsignedBundle({
      ratingRefs: [{
        anchor: { kind: "storage-program", locator: `dacs5:rating:${fixtureUnsignedBundle().jobId}` },
        contentHash: "8".repeat(64),
      }],
    });
    const artifact = JSON.parse(signUncheckedBundle(input, ["buyer", "seller"], "buyer")) as {
      signatures: Array<{ value: string }>;
    };
    artifact.signatures[0]!.value = "A".repeat(86);
    expect(verifyCanonicalAttestationBundleJson(canonicalize(artifact), {
      expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: (ref, context) => context.usage === "rating"
        ? { status: "indeterminate" as const, reason: "rating resolver unavailable" }
        : fixtureReferenceResolver(ref, context),
    })).toMatchObject({ disposition: "rejected", stage: "signatures" });
  });

  test("does not let independent authority uncertainty mask signatures verifiable with available keys", () => {
    const input = fixtureUnsignedBundle();
    const corrupt = JSON.parse(signUncheckedBundle(input, ["buyer", "seller"], "buyer")) as {
      signatures: Array<{ party: string; value: string }>;
    };
    corrupt.signatures.find((signature) => signature.party === input.parties[1]!.primaryClaim)!.value = "A".repeat(86);
    const canonicalJson = canonicalize(corrupt);
    const cases = [
      {
        ...fixtureBundleAuthorityOptions,
        resolveListingRef: () => ({ status: "indeterminate" as const, reason: "Listing timeout" }),
      },
      {
        ...fixtureBundleAuthorityOptions,
        resolveExecutedPhasePlan: () => ({ status: "indeterminate" as const, reason: "phase-plan timeout" }),
      },
      {
        ...fixtureBundleAuthorityOptions,
        resolvePartyIdentity: (party: Readonly<Record<string, unknown>>) =>
          party["role"] === "buyer"
            ? { status: "indeterminate" as const, reason: "buyer identity timeout" }
            : fixtureBundleAuthorityOptions.resolvePartyIdentity(party),
      },
    ];
    for (const authorities of cases) {
      expect(verifyCanonicalAttestationBundleJson(canonicalJson, {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...authorities,
        resolveAttestationRef: fixtureReferenceResolver,
      })).toMatchObject({ disposition: "rejected", stage: "signatures" });
    }
  });

  test("rejects non-bijective settlement references before resolver uncertainty", () => {
    const input = fixtureUnsignedBundle();
    const cases = [
      { ...input, settlementEvidence: [input.settlementEvidence[0]!, input.settlementEvidence[0]!] },
      { ...input, settlementEvidence: input.settlementEvidence.slice(1) },
    ];
    for (const candidate of cases) {
      expect(verifyCanonicalAttestationBundleJson(
        signUncheckedBundle(candidate, ["buyer", "seller"], "buyer"),
        {
          expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
          ...fixtureBundleAuthorityOptions,
          resolveAttestationRef: () => ({ status: "indeterminate", reason: "resolver unavailable" }),
        },
      )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    }
  });

  test("validates signature encoding before an unavailable signer key", () => {
    const input = fixtureUnsignedBundle();
    const artifact = JSON.parse(signUncheckedBundle(input, ["buyer", "seller"], "buyer")) as {
      signatures: Array<{ party: string; value: string }>;
    };
    artifact.signatures[0]!.value = "not-base64url";
    expect(verifyCanonicalAttestationBundleJson(canonicalize(artifact), {
      expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
      ...fixtureBundleAuthorityOptions,
      resolvePartyIdentity: (party) => party["role"] === "buyer"
        ? { status: "indeterminate", reason: "buyer identity unavailable" }
        : fixtureBundleAuthorityOptions.resolvePartyIdentity(party),
      resolveAttestationRef: fixtureReferenceResolver,
    })).toMatchObject({ disposition: "rejected", stage: "signatures" });
  });

  test("rejects malformed optional reference arrays and unauthenticated signer hints", () => {
    const input = fixtureUnsignedBundle();
    for (const malformed of [
      { ...input, amendments: {} },
      { ...input, ratingRefs: [{ contentHash: "8".repeat(64) }] },
    ]) {
      const copy = signUncheckedBundle(malformed as typeof input, ["buyer", "seller"], "buyer");
      expect(verifyCanonicalAttestationBundleJson(copy, {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      })).toMatchObject({ disposition: "rejected", stage: "shape" });
    }
    const authority = orchestratorFixtureSigner().signer;
    const hintedRef = { ...input.settlementEvidence[0]!, signer: authority };
    const hinted = fixtureUnsignedBundle({
      phaseSummary: [
        { ...input.phaseSummary[0]!, attestationRef: hintedRef },
        input.phaseSummary[1]!,
      ],
      settlementEvidence: [hintedRef, input.settlementEvidence[1]!],
    });
    const copy = signUncheckedBundle(hinted, ["buyer", "seller"], "buyer");
    expect(verifyCanonicalAttestationBundleJson(copy, {
      expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: (ref, context) => {
        const resolved = fixtureReferenceResolver(ref, context);
        const { signer: _signer, ...withoutSigner } = resolved;
        return withoutSigner;
      },
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    const reused = fixtureUnsignedBundle({ phaseSummary: input.phaseSummary.map((phase) => ({
      ...phase, attestationRef: input.settlementEvidence[0]!,
    })) });
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(reused, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "rejected" });
  });

  test("distinguishes absent, indeterminate, and hash-mismatched AttestationRefs", () => {
    const copy = fixtureSignedBundle().copies[0]!;
    const base = {
      expectedAddress: copy.logicalAddress,
      ...fixtureBundleAuthorityOptions,
    };
    expect(verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
      ...base, resolveAttestationRef: () => ({ status: "absent" }),
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    expect(verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
      ...base, resolveAttestationRef: () => ({ status: "indeterminate", reason: "storage unavailable" }),
    })).toMatchObject({ disposition: "indeterminate", stage: "reference-resolution" });
    expect(verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
      ...base, resolveAttestationRef: () => ({ status: "rejected", reason: "authenticated evidence is corrupt" }),
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    expect(verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
      ...base, resolveAttestationRef: (ref, context) => ({
        ...fixtureReferenceResolver(ref, context), contentHash: "0".repeat(64),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    expect(verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
      ...base, resolveAttestationRef: (ref, context) => ({
        ...fixtureReferenceResolver(ref, context), jobId: "01ARZ3NDEKTSV4RRFFQ69G5FB0",
      }),
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    const phaseInput = fixtureUnsignedBundle({ phaseSummary: [
      { ...fixtureUnsignedBundle().phaseSummary[0]!, attestationRef: fixtureUnsignedBundle().settlementEvidence[0]! },
      fixtureUnsignedBundle().phaseSummary[1]!,
    ] });
    const phaseCopy = signAttestationBundle(
      phaseInput, fixtureBundleSigners(), ["buyer", "seller"], FIXTURE_SIGNING_CONTEXT,
      fixtureReferenceResolver, fixtureBundleAuthorityOptions,
    ).copies[0]!;
    expect(verifyCanonicalAttestationBundleJson(phaseCopy.canonicalJson, {
      ...base, resolveAttestationRef: (ref, context) => ({
        ...fixtureReferenceResolver(ref, context),
        ...(context.usage === "phase" ? { phaseIndex: context.expectedPhaseIndex! + 1 } : {}),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
  });

  test("binds settlement references to phases and resolves duplicate references in every usage", () => {
    const input = fixtureUnsignedBundle();
    const usages: string[] = [];
    const duplicate = {
      ...input,
      agreementRef: {
        anchor: { kind: "storage-program", locator: `dacs3:agreement:${input.jobId}` },
        contentHash: "2".repeat(64),
      },
    };
    const copy = signUncheckedBundle(duplicate, ["buyer", "seller"], "buyer");
    expect(verifyCanonicalAttestationBundleJson(copy, {
      expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: (ref, context) => {
        usages.push(context.usage);
        return fixtureReferenceResolver(ref, context);
      },
    })).toMatchObject({ disposition: "verified" });
    expect(usages.filter((usage) => usage === "agreement")).toHaveLength(1);
    expect(usages.filter((usage) => usage === "settlement")).toHaveLength(2);
    expect(usages.filter((usage) => usage === "phase")).toHaveLength(2);

    expect(verifyCanonicalAttestationBundleJson(copy, {
      expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: (ref, context) => ({
        ...fixtureReferenceResolver(ref, context),
        ...(context.usage === "phase" ? { signer: input.parties[0]!.primaryClaim } : {}),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });

    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle({ ...input, agreementRef: input.settlementEvidence[0]! }, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: fixtureReferenceResolver,
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });

    const contradictoryPointer = {
      anchor: { kind: "storage-program", locator: `dacs4:alternate-payment-evidence:${input.jobId}:2` },
      contentHash: "9".repeat(64),
    };
    const pointerConflict = {
      ...input,
      phaseSummary: [{ ...input.phaseSummary[0]!, attestationRef: contradictoryPointer }, input.phaseSummary[1]!],
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(pointerConflict, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: (ref, context) => context.usage === "phase"
          ? {
            ...fixtureReferenceResolver(input.settlementEvidence[0]!, context),
            anchorLocator: (ref["anchor"] as Record<string, unknown>)["locator"] as string,
            contentHash: ref["contentHash"] as string,
          }
          : fixtureReferenceResolver(ref, context),
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });

    for (const settlementEvidence of [
      input.settlementEvidence.slice(0, 1),
      [input.settlementEvidence[0]!, input.settlementEvidence[0]!, input.settlementEvidence[1]!],
    ]) {
      expect(verifyCanonicalAttestationBundleJson(
        signUncheckedBundle({ ...input, settlementEvidence }, ["buyer", "seller"], "buyer"),
        {
          expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
          ...fixtureBundleAuthorityOptions,
          resolveAttestationRef: fixtureReferenceResolver,
        },
      )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
    }

    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: (ref, context) => ({
          ...fixtureReferenceResolver(ref, context),
          ...(context.usage === "settlement"
            ? { phaseIndex: context.expectedPhaseIndex! + 1 }
            : {}),
        }),
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });

    const authenticatedPhases = [
      { index: 1, kind: "commit-payee-bound-agreement" },
      { index: 2, kind: "pay-x402" },
      { index: 3, kind: "deliver-attested-payload" },
    ] as const;
    const completePlan = {
      ...input,
      phaseSummary: authenticatedPhases.map(({ index, kind }) => ({ index, kind, outcome: "ok" as const })),
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(completePlan, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveExecutedPhasePlan: () => ({
          status: "verified" as const,
          railRegistryVersion: 1,
          recipeRegistryVersion: 1,
          phases: authenticatedPhases,
        }),
        resolveAttestationRef: (ref, context) => {
          const resolved = fixtureReferenceResolver(ref, context);
          if (context.usage !== "settlement") return resolved;
          const isPayment = ((ref["anchor"] as Record<string, unknown>)["locator"] as string)
            .includes(":payment-evidence:");
          return {
            ...resolved,
            phaseIndex: isPayment ? 1 : 2,
            phaseKind: isPayment ? "commit-payee-bound-agreement" : "pay-x402",
          };
        },
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });

    const incompleteWithUncertainRating = {
      ...input,
      settlementEvidence: input.settlementEvidence.slice(0, 1),
      ratingRefs: [{
        anchor: { kind: "storage-program", locator: `dacs5:rating:${input.jobId}` },
        contentHash: "8".repeat(64),
      }],
    };
    expect(verifyCanonicalAttestationBundleJson(
      signUncheckedBundle(incompleteWithUncertainRating, ["buyer", "seller"], "buyer"),
      {
        expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
        ...fixtureBundleAuthorityOptions,
        resolveAttestationRef: (ref, context) => context.usage === "rating"
          ? { status: "indeterminate" as const, reason: "rating store unavailable" }
          : fixtureReferenceResolver(ref, context),
      },
    )).toMatchObject({ disposition: "rejected", stage: "reference-resolution" });
  });
});

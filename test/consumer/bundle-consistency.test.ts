import { describe, expect, test } from "bun:test";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  reconcileAttestationBundleReads,
  type BundleLookupDisposition,
} from "../../src/consumer/bundle-consistency.ts";
import { verifyCanonicalAttestationBundleJson } from "../../src/consumer/attestation-bundle-verifier.ts";
import { bundleLogicalAddress } from "../../src/producer/attestation-bundle.ts";
import {
  fixtureBundleAuthorityOptions,
  fixtureReferenceResolver,
  fixtureSignedBundle,
  fixtureUnsignedBundle,
  orchestratorFixtureSigner,
  signUncheckedBundle,
} from "../fixtures/reference-bundle.ts";

const absent = { status: "absent", authority: "authoritative" } as const;
const options = { ...fixtureBundleAuthorityOptions, resolveAttestationRef: fixtureReferenceResolver };
type ExpectedLookupDisposition = "absent" | "indeterminate" | "one-sided" | "unified" | "divergent";
type IsExact<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends (<Value>() => Value extends Right ? 1 : 2)
    ? (<Value>() => Value extends Right ? 1 : 2) extends (<Value>() => Value extends Left ? 1 : 2)
      ? true
      : false
    : false;
const exactLookupDispositionType: IsExact<BundleLookupDisposition, ExpectedLookupDisposition> = true;
const lookupDispositions = {
  absent: true,
  indeterminate: true,
  "one-sided": true,
  unified: true,
  divergent: true,
} as const satisfies Record<BundleLookupDisposition, true>;

describe("two-address AttestationBundle reconciliation", () => {
  test("unifies two full copies and prefers the scored party's advisory copy", () => {
    const signed = fixtureSignedBundle();
    const result = reconcileAttestationBundleReads(fixtureUnsignedBundle().jobId, {
      buyer: { status: "present", canonicalJson: signed.copies[0]!.canonicalJson },
      seller: { status: "present", canonicalJson: signed.copies[1]!.canonicalJson },
    }, options, "seller");
    expect(result).toMatchObject({ disposition: "unified", reputationEligibility: "eligible", preferredRole: "seller" });
  });

  test("uses one immutable party-authority snapshot across authentication and full verification", () => {
    const signed = fixtureSignedBundle();
    const calls = new Map<string, number>();
    const result = reconcileAttestationBundleReads(fixtureUnsignedBundle().jobId, {
      buyer: { status: "present", canonicalJson: signed.copies[0]!.canonicalJson },
      seller: { status: "present", canonicalJson: signed.copies[1]!.canonicalJson },
    }, {
      ...options,
      resolvePartyIdentity: (party) => {
        const claim = party["primaryClaim"] as string;
        calls.set(claim, (calls.get(claim) ?? 0) + 1);
        return fixtureBundleAuthorityOptions.resolvePartyIdentity(party);
      },
    });
    expect(result).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });
    expect([...calls.values()].sort()).toEqual([1, 1]);
  });

  test("replays a party-authority resolver exception for the full reconciliation", () => {
    const signed = fixtureSignedBundle();
    let buyerCalls = 0;
    const result = reconcileAttestationBundleReads(fixtureUnsignedBundle().jobId, {
      buyer: { status: "present", canonicalJson: signed.copies[0]!.canonicalJson },
      seller: { status: "present", canonicalJson: signed.copies[1]!.canonicalJson },
    }, {
      ...options,
      resolvePartyIdentity: (party) => {
        if (party["role"] === "buyer") {
          buyerCalls += 1;
          if (buyerCalls === 1) throw new Error("identity store unavailable");
        }
        return fixtureBundleAuthorityOptions.resolvePartyIdentity(party);
      },
    });
    expect(result).toMatchObject({ disposition: "indeterminate", reputationEligibility: "indeterminate" });
    expect(buyerCalls).toBe(1);
  });

  test("treats finalisation and rating skew as advisory", () => {
    const input = fixtureUnsignedBundle();
    const buyer = signUncheckedBundle(input, ["buyer", "seller"], "buyer");
    const seller = signUncheckedBundle({ ...input, finalisedAt: input.finalisedAt + 1, ratingRefs: [{
      anchor: { kind: "storage-program", locator: "dacs5:rating:seller" }, contentHash: "8".repeat(64),
    }] }, ["buyer", "seller"], "seller");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer }, seller: { status: "present", canonicalJson: seller },
    }, options)).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });
  });

  test("normalizes amendment ordering but preserves amendment contents", () => {
    const input = fixtureUnsignedBundle();
    const amendments = [
      { anchor: { kind: "storage-program", locator: "dacs5:amendment:one" }, contentHash: "7".repeat(64) },
      { anchor: { kind: "storage-program", locator: "dacs5:amendment:two" }, contentHash: "8".repeat(64) },
    ];
    const buyerInput = { ...input, amendments };
    const reorderedSellerInput = { ...input, amendments: [...amendments].reverse() };
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: signUncheckedBundle(buyerInput, ["buyer", "seller"], "buyer") },
      seller: { status: "present", canonicalJson: signUncheckedBundle(reorderedSellerInput, ["buyer", "seller"], "seller") },
    }, options)).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });

    const changedSellerInput = {
      ...reorderedSellerInput,
      amendments: [{ ...amendments[0]!, contentHash: "9".repeat(64) }, amendments[1]!],
    };
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: signUncheckedBundle(buyerInput, ["buyer", "seller"], "buyer") },
      seller: { status: "present", canonicalJson: signUncheckedBundle(changedSellerInput, ["buyer", "seller"], "seller") },
    }, options)).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
  });

  test("fails reputation closed for outcome, phase-core, and phase-presence contradictions", () => {
    const input = fixtureUnsignedBundle();
    const failedCounterparty = {
      ...input,
      outcome: "failed-counterparty" as const,
      phaseSummary: [
        { ...input.phaseSummary[0]!, outcome: "fail" as const, errorClass: "counterparty" as const },
        input.phaseSummary[1]!,
      ],
    };
    const cases = [
      { name: "outcome", buyer: input, seller: { ...input, outcome: "aborted-by-self" as const } },
      {
        name: "phase kind",
        buyer: input,
        seller: { ...input, phaseSummary: [{ ...input.phaseSummary[0]!, kind: "pay-dem" }, input.phaseSummary[1]!] },
      },
      {
        name: "phase outcome",
        buyer: input,
        seller: { ...input, phaseSummary: failedCounterparty.phaseSummary },
      },
      {
        name: "phase errorClass",
        buyer: failedCounterparty,
        seller: {
          ...failedCounterparty,
          phaseSummary: [
            { ...failedCounterparty.phaseSummary[0]!, errorClass: "settlement-atomicity" as const },
            failedCounterparty.phaseSummary[1]!,
          ],
        },
      },
      {
        name: "phase presence",
        buyer: input,
        seller: {
          ...input,
          phaseSummary: input.phaseSummary.slice(0, 1),
          settlementEvidence: input.settlementEvidence.slice(0, 1),
        },
      },
    ];
    for (const candidate of cases) {
      const result = reconcileAttestationBundleReads(input.jobId, {
        buyer: { status: "present", canonicalJson: signUncheckedBundle(candidate.buyer, ["buyer", "seller"], "buyer") },
        seller: { status: "present", canonicalJson: signUncheckedBundle(candidate.seller, ["buyer", "seller"], "seller") },
      }, options);
      expect(result).toMatchObject({
        disposition: "divergent",
        reputationEligibility: "excluded",
      });
    }
  });

  test("fails reputation closed for every non-advisory shared authority difference", () => {
    const input = fixtureUnsignedBundle({ extensionProof: { version: 1, value: "bound" } });
    const cases = [
      { ...input, recipeRegistryVersion: 2 },
      { ...input, listingRef: { ...input.listingRef, contentHash: "9".repeat(64) } },
      { ...input, parties: input.parties.map((party, index) => index === 0
        ? { ...party, bundleHash: "a".repeat(64) } : party) },
      { ...input, extensionProof: { version: 1, value: "changed" } },
    ];
    for (const [index, sellerInput] of cases.entries()) {
      expect(reconcileAttestationBundleReads(input.jobId, {
        buyer: { status: "present", canonicalJson: signUncheckedBundle(input, ["buyer", "seller"], "buyer") },
        seller: { status: "present", canonicalJson: signUncheckedBundle(sellerInput, ["buyer", "seller"], "seller") },
      }, options)).toMatchObject({
        disposition: index === cases.length - 1 ? "divergent" : "rejected",
        reputationEligibility: "excluded",
      });
    }
  });

  test("distinguishes qualified absence from indeterminate and invalid content", () => {
    expect(exactLookupDispositionType).toBeTrue();
    const input = fixtureUnsignedBundle();
    const buyer = signUncheckedBundle(input, ["buyer", "seller"], "buyer");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer }, seller: absent,
    }, options)).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer }, seller: { status: "indeterminate", reason: "timeout" },
    }, options)).toMatchObject({ disposition: "indeterminate", reputationEligibility: "indeterminate" });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: absent, seller: absent,
    }, options)).toMatchObject({ disposition: "absent", reputationEligibility: "not-applicable" });
    for (const reads of [
      { buyer: { status: "indeterminate" as const, reason: "buyer timeout" }, seller: absent },
      { buyer: absent, seller: { status: "indeterminate" as const, reason: "seller timeout" } },
      {
        buyer: { status: "indeterminate" as const, reason: "buyer timeout" },
        seller: { status: "indeterminate" as const, reason: "seller timeout" },
      },
    ]) {
      expect(reconcileAttestationBundleReads(input.jobId, reads, options)).toMatchObject({
        disposition: "indeterminate", reputationEligibility: "indeterminate",
      });
    }
    const invalid = JSON.parse(buyer);
    invalid.finalisedAt += 1;
    const rejected = reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: canonicalize(invalid) }, seller: absent,
    }, options);
    expect(rejected).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
    expect(Object.hasOwn(lookupDispositions, rejected.disposition)).toBeFalse();
  });

  test("rejects every single-signed non-abort outcome", () => {
    const input = fixtureUnsignedBundle();
    const cases = [
      { outcome: "completed" as const, phaseSummary: input.phaseSummary },
      {
        outcome: "failed-perm" as const,
        phaseSummary: [{ ...input.phaseSummary[0]!, outcome: "fail" as const, errorClass: "permanent" as const }, input.phaseSummary[1]!],
      },
      {
        outcome: "failed-counterparty" as const,
        phaseSummary: [{ ...input.phaseSummary[0]!, outcome: "fail" as const, errorClass: "counterparty" as const }, input.phaseSummary[1]!],
      },
      {
        outcome: "failed-substrate" as const,
        phaseSummary: [{ ...input.phaseSummary[0]!, outcome: "fail" as const, errorClass: "substrate" as const }, input.phaseSummary[1]!],
      },
    ];
    for (const candidate of cases) {
      for (const role of ["buyer", "seller"] as const) {
        const copy = signUncheckedBundle({ ...input, ...candidate }, [role], role);
        const reads = role === "buyer"
          ? { buyer: { status: "present" as const, canonicalJson: copy }, seller: absent }
          : { buyer: absent, seller: { status: "present" as const, canonicalJson: copy } };
        expect(reconcileAttestationBundleReads(input.jobId, reads, options)).toMatchObject({
          disposition: "rejected", reputationEligibility: "excluded",
        });
      }
    }
  });

  test("rejects unexpected orchestrator-address content for a two-party bundle", () => {
    const input = fixtureUnsignedBundle();
    const buyer = signUncheckedBundle(input, ["buyer", "seller"], "buyer");
    const seller = signUncheckedBundle(input, ["buyer", "seller"], "seller");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "present", canonicalJson: seller },
      orchestrator: { status: "present", canonicalJson: buyer },
    }, options)).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
  });

  test("attributes a single-signed abort only with qualified counterpart absence", () => {
    const completed = fixtureUnsignedBundle();
    const input = fixtureUnsignedBundle({
      outcome: "aborted-by-other",
      phaseSummary: completed.phaseSummary.slice(0, -1),
      settlementEvidence: completed.settlementEvidence.slice(0, -1),
    });
    const buyer = signUncheckedBundle(input, ["buyer"], "buyer");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer }, seller: absent,
    }, options)).toMatchObject({
      disposition: "one-sided", reputationEligibility: "eligible",
      attribution: { buyer: "counterparty", seller: "self" },
    });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "indeterminate", reason: "seller timeout" },
    }, options)).toMatchObject({ disposition: "indeterminate", reputationEligibility: "indeterminate" });
    const sellerAbort = signUncheckedBundle(input, ["seller"], "seller");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "indeterminate", reason: "buyer timeout" },
      seller: { status: "present", canonicalJson: sellerAbort },
    }, options)).toMatchObject({ disposition: "indeterminate", reputationEligibility: "indeterminate" });
    const nonAbort = signUncheckedBundle({ ...input, outcome: "completed" }, ["buyer"], "buyer");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: nonAbort }, seller: absent,
    }, options)).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
    const wrongAnchor = signUncheckedBundle(input, ["seller"], "buyer");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: wrongAnchor }, seller: absent,
    }, options)).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
    const seller = signUncheckedBundle(input, ["seller"], "seller");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "present", canonicalJson: seller },
    }, options)).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
  });

  test("rejects an undeclared distinct phase-evidence authority", () => {
    const input = fixtureUnsignedBundle();
    const authority = `key:${"a".repeat(64)}`;
    const settlementEvidence = input.settlementEvidence.map((ref, index) =>
      index === 0 ? { ...ref, signer: authority } : ref);
    const mutated = { ...input, settlementEvidence };
    const buyer = signUncheckedBundle(mutated, ["buyer", "seller"], "buyer");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer }, seller: absent,
    }, options)).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
  });

  test("requires the declared orchestrator copy to converge after restart", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    const buyer = signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "buyer");
    const seller = signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "seller");
    const orchestratorCopy = signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "orchestrator");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "present", canonicalJson: seller },
      orchestrator: absent,
    }, options)).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "present", canonicalJson: seller },
      orchestrator: { status: "present", canonicalJson: orchestratorCopy },
    }, options)).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: absent,
      orchestrator: { status: "present", canonicalJson: orchestratorCopy },
    }, options)).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });
  });

  test("classifies an orchestrator-only canonical copy as divergent", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    const orchestratorCopy = signUncheckedBundle(
      input, ["buyer", "seller", "orchestrator"], "orchestrator",
    );
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: absent,
      seller: absent,
      orchestrator: { status: "present", canonicalJson: orchestratorCopy },
    }, options)).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "indeterminate", reason: "buyer store timeout" },
      seller: absent,
      orchestrator: { status: "present", canonicalJson: orchestratorCopy },
    }, options)).toMatchObject({ disposition: "indeterminate", reputationEligibility: "indeterminate" });
  });

  test("distinguishes contradictory and uncertain optional-orchestrator presence", () => {
    const input = fixtureUnsignedBundle();
    const buyer = signUncheckedBundle(input, ["buyer", "seller"], "buyer");
    const seller = signUncheckedBundle(input, ["buyer", "seller"], "seller");
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "present", canonicalJson: seller },
      orchestrator: { status: "indeterminate", reason: "read timeout" },
    }, options)).toMatchObject({ disposition: "unified", reputationEligibility: "eligible" });

    const orchestrator = orchestratorFixtureSigner();
    const abort = fixtureUnsignedBundle({
      outcome: "aborted-by-other",
      parties: [
        ...input.parties,
        { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
      ],
    });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: signUncheckedBundle(abort, ["buyer"], "buyer") },
      seller: absent,
      orchestrator: {
        status: "present",
        canonicalJson: signUncheckedBundle(abort, ["orchestrator"], "orchestrator"),
      },
    }, options)).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
  });

  test("does not let an orchestrator timeout mask known buyer-seller divergence", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    const sellerInput = { ...input, extensionProof: { version: 1, value: "seller-contradiction" } };
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "buyer"),
      },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(sellerInput, ["buyer", "seller", "orchestrator"], "seller"),
      },
      orchestrator: { status: "indeterminate", reason: "read timeout" },
    }, options)).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
  });

  test("does not let present-orchestrator verification uncertainty mask known party divergence", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    const sellerInput = { ...input, extensionProof: { version: 1, value: "seller-contradiction" } };
    const orchestratorInput = {
      ...input,
      ratingRefs: [{
        anchor: { kind: "storage-program", locator: "dacs5:rating:orchestrator" },
        contentHash: "8".repeat(64),
      }],
    };
    const unresolvedOrchestratorOptions = {
      ...options,
      resolveAttestationRef: (
        ref: Parameters<typeof fixtureReferenceResolver>[0],
        context: Parameters<typeof fixtureReferenceResolver>[1],
      ) => context.usage === "rating"
        ? { status: "indeterminate" as const, reason: "rating read timeout" }
        : fixtureReferenceResolver(ref, context),
    };
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "buyer"),
      },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(sellerInput, ["buyer", "seller", "orchestrator"], "seller"),
      },
      orchestrator: {
        status: "present",
        canonicalJson: signUncheckedBundle(orchestratorInput, ["buyer", "seller", "orchestrator"], "orchestrator"),
      },
    }, unresolvedOrchestratorOptions)).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
  });

  test("does not let buyer reference uncertainty mask a rejected seller copy", () => {
    const input = fixtureUnsignedBundle();
    const buyerInput = {
      ...input,
      ratingRefs: [{
        anchor: { kind: "storage-program", locator: "dacs5:rating:buyer" },
        contentHash: "8".repeat(64),
      }],
    };
    const buyer = signUncheckedBundle(buyerInput, ["buyer", "seller"], "buyer");
    const sellerValue = JSON.parse(signUncheckedBundle(input, ["buyer", "seller"], "seller")) as Record<string, unknown>;
    const signatures = sellerValue["signatures"] as Record<string, unknown>[];
    signatures[0]!["value"] = `${signatures[0]!["value"] as string}A`;
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "present", canonicalJson: buyer },
      seller: { status: "present", canonicalJson: canonicalize(sellerValue) },
    }, {
      ...options,
      resolveAttestationRef: (ref, context) => context.usage === "rating"
        ? { status: "indeterminate" as const, reason: "rating unavailable" }
        : fixtureReferenceResolver(ref, context),
    })).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
  });

  test("does not let authenticated advisory uncertainty mask party-copy divergence", () => {
    const input = fixtureUnsignedBundle();
    const sellerInput = {
      ...input,
      extensionProof: { version: 1, value: "seller-contradiction" },
      ratingRefs: [{
        anchor: { kind: "storage-program", locator: "dacs5:rating:seller-uncertain" },
        contentHash: "8".repeat(64),
      }],
    };
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(sellerInput, ["buyer", "seller"], "seller"),
      },
    }, {
      ...options,
      resolveAttestationRef: (ref, context) => context.usage === "rating"
        ? { status: "indeterminate" as const, reason: "rating unavailable" }
        : fixtureReferenceResolver(ref, context),
    })).toMatchObject({ disposition: "divergent", reputationEligibility: "excluded" });
  });

  test("requires repeated reference authority to converge across role-local copies", () => {
    const input = fixtureUnsignedBundle();
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller"], "seller"),
      },
    }, {
      ...options,
      resolveAttestationRef: (ref, context) => {
        const resolved = fixtureReferenceResolver(ref, context);
        return resolved.artifactType === "phase-evidence"
          ? { ...resolved, signer: context.anchoredByRole === "buyer"
            ? input.parties[0]!.primaryClaim : input.parties[1]!.primaryClaim }
          : resolved;
      },
    })).toMatchObject({
      disposition: "rejected",
      reputationEligibility: "excluded",
      reason: "Role-local copies resolved one AttestationRef to inconsistent authenticated authority",
    });
  });

  test("rejects authenticated reference-authority drift from the orchestrator copy", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    let orchestratorReferences = 0;
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "buyer"),
      },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "seller"),
      },
      orchestrator: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "orchestrator"),
      },
    }, {
      ...options,
      resolveAttestationRef: (ref, context) => {
        const resolved = fixtureReferenceResolver(ref, context);
        if (resolved.artifactType !== "phase-evidence" || context.anchoredByRole !== "orchestrator") {
          return resolved;
        }
        orchestratorReferences += 1;
        return { ...resolved, signer: orchestrator.signer };
      },
    })).toMatchObject({
      disposition: "rejected",
      reputationEligibility: "excluded",
      reason: "Role-local copies resolved one AttestationRef to inconsistent authenticated authority",
    });
    expect(orchestratorReferences).toBeGreaterThan(0);
  });

  test("classifies signed shared-scope divergence before reference-authority conflict", () => {
    const input = fixtureUnsignedBundle();
    const sellerInput = { ...input, extensionProof: { version: 1, value: "seller-contradiction" } };
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller"], "buyer"),
      },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(sellerInput, ["buyer", "seller"], "seller"),
      },
    }, {
      ...options,
      resolveAttestationRef: (ref, context) => {
        const resolved = fixtureReferenceResolver(ref, context);
        return resolved.artifactType === "phase-evidence"
          ? { ...resolved, signer: context.anchoredByRole === "buyer"
            ? input.parties[0]!.primaryClaim : input.parties[1]!.primaryClaim }
          : resolved;
      },
    })).toMatchObject({
      disposition: "divergent",
      reputationEligibility: "excluded",
      reason: "Authenticated party copies contradict on required shared authority fields",
    });
  });

  test("classifies an authenticated-indeterminate orchestrator contradiction as divergent", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    const orchestratorInput = {
      ...input,
      extensionProof: { version: 1, value: "orchestrator-contradiction" },
      ratingRefs: [{
        anchor: { kind: "storage-program", locator: "dacs5:rating:orchestrator-uncertain" },
        contentHash: "8".repeat(64),
      }],
    };
    const orchestratorCopy = signUncheckedBundle(
      orchestratorInput, ["buyer", "seller", "orchestrator"], "orchestrator",
    );
    let ratingResolutions = 0;
    const resolver = (
      ref: Parameters<typeof fixtureReferenceResolver>[0],
      context: Parameters<typeof fixtureReferenceResolver>[1],
    ) => {
      if (context.usage === "rating") {
        ratingResolutions += 1;
        return { status: "indeterminate" as const, reason: "rating unavailable" };
      }
      return fixtureReferenceResolver(ref, context);
    };
    const standalone = verifyCanonicalAttestationBundleJson(orchestratorCopy, {
      expectedAddress: bundleLogicalAddress(input.jobId, "orchestrator"),
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: resolver,
    });
    expect(standalone.disposition).toBe("indeterminate");
    if (standalone.disposition !== "indeterminate") throw new Error(JSON.stringify(standalone));
    expect(standalone.authenticatedArtifact).toBeDefined();
    expect(ratingResolutions).toBe(1);

    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "buyer"),
      },
      seller: absent,
      orchestrator: {
        status: "present",
        canonicalJson: orchestratorCopy,
      },
    }, {
      ...options,
      resolveAttestationRef: resolver,
    })).toMatchObject({
      disposition: "divergent",
      reputationEligibility: "excluded",
      reason: "Authenticated party and orchestrator copies contradict",
    });
    expect(ratingResolutions).toBe(2);
  });

  test("does not let party uncertainty mask a rejected declared orchestrator read", () => {
    const orchestrator = orchestratorFixtureSigner();
    const input = fixtureUnsignedBundle({ parties: [
      ...fixtureUnsignedBundle().parties,
      { role: "orchestrator", bundleHash: "7".repeat(64), primaryClaim: orchestrator.signer },
    ] });
    expect(reconcileAttestationBundleReads(input.jobId, {
      buyer: { status: "indeterminate", reason: "buyer read timeout" },
      seller: {
        status: "present",
        canonicalJson: signUncheckedBundle(input, ["buyer", "seller", "orchestrator"], "seller"),
      },
      orchestrator: { status: "rejected", reason: "authoritative orchestrator corruption" },
    }, options)).toMatchObject({ disposition: "rejected", reputationEligibility: "excluded" });
  });
});

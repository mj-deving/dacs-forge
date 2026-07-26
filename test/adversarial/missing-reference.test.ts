import { describe, expect, test } from "bun:test";

import { verifyCanonicalAttestationBundleJson } from "../../src/consumer/attestation-bundle-verifier.ts";
import { bundleLogicalAddress } from "../../src/producer/attestation-bundle.ts";
import {
  fixtureBundleAuthorityOptions,
  fixtureReferenceResolver,
  fixtureSignedBundle,
  fixtureUnsignedBundle,
  signUncheckedBundle,
} from "../fixtures/reference-bundle.ts";

describe("ISC-39 required bundle references", () => {
  test("rejects each structurally required reference surface when omitted", () => {
    const input = fixtureUnsignedBundle();
    for (const field of ["listingRef", "settlementEvidence"] as const) {
      const candidate = structuredClone(input) as Record<string, unknown>;
      delete candidate[field];
      const result = verifyCanonicalAttestationBundleJson(
        signUncheckedBundle(candidate as typeof input, ["buyer", "seller"], "buyer"),
        {
          expectedAddress: bundleLogicalAddress(input.jobId, "buyer"),
          ...fixtureBundleAuthorityOptions,
          resolveAttestationRef: fixtureReferenceResolver,
        },
      );
      expect(result.disposition, field).toBe("rejected");
    }
  });

  test("maps authoritative absence on every required authority class to refusal", () => {
    const copy = fixtureSignedBundle().copies[0]!;
    const base = {
      expectedAddress: copy.logicalAddress,
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: fixtureReferenceResolver,
    };
    const cases = [
      { ...base, resolveListingRef: () => ({ status: "absent" as const }) },
      { ...base, resolvePartyIdentity: () => ({ status: "absent" as const }) },
      { ...base, resolveExecutedPhasePlan: () => ({ status: "absent" as const }) },
      { ...base, resolveAttestationRef: () => ({ status: "absent" as const }) },
    ];
    for (const options of cases) {
      expect(verifyCanonicalAttestationBundleJson(copy.canonicalJson, options).disposition)
        .toBe("rejected");
    }
  });
});

import { describe, expect, test } from "bun:test";
import { verifyCanonicalAgreementJson } from "../../src/consumer/agreement-verifier.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  ceilCanonicalDecimalToInteger,
  computeMeteredTotal,
} from "../../src/protocol/decimal.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import type { UnsignedAgreementArtifact } from "../../src/producer/agreement.ts";
import {
  FIXTURE_COMMITTED_AT,
  FIXTURE_JOB_ID,
  fixtureSignedPaidListing,
  fixtureUnsignedPayeeBoundAgreement,
  fixtureVettedPartyCheck,
  signUncheckedFixtureAgreement,
} from "../fixtures/reference-agreement.ts";

const VECTOR_PATH = new URL(
  "../../vectors/dacs-standard-metered-pricing-4bb9e48.json",
  import.meta.url,
);

interface MeteredVector {
  readonly name: string;
  readonly rule: string;
  readonly surface: "agreement-validation" | "quantity-derivation";
  readonly expected: "accept" | "reject";
  readonly pricing?: Record<string, unknown>;
  readonly terms?: Record<string, unknown>;
  readonly rawMeasurement?: string;
  readonly want: {
    readonly quantity?: string;
    readonly computedAmount?: string;
    readonly reason?: string;
    readonly commitAgreement?: boolean;
  };
}

interface MeteredCorpus {
  readonly set: string;
  readonly spec: string;
  readonly hash: string;
  readonly count: number;
  readonly vectors: readonly MeteredVector[];
}

const corpus = JSON.parse(await Bun.file(VECTOR_PATH).text()) as MeteredCorpus;

describe("DACS v0.4 metered-pricing conformance", () => {
  test("pins the exact upstream corpus projection", () => {
    expect(corpus.set).toBe("metered-pricing-v0.3");
    expect(corpus.count).toBe(22);
    expect(corpus.vectors).toHaveLength(corpus.count);
    expect(sha256Hex(canonicalize(corpus.vectors))).toBe(corpus.hash);
    expect(corpus.hash).toBe("aa23887618b8c7670e43504a2ce9837ae32ced5eb72c236c61768724864efddb");
    const covered = new Set(corpus.vectors.flatMap((vector) => vector.rule.match(/MTR-[1-5]/g) ?? []));
    expect([...covered].sort()).toEqual(["MTR-1", "MTR-2", "MTR-3", "MTR-4", "MTR-5"]);
  });

  test("derives canonical whole-unit quantities with exact decimal ceil", () => {
    const vectors = corpus.vectors.filter((vector) => vector.surface === "quantity-derivation");
    expect(vectors).toHaveLength(3);
    for (const vector of vectors) {
      expect(vector.expected, vector.name).toBe("accept");
      expect(ceilCanonicalDecimalToInteger(vector.rawMeasurement!), vector.name).toBe(vector.want.quantity!);
    }
  });

  test("executes every agreement vector through the independent consumer", () => {
    const vectors = corpus.vectors.filter((vector) => vector.surface === "agreement-validation");
    expect(vectors).toHaveLength(19);
    for (const vector of vectors) {
      const result = verifyAgreementVector(vector);
      if (vector.expected === "accept") {
        expect(result.disposition, vector.name).toBe("verified");
      } else if (vector.want.reason === "unrecognized-pricing-kind") {
        expect(result, vector.name).toMatchObject({
          disposition: "refused-unsupported",
          stage: "pricing",
          reason: "unrecognized-pricing-kind",
        });
        expect(vector.want.commitAgreement).toBe(false);
      } else {
        expect(result.disposition, vector.name).toBe("rejected");
      }

      if (vector.want.computedAmount !== undefined) {
        const pricing = vector.pricing!;
        const terms = vector.terms!;
        const unitPrice = pricing["unitPrice"] as Record<string, unknown>;
        const quantity = terms["meteredQuantity"] as Record<string, unknown>;
        const minimum = pricing["minTotal"] as Record<string, unknown> | undefined;
        expect(computeMeteredTotal(
          unitPrice["amount"] as string,
          quantity["quantity"] as string,
          minimum?.["amount"] as string | undefined,
        ), vector.name).toBe(vector.want.computedAmount);
      }
    }
  });
});

function verifyAgreementVector(vector: MeteredVector) {
  const source = fixtureSignedPaidListing();
  const listing = clone(source.listing) as Record<string, unknown>;
  listing["pricing"] = clone(vector.pricing!);
  const listingCanonicalJson = canonicalize(listing);
  const listingHash = sha256Hex(canonicalize(omit(listing, "signature")));

  const input = clone(fixtureUnsignedPayeeBoundAgreement(source)) as unknown as Record<string, unknown>;
  (input["listingRef"] as Record<string, unknown>)["contentHash"] = listingHash;
  input["terms"] = {
    ...(input["terms"] as Record<string, unknown>),
    ...clone(vector.terms!),
  };
  const agreementInput = input as unknown as UnsignedAgreementArtifact;
  const signed = signUncheckedFixtureAgreement(agreementInput);
  return verifyCanonicalAgreementJson(signed.canonicalJson, {
    temporalContext: {
      mode: "post-anchor",
      committedAt: FIXTURE_COMMITTED_AT,
      agreementHash: signed.agreementHash,
    },
    expectedCommitPhase: "commit-payee-bound-agreement",
    expectedJobId: FIXTURE_JOB_ID,
    listingCanonicalJson,
    listingVerification: {
      disposition: "accepted",
      contentHash: listingHash,
      listingId: listing["listingId"] as string,
      listingVersion: listing["listingVersion"] as number,
    },
    vettedPartyCheck: fixtureVettedPartyCheck(agreementInput),
  });
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function omit(value: Record<string, unknown>, field: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

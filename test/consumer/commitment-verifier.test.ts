import { describe, expect, test } from "bun:test";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  COMMITMENT_DOMAIN,
  commitmentLogicalAddress,
  signCommitmentRecord,
  type UnsignedCommitmentRecord,
} from "../../src/producer/commitment.ts";
import {
  verifyCanonicalCommitmentJson as verifyCanonicalCommitmentJsonRaw,
  verifyCommittedAgreementCryptography,
  type CommitmentVerificationOptions,
  type CommitmentVerificationResult,
} from "../../src/consumer/commitment-verifier.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { fixtureSigner, FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";
import {
  FIXTURE_COMMITTED_AT,
  FIXTURE_JOB_ID,
  fixtureUnsignedPayeeBoundAgreement,
  signUncheckedFixtureAgreement,
} from "../fixtures/reference-agreement.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";

describe("independent commitment verifier", () => {
  test("verifies the exact signed scope and retains unknown signed fields", () => {
    const signed = signCommitmentRecord({
      ...unsignedCommitment(),
      futureSignedField: { policy: "retained" },
    }, fixtureSigner(), FIXTURE_SIGNING_CONTEXT);
    const verified = verifyCanonicalCommitmentJson(signed.canonicalJson, {
      expectedAgreementHash: signed.commitment.agreementHash,
      expectedJobId: FIXTURE_JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
    });

    expect(verified).toEqual({
      disposition: "verified",
      agreementHash: signed.commitment.agreementHash,
      commitmentHash: signed.commitmentHash,
      committedAt: FIXTURE_COMMITTED_AT,
      jobId: FIXTURE_JOB_ID,
      orchestrator: fixtureSigner().signer,
    });
    expect(signed.commitment.signature.value).toMatch(/^[A-Za-z0-9_-]{86}$/);

    const changed = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    changed["futureSignedField"] = { policy: "changed" };
    expect(verifyCanonicalCommitmentJson(canonicalize(changed)).disposition).toBe("rejected");
  });

  test("requires an authenticated orchestrator binding before accepting a self-signed commitment", () => {
    const attacker = createFixtureEd25519Signer(Buffer.alloc(32, 99), {
      authorityMode: "fixture",
      deploymentMode: "fixture",
    });
    const signed = signCommitmentRecord(
      unsignedCommitment(),
      attacker,
      FIXTURE_SIGNING_CONTEXT,
    );

    expect((verifyCanonicalCommitmentJsonRaw as unknown as (
      canonicalJson: string,
    ) => CommitmentVerificationResult)(signed.canonicalJson)).toMatchObject({
      disposition: "rejected",
      stage: "binding",
      reason: expect.stringContaining("required"),
    });
    expect(verifyCanonicalCommitmentJsonRaw(signed.canonicalJson, {
      expectedOrchestrator: fixtureSigner().signer,
    })).toMatchObject({
      disposition: "rejected",
      stage: "binding",
      reason: expect.stringContaining("expected session orchestrator"),
    });
    expect(verifyCanonicalCommitmentJsonRaw(signed.canonicalJson, {
      expectedOrchestrator: attacker.signer,
    })).toMatchObject({
      disposition: "verified",
      orchestrator: attacker.signer,
    });
  });

  test("rejects non-canonical bytes, signature mutation, and expected-binding mismatch", () => {
    const signed = signCommitmentRecord(unsignedCommitment(), fixtureSigner(), FIXTURE_SIGNING_CONTEXT);
    expect(verifyCanonicalCommitmentJson(JSON.stringify(signed.commitment, null, 2))).toMatchObject({
      disposition: "rejected",
      stage: "canonical-form",
    });

    const invalidSignature = JSON.parse(signed.canonicalJson) as {
      signature: { value: string };
    };
    invalidSignature.signature.value = "A".repeat(86);
    expect(verifyCanonicalCommitmentJson(canonicalize(invalidSignature))).toMatchObject({
      disposition: "rejected",
      stage: "signature",
    });
    expect(verifyCanonicalCommitmentJson(signed.canonicalJson, {
      expectedAgreementHash: "f".repeat(64),
    })).toMatchObject({
      disposition: "rejected",
      stage: "binding",
    });
    expect(verifyCanonicalCommitmentJson(signed.canonicalJson, {
      expectedOrchestrator: `key:${"f".repeat(64)}`,
    })).toMatchObject({
      disposition: "rejected",
      stage: "binding",
    });
  });

  test("fails closed on unsupported algorithms, indirect signers, and byte limits", () => {
    const signed = signCommitmentRecord(unsignedCommitment(), fixtureSigner(), FIXTURE_SIGNING_CONTEXT);
    const unsupportedAlgorithm = JSON.parse(signed.canonicalJson) as {
      signature: { algorithm: string };
    };
    unsupportedAlgorithm.signature.algorithm = "sr1-aggregate";
    expect(verifyCanonicalCommitmentJson(canonicalize(unsupportedAlgorithm))).toMatchObject({
      disposition: "refused-unsupported",
      stage: "signature",
    });

    const indirect = JSON.parse(signed.canonicalJson) as {
      signature: { signer: string };
    };
    indirect.signature.signer = "did:demos:orchestrator";
    expect(verifyCanonicalCommitmentJson(canonicalize(indirect))).toMatchObject({
      disposition: "refused-unsupported",
      stage: "signature",
    });
    expect(verifyCanonicalCommitmentJson(signed.canonicalJson, { maxArtifactBytes: 1 })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "canonical-form",
    });
  });

  test("producer rejects non-canonical, duplicate, and undersized party sets", () => {
    const base = unsignedCommitment();
    expect(() => signCommitmentRecord({
      ...base,
      parties: [base.parties[0]!],
    }, fixtureSigner(), FIXTURE_SIGNING_CONTEXT)).toThrow(/at least two/);
    expect(() => signCommitmentRecord({
      ...base,
      parties: [base.parties[0]!, base.parties[0]!],
    }, fixtureSigner(), FIXTURE_SIGNING_CONTEXT)).toThrow(/unique/);
    expect(() => signCommitmentRecord({
      ...base,
      parties: ["KEY:ABC", base.parties[1]!],
    }, fixtureSigner(), FIXTURE_SIGNING_CONTEXT)).toThrow();
    expect(() => commitmentLogicalAddress([FIXTURE_JOB_ID] as unknown as string)).toThrow(/ULID/);
    expect(() => signCommitmentRecord({
      ...base,
      jobId: [base.jobId],
    } as unknown as UnsignedCommitmentRecord, fixtureSigner(), FIXTURE_SIGNING_CONTEXT)).toThrow(/jobId/);
    expect(() => signCommitmentRecord({
      ...base,
      agreementHash: [base.agreementHash],
    } as unknown as UnsignedCommitmentRecord, fixtureSigner(), FIXTURE_SIGNING_CONTEXT)).toThrow(/agreementHash/);
    expect(() => signCommitmentRecord({
      ...base,
      listingRef: { ...base.listingRef, contentHash: [base.listingRef.contentHash] },
    } as unknown as UnsignedCommitmentRecord, fixtureSigner(), FIXTURE_SIGNING_CONTEXT)).toThrow(/listingRef/);
  });

  test("consumer rejects correctly signed array-coercible ULIDs and hashes", () => {
    const base = unsignedCommitment() as unknown as Record<string, unknown>;
    const mutations: Record<string, unknown>[] = [
      { ...base, jobId: [base["jobId"]] },
      { ...base, agreementHash: [base["agreementHash"]] },
      {
        ...base,
        listingRef: {
          ...(base["listingRef"] as Record<string, unknown>),
          contentHash: [(base["listingRef"] as Record<string, unknown>)["contentHash"]],
        },
      },
    ];
    for (const malformed of mutations) {
      expect(verifyCanonicalCommitmentJson(signUncheckedCommitment(malformed))).toMatchObject({
        disposition: "rejected",
        stage: "shape",
      });
    }
  });

  test("agreement cryptography bounds bytes and rejects non-object array elements without throwing", () => {
    const signed = signUncheckedFixtureAgreement(fixtureUnsignedPayeeBoundAgreement());
    expect(verifyCommittedAgreementCryptography(signed.canonicalJson, signed.agreementHash, {
      maxArtifactBytes: 1,
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: expect.stringContaining("input limit"),
    });
    expect(verifyCommittedAgreementCryptography(signed.canonicalJson, signed.agreementHash, {
      maxArtifactBytes: 0,
    })).toMatchObject({ disposition: "refused-unsupported" });
    expect(verifyCommittedAgreementCryptography(signed.canonicalJson, [signed.agreementHash] as unknown as string))
      .toMatchObject({ disposition: "rejected", reason: expect.stringContaining("hash") });

    const nullParty = structuredClone(signed.agreement) as Record<string, unknown>;
    nullParty["parties"] = [null];
    const unsignedNullParty = { ...nullParty };
    delete unsignedNullParty["signatures"];
    expect(() => verifyCommittedAgreementCryptography(
      canonicalize(nullParty),
      sha256Hex(canonicalize(unsignedNullParty)),
    )).not.toThrow();
    expect(verifyCommittedAgreementCryptography(
      canonicalize(nullParty),
      sha256Hex(canonicalize(unsignedNullParty)),
    )).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("shape") });

    const nullSignature = structuredClone(signed.agreement) as Record<string, unknown>;
    nullSignature["signatures"] = [null];
    expect(() => verifyCommittedAgreementCryptography(canonicalize(nullSignature), signed.agreementHash)).not.toThrow();
    expect(verifyCommittedAgreementCryptography(canonicalize(nullSignature), signed.agreementHash))
      .toMatchObject({ disposition: "rejected", reason: expect.stringContaining("shape") });
  });
});

function signUncheckedCommitment(unsigned: Record<string, unknown>): string {
  const canonicalScope = canonicalize(unsigned);
  const commitmentHash = sha256Hex(canonicalScope);
  const signer = fixtureSigner();
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(
      new TextEncoder().encode(`${COMMITMENT_DOMAIN}${commitmentHash}`),
      FIXTURE_SIGNING_CONTEXT,
    ),
    "standard-base64-padded",
    64,
  ));
  return canonicalize({
    ...unsigned,
    signature: { algorithm: "ed25519", signer: signer.signer, value: signature },
  });
}

function verifyCanonicalCommitmentJson(
  canonicalJson: string,
  options: Partial<CommitmentVerificationOptions> = {},
): CommitmentVerificationResult {
  return verifyCanonicalCommitmentJsonRaw(canonicalJson, {
    expectedOrchestrator: fixtureSigner().signer,
    ...options,
  });
}

function unsignedCommitment(): UnsignedCommitmentRecord {
  const agreement = fixtureUnsignedPayeeBoundAgreement();
  return {
    dacsVersion: "1",
    jobId: FIXTURE_JOB_ID,
    agreementHash: sha256Hex(canonicalize(agreement)),
    listingRef: agreement.listingRef,
    parties: agreement.parties.map((party) => party.primaryClaim),
    pattern: agreement.derivedFromPattern,
    committedAt: FIXTURE_COMMITTED_AT,
  };
}

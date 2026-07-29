import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  aggregateVetResults,
  compositeVerificationLogicalAddress,
  verifyResultLogicalAddress,
  type RecipeAvailability,
  type VetDecision,
} from "../../src/protocol/vet.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { signVerifyResult } from "../../src/producer/verify-result.ts";
import { signCompositeVerificationRecord } from "../../src/producer/composite-verification-record.ts";
import { signBuyerVetRequirement } from "../../src/producer/buyer-vet-requirement.ts";
import { signFixtureKeyPossession } from "../../src/producer/fixture-key-possession.ts";
import { verifyCanonicalVerifyResultJson } from "../../src/consumer/verify-result-verifier.ts";
import { verifyCanonicalCompositeVerificationRecordJson } from "../../src/consumer/composite-verification-record-verifier.ts";
import { verifyBuyerVetRequirementJson } from "../../src/consumer/buyer-vet-requirement-verifier.ts";
import { verifyFixtureKeyPossessionJson } from "../../src/consumer/fixture-key-possession-verifier.ts";

const JOB_ID = "01J00000000000000000000000";
const NOW = 1_784_073_610_000;
const CONTEXT = Object.freeze({ deploymentMode: "fixture" as const, requestMode: "fixture" as const });
const verifier = fixtureSigner("vet-verifier");
const evaluated = fixtureSigner("vet-evaluated");
const attestation = Object.freeze({ assertionVersion: "1", possessionVerified: true });
const attestationJson = canonicalize(attestation);
const attestationHash = sha256Hex(attestationJson);
const requirement = Object.freeze({ required: Object.freeze([{ scheme: "key" }]) });
const requirementHash = sha256Hex(canonicalize(requirement));

describe("DACS-2 Vet protocol core", () => {
  test("derives CM-2 and composite logical addresses with CF-4 escaping", () => {
    expect(verifyResultLogicalAddress(JOB_ID, "did", "example:alice?x=1", 2)).toBe(
      `dacs2:${JOB_ID}:did:example%3Aalice%3Fx%3D1:v2`,
    );
    expect(compositeVerificationLogicalAddress(JOB_ID, evaluated.signer)).toBe(
      `dacs2:composite:${JOB_ID}:${evaluated.signer.replace(":", "%3A")}`,
    );
  });

  test("preserves DACS-2 global and oneOf precedence exactly", () => {
    const global = aggregateVetResults([
      summary("key", "error"), summary("domain", "fail"), summary("did", "indeterminate"),
    ], { required: [{ scheme: "key" }, { scheme: "domain" }, { scheme: "did" }] });
    expect(global).toEqual({ decision: "fail", reasons: ["required failing: domain"] });

    const oneOf = aggregateVetResults([
      summary("key", "fail"), summary("domain", "error"), summary("did", "indeterminate"),
    ], { required: [], oneOf: [[{ scheme: "key" }, { scheme: "domain" }, { scheme: "did" }]] });
    expect(oneOf).toEqual({ decision: "error", reasons: ["oneOf group: at least one claim errored"] });
    expect(aggregateVetResults([], { required: [{ scheme: "key" }] })).toEqual({
      decision: "fail", reasons: ["required not present: key"],
    });
  });

  test("lets any same-scheme pass satisfy required and oneOf claims per DACS-2 section 7.7.1", () => {
    for (const other of ["fail", "error", "indeterminate"] as const) {
      expect(aggregateVetResults([
        summary("key", "pass"), summary("key", other),
      ], requirement)).toEqual({ decision: "pass", reasons: [] });
    }
    expect(aggregateVetResults([
      summary("key", "pass"), summary("key", "fail"),
    ], { required: [], oneOf: [[{ scheme: "key" }]] })).toEqual({
      decision: "pass", reasons: [],
    });
  });

  test("qualifies same-scheme results against every ClaimRequirement constraint", () => {
    const constrained = {
      required: [{
        scheme: "key", verificationRequired: true, recipeVersion: 2, maxAge: 10,
        parameters: { possessionVerified: true },
      }],
    } as const;
    const matching = {
      scheme: "key", decision: "pass" as const, availability: "live" as const,
      recipeVersion: 2, verifiedAt: NOW, verificationPerformed: true,
      data: { possessionVerified: true },
    };
    expect(aggregateVetResults([matching], constrained, NOW + 10_000)).toEqual({
      decision: "pass", reasons: [],
    });
    for (const mismatch of [
      { ...matching, recipeVersion: 1 },
      { ...matching, verifiedAt: NOW - 10_001 },
      { ...matching, verificationPerformed: false },
      { ...matching, data: { possessionVerified: false } },
      { scheme: "key", decision: "pass" as const, availability: "live" as const },
    ]) {
      expect(aggregateVetResults([mismatch], constrained, NOW)).toEqual({
        decision: "fail", reasons: ["required constraints not satisfied: key"],
      });
    }
  });

  for (const availability of ["mocked", "disabled", "failed"] as const) {
    test(`forces an underlying pass from ${availability} availability to error`, () => {
      expect(aggregateVetResults([summary("key", "pass", availability)], requirement)).toEqual({
        decision: "error", reasons: ["required errored: key"],
      });
    });
  }

  test("signs and independently verifies a privacy-bounded VerifyResult", () => {
    const signed = fixtureVerifyResult("pass", "live");
    const verified = verifyResult(signed.canonicalJson, "live");
    expect(verified).toMatchObject({
      disposition: "verified",
      contentHash: signed.contentHash,
      decision: "pass",
      effectiveDecision: "pass",
      verificationPerformed: true,
      logicalAddress: verifyResultLogicalAddress(JOB_ID, "key", evaluated.signer.slice(4), 1),
    });
    expect(signed.contentHash).toBe(sha256Hex(canonicalize(withoutFields(
      signed.verifyResult as Record<string, unknown>,
      "signature",
    ))));
    expect(signed.contentHash).not.toBe(sha256Hex(signed.canonicalJson));
  });

  test("does not infer performed verification from an unsigned attestation reference", () => {
    const unsigned = unsignedVerifyResult();
    const signed = signVerifyResult({
      ...unsigned,
      attestation: {
        anchor: unsigned.attestation.anchor,
        contentHash: unsigned.attestation.contentHash,
      },
    }, "live", verifier, CONTEXT);
    const verified = verifyCanonicalVerifyResultJson(signed.canonicalJson, {
      availability: "live",
      expectedScheme: "key",
      expectedIdentifier: evaluated.signer.slice("key:".length),
      expectedRecipeVersion: 1,
      expectedMethod: "self-signed",
      expectedVerifier: verifier.signer,
      jobId: JOB_ID,
      resolveAttestation: () => ({ status: "resolved", canonicalJson: attestationJson }),
    });
    expect(verified).toMatchObject({ disposition: "verified", verificationPerformed: false });
    if (verified.disposition !== "verified") throw new Error("expected verified result");
    expect(aggregateVetResults([{
      scheme: verified.scheme,
      decision: verified.decision,
      availability: verified.availability,
      recipeVersion: verified.recipeVersion,
      verifiedAt: verified.verifiedAt,
      verificationPerformed: verified.verificationPerformed,
      ...(verified.data === undefined ? {} : { data: verified.data }),
    }], { required: [{ scheme: "key", verificationRequired: true }] }, NOW)).toEqual({
      decision: "fail", reasons: ["required constraints not satisfied: key"],
    });
  });

  test("enforces the fixture recipe's closed public predicate schema", () => {
    for (const data of [
      { birthDate: "1990-01-01" },
      { email: "person@example.com" },
      { income: 90_000 },
      { nested: { possessionVerified: true } },
    ]) {
      expect(() => fixtureVerifyResult("pass", "live", data)).toThrow(
        "exactly possessionVerified=true",
      );
    }
    expect(() => signVerifyResult({
      ...(JSON.parse(fixtureVerifyResult("pass", "live").canonicalJson) as Record<string, unknown>),
      signature: undefined,
      privateNote: "sensitive",
    } as never, "live", verifier, CONTEXT)).toThrow("VerifyResult input is invalid");
  });

  test("rejects non-canonical claim and requirement bindings", () => {
    expect(() => signVerifyResult({
      resultVersion: "1",
      scheme: "key",
      identifier: evaluated.signer.slice(4).toUpperCase(),
      recipeVersion: 1,
      method: "self-signed",
      decision: "pass",
      reason: "invalid canonical claim",
      attestation: {
        anchor: { kind: "storage-program", locator: "dacs2:fixture" },
        contentHash: attestationHash,
      },
      fetchedAt: NOW,
      verifiedAt: NOW,
    }, "live", verifier, CONTEXT)).toThrow("not canonical");
    expect(() => signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash: "b".repeat(64),
      requirement,
      freshness: [],
      dealSpecific: [],
      generatedAt: NOW,
    }, verifier, CONTEXT)).toThrow("does not match the exact requirement");
  });

  test("independently verifies the buyer-signed seller requirement and rejects scope drift", () => {
    const signed = signBuyerVetRequirement({
      jobId: JOB_ID,
      buyer: verifier.signer,
      seller: evaluated.signer,
      requirement,
      generatedAt: NOW,
    }, verifier, CONTEXT);
    const expectation = { jobId: JOB_ID, buyer: verifier.signer, seller: evaluated.signer };
    expect(verifyBuyerVetRequirementJson(signed.canonicalJson, expectation)).toEqual({
      disposition: "verified",
      contentHash: signed.contentHash,
      logicalAddress: signed.logicalAddress,
      requirement,
      requirementHash,
      generatedAt: NOW,
    });

    const changed = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    changed["seller"] = fixtureSigner("other-seller").signer;
    expect(verifyBuyerVetRequirementJson(canonicalize(changed), expectation)).toMatchObject({
      disposition: "rejected",
      stage: "binding",
    });

    const signatureChanged = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    const signature = signatureChanged["signature"] as Record<string, unknown>;
    signature["value"] = `${signature["value"] as string}`.replace(/^./, (value) => value === "A" ? "B" : "A");
    expect(verifyBuyerVetRequirementJson(canonicalize(signatureChanged), expectation)).toMatchObject({
      disposition: "rejected",
      stage: "signature",
    });

    const unknownTopLevel = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    unknownTopLevel["privateNote"] = "sensitive";
    expect(verifyBuyerVetRequirementJson(canonicalize(unknownTopLevel), expectation)).toMatchObject({
      disposition: "rejected",
      stage: "shape",
    });
    const unknownNested = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    ((unknownNested["requirement"] as { required: Record<string, unknown>[] }).required[0]!)["note"] = "sensitive";
    expect(verifyBuyerVetRequirementJson(canonicalize(unknownNested), expectation)).toMatchObject({
      disposition: "rejected",
      stage: "shape",
    });
    expect(() => signBuyerVetRequirement({
      jobId: JOB_ID,
      buyer: verifier.signer,
      seller: evaluated.signer,
      requirement: { required: [{ scheme: "key", note: "sensitive" } as never] },
      generatedAt: NOW,
    }, verifier, CONTEXT)).toThrow("Vet bundle requirement is invalid");
  });

  test("rejects signature, attestation hash, and signer-authority mutations", () => {
    const signed = fixtureVerifyResult("pass", "live");
    const changed = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    changed["decision"] = "fail";
    expect(verifyResult(canonicalize(changed), "live")).toMatchObject({
      disposition: "rejected", stage: "signature",
    });
    expect(verifyResult(signed.canonicalJson, "live", canonicalize({ ...attestation, possessionVerified: false })))
      .toMatchObject({ disposition: "rejected", stage: "attestation" });
    expect(verifyResult(signed.canonicalJson, "live", attestationJson, false))
      .toMatchObject({ disposition: "rejected", stage: "attestation" });
    for (const nonCanonical of [
      JSON.stringify(attestation, null, 2),
      '{"assertionVersion":"1","assertionVersion":"1","possessionVerified":true}',
    ]) {
      expect(verifyResult(signed.canonicalJson, "live", nonCanonical)).toMatchObject({
        disposition: "rejected", stage: "attestation",
      });
    }
    const extra = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
    extra["privateNote"] = "sensitive";
    expect(verifyResult(canonicalize(extra), "live")).toMatchObject({
      disposition: "rejected", stage: "shape",
    });
    for (const path of ["attestation", "anchor", "signature"] as const) {
      const unknownNested = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
      const target = path === "anchor"
        ? ((unknownNested["attestation"] as Record<string, unknown>)["anchor"] as Record<string, unknown>)
        : unknownNested[path] as Record<string, unknown>;
      target["privateNote"] = "sensitive";
      expect(verifyResult(canonicalize(unknownNested), "live")).toMatchObject({
        disposition: "rejected", stage: "shape",
      });
    }
    expect(() => signVerifyResult({
      ...unsignedVerifyResult(),
      attestation: {
        ...unsignedVerifyResult().attestation,
        privateNote: "sensitive",
      } as never,
    }, "live", verifier, CONTEXT)).toThrow("attestation reference is invalid");
    expect(() => signVerifyResult({
      ...unsignedVerifyResult(),
      attestation: {
        ...unsignedVerifyResult().attestation,
        anchor: { ...unsignedVerifyResult().attestation.anchor, privateNote: "sensitive" } as never,
      },
    }, "live", verifier, CONTEXT)).toThrow("attestation reference is invalid");
  });

  test("closes fixture key-possession producer input and signed assertion schemas", () => {
    const input = {
      jobId: JOB_ID, evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64), observedAt: NOW,
    };
    const signed = signFixtureKeyPossession(input, evaluated, CONTEXT);
    const expectation = { jobId: JOB_ID, evaluatedParty: evaluated.signer, bundleHash: "a".repeat(64) };
    expect(verifyFixtureKeyPossessionJson(signed.canonicalJson, expectation)).toMatchObject({
      disposition: "verified",
    });
    for (const targetName of ["assertion", "signature"] as const) {
      const changed = JSON.parse(signed.canonicalJson) as Record<string, unknown>;
      const target = targetName === "assertion"
        ? changed : changed["signature"] as Record<string, unknown>;
      target["privateNote"] = "sensitive";
      expect(verifyFixtureKeyPossessionJson(canonicalize(changed), expectation)).toMatchObject({
        disposition: "rejected", stage: "shape",
      });
    }
    expect(() => signFixtureKeyPossession({ ...input, privateNote: "sensitive" } as never, evaluated, CONTEXT))
      .toThrow("binding is invalid");
  });

  test("signs a composite and independently resolves, verifies, and re-aggregates every result", () => {
    const result = fixtureVerifyResult("pass", "live");
    const reference = Object.freeze({
      anchor: {
        kind: "storage-program" as const,
        locator: verifyResultLogicalAddress(JOB_ID, "key", evaluated.signer.slice(4), 1),
      },
      contentHash: result.contentHash,
      recipeVersion: 1,
    });
    const composite = signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      freshness: [],
      dealSpecific: [{ reference, scheme: "key", decision: "pass", availability: "live" }],
      generatedAt: NOW,
    }, verifier, CONTEXT);
    expect(composite.contentHash).toBe(sha256Hex(canonicalize(withoutFields(
      composite.record as Record<string, unknown>,
      "signature",
    ))));
    expect(composite.contentHash).not.toBe(sha256Hex(composite.canonicalJson));
    const verified = verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({ status: "resolved", availability: "live", canonicalJson: result.canonicalJson }),
    });
    expect(verified).toEqual({
      disposition: "verified",
      contentHash: composite.contentHash,
      generatedAt: NOW,
      logicalAddress: compositeVerificationLogicalAddress(JOB_ID, evaluated.signer),
      overallDecision: "pass",
      verifyResultCount: 1,
    });

    const availabilityDrift = verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({ status: "resolved", availability: "mocked", canonicalJson: result.canonicalJson }),
    });
    expect(availabilityDrift).toMatchObject({ disposition: "rejected", stage: "binding" });

    const unknownCompositeField = JSON.parse(composite.canonicalJson) as Record<string, unknown>;
    unknownCompositeField["privateNote"] = "sensitive";
    expect(verifyCanonicalCompositeVerificationRecordJson(canonicalize(unknownCompositeField), {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({ status: "resolved", availability: "live", canonicalJson: result.canonicalJson }),
    })).toMatchObject({ disposition: "rejected", stage: "shape" });
    const unknownReferenceField = JSON.parse(composite.canonicalJson) as Record<string, unknown>;
    ((unknownReferenceField["dealSpecific"] as Record<string, unknown>[])[0]!)["note"] = "sensitive";
    expect(verifyCanonicalCompositeVerificationRecordJson(canonicalize(unknownReferenceField), {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({ status: "resolved", availability: "live", canonicalJson: result.canonicalJson }),
    })).toMatchObject({ disposition: "rejected", stage: "shape" });
    expect(() => signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      freshness: [],
      dealSpecific: [{
        reference: { ...reference, note: "sensitive" } as never,
        scheme: "key", decision: "pass", availability: "live",
      }],
      generatedAt: NOW,
    }, verifier, CONTEXT)).toThrow("Composite VerifyResultRef is invalid");
  });

  test("re-aggregates ClaimRequirement constraints from verified results, not producer claims", () => {
    const result = fixtureVerifyResult("pass", "live");
    const constrainedRequirement = Object.freeze({
      required: Object.freeze([Object.freeze({
        scheme: "key", verificationRequired: true, recipeVersion: 2,
        maxAge: 0, parameters: Object.freeze({ possessionVerified: false }),
      })]),
    });
    const constrainedHash = sha256Hex(canonicalize(constrainedRequirement));
    const reference = Object.freeze({
      anchor: Object.freeze({
        kind: "storage-program" as const,
        locator: verifyResultLogicalAddress(JOB_ID, "key", evaluated.signer.slice(4), 1),
      }),
      contentHash: result.contentHash,
      recipeVersion: 1,
    });
    const composite = signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash: constrainedHash,
      requirement: constrainedRequirement,
      freshness: [],
      dealSpecific: [{
        reference, scheme: "key", decision: "pass", availability: "live",
        recipeVersion: 2, verifiedAt: NOW, verificationPerformed: true,
        data: { possessionVerified: false },
      }],
      generatedAt: NOW,
    }, verifier, CONTEXT);
    expect(composite.overallDecision).toBe("pass");
    expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash: constrainedHash,
      requirement: constrainedRequirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({
        status: "resolved", availability: "live", canonicalJson: result.canonicalJson,
      }),
    })).toMatchObject({ disposition: "rejected", stage: "aggregation" });
  });

  test("classifies malformed and hostile Vet authority resolvers without throwing", () => {
    const result = fixtureVerifyResult("pass", "live");
    const reference = Object.freeze({
      anchor: {
        kind: "storage-program" as const,
        locator: verifyResultLogicalAddress(JOB_ID, "key", evaluated.signer.slice(4), 1),
      },
      contentHash: result.contentHash,
      recipeVersion: 1,
    });
    const composite = signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      freshness: [],
      dealSpecific: [{ reference, scheme: "key", decision: "pass", availability: "live" }],
      generatedAt: NOW,
    }, verifier, CONTEXT);
    const base = {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved" as const,
        canonicalJson: attestationJson,
        signer: evaluated.signer,
        signatureVerified: true,
      }),
      resolveVerifyResult: () => ({
        status: "resolved" as const,
        availability: "live" as const,
        canonicalJson: result.canonicalJson,
      }),
    };
    const hostileStatus = Object.defineProperty({}, "status", {
      get: () => { throw new Error("hostile status getter"); },
    });
    for (const authority of [
      { status: "resolved", availability: "live" },
      { status: "unexpected" },
      hostileStatus,
    ]) {
      expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
        ...base,
        resolveVerifyResult: () => authority as never,
      })).toMatchObject({ disposition: "indeterminate", stage: "reference" });
    }
    expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      ...base,
      resolveRecipeAuthority: () => hostileStatus as never,
    })).toMatchObject({ disposition: "indeterminate", stage: "reference" });
    expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      ...base,
      resolveAttestation: () => hostileStatus as never,
    })).toMatchObject({ disposition: "indeterminate", stage: "reference" });
    let prototypeReads = 0;
    const hostileBytes = new Proxy(new Uint8Array([1, 2, 3]), {
      getPrototypeOf: (target) => {
        prototypeReads += 1;
        if (prototypeReads > 1) throw new Error("hostile byte prototype getter");
        return Reflect.getPrototypeOf(target);
      },
    });
    expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      ...base,
      resolveAttestation: () => ({ status: "resolved", rawBytes: hostileBytes }),
    })).toMatchObject({ disposition: "indeterminate", stage: "reference" });
  });

  test("binds every composite result to an authenticated evaluated claim", () => {
    const unrelated = fixtureSigner("unrelated-evaluated");
    const result = signVerifyResult({
      resultVersion: "1",
      scheme: "key",
      identifier: unrelated.signer.slice("key:".length),
      recipeVersion: 1,
      method: "self-signed",
      decision: "pass",
      reason: "unrelated fixture key possession evaluated",
      attestation: {
        anchor: { kind: "storage-program", locator: `dacs2:fixture-attestation:${JOB_ID}:unrelated` },
        contentHash: attestationHash,
        signer: evaluated.signer,
      },
      data: { possessionVerified: true },
      fetchedAt: NOW,
      verifiedAt: NOW,
    }, "live", verifier, CONTEXT);
    const reference = Object.freeze({
      anchor: {
        kind: "storage-program" as const,
        locator: verifyResultLogicalAddress(JOB_ID, "key", unrelated.signer.slice("key:".length), 1),
      },
      contentHash: result.contentHash,
      recipeVersion: 1,
    });
    const composite = signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      freshness: [],
      dealSpecific: [{ reference, scheme: "key", decision: "pass", availability: "live" }],
      generatedAt: NOW,
    }, verifier, CONTEXT);
    expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({ status: "resolved", availability: "live", canonicalJson: result.canonicalJson }),
    })).toMatchObject({ disposition: "rejected", stage: "binding" });
  });

  test.each([
    ["not-yet-verified", { verifiedAt: NOW + 2 }, NOW + 1],
    ["expired", { validUntil: NOW }, NOW + 1],
    ["older than recipe defaultMaxAgeSec", {}, NOW + 300_001],
  ] as const)("rejects %s VerifyResult evidence at composite generation time", (_label, temporal, generatedAt) => {
    const unsigned = JSON.parse(fixtureVerifyResult("pass", "live").canonicalJson) as Record<string, unknown>;
    delete unsigned["signature"];
    Object.assign(unsigned, temporal);
    const result = signVerifyResult(unsigned as never, "live", verifier, CONTEXT);
    const reference = Object.freeze({
      anchor: {
        kind: "storage-program" as const,
        locator: verifyResultLogicalAddress(JOB_ID, "key", evaluated.signer.slice("key:".length), 1),
      },
      contentHash: result.contentHash,
      recipeVersion: 1,
    });
    const composite = signCompositeVerificationRecord({
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      freshness: [],
      dealSpecific: [{ reference, scheme: "key", decision: "pass", availability: "live" }],
      generatedAt,
    }, verifier, CONTEXT);
    expect(verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: JOB_ID,
      evaluatedParty: evaluated.signer,
      evaluatedClaims: [evaluated.signer],
      bundleHash: "a".repeat(64),
      requirementHash,
      requirement,
      expectedVerifier: verifier.signer,
      resolveRecipeAuthority: recipeAuthority(),
      resolveAttestation: () => ({
        status: "resolved", canonicalJson: attestationJson,
        signer: evaluated.signer, signatureVerified: true,
      }),
      resolveVerifyResult: () => ({ status: "resolved", availability: "live", canonicalJson: result.canonicalJson }),
    })).toMatchObject({ disposition: "rejected", stage: "binding" });
  });
});

function fixtureVerifyResult(
  decision: VetDecision,
  availability: RecipeAvailability,
  data: Readonly<Record<string, unknown>> = { possessionVerified: true },
) {
  return signVerifyResult(unsignedVerifyResult(decision, data), availability, verifier, CONTEXT);
}

function unsignedVerifyResult(
  decision: VetDecision = "pass",
  data: Readonly<Record<string, unknown>> = { possessionVerified: true },
) {
  return {
    resultVersion: "1",
    scheme: "key",
    identifier: evaluated.signer.slice("key:".length),
    recipeVersion: 1,
    method: "self-signed",
    decision,
    reason: "fixture key possession evaluated",
    attestation: {
      anchor: { kind: "storage-program", locator: `dacs2:fixture-attestation:${JOB_ID}:key` },
      contentHash: attestationHash,
      signer: evaluated.signer,
    },
    data,
    fetchedAt: NOW,
    verifiedAt: NOW,
  } as const;
}

function verifyResult(
  canonicalJson: string,
  availability: RecipeAvailability,
  resolvedAttestation = attestationJson,
  signatureVerified = true,
) {
  return verifyCanonicalVerifyResultJson(canonicalJson, {
    availability,
    expectedScheme: "key",
    expectedIdentifier: evaluated.signer.slice("key:".length),
    expectedRecipeVersion: 1,
    expectedMethod: "self-signed",
    expectedVerifier: verifier.signer,
    jobId: JOB_ID,
    resolveAttestation: () => ({
      status: "resolved",
      canonicalJson: resolvedAttestation,
      signer: evaluated.signer,
      signatureVerified,
    }),
  });
}

function summary(
  scheme: string,
  decision: VetDecision,
  availability: RecipeAvailability = "live",
) {
  return { scheme, decision, availability };
}

function recipeAuthority(
  availability: RecipeAvailability = "live",
  defaultMaxAgeSec = 300,
) {
  return () => ({ status: "resolved" as const, availability, defaultMaxAgeSec });
}

function fixtureSigner(label: string) {
  return createFixtureEd25519Signer(createHash("sha256").update(label).digest(), {
    deploymentMode: "fixture",
    authorityMode: "fixture",
  });
}

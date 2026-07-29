import { describe, expect, test } from "bun:test";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { signFixtureDeliveryAttestation } from "../../src/producer/delivery-attestation.ts";
import { verifyDeliveryAttestation } from "../../src/consumer/delivery-attestation-verifier.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import {
  DELIVERY_AGREEMENT_HASH,
  DELIVERY_OBSERVED_AT,
  DELIVERY_PAYLOAD_FORMAT,
  DELIVERY_PHASE_INDEX,
} from "../delivery/fixtures.ts";

const JOB_ID = "01J8ME0SXKQ4T9V2RC5HJ6WX7D";
const CONTENT_HASH = "b".repeat(64);
const SESSION_BINDING_HASH = "c".repeat(64);

describe("DACS-2 attested delivery", () => {
  test("emits and independently verifies the fixture self-signed assertion chain", () => {
    const signer = fixtureSigner();
    const input = {
      agreementHash: DELIVERY_AGREEMENT_HASH,
      deliverableContentHash: CONTENT_HASH,
      jobId: JOB_ID,
      observedAt: DELIVERY_OBSERVED_AT,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      phaseIndex: DELIVERY_PHASE_INDEX,
      sessionBindingHash: SESSION_BINDING_HASH,
      signer: signer.signer,
    } as const;
    const signed = signFixtureDeliveryAttestation(
      input,
      signer,
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    const verifyResultContentHash = sha256Hex(canonicalize(withoutFields(
      signed.verifyResult,
      "signature",
    )));
    expect(verifyResultContentHash).not.toBe(signed.verifyResultArtifactHash);
    expect(signed.verifyResultContentHash).toBe(verifyResultContentHash);
    expect(signed.verifyResultRef).toEqual({
      anchor: { kind: "storage-program", locator: signed.verifyResultLogicalAddress },
      contentHash: verifyResultContentHash,
      signer: signer.signer,
    });
    expect(verifyDeliveryAttestation(
      signed.assertionCanonicalJson,
      signed.verifyResultCanonicalJson,
      { ...input, anchorContext: { mode: "pre-anchor" } },
    )).toMatchObject({
      disposition: "provisionally-verified",
      verifyResultArtifactHash: signed.verifyResultArtifactHash,
      verifyResultContentHash,
    });
  });

  test("rejects omitted, mutated, and cross-session attestation material", () => {
    const signer = fixtureSigner();
    const input = {
      agreementHash: DELIVERY_AGREEMENT_HASH,
      deliverableContentHash: CONTENT_HASH,
      jobId: JOB_ID,
      observedAt: DELIVERY_OBSERVED_AT,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      phaseIndex: DELIVERY_PHASE_INDEX,
      sessionBindingHash: SESSION_BINDING_HASH,
      signer: signer.signer,
    } as const;
    const signed = signFixtureDeliveryAttestation(
      input,
      signer,
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    const result = JSON.parse(signed.verifyResultCanonicalJson) as Record<string, unknown>;
    delete result["attestation"];
    expect(verifyDeliveryAttestation(
      signed.assertionCanonicalJson,
      canonicalize(result),
      { ...input, anchorContext: { mode: "pre-anchor" } },
    )).toMatchObject({ disposition: "rejected", stage: "shape" });

    expect(verifyDeliveryAttestation(
      signed.assertionCanonicalJson,
      signed.verifyResultCanonicalJson,
      { ...input, sessionBindingHash: "d".repeat(64), anchorContext: { mode: "pre-anchor" } },
    )).toMatchObject({ disposition: "rejected", stage: "binding" });

    const assertion = JSON.parse(signed.assertionCanonicalJson) as Record<string, unknown>;
    assertion["futureSignedField"] = "tampered";
    expect(verifyDeliveryAttestation(
      canonicalize(assertion),
      signed.verifyResultCanonicalJson,
      { ...input, anchorContext: { mode: "pre-anchor" } },
    )).toMatchObject({ disposition: "rejected", stage: "signature" });
  });

  test("preserves deterministic anchor-reader rejection", () => {
    const signer = fixtureSigner();
    const input = {
      agreementHash: DELIVERY_AGREEMENT_HASH,
      deliverableContentHash: CONTENT_HASH,
      jobId: JOB_ID,
      observedAt: DELIVERY_OBSERVED_AT,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      phaseIndex: DELIVERY_PHASE_INDEX,
      sessionBindingHash: SESSION_BINDING_HASH,
      signer: signer.signer,
    } as const;
    const signed = signFixtureDeliveryAttestation(
      input,
      signer,
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    expect(verifyDeliveryAttestation(
      signed.assertionCanonicalJson,
      signed.verifyResultCanonicalJson,
      {
        ...input,
        anchorContext: {
          mode: "post-anchor",
          read: () => ({ status: "rejected", reason: "persisted anchor content binding is corrupt" }),
        },
      },
    )).toMatchObject({ disposition: "rejected", stage: "anchor-binding" });
  });
});

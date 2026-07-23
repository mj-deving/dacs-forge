import { describe, expect, test } from "bun:test";
import { ArtifactSizeLimitError } from "../../src/core/artifact-size.ts";
import {
  signWorkProductReceipt,
  type UnsignedWorkProductReceipt,
} from "../../src/producer/work-product-receipt.ts";
import type { ArtifactSigner } from "../../src/producer/fixture-ed25519.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

describe("work-product receipt producer", () => {
  test("emits canonical unpadded base64url signature values", () => {
    const signer = fixtureSigner();
    const signed = signWorkProductReceipt(
      receiptInput(signer),
      signer,
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    expect(signed.receipt.signature.value).toMatch(/^[A-Za-z0-9_-]{86}$/);
  });

  test("refuses to sign a receipt the independent consumer cannot admit", () => {
    const signer = fixtureSigner();
    const oversizedSchemaId = `urn:fixture:${"x".repeat(16_384)}`;

    let error: unknown;
    try {
      signWorkProductReceipt(receiptInput(signer, oversizedSchemaId), signer, {
        deploymentMode: "fixture",
        requestMode: "fixture",
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(ArtifactSizeLimitError);
    expect((error as ArtifactSizeLimitError).artifact).toBe("Work-product receipt");
    expect((error as ArtifactSizeLimitError).actualBytes).toBeGreaterThan(16_384);
    expect((error as ArtifactSizeLimitError).limitBytes).toBe(16_384);
  });

  test("rejects unknown fields at every signed receipt object boundary", () => {
    const signer = fixtureSigner();
    const base = receiptInput(signer);
    const variants = [
      { ...base, unknown: true },
      { ...base, service: { ...base.service, unknown: true } },
      { ...base, input: { ...base.input, unknown: true } },
      { ...base, input: { ...base.input, schema: { ...base.input.schema, unknown: true } } },
      { ...base, output: { ...base.output, unknown: true } },
      { ...base, output: { ...base.output, schema: { ...base.output.schema, unknown: true } } },
    ];

    for (const variant of variants) {
      expect(() => signWorkProductReceipt(
        variant as unknown as UnsignedWorkProductReceipt,
        signer,
        { deploymentMode: "fixture", requestMode: "fixture" },
      )).toThrow(/must contain exactly/);
    }
  });
});

function receiptInput(
  signer: ArtifactSigner,
  inputSchemaId = "urn:fixture:input",
): UnsignedWorkProductReceipt {
  return {
    receiptVersion: "2",
    jobId: "01J00000000000000000000001",
    requestHash: "0".repeat(64),
    service: { id: "reference-service", version: "1.0.0" },
    evidenceMode: "fixture",
    input: {
      contentHash: "1".repeat(64),
      schema: { id: inputSchemaId, version: "1", contentHash: "2".repeat(64) },
    },
    output: {
      kind: "fixture-output",
      contentHash: "3".repeat(64),
      schema: { id: "urn:fixture:output", version: "1", contentHash: "4".repeat(64) },
    },
    producedAt: "2026-07-17T08:00:00.000Z",
    seller: signer.signer,
  };
}

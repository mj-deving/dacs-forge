import { describe, expect, test } from "bun:test";
import vector from "../../vectors/dacs-standard-storage-program-fcbf804.json";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { signFixtureDeliveryAttestation } from "../../src/producer/delivery-attestation.ts";
import {
  STORAGE_PROGRAM_INLINE_LIMIT_BYTES,
  storageProgramDeliverableAddress,
  verifyListingSelectedDeliveryAttestation,
  verifyStorageProgramCompatibility,
  type AgreementBoundBuyer,
  type StorageProgramCompatibilityInput,
  type StorageProgramDeliverableSpec,
  type StorageProgramDeliveryEvidence,
  type StorageProgramReaderIdentity,
} from "../../src/compat/storage-program-delivery.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import {
  DELIVERY_AGREEMENT_HASH,
  DELIVERY_OBSERVED_AT,
  DELIVERY_PHASE_INDEX,
} from "../delivery/fixtures.ts";

const fixture = vector.fixture;
const payload = new Uint8Array(fixture.payload.sizeBytes).fill(fixture.payload.byte);
const pointerCanonicalJson = canonicalize(fixture.pointer);
const pointerBytes = new TextEncoder().encode(pointerCanonicalJson);
const authorizedReader = fixture.agreementBuyer as AgreementBoundBuyer & StorageProgramReaderIdentity;

describe("DACS-4 Storage Program delivery compatibility", () => {
  test("binds the exact delivered result to the Listing-selected verification method", () => {
    const signer = fixtureSigner();
    const payloadCanonicalJson = canonicalize({ answer: 42, nested: { ok: true } });
    const input = {
      agreementHash: DELIVERY_AGREEMENT_HASH,
      deliverableContentHash: new Bun.CryptoHasher("sha256").update(payloadCanonicalJson).digest("hex"),
      jobId: fixture.jobId,
      observedAt: DELIVERY_OBSERVED_AT,
      payloadFormat: "application/json",
      phaseIndex: DELIVERY_PHASE_INDEX,
      sessionBindingHash: "c".repeat(64),
      signer: signer.signer,
    } as const;
    const signed = signFixtureDeliveryAttestation(
      input,
      signer,
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    const expectation = {
      agreementHash: input.agreementHash,
      anchorContext: { mode: "pre-anchor" as const },
      assertionCanonicalJson: signed.assertionCanonicalJson,
      jobId: input.jobId,
      listingDeliverable: {
        kind: "attested-payload" as const,
        payloadFormat: input.payloadFormat,
        verificationMethod: { kind: "self-signed" },
      },
      payloadCanonicalJson,
      phaseIndex: input.phaseIndex,
      sessionBindingHash: input.sessionBindingHash,
      signer: input.signer,
      verifyResultCanonicalJson: signed.verifyResultCanonicalJson,
    };
    expect(verifyListingSelectedDeliveryAttestation(expectation)).toMatchObject({
      disposition: "provisionally-verified",
    });
    expect(verifyListingSelectedDeliveryAttestation({
      ...expectation,
      payloadCanonicalJson: canonicalize({ answer: 43, nested: { ok: true } }),
    })).toMatchObject({ disposition: "rejected", stage: "binding" });
    expect(verifyListingSelectedDeliveryAttestation({
      ...expectation,
      listingDeliverable: {
        ...expectation.listingDeliverable,
        verificationMethod: { kind: "tlsnotary" },
      },
    })).toEqual({
      disposition: "refused-unsupported",
      stage: "binding",
      reason: "Listing-selected delivery verification method is unsupported",
    });
    expect(verifyListingSelectedDeliveryAttestation({
      ...expectation,
      payloadCanonicalJson: `"${"a".repeat(1_048_576)}"`,
    })).toEqual({
      disposition: "refused-unsupported",
      stage: "binding",
      reason: "Delivered result exceeds the input limit",
    });
    expect(verifyListingSelectedDeliveryAttestation({
      ...expectation,
      listingDeliverable: {
        ...expectation.listingDeliverable,
        expectedSizeBytes: Buffer.byteLength(payloadCanonicalJson) + 1,
      },
    })).toEqual({
      disposition: "rejected",
      stage: "binding",
      reason: "Delivered result size does not match the Listing",
    });

    const nonAsciiPayloadCanonicalJson = canonicalize({ text: "Größe €" });
    const nonAsciiSigned = signFixtureDeliveryAttestation(
      {
        ...input,
        deliverableContentHash: sha256(new TextEncoder().encode(nonAsciiPayloadCanonicalJson)),
      },
      signer,
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    expect(Buffer.byteLength(nonAsciiPayloadCanonicalJson)).toBeGreaterThan(nonAsciiPayloadCanonicalJson.length);
    expect(verifyListingSelectedDeliveryAttestation({
      ...expectation,
      assertionCanonicalJson: nonAsciiSigned.assertionCanonicalJson,
      listingDeliverable: {
        ...expectation.listingDeliverable,
        expectedSizeBytes: Buffer.byteLength(nonAsciiPayloadCanonicalJson),
      },
      payloadCanonicalJson: nonAsciiPayloadCanonicalJson,
      verifyResultCanonicalJson: nonAsciiSigned.verifyResultCanonicalJson,
    })).toMatchObject({ disposition: "provisionally-verified" });
    expect(verifyListingSelectedDeliveryAttestation(null as never)).toEqual({
      disposition: "rejected",
      stage: "binding",
      reason: "Delivery attestation input is malformed",
    });

    let payloadFormatReads = 0;
    const changingDeliverable = {
      kind: "attested-payload" as const,
      get payloadFormat(): string {
        payloadFormatReads += 1;
        return payloadFormatReads === 1 ? "text/plain" : "application/json";
      },
      verificationMethod: { kind: "self-signed" },
    };
    expect(verifyListingSelectedDeliveryAttestation({
      ...expectation,
      listingDeliverable: changingDeliverable,
    })).toMatchObject({ disposition: "rejected", stage: "binding" });
    expect(payloadFormatReads).toBe(1);
  });

  test("retrieves the one-byte-over-limit fixture through its pinned hash-bound pointer", () => {
    let storageReads = 0;
    let externalReads = 0;
    const result = verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: (address, reader) => {
        storageReads += 1;
        expect(address).toBe(storageProgramDeliverableAddress(fixture.jobId));
        expect(reader).toEqual(authorizedReader);
        return {
          status: "resolved",
          access: { model: "buyer-only", allowed: [fixture.agreementBuyer.address], blacklist: [] },
          value: pointerBytes,
        };
      },
      externalRead: (url, maxBytes) => {
        externalReads += 1;
        expect(url).toBe(fixture.pointer.externalUrl);
        expect(maxBytes).toBe(16 * 1024 * 1024);
        return { status: "resolved", value: payload };
      },
    }));
    expect(result).toEqual({
      disposition: "verified",
      accessModel: "buyer-only",
      address: fixture.evidence.deliverableAnchor.locator,
      deliverableContentHash: fixture.payload.sha256,
      payloadBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES + 1,
      pointerContentHash: fixture.pointerCanonicalSha256,
    });
    expect({ storageReads, externalReads }).toEqual({ storageReads: 1, externalReads: 1 });
    expect(() => storageProgramDeliverableAddress([fixture.jobId] as never)).toThrow(TypeError);
  });

  test("rejects an unauthorized fixture identity before any storage or payload read", () => {
    let reads = 0;
    const result = verifyStorageProgramCompatibility(compatibilityInput({
      reader: fixture.unauthorizedReader,
      storageRead: () => {
        reads += 1;
        return { status: "resolved", access: { model: "public" }, value: pointerBytes };
      },
      externalRead: () => {
        reads += 1;
        return { status: "resolved", value: payload };
      },
    }));
    expect(result).toEqual({
      disposition: "rejected",
      stage: "access",
      reason: "Reader is not the agreement-bound buyer",
    });
    expect(reads).toBe(0);
  });

  test("snapshots agreement-bound expectations before invoking caller-owned readers", () => {
    const buyer = { ...fixture.agreementBuyer };
    const reader = { ...fixture.agreementBuyer };
    const listing: StorageProgramDeliverableSpec = {
      kind: "storage-program",
      accessModel: "buyer-only",
      expectedSizeBytes: fixture.payload.sizeBytes,
    };
    const evidence: StorageProgramDeliveryEvidence & { deliverableContentHash: string } = {
      deliverableAnchor: {
        kind: "storage-program",
        locator: fixture.evidence.deliverableAnchor.locator,
      },
      deliverableContentHash: fixture.evidence.deliverableContentHash,
    };
    let mutableInput: StorageProgramCompatibilityInput;
    mutableInput = compatibilityInput({
      agreementBuyer: buyer,
      evidence,
      listingDeliverable: listing,
      reader,
      storageRead: (_address, snapshottedReader) => {
        expect(Object.isFrozen(snapshottedReader)).toBe(true);
        expect(snapshottedReader).toEqual(fixture.agreementBuyer);
        buyer.primaryClaim = fixture.unauthorizedReader.primaryClaim;
        reader.primaryClaim = fixture.unauthorizedReader.primaryClaim;
        (listing as { expectedSizeBytes?: number }).expectedSizeBytes = 1;
        evidence.deliverableContentHash = "0".repeat(64);
        (mutableInput as { expectedPointerContentHash?: string }).expectedPointerContentHash = "0".repeat(64);
        return {
          status: "resolved",
          access: { model: "buyer-only", allowed: [fixture.agreementBuyer.address] },
          value: pointerBytes,
        };
      },
    });
    expect(verifyStorageProgramCompatibility(mutableInput)).toMatchObject({
      disposition: "verified",
      deliverableContentHash: fixture.payload.sha256,
    });

    const malformed = compatibilityInput();
    Object.defineProperty(malformed, "jobId", { get: () => { throw new Error("fixture-accessor"); } });
    expect(verifyStorageProgramCompatibility(malformed)).toEqual({
      disposition: "refused-unsupported",
      stage: "configuration",
      reason: "Storage Program compatibility expectation is malformed",
    });

    let anchorReads = 0;
    const changingEvidence = {
      deliverableContentHash: fixture.evidence.deliverableContentHash,
      get deliverableAnchor(): StorageProgramDeliveryEvidence["deliverableAnchor"] {
        anchorReads += 1;
        return anchorReads === 1
          ? { kind: "storage-program", locator: `${fixture.evidence.deliverableAnchor.locator}:wrong` }
          : fixture.evidence.deliverableAnchor as StorageProgramDeliveryEvidence["deliverableAnchor"];
      },
    };
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      evidence: changingEvidence,
    }))).toMatchObject({ disposition: "rejected", stage: "configuration" });
    expect(anchorReads).toBe(1);
  });

  test("keeps a private-to-public downgrade indeterminate and never fetches payload", () => {
    let externalReads = 0;
    const result = verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({ status: "resolved", access: { model: "public" }, value: pointerBytes }),
      externalRead: () => {
        externalReads += 1;
        return { status: "resolved", value: payload };
      },
    }));
    expect(result).toEqual({
      disposition: "indeterminate",
      stage: "access",
      reason: "Declared private delivery resolved as public",
    });
    expect(externalReads).toBe(0);
  });

  test("enforces resolved private authority even when the Listing declared public access", () => {
    const publicListing: StorageProgramDeliverableSpec = {
      kind: "storage-program",
      expectedSizeBytes: fixture.listingDeliverable.expectedSizeBytes,
      accessModel: "public",
    };
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      listingDeliverable: publicListing,
      reader: fixture.unauthorizedReader,
      storageRead: storageValue(pointerBytes),
    }))).toMatchObject({ disposition: "rejected", stage: "access" });

    const encryptedBuyer = { ...fixture.agreementBuyer, encryptionKey: "fixture-buyer-key" };
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      agreementBuyer: encryptedBuyer,
      listingDeliverable: publicListing,
      reader: {
        primaryClaim: fixture.agreementBuyer.primaryClaim,
        encryptionKey: "fixture-wrong-key",
      },
      storageRead: () => ({
        status: "resolved",
        access: {
          model: "encrypt-to-buyer",
          sealedTo: encryptedBuyer.encryptionKey,
        },
        value: pointerBytes,
      }),
    }))).toMatchObject({ disposition: "rejected", stage: "access" });

    let modelReads = 0;
    const changingAccess = {
      get model(): "buyer-only" | "public" {
        modelReads += 1;
        return modelReads < 5 ? "buyer-only" : "public";
      },
      allowed: [fixture.unauthorizedReader.address],
    };
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      listingDeliverable: publicListing,
      reader: fixture.unauthorizedReader,
      storageRead: () => ({ status: "resolved", access: changingAccess, value: pointerBytes }),
    }))).toMatchObject({ disposition: "rejected", stage: "access" });
    expect(modelReads).toBe(1);

    let blacklistIteratorCalls = 0;
    const blacklist = [fixture.agreementBuyer.address];
    blacklist[Symbol.iterator] = function* (): Generator<string> {
      blacklistIteratorCalls += 1;
      yield fixture.unauthorizedReader.address;
    };
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({
        status: "resolved",
        access: {
          model: "buyer-only",
          allowed: [fixture.agreementBuyer.address],
          blacklist,
        },
        value: pointerBytes,
      }),
    }))).toMatchObject({ disposition: "rejected", stage: "access" });
    expect(blacklistIteratorCalls).toBe(0);

    const negativeLengthBlacklist = new Proxy([fixture.agreementBuyer.address], {
      get: (target, property, receiver) => property === "length"
        ? -1 : Reflect.get(target, property, receiver),
    });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({
        status: "resolved",
        access: {
          model: "buyer-only",
          allowed: [fixture.agreementBuyer.address],
          blacklist: negativeLengthBlacklist,
        },
        value: pointerBytes,
      }),
    }))).toMatchObject({ disposition: "indeterminate", stage: "storage-read" });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      listingDeliverable: publicListing,
      storageRead: () => ({ status: "resolved", access: { model: "public" }, value: pointerBytes }),
    }))).toMatchObject({ disposition: "verified", accessModel: "public" });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      agreementBuyer: encryptedBuyer,
      listingDeliverable: {
        kind: "storage-program",
        accessModel: "encrypt-to-buyer",
        expectedSizeBytes: fixture.payload.sizeBytes,
      },
      reader: encryptedBuyer,
      storageRead: () => ({
        status: "resolved",
        access: { model: "encrypt-to-buyer", sealedTo: encryptedBuyer.encryptionKey },
        value: pointerBytes,
      }),
    }))).toMatchObject({ disposition: "verified", accessModel: "encrypt-to-buyer" });
  });

  test("rejects pointer URL and segment mutations against the immutable pointer pin", () => {
    const urlMutation = canonicalize({ ...fixture.pointer, externalUrl: `${fixture.pointer.externalUrl}?changed=1` });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: storageValue(new TextEncoder().encode(urlMutation)),
    }))).toMatchObject({ disposition: "rejected", stage: "pointer" });

    const segmentMutation = canonicalize({
      ...fixture.pointer,
      segmentRefs: [{ ...fixture.pointer.segmentRefs[0], contentHash: "0".repeat(64) }],
    });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: storageValue(new TextEncoder().encode(segmentMutation)),
    }))).toMatchObject({ disposition: "rejected", stage: "pointer" });

    const bomPrefixedPointer = new Uint8Array(pointerBytes.byteLength + 3);
    bomPrefixedPointer.set([0xef, 0xbb, 0xbf]);
    bomPrefixedPointer.set(pointerBytes, 3);
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      expectedPointerContentHash: sha256(bomPrefixedPointer),
      storageRead: storageValue(bomPrefixedPointer),
    }))).toMatchObject({ disposition: "rejected", stage: "pointer" });
  });

  test("rejects payload, size, ACL, anchor, and inline-cap mutations", () => {
    const mutatedPayload = new Uint8Array(payload);
    mutatedPayload[mutatedPayload.length - 1] = 0x62;
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      externalRead: () => ({ status: "resolved", value: mutatedPayload }),
    }))).toMatchObject({ disposition: "rejected", stage: "payload" });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      externalRead: () => ({ status: "resolved", value: payload.subarray(0, payload.length - 1) }),
    }))).toEqual({
      disposition: "rejected",
      stage: "payload",
      reason: "External payload size does not match the Listing",
    });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({
        status: "resolved",
        access: { model: "buyer-only", allowed: [fixture.unauthorizedReader.address] },
        value: pointerBytes,
      }),
    }))).toMatchObject({ disposition: "rejected", stage: "access" });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({
        status: "resolved",
        access: {
          model: "buyer-only",
          allowed: [fixture.agreementBuyer.address, fixture.unauthorizedReader.address],
        },
        value: pointerBytes,
      }),
    }))).toMatchObject({ disposition: "rejected", stage: "access" });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      evidence: {
        ...fixture.evidence,
        deliverableAnchor: { kind: "storage-program", locator: `${fixture.evidence.deliverableAnchor.locator}:other` },
      },
    }))).toMatchObject({ disposition: "rejected", stage: "configuration" });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: storageValue(new Uint8Array(STORAGE_PROGRAM_INLINE_LIMIT_BYTES + 1)),
    }))).toEqual({
      disposition: "rejected",
      stage: "storage-read",
      reason: "Storage Program value exceeds the inline size limit",
    });

    class MisreportingBytes extends Uint8Array {
      override get byteLength(): number { return 1; }
    }
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: storageValue(new MisreportingBytes(STORAGE_PROGRAM_INLINE_LIMIT_BYTES + 1)),
    }))).toEqual({
      disposition: "rejected",
      stage: "storage-read",
      reason: "Storage Program value exceeds the inline size limit",
    });

    const exactLimitPayload = new Uint8Array(STORAGE_PROGRAM_INLINE_LIMIT_BYTES).fill(0x7a);
    const exactLimitInput = compatibilityInput({
      evidence: {
        deliverableAnchor: fixture.evidence.deliverableAnchor as StorageProgramDeliveryEvidence["deliverableAnchor"],
        deliverableContentHash: sha256(exactLimitPayload),
      },
      externalRead: () => { throw new Error("external read must not run"); },
      listingDeliverable: {
        kind: "storage-program",
        accessModel: "buyer-only",
        expectedSizeBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES,
      },
      storageRead: storageValue(exactLimitPayload),
    });
    delete (exactLimitInput as { expectedPointerContentHash?: string }).expectedPointerContentHash;
    expect(verifyStorageProgramCompatibility(exactLimitInput)).toEqual({
      disposition: "verified",
      accessModel: "buyer-only",
      address: fixture.evidence.deliverableAnchor.locator,
      deliverableContentHash: sha256(exactLimitPayload),
      payloadBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES,
    });
  });

  test("validates segment references after the pointer pin and bounds external reads", () => {
    const invalidSegmentPointer = canonicalize({
      ...fixture.pointer,
      segmentRefs: [{
        ...fixture.pointer.segmentRefs[0]!,
        anchor: { ...fixture.pointer.segmentRefs[0]!.anchor, kind: "unregistered" },
      }],
    });
    const invalidSegmentBytes = new TextEncoder().encode(invalidSegmentPointer);
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      expectedPointerContentHash: sha256(invalidSegmentBytes),
      storageRead: storageValue(invalidSegmentBytes),
    }))).toEqual({
      disposition: "rejected",
      stage: "pointer",
      reason: "Extended pointer shape is invalid",
    });

    const invalidSignerPointer = canonicalize({
      ...fixture.pointer,
      segmentRefs: [{ ...fixture.pointer.segmentRefs[0]!, signer: "not-a-claim-reference" }],
    });
    const invalidSignerBytes = new TextEncoder().encode(invalidSignerPointer);
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      expectedPointerContentHash: sha256(invalidSignerBytes),
      storageRead: storageValue(invalidSignerBytes),
    }))).toMatchObject({ disposition: "rejected", stage: "pointer" });

    let malformedHashReads = 0;
    const malformedHashPointer = canonicalize({
      ...fixture.pointer,
      externalContentHash: [fixture.pointer.externalContentHash],
    });
    const malformedHashBytes = new TextEncoder().encode(malformedHashPointer);
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      expectedPointerContentHash: sha256(malformedHashBytes),
      storageRead: storageValue(malformedHashBytes),
      externalRead: () => {
        malformedHashReads += 1;
        return { status: "resolved", value: payload };
      },
    }))).toMatchObject({ disposition: "rejected", stage: "pointer" });
    expect(malformedHashReads).toBe(0);

    const malformedSegmentHashPointer = canonicalize({
      ...fixture.pointer,
      segmentRefs: [{
        ...fixture.pointer.segmentRefs[0]!,
        contentHash: [fixture.pointer.segmentRefs[0]!.contentHash],
      }],
    });
    const malformedSegmentHashBytes = new TextEncoder().encode(malformedSegmentHashPointer);
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      expectedPointerContentHash: sha256(malformedSegmentHashBytes),
      storageRead: storageValue(malformedSegmentHashBytes),
    }))).toMatchObject({ disposition: "rejected", stage: "pointer" });

    let reads = 0;
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      maxExternalPayloadBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES + 1,
      listingDeliverable: {
        kind: "storage-program",
        expectedSizeBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES + 2,
        accessModel: "buyer-only",
      },
      externalRead: () => {
        reads += 1;
        return { status: "resolved", value: payload };
      },
    }))).toEqual({
      disposition: "refused-unsupported",
      stage: "payload",
      reason: "Listing expected payload size exceeds the configured size limit",
    });
    expect(reads).toBe(0);

    const configuredBudget = STORAGE_PROGRAM_INLINE_LIMIT_BYTES + 1;
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      maxExternalPayloadBytes: configuredBudget,
      externalRead: (_url, maxBytes) => {
        expect(maxBytes).toBe(configuredBudget);
        return { status: "resolved", value: new Uint8Array(configuredBudget + 1) };
      },
    }))).toEqual({
      disposition: "rejected",
      stage: "payload",
      reason: "External payload exceeds the configured size limit",
    });

    expect(verifyStorageProgramCompatibility(compatibilityInput({
      listingDeliverable: {
        kind: "storage-program",
        expectedSizeBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES,
        accessModel: "buyer-only",
      },
      externalRead: () => {
        reads += 1;
        return { status: "resolved", value: payload };
      },
    }))).toEqual({
      disposition: "refused-unsupported",
      stage: "payload",
      reason: "Listing expected payload size is incompatible with an extended pointer",
    });
    expect(reads).toBe(0);
  });

  test("fails closed on malformed, unavailable, and over-budget readers", () => {
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({
        status: "resolved",
        access: { model: "buyer-only", allowed: null },
        value: pointerBytes,
      } as never),
    }))).toMatchObject({ disposition: "indeterminate", stage: "storage-read" });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({ status: "indeterminate" }),
    }))).toMatchObject({ disposition: "indeterminate", stage: "storage-read" });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      externalRead: () => ({ status: "absent" }),
    }))).toMatchObject({ disposition: "rejected", stage: "payload" });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      storageRead: () => ({
        status: "resolved",
        access: { model: "buyer-only", allowed: [fixture.agreementBuyer.address] },
        value: {} as never,
      }),
    }))).toMatchObject({ disposition: "indeterminate", stage: "storage-read" });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      externalRead: () => ({ status: "resolved", value: {} as never }),
    }))).toMatchObject({ disposition: "indeterminate", stage: "payload" });
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      maxExternalPayloadBytes: STORAGE_PROGRAM_INLINE_LIMIT_BYTES,
    }))).toMatchObject({ disposition: "refused-unsupported", stage: "configuration" });
    let reads = 0;
    expect(verifyStorageProgramCompatibility(compatibilityInput({
      maxExternalPayloadBytes: null as never,
      storageRead: () => {
        reads += 1;
        return storageValue(pointerBytes)(fixture.evidence.deliverableAnchor.locator, authorizedReader);
      },
    }))).toMatchObject({ disposition: "refused-unsupported", stage: "configuration" });
    expect(reads).toBe(0);
  });
});

function compatibilityInput(
  overrides: Partial<StorageProgramCompatibilityInput> = {},
): StorageProgramCompatibilityInput {
  return {
    agreementBuyer: fixture.agreementBuyer,
    evidence: fixture.evidence,
    expectedPointerContentHash: fixture.pointerCanonicalSha256,
    externalRead: () => ({ status: "resolved", value: payload }),
    jobId: fixture.jobId,
    listingDeliverable: fixture.listingDeliverable,
    reader: authorizedReader,
    storageRead: storageValue(pointerBytes),
    ...overrides,
  } as StorageProgramCompatibilityInput;
}

function storageValue(value: Uint8Array): StorageProgramCompatibilityInput["storageRead"] {
  return () => ({
    status: "resolved",
    access: { model: "buyer-only", allowed: [fixture.agreementBuyer.address], blacklist: [] },
    value,
  });
}

function sha256(value: Uint8Array): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

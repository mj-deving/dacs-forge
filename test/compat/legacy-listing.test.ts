import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import { readPinnedLegacySdkListingEnvelopeJson } from "../../src/compat/legacy-listing.ts";

const FIXTURE_URL = new URL(
  "../../vectors/community-directory/reviewbot-legacy-listing-634caef.json",
  import.meta.url,
);
const FIXTURE_SHA256 = "a390974f6579d2e57df259c3e13787458bf9ebc856c19b5e4f821230b8ee18f3";
const PROVENANCE = Object.freeze({
  expectedEnvelopeSha256: FIXTURE_SHA256,
  expectedOwner: "0x4401feab4dfc36e1166ad0dc1c4987dd0c728a57616fa496c25ca2a260651808",
  expectedStorageAddress: "stor-9f990919614234174e89241dc221f31fb516acbe",
});

describe("legacy Directory listing compatibility", () => {
  test("retains and verifies the pinned legacy-sdk-v0.1 artifact without rewriting it", async () => {
    const raw = await Bun.file(FIXTURE_URL).text();
    expect(createHash("sha256").update(raw).digest("hex")).toBe(FIXTURE_SHA256);

    const read = readPinnedLegacySdkListingEnvelopeJson(raw, PROVENANCE);
    const source = JSON.parse(raw) as Record<string, unknown>;
    const data = source["data"] as Record<string, unknown>;
    expect(read.artifactProfile).toBe("legacy-sdk-v0.1");
    expect(read.contentHash).toBe("990f00bb76cc652a90db998694f3e0bf9aec65569b92d852886a1bad6a1bd85f");
    expect(read.sourceEnvelopeSha256).toBe(FIXTURE_SHA256);
    expect(read.signer).toBe("did:demos:agent:4401feab4dfc36e1166ad0dc1c4987dd0c728a57616fa496c25ca2a260651808");
    expect(read.sourceEnvelope).toEqual(source);
    expect(canonicalize(read.scope)).toBe(canonicalize(withoutFields(data, "signature")));
    expect(read.scope).not.toHaveProperty("dacsVersion");
    expect(read.scope).not.toHaveProperty("listingVersion");
    expect(read.scope).not.toHaveProperty("seller");
    expect(read.scope).not.toHaveProperty("offering");
    expect(Object.isFrozen(read)).toBe(true);
    expect(Object.isFrozen(read.sourceEnvelope)).toBe(true);
    expect(Object.isFrozen(read.scope.supportedPaymentRails)).toBe(true);
  });

  test("rejects signed-field tampering, owner substitution, and current-profile ambiguity", async () => {
    const source = JSON.parse(await Bun.file(FIXTURE_URL).text()) as Record<string, unknown>;
    const tampered = structuredClone(source);
    (tampered["data"] as Record<string, unknown>)["description"] = "tampered";
    const tamperedRaw = JSON.stringify(tampered);
    expect(() => readPinnedLegacySdkListingEnvelopeJson(tamperedRaw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: createHash("sha256").update(tamperedRaw).digest("hex"),
    })).toThrow(/signature is invalid/);

    const wrongOwner = structuredClone(source);
    wrongOwner["owner"] = `0x${"00".repeat(32)}`;
    const wrongOwnerRaw = JSON.stringify(wrongOwner);
    expect(() => readPinnedLegacySdkListingEnvelopeJson(wrongOwnerRaw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: createHash("sha256").update(wrongOwnerRaw).digest("hex"),
    })).toThrow(/trusted storage provenance/);

    const wrongLocator = structuredClone(source);
    wrongLocator["storageAddress"] = `stor-${"00".repeat(20)}`;
    const wrongLocatorRaw = JSON.stringify(wrongLocator);
    expect(() => readPinnedLegacySdkListingEnvelopeJson(wrongLocatorRaw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: createHash("sha256").update(wrongLocatorRaw).digest("hex"),
    })).toThrow(/trusted storage provenance/);

    const mixedProfile = structuredClone(source);
    (mixedProfile["data"] as Record<string, unknown>)["dacsVersion"] = "1";
    const mixedRaw = `${JSON.stringify(mixedProfile)}\n`;
    expect(() => readPinnedLegacySdkListingEnvelopeJson(mixedRaw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: createHash("sha256").update(mixedRaw).digest("hex"),
    })).toThrow(/unsupported profile field dacsVersion/);
  });

  test("fails closed on malformed legacy compatibility fields", async () => {
    const source = JSON.parse(await Bun.file(FIXTURE_URL).text()) as Record<string, unknown>;
    const duplicateRails = structuredClone(source);
    (duplicateRails["data"] as Record<string, unknown>)["supportedPaymentRails"] = ["pay-dem", "pay-dem"];
    const duplicateRaw = `${JSON.stringify(duplicateRails)}\n`;
    expect(() => readPinnedLegacySdkListingEnvelopeJson(duplicateRaw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: createHash("sha256").update(duplicateRaw).digest("hex"),
    })).toThrow(/supportedPaymentRails is invalid/);

    const oversized = JSON.stringify({ value: "x".repeat(32_769) });
    expect(() => readPinnedLegacySdkListingEnvelopeJson(oversized, PROVENANCE))
      .toThrow(/no larger than 32768/);
  });

  test("rejects a well-formed mismatched pin and malformed provenance", async () => {
    const raw = await Bun.file(FIXTURE_URL).text();
    expect(() => readPinnedLegacySdkListingEnvelopeJson(raw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: "00".repeat(32),
    })).toThrow(/immutable source pin/);
    expect(() => readPinnedLegacySdkListingEnvelopeJson(raw, {
      ...PROVENANCE,
      expectedEnvelopeSha256: "not-a-sha256",
    })).toThrow(/source provenance is invalid/);
  });
});

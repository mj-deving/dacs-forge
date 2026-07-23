import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { readPinnedLegacySdkListingEnvelopeJson } from "../../src/compat/legacy-listing.ts";
import { projectLegacyDirectorySummary } from "../../src/directory/listing-summary.ts";
import {
  COMMUNITY_DIRECTORY_COMMIT,
  LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
  PINNED_LISTING_SUMMARY_SCHEMA_JSON,
  validateDirectoryListingSummary,
} from "../../src/protocol/directory-summary-schema.ts";

const FIXTURE_URL = new URL(
  "../../vectors/community-directory/reviewbot-legacy-listing-634caef.json",
  import.meta.url,
);
const OBSERVED_AT = 1_784_657_035_680;
const LEGACY_PROVENANCE = Object.freeze({
  expectedEnvelopeSha256: "a390974f6579d2e57df259c3e13787458bf9ebc856c19b5e4f821230b8ee18f3",
  expectedOwner: "0x4401feab4dfc36e1166ad0dc1c4987dd0c728a57616fa496c25ca2a260651808",
  expectedStorageAddress: "stor-9f990919614234174e89241dc221f31fb516acbe",
});

describe("Directory ListingSummary compatibility", () => {
  test("binds the validator to the captured live schema bytes and Community commit", () => {
    expect(COMMUNITY_DIRECTORY_COMMIT).toBe("634caef4b952838281c8c602402e657d41074703");
    expect(createHash("sha256").update(PINNED_LISTING_SUMMARY_SCHEMA_JSON).digest("hex"))
      .toBe(LIVE_LISTING_SUMMARY_SCHEMA_SHA256);
  });

  test("projects the pinned legacy artifact into a schema-valid, explicitly legacy summary", async () => {
    const raw = await Bun.file(FIXTURE_URL).text();
    const read = readPinnedLegacySdkListingEnvelopeJson(raw, LEGACY_PROVENANCE);
    const before = JSON.stringify(read.sourceEnvelope);
    const summary = projectLegacyDirectorySummary(read, {
      sellerDisplayName: "ReviewBot",
      catalogObservedAt: OBSERVED_AT,
      status: "active",
    });

    expect(summary).toEqual({
      listingId: "pr-review",
      version: 1,
      contentHash: "990f00bb76cc652a90db998694f3e0bf9aec65569b92d852886a1bad6a1bd85f",
      anchor: {
        kind: "storage-program",
        locator: "stor-9f990919614234174e89241dc221f31fb516acbe",
      },
      seller: {
        primaryClaim: "did:demos:agent:4401feab4dfc36e1166ad0dc1c4987dd0c728a57616fa496c25ca2a260651808",
        displayName: "ReviewBot",
      },
      artifactProfile: "legacy-sdk-v0.1",
      offering: {
        title: "LLM code review from a CCI-verified GitHub identity",
        description: "Automated LLM code review delivered as a GitHub PR review, authored from a CCI-verified GitHub identity. Fee: 0.5 DEM per 100-diff-lines (min 1 DEM).",
        category: "services.other",
        tags: [],
        rails: ["pay-dem", "pay-x402"],
        delivery: ["deliver-github-pr-review"],
        negotiation: ["negotiate-fixed-price"],
      },
      pricing: {},
      status: "active",
      catalogObservedAt: OBSERVED_AT,
    });
    expect(validateDirectoryListingSummary(summary)).toEqual({ valid: true, errors: [] });
    expect(JSON.stringify(read.sourceEnvelope)).toBe(before);
    expect(Object.isFrozen(summary)).toBe(true);
  });

  test("rejects summaries outside the pinned live contract", () => {
    const missingAnchor = {
      listingId: "pr-review",
      version: 1,
      contentHash: "hash",
      seller: { primaryClaim: "did:demos:agent:abc", displayName: "ReviewBot" },
      offering: { title: "Review", category: "services.other", tags: [] },
      pricing: {},
      status: "active",
      catalogObservedAt: OBSERVED_AT,
    };
    const invalidProfile = {
      ...missingAnchor,
      anchor: { kind: "storage-program", locator: "stor-example" },
      artifactProfile: "dacs-forge-current",
    };
    expect(validateDirectoryListingSummary(missingAnchor).valid).toBe(false);
    expect(validateDirectoryListingSummary(invalidProfile).valid).toBe(false);
  });

  test("refuses a structurally forged legacy read result", () => {
    expect(() => projectLegacyDirectorySummary({
      artifactProfile: "legacy-sdk-v0.1",
      sourceEnvelope: {},
      scope: {
        name: "forged",
        agentId: `did:demos:agent:${"00".repeat(32)}`,
        serviceId: "forged",
        description: "forged",
        claimRequirements: [],
        supportedDelivery: [],
        supportedNegotiation: [],
        supportedPaymentRails: [],
      },
      contentHash: "00".repeat(32),
      signer: `did:demos:agent:${"00".repeat(32)}`,
      storageAddress: `stor-${"00".repeat(20)}`,
      sourceEnvelopeSha256: "00".repeat(32),
    }, {
      sellerDisplayName: "forged",
      catalogObservedAt: OBSERVED_AT,
      status: "active",
    })).toThrow(/verified legacy Listing read result/);
  });
});

import { describe, expect, test } from "bun:test";
import {
  createServiceDirectoryFixture,
} from "../../scripts/verify-directory-supply.ts";
import { validateDirectoryListingSummary } from "../../src/protocol/directory-summary-schema.ts";
import type { ServiceContract } from "../../src/service/contract.ts";
import { serviceContract as baseContract } from "../../service/service.config.ts";

function alternateContract(): ServiceContract<unknown, unknown> {
  return {
    ...baseContract,
    service: {
      id: `${baseContract.service.id}-alternate`,
      version: "1.0.0",
      title: `${baseContract.service.title} Alternate`,
      deliverableKind: `${baseContract.service.deliverableKind}-alternate`,
    },
  } as ServiceContract<unknown, unknown>;
}

describe("Product Seal Directory supply qualification", () => {
  test("emits distinct service-bound signed Listings and crawl artifacts", () => {
    const base = createServiceDirectoryFixture(
      baseContract as ServiceContract<unknown, unknown>,
      "1".repeat(64),
    );
    const alternate = createServiceDirectoryFixture(alternateContract(), "1".repeat(64));

    expect(base.service.id).toBe(baseContract.service.id);
    expect(alternate.service.id).toBe(`${baseContract.service.id}-alternate`);
    expect(base.listingCanonicalJson).not.toBe(alternate.listingCanonicalJson);
    expect(base.discoveryCanonicalJson).not.toBe(alternate.discoveryCanonicalJson);
    expect(JSON.parse(base.listingCanonicalJson)).toMatchObject({
      listingId: baseContract.service.id,
      seller: { displayName: baseContract.service.title },
    });
    expect(JSON.parse(alternate.listingCanonicalJson)).toMatchObject({
      listingId: `${baseContract.service.id}-alternate`,
      seller: { displayName: `${baseContract.service.title} Alternate` },
    });
    const baseDiscovery = JSON.parse(base.discoveryCanonicalJson);
    const alternateDiscovery = JSON.parse(alternate.discoveryCanonicalJson);
    expect(baseDiscovery).toMatchObject({
      listingId: baseContract.service.id,
      seller: { displayName: baseContract.service.title },
    });
    expect(alternateDiscovery).toMatchObject({
      listingId: `${baseContract.service.id}-alternate`,
      seller: { displayName: `${baseContract.service.title} Alternate` },
    });
    expect(validateDirectoryListingSummary(baseDiscovery)).toEqual({
      valid: true,
      errors: [],
    });
    expect(validateDirectoryListingSummary(alternateDiscovery)).toEqual({
      valid: true,
      errors: [],
    });
  });

  test("rejects generic fixture or substituted fork artifacts", () => {
    const fixture = createServiceDirectoryFixture(
      baseContract as ServiceContract<unknown, unknown>,
      "1".repeat(64),
    );
    for (const index of [0, 1, 2, 3]) {
      expect(fixture.listingCanonicalJson).toContain(`impl-sha256-${index}-${"1".repeat(16)}`);
    }
    expect(() => createServiceDirectoryFixture(alternateContract(), "invalid")).toThrow(
      "Service implementation digest is invalid",
    );
  });

  test("fails closed on an invalid target service descriptor", () => {
    const invalid = {
      ...alternateContract(),
      service: { ...alternateContract().service, id: "Invalid Service" },
    } as ServiceContract<unknown, unknown>;
    expect(() => createServiceDirectoryFixture(invalid, "1".repeat(64))).toThrow(/ListingId|listingId|URL-safe|Service id/i);
  });
});

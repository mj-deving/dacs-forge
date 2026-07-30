import { describe, expect, test } from "bun:test";
import {
  createServiceDirectoryFixture,
} from "../../scripts/verify-directory-supply.ts";
import { validateDirectoryListingSummary } from "../../src/protocol/directory-summary-schema.ts";
import type { ServiceContract } from "../../src/service/contract.ts";
import { serviceContract as baseContract } from "../../service/service.config.ts";

function forkContract(): ServiceContract<unknown, unknown> {
  return {
    ...baseContract,
    service: {
      id: "counterparty-evidence",
      version: "1.0.0",
      title: "Counterparty Evidence",
      deliverableKind: "counterparty-evidence-result",
    },
  } as ServiceContract<unknown, unknown>;
}

describe("Product Seal Directory supply qualification", () => {
  test("emits distinct service-bound signed Listings and crawl artifacts", () => {
    const base = createServiceDirectoryFixture(
      baseContract as ServiceContract<unknown, unknown>,
      "1".repeat(64),
    );
    const fork = createServiceDirectoryFixture(forkContract(), "2".repeat(64));

    expect(base.service.id).toBe("reference-json-transform");
    expect(fork.service.id).toBe("counterparty-evidence");
    expect(base.listingCanonicalJson).not.toBe(fork.listingCanonicalJson);
    expect(base.discoveryCanonicalJson).not.toBe(fork.discoveryCanonicalJson);
    expect(JSON.parse(base.listingCanonicalJson)).toMatchObject({
      listingId: "reference-json-transform",
      seller: { displayName: "Reference JSON Transform" },
    });
    expect(JSON.parse(fork.listingCanonicalJson)).toMatchObject({
      listingId: "counterparty-evidence",
      seller: { displayName: "Counterparty Evidence" },
    });
    expect(validateDirectoryListingSummary(JSON.parse(base.discoveryCanonicalJson))).toEqual({
      valid: true,
      errors: [],
    });
    expect(validateDirectoryListingSummary(JSON.parse(fork.discoveryCanonicalJson))).toEqual({
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
    expect(() => createServiceDirectoryFixture(forkContract(), "invalid")).toThrow(
      "Service implementation digest is invalid",
    );
  });

  test("fails closed on an invalid target service descriptor", () => {
    const invalid = {
      ...forkContract(),
      service: { ...forkContract().service, id: "Counterparty Evidence" },
    } as ServiceContract<unknown, unknown>;
    expect(() => createServiceDirectoryFixture(invalid, "1".repeat(64))).toThrow(/ListingId|listingId|URL-safe|Service id/i);
  });
});

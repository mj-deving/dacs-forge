import { describe, expect, test } from "bun:test";
import { integratedServiceLifecycleRequestHash } from "../../src/protocol/integrated-service-request.ts";

describe("integrated service lifecycle request authority", () => {
  test("binds the Agreement and Service request hashes into one admission authority", () => {
    const agreement = "a".repeat(64);
    const service = "b".repeat(64);
    const combined = integratedServiceLifecycleRequestHash(agreement, service);

    expect(combined).toMatch(/^[0-9a-f]{64}$/);
    expect(combined).not.toBe(integratedServiceLifecycleRequestHash("c".repeat(64), service));
    expect(combined).not.toBe(integratedServiceLifecycleRequestHash(agreement, "d".repeat(64)));
  });
});

import { describe, expect, test } from "bun:test";
import {
  containerFixtureReceipt,
  main,
  normalizeHealthDocument,
} from "../../scripts/container-fixture-runtime.ts";
import { parseContainerFixtureReceipt } from "../../scripts/verify-container-fixture.ts";

describe("container fixture runtime contract", () => {
  test("binds the complete fixture proofs to zero live or telemetry effects", () => {
    expect(containerFixtureReceipt()).toEqual({
      schema: "dacs-container-fixture/v1",
      evidenceMode: "fixture",
      lifecycle: "verified",
      tests: [
        "test/runtime/service-runtime.test.ts",
        "test/e2e/full-handshake.test.ts",
        "test/security/secret-boundary.test.ts",
      ],
      effects: {
        analytics: 0,
        liveAnchors: 0,
        liveBroadcasts: 0,
        liveRegistrations: 0,
        liveTransfers: 0,
        liveWrites: 0,
        telemetry: 0,
      },
    });
  });

  test("normalizes only the exact public health contract", () => {
    expect(normalizeHealthDocument({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      timestamp: "2026-07-27T18:00:00.000Z",
      version: "0.1.1",
    })).toEqual({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      version: "0.1.1",
    });
    expect(() => normalizeHealthDocument({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      timestamp: "not-a-time",
      version: "0.1.1",
    })).toThrow("health contract");
    expect(() => normalizeHealthDocument({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      timestamp: "2026-07-27T18:00:00.000Z",
      version: "0.1.1",
      detail: "unexpected",
    })).toThrow("unexpected shape");
  });

  test("refuses unknown commands without starting a runtime", async () => {
    expect(await main(["publish"])).toBe(2);
    expect(await main([])).toBe(2);
  });

  test("refuses a missing or path-unsafe external boundary marker", async () => {
    const previous = process.env["DACS_FORGE_SECRET_SENTINEL"];
    try {
      for (const marker of [undefined, `sentinel-${"x".repeat(33)}-${"a".repeat(32)}`]) {
        if (marker === undefined) delete process.env["DACS_FORGE_SECRET_SENTINEL"];
        else process.env["DACS_FORGE_SECRET_SENTINEL"] = marker;
        let diagnostic = "";
        try {
          await main(["self-test"]);
        } catch (error) {
          diagnostic = error instanceof Error ? error.message : "non-error failure";
        }
        expect(diagnostic.includes("requires a valid boundary marker")).toBe(true);
        if (marker !== undefined) expect(diagnostic.includes(marker)).toBe(false);
      }
    } finally {
      if (previous === undefined) delete process.env["DACS_FORGE_SECRET_SENTINEL"];
      else process.env["DACS_FORGE_SECRET_SENTINEL"] = previous;
    }
  });

  test("requires the exact complete fixture receipt", () => {
    const valid = JSON.stringify(containerFixtureReceipt());
    expect(parseContainerFixtureReceipt(`runner output\n${valid}\n`)).toEqual(
      containerFixtureReceipt(),
    );
    for (const malformed of [
      { ...containerFixtureReceipt(), tests: [] },
      { ...containerFixtureReceipt(), effects: {} },
      {
        ...containerFixtureReceipt(),
        effects: { ...containerFixtureReceipt().effects, liveWrites: 1 },
      },
      { ...containerFixtureReceipt(), extra: true },
    ]) {
      expect(() => parseContainerFixtureReceipt(JSON.stringify(malformed))).toThrow(
        "bounded no-live-effect contract",
      );
    }
  });
});

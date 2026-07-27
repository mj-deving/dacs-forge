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
      version: "0.0.0-private",
    })).toEqual({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      version: "0.0.0-private",
    });
    expect(() => normalizeHealthDocument({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      timestamp: "not-a-time",
      version: "0.0.0-private",
    })).toThrow("health contract");
    expect(() => normalizeHealthDocument({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      timestamp: "2026-07-27T18:00:00.000Z",
      version: "0.0.0-private",
      detail: "unexpected",
    })).toThrow("unexpected shape");
  });

  test("refuses unknown commands without starting a runtime", async () => {
    expect(await main(["publish"])).toBe(2);
    expect(await main([])).toBe(2);
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

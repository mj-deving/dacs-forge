import { describe, expect, test } from "bun:test";
import {
  EvidenceModeError,
  assertFixtureAuthority,
  parseEvidenceMode,
} from "../../src/core/evidence-mode.ts";

describe("evidence mode", () => {
  test("parses only the closed evidence-mode set", () => {
    expect(parseEvidenceMode("fixture")).toBe("fixture");
    expect(parseEvidenceMode("local-chain")).toBe("local-chain");
    expect(parseEvidenceMode("live")).toBe("live");
    expect(() => parseEvidenceMode("test")).toThrow(EvidenceModeError);
  });

  test("administrator fixture authority is mode-bound on both sides", () => {
    expect(() => assertFixtureAuthority("fixture", "fixture")).not.toThrow();
    expect(() => assertFixtureAuthority("local-chain", "fixture")).toThrow();
    expect(() => assertFixtureAuthority("live", "fixture")).toThrow();
    expect(() => assertFixtureAuthority("fixture", "live")).toThrow();
  });
});

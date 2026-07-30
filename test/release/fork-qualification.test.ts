import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertExactEffectsRecord } from "../../scripts/qualify-fork.ts";

function effects(): Record<string, false> {
  return {
    public: false,
    release: false,
    registration: false,
    deployment: false,
    payment: false,
    transfer: false,
    spend: false,
    liveValue: false,
  };
}

describe("Product Seal fork qualification trust boundary", () => {
  test("accepts only the complete exact no-effect record", () => {
    expect(assertExactEffectsRecord(effects())).toEqual(effects());
  });

  test("rejects missing, additional, and nonfalse effects", () => {
    const missing = effects();
    delete missing["transfer"];
    expect(() => assertExactEffectsRecord(missing)).toThrow(/incomplete or unexpected/);

    expect(() => assertExactEffectsRecord({ ...effects(), network: false })).toThrow(
      /incomplete or unexpected/,
    );
    expect(() => assertExactEffectsRecord({ ...effects(), liveValue: true })).toThrow(
      /liveValue is not false/,
    );
  });

  test("exposes no caller-supplied evidence-file interface", () => {
    const source = readFileSync(resolve(import.meta.dir, "../../scripts/qualify-fork.ts"), "utf8");
    for (const forbidden of [
      "--rig-evidence",
      "--readiness-report",
      "--container-receipt",
      "--directory-supply",
      "validateForkQualificationInputs",
      "exactJsonFile",
    ]) expect(source).not.toContain(forbidden);
    expect(source).toContain("fresh-local-no-hardlinks-exact-commits");
    expect(source).toContain("runTrustedCommand(baseClone, FULL_RIG)");
    expect(source).toContain("runTrustedCommand(forkClone, FULL_RIG)");
  });
});

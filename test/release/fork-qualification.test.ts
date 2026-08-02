import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertExactEffectsRecord, candidateRigDefinition } from "../../scripts/qualify-fork.ts";
import { rigInventory } from "../../scripts/verify-release-manifest.ts";

const ROOT = resolve(import.meta.dir, "../..");

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
    expect(source).toContain('["bun", "install", "--frozen-lockfile", "--ignore-scripts"]');
    expect(source).toContain("runTrustedCommand(baseClone, FROZEN_INSTALL)");
    expect(source).toContain("runTrustedCommand(forkClone, FROZEN_INSTALL)");
    expect(source).toContain("runTrustedCommand(baseClone, FULL_RIG)");
    expect(source).toContain("runTrustedCommand(forkClone, FORK_RIG)");
  });

  test("qualifies the exact current candidate rig while preserving the historical release pin", () => {
    expect(candidateRigDefinition(ROOT)).toBe(rigInventory(ROOT));
    expect(candidateRigDefinition(ROOT)).not.toBe(rigInventory(ROOT, "v0.1.1"));
  });
});

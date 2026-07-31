import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { fixtureExecutionProfile } from "../../src/live/profile.ts";

describe("zero-effect defaults", () => {
  test("default profile and package commands expose no live adapter entry point", async () => {
    expect(fixtureExecutionProfile()).toMatchObject({ networkEffects: false, allowedEffects: [] });
    const packageJson = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8")) as {
      scripts: Record<string, string>;
    };
    for (const name of ["build", "check", "test", "container:self-test", "verify:product-seal-candidate"]) {
      const command = packageJson.scripts[name];
      expect(command, name).toBeString();
      expect(command).not.toContain("src/adapters/");
      expect(command).not.toContain("live-testnet");
    }
  });
});

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyGovernance } from "../../scripts/verify-governance.ts";

const governance = readFileSync(resolve(import.meta.dir, "../../GOVERNANCE.md"), "utf8");

describe("Product Seal public governance", () => {
  test("names every required authority, policy, support, and no-endorsement boundary", () => {
    expect(verifyGovernance(governance)).toEqual({
      schema: "dacs-forge-governance-verification/v1",
      checks: 20,
    });
  });

  test("rejects a missing security path or support activation boundary", () => {
    expect(() => verifyGovernance(governance.replace("[security policy](SECURITY.md)", "security policy"))).toThrow();
    expect(() => verifyGovernance(governance.replace("immutable release readback", "publication"))).toThrow();
  });
});

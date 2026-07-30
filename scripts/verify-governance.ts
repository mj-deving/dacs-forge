#!/usr/bin/env bun

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const REQUIRED = [
  "## Authority boundaries", "## Maintainers", "## Decision standard", "## Releases",
  "## Security reporting", "[security policy](SECURITY.md)", "## Contribution boundary",
  "[contribution guide](CONTRIBUTING.md)", "## Supported release",
  "v0.1.0", "immutable release readback", "minor bump", "migration guidance",
  "Patch releases preserve", "Community", "Demos-team", "canonical", "steward",
  "adoption", "support organization",
] as const;

export function verifyGovernance(text: string): Readonly<{ schema: string; checks: number }> {
  for (const required of REQUIRED) if (!text.includes(required)) throw new Error(`governance is missing: ${required}`);
  return Object.freeze({ schema: "dacs-forge-governance-verification/v1", checks: REQUIRED.length });
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, "..");
  console.log(JSON.stringify(verifyGovernance(readFileSync(resolve(root, "GOVERNANCE.md"), "utf8"))));
}

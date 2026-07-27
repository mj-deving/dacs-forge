import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { initializeProductionSigning } from "../../src/substrate/keys/production-key-lifecycle.ts";
import { TestSignerProvider } from "../fixtures/production-key-provider.ts";

const FIXTURE_LABELS = [
  "reference-dacs-template-listing-v1",
  "reference-dacs-template-buyer-v1",
  "reference-dacs-template-attacker-v1",
  "reference-dacs-template-orchestrator-v1",
] as const;

describe("fixture fingerprint startup boundary", () => {
  test.each(["local-chain", "live"] as const)(
    "rejects every recognized fixture key before %s action initialization",
    (deploymentMode) => {
      for (const [index, label] of FIXTURE_LABELS.entries()) {
        const seed = createHash("sha256").update(label).digest();
        const provider = new TestSignerProvider().add(`fixture-${index}`, seed);
        let initialized = 0;
        expect(() => initializeProductionSigning({
          deploymentMode,
          provider,
          keyHandle: `fixture-${index}`,
          initializeActionProvider: () => { initialized += 1; return {}; },
        })).toThrow(/recognized fixture key fingerprint/i);
        expect(initialized).toBe(0);
      }
    },
  );
});

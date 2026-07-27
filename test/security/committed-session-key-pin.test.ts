import { describe, expect, test } from "bun:test";
import { ProductionKeyLifecycle } from "../../src/substrate/keys/production-key-lifecycle.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { withProductionKeyLifecycle } from "../fixtures/production-key-provider.ts";

describe("committed session key pin", () => {
  test("survives restart and preserves only exact pre-revocation evidence", async () => {
    await withProductionKeyLifecycle(({ database, lifecycle, path, provider, resolver }) => {
      const first = provider.claim("primary-v1");
      const second = provider.claim("primary-v2");
      resolver.current(first);
      lifecycle.activateInitialKey("primary-v1", 10);
      lifecycle.pinCommittedSession({
        jobId: "01J00000000000000000000000",
        agreementHash: "a".repeat(64),
        keyClaim: first,
        committedAt: 90,
      });
      resolver.current(second);
      expect(() => lifecycle.rotate("primary-v2", 90))
        .toThrow(/follow every committed session pin/i);
      lifecycle.rotate("primary-v2", 100);
      database.close(false);
      const reopened = openDatabase(path);
      const restarted = new ProductionKeyLifecycle(reopened, {
        deploymentMode: "local-chain", provider, resolver,
      });
      try {
        restarted.assertCommittedSessionKey({
          jobId: "01J00000000000000000000000",
          agreementHash: "a".repeat(64),
          checkedAt: 101,
          keyClaim: first,
          evidenceSignedAt: 99,
        });
        expect(() => restarted.assertCommittedSessionKey({
          jobId: "01J00000000000000000000000",
          agreementHash: "a".repeat(64),
          checkedAt: 101,
          keyClaim: first,
          evidenceSignedAt: 89,
        })).toThrow(/validity interval/i);
        expect(() => restarted.assertCommittedSessionKey({
          jobId: "01J00000000000000000000000",
          agreementHash: "a".repeat(64),
          checkedAt: 101,
          keyClaim: first,
          evidenceSignedAt: 101,
        })).toThrow(/validity interval/i);
        expect(() => restarted.assertCommittedSessionKey({
          jobId: "01J00000000000000000000000",
          agreementHash: "a".repeat(64),
          checkedAt: 101,
          keyClaim: second,
          evidenceSignedAt: 89,
        })).toThrow(/pre-revocation key pin/i);
        expect(() => restarted.assertCommittedSessionKey({
          jobId: "01J00000000000000000000000",
          agreementHash: "a".repeat(64),
          checkedAt: 101,
          keyClaim: first,
          evidenceSignedAt: 102,
        })).toThrow(/validity interval/i);
      } finally {
        reopened.close(false);
      }
    });
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runRecoverableEffect, type EffectAdapter } from "../../src/live/effect-runner.ts";
import { LiveEffectStore } from "../../src/live/effect-store.ts";
import { admitExecutionProfile } from "../../src/live/profile.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";

const directories: string[] = [];
const TEST_PROFILE = admitExecutionProfile({
  mode: "live-testnet",
  signer: {
    kind: "injected",
    keyReference: "fixture:seller",
    publicKeyHex: "2".repeat(64),
    expectedClaim: `did:demos:agent:${"1".repeat(64)}`,
  },
  anchor: {
    adapter: "demos-sdk",
    chain: "demos-testnet",
    rpcUrl: "https://demos.example",
    sdkCommit: "e2070e0085414c67d139e1e62924ca9ef8b316c7",
  },
  directory: {
    endpoint: "https://community.example/api/dacs",
    manifestUrl: "https://community.example/.well-known/dacs-directory.json",
    schemaSha256: "2".repeat(64),
  },
  rail: { id: "fixture", chain: "demos-testnet", maxAtomicAmount: "0" },
  effects: { environment: "testnet", allow: ["anchor", "directory-register"], maxAttempts: 1 },
});
const effectStore = (database: ReturnType<typeof openDatabase>) => new LiveEffectStore(
  database,
  () => "2026-07-31T00:00:00.000Z",
);
afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("live effect recovery", () => {
  for (const crashAt of ["before-submit", "after-submit", "after-observation", "before-commit"] as const) {
    test(`${crashAt} restart reconciles without a duplicate effect`, async () => {
      const directory = await mkdtemp(join(tmpdir(), "dacs-live-effect-"));
      directories.push(directory);
      const path = join(directory, "state.sqlite");
      const external = new Map<string, Readonly<{ externalRef: string; value: string }>>();
      let submissions = 0;
      const adapter: EffectAdapter<{ value: string }> = {
        reconcile: async ({ effectKey }) => external.get(effectKey) ?? { disposition: "absent" },
        submit: async ({ effectKey, payload }) => {
          submissions += 1;
          const result = Object.freeze({ externalRef: `tx-${effectKey}`, value: payload.value });
          external.set(effectKey, result);
          return result;
        },
      };

      let database = openDatabase(path);
      await expect(runRecoverableEffect({
        store: effectStore(database),
        profile: TEST_PROFILE,
        effectKey: "listing-anchor:reference:v1",
        kind: "anchor",
        payload: { value: "canonical-listing-bytes" },
        adapter,
        crash: (boundary) => {
          if (boundary === crashAt) throw new Error(`crash:${boundary}`);
        },
      })).rejects.toThrow(`crash:${crashAt}`);
      database.close();

      database = openDatabase(path);
      const result = await runRecoverableEffect({
        store: effectStore(database),
        profile: TEST_PROFILE,
        effectKey: "listing-anchor:reference:v1",
        kind: "anchor",
        payload: { value: "canonical-listing-bytes" },
        adapter,
      });
      expect(result).toEqual({ externalRef: "tx-listing-anchor:reference:v1", value: "canonical-listing-bytes" });
      expect(submissions).toBe(1);
      expect(effectStore(database).get("listing-anchor:reference:v1")?.state).toBe("committed");
      database.close();
    });
  }

  test("fails closed when reconciliation is indeterminate", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-effect-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    let submitted = false;
    const adapter: EffectAdapter<{ value: string }, { externalRef: string }> = {
      reconcile: async () => ({ disposition: "indeterminate", reason: "catalog unavailable" }),
      submit: async () => {
        submitted = true;
        return { externalRef: "unexpected" };
      },
    };
    await expect(runRecoverableEffect({
      store: effectStore(database),
      profile: TEST_PROFILE,
      effectKey: "directory:reference:v1",
      kind: "directory-register",
      payload: { value: "projection" },
      adapter,
    })).rejects.toThrow(/indeterminate/);
    expect(submitted).toBe(false);
    database.close();
  });

  test("never resubmits an attempted effect while reconciliation remains absent", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-effect-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    let submissions = 0;
    const adapter: EffectAdapter<{ value: string }, { externalRef: string }> = {
      reconcile: async () => ({ disposition: "absent" }),
      submit: async () => {
        submissions += 1;
        return { externalRef: "queued" };
      },
    };
    const input = {
      store: effectStore(database),
      profile: TEST_PROFILE,
      effectKey: "directory:queued:v1",
      kind: "directory-register" as const,
      payload: { value: "projection" },
      adapter,
    };
    await expect(runRecoverableEffect(input)).rejects.toThrow(/not yet observable/);
    await expect(runRecoverableEffect(input)).rejects.toThrow(/refusing to resubmit/);
    expect(submissions).toBe(1);
    database.close();
  });

  test("allows only one concurrent runner to win the submission transition", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-effect-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    let initialReconciliations = 0;
    let releaseInitial!: () => void;
    const initialBarrier = new Promise<void>((resolve) => { releaseInitial = resolve; });
    let external: Readonly<{ externalRef: string; value: string }> | undefined;
    let submissions = 0;
    const adapter: EffectAdapter<{ value: string }> = {
      reconcile: async () => {
        if (external !== undefined) return external;
        initialReconciliations += 1;
        if (initialReconciliations === 2) releaseInitial();
        await initialBarrier;
        return { disposition: "absent" };
      },
      submit: async ({ payload }) => {
        submissions += 1;
        external = { externalRef: "single-winner", value: payload.value };
        return external;
      },
    };
    const input = {
      store: effectStore(database),
      profile: TEST_PROFILE,
      effectKey: "anchor:concurrent:v1",
      kind: "anchor" as const,
      payload: { value: "canonical" },
      adapter,
    };
    const results = await Promise.allSettled([
      runRecoverableEffect(input),
      runRecoverableEffect(input),
    ]);
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(1);
    expect(submissions).toBe(1);
    expect(effectStore(database).get("anchor:concurrent:v1")?.state).toBe("committed");
    database.close();
  });

  test("rejects an effect outside the admitted profile allow-list before persistence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-effect-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    const adapter: EffectAdapter<{ value: string }, { externalRef: string }> = {
      reconcile: async () => ({ disposition: "absent" }),
      submit: async () => ({ externalRef: "unexpected" }),
    };
    await expect(runRecoverableEffect({
      store: effectStore(database),
      profile: TEST_PROFILE,
      effectKey: "payment:not-admitted",
      kind: "payment",
      payload: { value: "0" },
      adapter,
    })).rejects.toThrow(/does not admit payment/);
    expect(effectStore(database).get("payment:not-admitted")).toBeNull();
    database.close();
  });

  test("never rebinds an effect key to mutated payload bytes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-effect-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    const store = effectStore(database);
    store.prepare("anchor:immutable", "anchor", { value: "first" });
    expect(() => store.prepare("anchor:immutable", "anchor", { value: "second" }))
      .toThrow(/different immutable intent/);
    database.close();
  });
});

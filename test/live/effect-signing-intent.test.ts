import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  runTurnkeySellerAnchorSigning,
  TurnkeySigningIntentStore,
  type TurnkeyActivity,
  type TurnkeyActivityClient,
  type TurnkeySigningCrashBoundary,
} from "../../src/live/turnkey-signing-activity.ts";
import { admitExecutionProfile } from "../../src/live/profile.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";

const ORGANIZATION_ID = "ff8538a0-b57b-4f71-bfac-2040ca822501";
const PRIVATE_KEY_ID = "5c5db24b-b4d5-4c75-852a-ebdf9e108519";
const SELLER_CLAIM = `did:demos:agent:${"1".repeat(64)}`;
const PAYLOAD = "ab".repeat(64);
const TIMESTAMP_MS = "1785564000000";
const PUBLIC_KEY_HEX = "565892c69c5bddce1f54e6af531e3b58da492883dbb2e96a2b38a3dd218eb110";
const SIGNATURE = Object.freeze({
  r: "ad89eda7b7673750d27ec7518d82c27fa945210a957097af22f04cbed9d82d05",
  s: "7bd345f63894133016d2ad5089855c8e5f728a7c15d7e214d2f2fefe184f3c0e",
  v: "",
});
const directories: string[] = [];

const profile = admitExecutionProfile({
  mode: "live-testnet",
  signer: {
    kind: "injected",
    keyReference: `turnkey:private-key:${PRIVATE_KEY_ID}`,
    publicKeyHex: PUBLIC_KEY_HEX,
    expectedClaim: SELLER_CLAIM,
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
    schemaSha256: "4".repeat(64),
  },
  rail: { id: "fixture", chain: "demos-testnet", maxAtomicAmount: "0" },
  effects: { environment: "testnet", allow: ["anchor"], maxAttempts: 1 },
});

const config = Object.freeze({
  organizationId: ORGANIZATION_ID,
  privateKeyId: PRIVATE_KEY_ID,
  publicKeyHex: PUBLIC_KEY_HEX,
  sellerClaim: SELLER_CLAIM,
  chain: "demos-testnet" as const,
  signingDomain: "demos-storage-program:v1",
  maxFeeAtomic: "25",
});

afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe("Turnkey seller-anchor signing Activity recovery", () => {
  for (const crashAt of [
    "after-prepare",
    "after-submit",
    "after-activity-observed",
    "after-signed-persist",
  ] as const) {
    test(`${crashAt} restart resolves one immutable Activity`, async () => {
      const path = await databasePath();
      const provider = fakeTurnkey();
      let database = openDatabase(path);
      await expect(run(database, provider.client, {
        crash: (boundary: TurnkeySigningCrashBoundary) => {
          if (boundary === crashAt) throw new Error(`crash:${boundary}`);
        },
      })).rejects.toThrow(`crash:${crashAt}`);
      database.close();

      database = openDatabase(path);
      const signed = await run(database, provider.client);
      const record = new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1");
      expect(signed.signature).toEqual(SIGNATURE);
      expect(record).toMatchObject({
        state: "signed",
        activityId: provider.activityId,
        providerRequestId: record?.requestBodyHash,
        payloadHash: expect.stringMatching(/^[0-9a-f]{64}$/),
        signatureDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(JSON.parse(record!.requestBodyJson)).toMatchObject({
        type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
        timestampMs: TIMESTAMP_MS,
        organizationId: ORGANIZATION_ID,
        parameters: {
          signWith: PRIVATE_KEY_ID,
          payload: PAYLOAD,
          encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
          hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
        },
      });
      expect(provider.createdActivities).toBe(1);
      database.close();
    });
  }

  test("persists a pending Activity and resumes through getActivity", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ initiallyPending: true });
    let database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/pending/);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1"))
      .toMatchObject({ state: "activity-observed", activityId: provider.activityId });
    database.close();

    provider.complete();
    database = openDatabase(path);
    expect((await run(database, provider.client)).signature).toEqual(SIGNATURE);
    expect(provider.submitCalls).toBe(1);
    expect(provider.getCalls).toBe(1);
    database.close();
  });

  test("a failed Activity remains terminal and is never resubmitted", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ failed: true });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/failed/);
    await expect(run(database, provider.client)).rejects.toThrow(/failed/);
    expect(provider.submitCalls).toBe(1);
    expect(provider.getCalls).toBe(0);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1")?.state).toBe("failed");
    database.close();
  });

  test("a rejected Activity remains terminal and is never resubmitted", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ rejected: true });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/failed/);
    await expect(run(database, provider.client)).rejects.toThrow(/failed/);
    expect(provider.submitCalls).toBe(1);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1"))
      .toMatchObject({ state: "failed", activityStatus: "ACTIVITY_STATUS_REJECTED" });
    database.close();
  });

  test("persists authenticator-needed state and resumes only through getActivity", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ initiallyAuthenticatorsNeeded: true });
    let database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/pending/);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1"))
      .toMatchObject({ state: "activity-observed", activityStatus: "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED" });
    database.close();

    provider.complete();
    database = openDatabase(path);
    expect((await run(database, provider.client)).signature).toEqual(SIGNATURE);
    expect(provider.submitCalls).toBe(1);
    expect(provider.getCalls).toBe(1);
    database.close();
  });

  test("never rebinds an effect key to changed timestamp, payload, role, or fee", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey();
    const database = openDatabase(path);
    await run(database, provider.client);
    for (const override of [
      { timestampMs: "1785564000001" },
      { payloadHex: "cd".repeat(64) },
      { feeAtomic: "2" },
      { config: { ...config, signingDomain: "other-domain" } },
    ]) {
      await expect(run(database, provider.client, override)).rejects.toThrow(/immutable intent/);
    }
    expect(provider.createdActivities).toBe(1);
    database.close();
  });

  test("rejects provider intent substitution before persisting a signature", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ substitutePayload: true });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/does not match/);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1")?.state)
      .toBe("submitting");
    database.close();
  });

  test("rejects a non-empty recovery component in an Ed25519 signature", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ signatureV: "1b" });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/invalid signature envelope/);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1")?.state)
      .toBe("submitting");
    database.close();
  });

  test("rejects a well-shaped Ed25519 signature that does not verify the durable payload", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ corruptSignature: true });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/does not verify/);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1")?.state)
      .toBe("submitting");
    database.close();
  });

  test("requires the admitted seller claim, exact key locator, anchor effect, and fee cap", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey();
    const database = openDatabase(path);
    await expect(run(database, provider.client, { feeAtomic: "26" })).rejects.toThrow(/fee cap/);
    await expect(run(database, provider.client, {
      config: { ...config, sellerClaim: `did:demos:agent:${"9".repeat(64)}` },
    })).rejects.toThrow(/profile/);
    await expect(run(database, provider.client, {
      config: { ...config, publicKeyHex: "f".repeat(64) },
    })).rejects.toThrow(/profile/);
    expect(provider.submitCalls).toBe(0);
    database.close();
  });

  test("concurrent runners converge on one provider Activity and one signed envelope", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey();
    const database = openDatabase(path);
    const [left, right] = await Promise.all([
      run(database, provider.client),
      run(database, provider.client),
    ]);
    expect(left).toEqual(right);
    expect(provider.createdActivities).toBe(1);
    expect(new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1")?.state).toBe("signed");
    database.close();
  });

  test("a concurrent signed state after prepare returns without a second provider submit", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey();
    const database = openDatabase(path);
    const competitor = new TurnkeySigningIntentStore(database, () => "2026-08-01T06:00:00.000Z");
    class RacingStore extends TurnkeySigningIntentStore {
      override markSubmitting(effectKey: string) {
        competitor.markSubmitting(effectKey);
        const durable = competitor.get(effectKey)!;
        const request = JSON.parse(durable.requestBodyJson) as Parameters<
          TurnkeyActivityClient["submitSignRawPayload"]
        >[0];
        const activity = completedActivity(request);
        competitor.observeActivity(effectKey, activity);
        competitor.persistSignature(effectKey, activity);
        return super.markSubmitting(effectKey);
      }
    }
    const result = await runTurnkeySellerAnchorSigning({
      store: new RacingStore(database, () => "2026-08-01T06:00:00.000Z"),
      profile,
      client: provider.client,
      config,
      effectKey: "demos-anchor:reference:v1",
      payloadHex: PAYLOAD,
      timestampMs: TIMESTAMP_MS,
      feeAtomic: "1",
    });
    expect(result.signature).toEqual(SIGNATURE);
    expect(provider.submitCalls).toBe(0);
    expect(competitor.get("demos-anchor:reference:v1")?.state).toBe("signed");
    database.close();
  });

  test("a stale pending response yields the signature already persisted by a concurrent runner", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ initiallyPending: true });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/pending/);
    const store = new TurnkeySigningIntentStore(database);
    const stale = provider.currentActivity();
    provider.complete();
    const completed = await provider.client.getActivity({
      organizationId: ORGANIZATION_ID,
      activityId: provider.activityId,
    });
    store.observeActivity("demos-anchor:reference:v1", completed);
    store.persistSignature("demos-anchor:reference:v1", completed);
    expect(store.observeActivity("demos-anchor:reference:v1", stale).state).toBe("signed");
    database.close();
  });

  test("a concurrent terminal response cannot override or hide durable signed state", async () => {
    const path = await databasePath();
    const provider = fakeTurnkey({ initiallyPending: true });
    const database = openDatabase(path);
    await expect(run(database, provider.client)).rejects.toThrow(/pending/);
    const store = new TurnkeySigningIntentStore(database);
    const stale = provider.currentActivity();
    provider.complete();
    const completed = await provider.client.getActivity({
      organizationId: ORGANIZATION_ID,
      activityId: provider.activityId,
    });
    store.observeActivity("demos-anchor:reference:v1", completed);
    store.persistSignature("demos-anchor:reference:v1", completed);
    const failed: TurnkeyActivity = {
      ...stale,
      status: "ACTIVITY_STATUS_FAILED",
      failure: { message: "terminal race" },
    };
    expect(() => store.observeActivity("demos-anchor:reference:v1", failed))
      .toThrow(/Terminal Turnkey Activity conflicts/);
    database.close();
  });

  test("fails closed on direct durable request or signature mutation", async () => {
    for (const column of ["request_body_json", "signature_json"] as const) {
      const path = await databasePath();
      const provider = fakeTurnkey();
      const database = openDatabase(path);
      await run(database, provider.client);
      const replacement = column === "request_body_json"
        ? canonicalize({ corrupted: true })
        : canonicalize({ r: "4".repeat(64), s: "5".repeat(64), v: "" });
      database.query<never, { replacement: string }>(
        `UPDATE turnkey_signing_intents SET ${column} = $replacement`,
      ).run({ replacement });
      expect(() => new TurnkeySigningIntentStore(database).get("demos-anchor:reference:v1"))
        .toThrow(/Turnkey/);
      database.close();
    }
  });
});

async function databasePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-turnkey-signing-"));
  directories.push(directory);
  return join(directory, "state.sqlite");
}

function run(
  database: ReturnType<typeof openDatabase>,
  client: TurnkeyActivityClient,
  overrides: Readonly<Record<string, unknown>> = {},
) {
  return runTurnkeySellerAnchorSigning({
    store: new TurnkeySigningIntentStore(database, () => "2026-08-01T06:00:00.000Z"),
    profile,
    client,
    config,
    effectKey: "demos-anchor:reference:v1",
    payloadHex: PAYLOAD,
    timestampMs: TIMESTAMP_MS,
    feeAtomic: "1",
    ...overrides,
  });
}

function fakeTurnkey(options: Readonly<{
  initiallyPending?: boolean;
  initiallyAuthenticatorsNeeded?: boolean;
  failed?: boolean;
  rejected?: boolean;
  corruptSignature?: boolean;
  signatureV?: string;
  substitutePayload?: boolean;
}> = {}) {
  const activityId = "019fbb00-0000-7000-8000-000000000001";
  const activities = new Map<string, TurnkeyActivity>();
  let submitCalls = 0;
  let getCalls = 0;
  let createdActivities = 0;
  let complete = !options.initiallyPending && !options.initiallyAuthenticatorsNeeded;

  const activity = (request: Parameters<TurnkeyActivityClient["submitSignRawPayload"]>[0]): TurnkeyActivity => ({
    id: activityId,
    organizationId: request.organizationId,
    status: options.failed
      ? "ACTIVITY_STATUS_FAILED"
      : options.rejected ? "ACTIVITY_STATUS_REJECTED"
      : options.initiallyAuthenticatorsNeeded && !complete ? "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED"
      : complete ? "ACTIVITY_STATUS_COMPLETED" : "ACTIVITY_STATUS_PENDING",
    type: request.type,
    intent: {
      signRawPayloadIntentV2: {
        ...request.parameters,
        ...(options.substitutePayload ? { payload: "ff" } : {}),
      },
    },
    ...(options.failed || options.rejected
      ? { failure: { message: "policy denied" } }
      : complete ? { result: { signRawPayloadResult: {
        ...(options.corruptSignature
          ? { r: "0".repeat(64), s: "0".repeat(64), v: "" }
          : SIGNATURE),
        ...(options.signatureV === undefined ? {} : { v: options.signatureV }),
      } } } : {}),
  });

  const client: TurnkeyActivityClient = {
    submitSignRawPayload: async (request) => {
      submitCalls += 1;
      const key = canonicalize(request);
      if (!activities.has(key)) {
        createdActivities += 1;
        activities.set(key, activity(request));
      }
      const existing = activities.get(key)!;
      if (complete && existing.status === "ACTIVITY_STATUS_PENDING") {
        const completed = activity(request);
        activities.set(key, completed);
        return completed;
      }
      return existing;
    },
    getActivity: async ({ activityId: requested }) => {
      getCalls += 1;
      if (requested !== activityId) throw new Error("unknown Activity");
      const request = [...activities.keys()][0];
      if (request === undefined) throw new Error("Activity missing");
      const parsed = JSON.parse(request) as Parameters<TurnkeyActivityClient["submitSignRawPayload"]>[0];
      const next = activity(parsed);
      activities.set(request, next);
      return next;
    },
  };

  return {
    activityId,
    client,
    currentActivity: () => {
      const request = [...activities.keys()][0];
      if (request === undefined) throw new Error("Activity missing");
      return activity(JSON.parse(request));
    },
    complete: () => { complete = true; },
    get submitCalls() { return submitCalls; },
    get getCalls() { return getCalls; },
    get createdActivities() { return createdActivities; },
  };
}

function completedActivity(
  request: Parameters<TurnkeyActivityClient["submitSignRawPayload"]>[0],
): TurnkeyActivity {
  return {
    id: "019fbb00-0000-7000-8000-000000000001",
    organizationId: request.organizationId,
    status: "ACTIVITY_STATUS_COMPLETED",
    type: request.type,
    intent: { signRawPayloadIntentV2: request.parameters },
    result: { signRawPayloadResult: SIGNATURE },
  };
}

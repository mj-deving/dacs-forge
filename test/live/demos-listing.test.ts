import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LiveEffectStore } from "../../src/live/effect-store.ts";
import {
  publishListingThroughLiveProfile,
  type LiveDirectoryAdapter,
  type LiveListingAnchorAdapter,
} from "../../src/live/listing-publication.ts";
import { admitExecutionProfile } from "../../src/live/profile.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { signedListingVersion } from "../fixtures/identity-listing/lifecycle.ts";
import { FIXTURE_NOW_MS, fixtureSigner } from "../fixtures/reference-listing.ts";

const TEST_PROFILE = admitExecutionProfile({
  mode: "live-testnet",
  signer: {
    kind: "injected",
    keyReference: "fixture:seller",
    expectedClaim: `did:demos:agent:${"1".repeat(64)}`,
  },
  anchor: {
    adapter: "demos-sdk",
    chain: "demos-testnet",
    rpcUrl: "https://demos.example",
    sdkCommit: "15ceafa262299f258e2cc35bef7a5e74dc4fb225",
  },
  directory: {
    endpoint: "https://community.example/api/dacs",
    manifestUrl: "https://community.example/.well-known/dacs-directory.json",
    schemaSha256: "2".repeat(64),
  },
  rail: { id: "fixture", chain: "demos-testnet", maxAtomicAmount: "0" },
  effects: { environment: "testnet", allow: ["anchor", "directory-register"], maxAttempts: 1 },
});

describe("live-profile Listing contract with fixture adapters", () => {
  test("anchors, independently reads, verifies, then projects to Directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-listing-"));
    const database = openDatabase(join(directory, "state.sqlite"));
    const listing = signedListingVersion(1);
    const events: string[] = [];
    const anchors = new Map<string, { nativeAddress: string; canonicalJson: string; externalRef: string }>();
    let projection: Readonly<Record<string, unknown>> | undefined;
    const anchorAdapter: LiveListingAnchorAdapter = {
      reconcile: async ({ effectKey }) => anchors.get(effectKey) ?? { disposition: "absent" },
      submit: async ({ effectKey, payload }) => {
        events.push("anchor-submit");
        const anchored = {
          externalRef: "demos-tx-fixture",
          nativeAddress: `stor-${"a".repeat(40)}`,
          canonicalJson: payload.canonicalJson,
        };
        anchors.set(effectKey, anchored);
        return anchored;
      },
      read: async (nativeAddress) => {
        events.push("anchor-read");
        return [...anchors.values()].find((value) => value.nativeAddress === nativeAddress)?.canonicalJson ?? null;
      },
      revocation: async () => "absent",
    };
    const directoryAdapter: LiveDirectoryAdapter = {
      reconcile: async () => projection === undefined
        ? { disposition: "absent" }
        : { externalRef: "directory-fixture", projection },
      submit: async ({ payload }) => {
        events.push("directory-submit");
        projection = payload.expectedProjection;
        return { externalRef: "directory-fixture", projection: payload.expectedProjection };
      },
    };
    const paymentRailCheck: Parameters<typeof publishListingThroughLiveProfile>[0]["paymentRailCheck"] =
      ({ referencedByPhaseKinds }) => ({
        status: "resolved", phaseHandler: referencedByPhaseKinds[0] ?? "fixture",
      });
    const store = new LiveEffectStore(database);
    const publication = {
      store,
      profile: TEST_PROFILE,
      canonicalJson: listing.canonicalJson,
      expectedSeller: fixtureSigner().signer,
      paymentRailCheck,
      anchorAdapter,
      directoryAdapter,
    } as const;
    const result = await publishListingThroughLiveProfile({ ...publication, nowMs: FIXTURE_NOW_MS });
    expect(events).toEqual(["anchor-submit", "anchor-read", "directory-submit"]);
    expect(result.listing.contentHash).toBe(listing.contentHash);
    expect(result.directory.projection).toMatchObject({
      listingId: "reference-json-transform",
      version: 1,
      contentHash: listing.contentHash,
      anchor: { kind: "storage-program", locator: `stor-${"a".repeat(40)}` },
    });
    const replay = await publishListingThroughLiveProfile({ ...publication, nowMs: FIXTURE_NOW_MS + 1 });
    expect(replay).toEqual(result);
    expect(events).toEqual(["anchor-submit", "anchor-read", "directory-submit", "anchor-read"]);
    database.close();
    await rm(directory, { recursive: true, force: true });
  });

  test("never registers mutated read-back bytes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-live-listing-"));
    const database = openDatabase(join(directory, "state.sqlite"));
    let submitted = false;
    let anchored: Readonly<{
      externalRef: string; nativeAddress: string; canonicalJson: string;
    }> | undefined;
    await expect(publishListingThroughLiveProfile({
      store: new LiveEffectStore(database),
      profile: TEST_PROFILE,
      canonicalJson: signedListingVersion(1).canonicalJson,
      nowMs: FIXTURE_NOW_MS,
      expectedSeller: fixtureSigner().signer,
      paymentRailCheck: ({ referencedByPhaseKinds }) => ({
        status: "resolved", phaseHandler: referencedByPhaseKinds[0] ?? "fixture",
      }),
      anchorAdapter: {
        reconcile: async () => anchored ?? { disposition: "absent" },
        submit: async () => {
          anchored = {
            externalRef: "tx",
            nativeAddress: `stor-${"b".repeat(40)}`,
            canonicalJson: signedListingVersion(1).canonicalJson,
          };
          return anchored;
        },
        read: async () => '{"mutated":true}',
        revocation: async () => "absent",
      },
      directoryAdapter: {
        reconcile: async () => ({ disposition: "absent" }),
        submit: async () => {
          submitted = true;
          return { externalRef: "unexpected", projection: {} };
        },
      },
    })).rejects.toThrow(/read-back/);
    expect(submitted).toBe(false);
    database.close();
    await rm(directory, { recursive: true, force: true });
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { createCommunityDirectoryAdapter } from "../../src/adapters/community-directory.ts";
import {
  connectDemosSdkListingAdapter,
  type InjectedDemosStorageSdk,
} from "../../src/adapters/demos-sdk-listing.ts";
import { OFFICIAL_DACS_SDK_COMMIT } from "../../src/live/profile.ts";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

describe("optional live adapters", () => {
  test("Demos adapter enforces the exact SDK pin and resolves with the raw owner address", async () => {
    const owner = "1".repeat(64);
    let expectedOwner = "";
    const sdk: InjectedDemosStorageSdk = {
      getAddress: () => `0x${owner}`,
      resolveAnchorByName: async (_name, expected) => {
        expectedOwner = expected;
        return { status: "absent" };
      },
      anchorWriteOnce: async () => ({ address: `stor-${"a".repeat(40)}` }),
      readAnchor: async () => null,
    };
    const adapter = await connectDemosSdkListingAdapter({
      sdkCommit: OFFICIAL_DACS_SDK_COMMIT,
      expectedOwner: `did:demos:agent:${owner}`,
      readRevocation: async () => "absent",
    }, sdk);
    await adapter.reconcile({ effectKey: "anchor:x", payload: { logicalAddress: "dacs1:x", canonicalJson: "{}" } });
    expect(expectedOwner).toBe(owner);
    await expect(connectDemosSdkListingAdapter({
      sdkCommit: "0".repeat(40) as typeof OFFICIAL_DACS_SDK_COMMIT,
      expectedOwner: `did:demos:agent:${owner}`,
      readRevocation: async () => "absent",
    }, sdk)).rejects.toThrow(/exact admitted SDK commit/);
  });

  test("Community adapter treats catalog absence as discovery absence and submits only the chain pointer", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(url), ...(init === undefined ? {} : { init }) });
      if (init?.method === "POST") {
        return new Response(JSON.stringify({ ok: true, queued: true }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ listings: [], total: 0 }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    const adapter = createCommunityDirectoryAdapter({
      endpoint: "https://community.example/api/dacs",
    });
    const projection = {
      listingId: "service",
      version: 1,
      contentHash: "2".repeat(64),
      anchor: { kind: "storage-program", locator: `stor-${"a".repeat(40)}` },
      seller: { displayName: "Service" },
    };
    const payload = {
      registration: {
        primaryClaim: `did:demos:agent:${"1".repeat(64)}`,
        displayName: "Service",
        listingAnchors: [`stor-${"a".repeat(40)}`],
      },
      expectedProjection: projection,
    };
    expect(await adapter.reconcile({ effectKey: "directory:x", payload }))
      .toEqual({ disposition: "absent" });
    await adapter.submit({ effectKey: "directory:x", payload });
    expect(JSON.parse(requests[1]!.init?.body as string)).toEqual({
      primaryClaim: `did:demos:agent:${"1".repeat(64)}`,
      displayName: "Service",
      listingAnchors: [`stor-${"a".repeat(40)}`],
    });
  });
});

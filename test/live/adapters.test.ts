import { afterEach, describe, expect, test } from "bun:test";
import type { TurnkeyClient } from "@turnkey/http";
import { createCommunityDirectoryAdapter } from "../../src/adapters/community-directory.ts";
import {
  connectDemosSdkListingAdapter,
  type InjectedDemosStorageSdk,
} from "../../src/adapters/demos-sdk-listing.ts";
import { OFFICIAL_DACS_SDK_COMMIT } from "../../src/live/profile.ts";
import {
  assertTurnkeyRequestUsesEd25519RawSigning,
  connectOfficialTurnkeyActivityClient,
} from "../../src/adapters/turnkey-signing.ts";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

describe("optional live adapters", () => {
  test("Turnkey adapter delegates exact Ed25519 input to the official SDK client", async () => {
    const calls: unknown[] = [];
    const activity = {
      id: "019fbb00-0000-7000-8000-000000000001",
      organizationId: "org",
      status: "ACTIVITY_STATUS_COMPLETED",
      type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
      intent: { signRawPayloadIntentV2: {
        signWith: "key",
        payload: "ab",
        encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
        hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
      } },
      result: { signRawPayloadResult: { r: "1".repeat(64), s: "2".repeat(64), v: "" } },
      votes: [],
      fingerprint: "fingerprint",
      canApprove: false,
      canReject: false,
      createdAt: { seconds: "1", nanos: "0" },
      updatedAt: { seconds: "1", nanos: "0" },
    };
    const official = {
      signRawPayload: async (input: unknown) => {
        calls.push({ method: "signRawPayload", input });
        return { activity, r: "1".repeat(64), s: "2".repeat(64), v: "" };
      },
      getActivity: async (input: unknown) => {
        calls.push({ method: "getActivity", input });
        return { activity };
      },
    } as unknown as Pick<TurnkeyClient, "getActivity" | "signRawPayload">;
    const client = connectOfficialTurnkeyActivityClient(official);
    const request = {
      type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2" as const,
      timestampMs: "1785564000000",
      organizationId: "org",
      parameters: {
        signWith: "key",
        payload: "ab",
        encoding: "PAYLOAD_ENCODING_HEXADECIMAL" as const,
        hashFunction: "HASH_FUNCTION_NOT_APPLICABLE" as const,
      },
    };
    expect(await client.submitSignRawPayload(request)).toMatchObject({ id: activity.id, result: activity.result });
    expect(await client.getActivity({ organizationId: "org", activityId: activity.id }))
      .toMatchObject({ id: activity.id });
    expect(calls).toEqual([
      { method: "signRawPayload", input: {
        type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
        timestampMs: "1785564000000",
        organizationId: "org",
        parameters: {
          signWith: "key",
          payload: "ab",
          encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
          hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
        },
      } },
      { method: "getActivity", input: { organizationId: "org", activityId: activity.id } },
    ]);
  });

  test("Turnkey adapter rejects the obsolete raw-signing hash mode before provider invocation", async () => {
    expect(() => assertTurnkeyRequestUsesEd25519RawSigning({
      type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
      timestampMs: "1785564000000",
      organizationId: "org",
      parameters: {
        signWith: "key",
        payload: "ab",
        encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
        hashFunction: "HASH_FUNCTION_NO_OP",
      },
    } as never)).toThrow(/not the admitted Ed25519/);
  });

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

import { canonicalize } from "../protocol/canonical-json.ts";
import type { RevocationCheck } from "../consumer/listing-verifier.ts";
import type { EffectReconciliation } from "../live/effect-runner.ts";
import type { LiveListingAnchorAdapter } from "../live/listing-publication.ts";
import { OFFICIAL_DACS_SDK_COMMIT } from "../live/profile.ts";

interface AnchorPayload extends Record<string, unknown> {
  readonly logicalAddress: string;
  readonly canonicalJson: string;
}

interface AnchorResult extends Record<string, unknown> {
  readonly externalRef: string;
  readonly nativeAddress: string;
  readonly canonicalJson: string;
}

export interface DemosSdkListingAdapterConfig {
  readonly sdkCommit: typeof OFFICIAL_DACS_SDK_COMMIT;
  readonly expectedOwner: string;
  readonly readRevocation: (logicalAddress: string) => Promise<RevocationCheck>;
}

export interface InjectedDemosStorageSdk {
  readonly getAddress: () => string;
  readonly resolveAnchorByName: (
    name: string,
    expectedOwner: string,
  ) => Promise<
    | Readonly<{ readonly status: "present"; readonly address: string }>
    | Readonly<{ readonly status: "absent" }>
    | Readonly<{ readonly status: "indeterminate"; readonly reason: string }>
  >;
  readonly anchorWriteOnce: (
    name: string,
    value: Record<string, unknown>,
  ) => Promise<Readonly<{ readonly address: string; readonly txRef?: string }>>;
  readonly readAnchor: (address: string) => Promise<Record<string, unknown> | null>;
}

/** Optional live-only adapter. Forge Core and its consumer do not import this module. */
export async function connectDemosSdkListingAdapter(
  config: DemosSdkListingAdapterConfig,
  sdk: InjectedDemosStorageSdk,
): Promise<LiveListingAnchorAdapter> {
  if (config.sdkCommit !== OFFICIAL_DACS_SDK_COMMIT || config.expectedOwner.length === 0) {
    throw new TypeError("Demos live adapter requires the exact admitted SDK commit and owner");
  }
  if (sdk.getAddress().toLowerCase().replace(/^0x/, "") !== demosAddress(config.expectedOwner)) {
    throw new Error("Connected Demos signer does not match the admitted seller claim");
  }

  const reconcile = async ({ payload }: Readonly<{
    readonly effectKey: string; readonly payload: AnchorPayload;
  }>): Promise<EffectReconciliation<AnchorResult>> => {
    const resolution = await sdk.resolveAnchorByName(payload.logicalAddress, demosAddress(config.expectedOwner));
    if (resolution.status !== "present") return resolution.status === "absent"
      ? { disposition: "absent" }
      : { disposition: "indeterminate", reason: resolution.reason };
    let record: Record<string, unknown> | null;
    try { record = await sdk.readAnchor(resolution.address); }
    catch (error) {
      return { disposition: "indeterminate", reason: error instanceof Error ? error.message : String(error) };
    }
    if (record === null) return { disposition: "indeterminate", reason: "resolved Demos anchor is unreadable" };
    return Object.freeze({
      externalRef: resolution.address,
      nativeAddress: resolution.address,
      canonicalJson: canonicalize(record),
    });
  };

  const adapter: LiveListingAnchorAdapter = {
    reconcile,
    submit: async ({ payload }) => {
      const record = parseObject(payload.canonicalJson);
      const anchored = await sdk.anchorWriteOnce(payload.logicalAddress, record);
      const read = await sdk.readAnchor(anchored.address);
      if (read === null) throw new Error("Demos anchor was not read-visible after submission");
      return Object.freeze({
        externalRef: anchored.address,
        nativeAddress: anchored.address,
        canonicalJson: canonicalize(read),
      });
    },
    read: async (nativeAddress) => {
      const record = await sdk.readAnchor(nativeAddress);
      return record === null ? null : canonicalize(record);
    },
    revocation: config.readRevocation,
  };
  return Object.freeze(adapter);
}

function demosAddress(claim: string): string {
  const match = /^did:demos:agent:([0-9a-f]{64})$/.exec(claim);
  if (match === null) throw new TypeError("Expected owner must be a canonical Demos agent claim");
  return match[1]!;
}

function parseObject(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || canonicalize(parsed) !== value) throw new TypeError("Anchor payload must be canonical JSON");
  return parsed as Record<string, unknown>;
}

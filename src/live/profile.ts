export const OFFICIAL_DACS_SDK_COMMIT = "e2070e0085414c67d139e1e62924ca9ef8b316c7" as const;

export type LiveEffectKind = "anchor" | "directory-register" | "payment";

export interface LiveTestnetProfileInput {
  readonly mode: "live-testnet";
  readonly signer: {
    readonly kind: "injected";
    readonly keyReference: string;
    readonly publicKeyHex: string;
    readonly expectedClaim: string;
  };
  readonly anchor: {
    readonly adapter: "demos-sdk";
    readonly chain: "demos-testnet";
    readonly rpcUrl: string;
    readonly sdkCommit: string;
  };
  readonly directory: {
    readonly endpoint: string;
    readonly manifestUrl: string;
    readonly schemaSha256: string;
  };
  readonly rail: {
    readonly id: string;
    readonly chain: "demos-testnet" | "base-sepolia";
    readonly maxAtomicAmount: string;
  };
  readonly effects: {
    readonly environment: "testnet";
    readonly allow: readonly LiveEffectKind[];
    readonly maxAttempts: 1;
  };
}

export interface AdmittedExecutionProfile {
  readonly mode: "fixture" | "live-testnet";
  readonly networkEffects: boolean;
  readonly allowedEffects: readonly LiveEffectKind[];
  readonly sdkCommit?: typeof OFFICIAL_DACS_SDK_COMMIT;
  readonly config?: Readonly<LiveTestnetProfileInput>;
}

export function fixtureExecutionProfile(): AdmittedExecutionProfile {
  return Object.freeze({ mode: "fixture", networkEffects: false, allowedEffects: Object.freeze([]) });
}

export function admitExecutionProfile(input: LiveTestnetProfileInput): AdmittedExecutionProfile {
  if (!isRecord(input) || input.mode !== "live-testnet") throw new TypeError("Live profile mode is required");
  const signer = input.signer;
  if (!isRecord(signer) || signer.kind !== "injected" || !field(signer.keyReference)
    || !lowerHex64(signer.publicKeyHex)
    || !/^did:demos:agent:[0-9a-f]{64}$/.test(signer.expectedClaim)) {
    throw new TypeError("Live profile requires an injected exact signer reference and Demos claim");
  }
  const anchor = input.anchor;
  if (!isRecord(anchor) || anchor.adapter !== "demos-sdk" || anchor.chain !== "demos-testnet"
    || anchor.sdkCommit !== OFFICIAL_DACS_SDK_COMMIT || !httpsUrl(anchor.rpcUrl)) {
    throw new TypeError("Live profile requires the exact official Demos SDK adapter pin and testnet RPC");
  }
  const directory = input.directory;
  if (!isRecord(directory) || !httpsUrl(directory.endpoint) || !httpsUrl(directory.manifestUrl)
    || !lowerHex64(directory.schemaSha256)) {
    throw new TypeError("Live profile requires exact Directory endpoint, manifest, and schema digest");
  }
  const rail = input.rail;
  if (!isRecord(rail) || !field(rail.id)
    || (rail.chain !== "demos-testnet" && rail.chain !== "base-sepolia")
    || !/^(0|[1-9][0-9]*)$/.test(rail.maxAtomicAmount)) {
    throw new TypeError("Live profile requires a bounded supported testnet rail");
  }
  const effects = input.effects;
  const permitted = new Set<LiveEffectKind>(["anchor", "directory-register", "payment"]);
  if (!isRecord(effects) || effects.environment !== "testnet" || effects.maxAttempts !== 1
    || !Array.isArray(effects.allow) || effects.allow.length === 0
    || new Set(effects.allow).size !== effects.allow.length
    || !effects.allow.every((effect) => permitted.has(effect))) {
    throw new TypeError("Live profile requires an explicit bounded testnet effect allow-list");
  }
  const snapshot: LiveTestnetProfileInput = {
    mode: "live-testnet",
    signer: {
      kind: "injected",
      keyReference: signer.keyReference as string,
      publicKeyHex: signer.publicKeyHex as string,
      expectedClaim: signer.expectedClaim as string,
    },
    anchor: {
      adapter: "demos-sdk",
      chain: "demos-testnet",
      rpcUrl: anchor.rpcUrl as string,
      sdkCommit: anchor.sdkCommit as string,
    },
    directory: {
      endpoint: directory.endpoint as string,
      manifestUrl: directory.manifestUrl as string,
      schemaSha256: directory.schemaSha256 as string,
    },
    rail: {
      id: rail.id as string,
      chain: rail.chain as "demos-testnet" | "base-sepolia",
      maxAtomicAmount: rail.maxAtomicAmount as string,
    },
    effects: {
      environment: "testnet",
      allow: [...effects.allow] as LiveEffectKind[],
      maxAttempts: 1,
    },
  };
  return Object.freeze({
    mode: "live-testnet",
    networkEffects: true,
    allowedEffects: Object.freeze([...snapshot.effects.allow]),
    sdkCommit: OFFICIAL_DACS_SDK_COMMIT,
    config: deepFreeze(snapshot),
  });
}

function field(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 && value === value.normalize("NFC");
}

function lowerHex64(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function httpsUrl(value: unknown): value is string {
  if (!field(value)) return false;
  try { return new URL(value).protocol === "https:"; }
  catch { return false; }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

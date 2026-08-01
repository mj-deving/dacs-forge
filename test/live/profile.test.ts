import { describe, expect, test } from "bun:test";
import {
  admitExecutionProfile,
  fixtureExecutionProfile,
  type LiveTestnetProfileInput,
} from "../../src/live/profile.ts";

const LIVE_INPUT: LiveTestnetProfileInput = {
  mode: "live-testnet",
  signer: {
    kind: "injected",
    keyReference: "demos-testnet:seller-1",
    publicKeyHex: "3".repeat(64),
    expectedClaim: `did:demos:agent:${"1".repeat(64)}`,
  },
  anchor: {
    adapter: "demos-sdk",
    chain: "demos-testnet",
    rpcUrl: "https://node2.demos.sh",
    sdkCommit: "e2070e0085414c67d139e1e62924ca9ef8b316c7",
  },
  directory: {
    endpoint: "https://community.example/api/dacs",
    manifestUrl: "https://community.example/.well-known/dacs-directory.json",
    schemaSha256: "2".repeat(64),
  },
  rail: {
    id: "pay-dem:testnet",
    chain: "demos-testnet",
    maxAtomicAmount: "1000000",
  },
  effects: {
    environment: "testnet",
    allow: ["anchor", "directory-register", "payment"],
    maxAttempts: 1,
  },
};

describe("Forge v0.2 execution profiles", () => {
  test("keeps the default fixture profile explicit and zero-effect", () => {
    expect(fixtureExecutionProfile()).toEqual({
      mode: "fixture",
      networkEffects: false,
      allowedEffects: [],
    });
  });

  test("admits only a complete, exact-pinned testnet profile", () => {
    expect(admitExecutionProfile(LIVE_INPUT)).toMatchObject({
      mode: "live-testnet",
      networkEffects: true,
      sdkCommit: LIVE_INPUT.anchor.sdkCommit,
      allowedEffects: ["anchor", "directory-register", "payment"],
    });
  });

  for (const [name, mutate] of [
    ["missing signer", (v: LiveTestnetProfileInput) => ({ ...v, signer: undefined })],
    ["missing signer public key", (v: LiveTestnetProfileInput) => ({
      ...v, signer: { ...v.signer, publicKeyHex: "" },
    })],
    ["floating SDK", (v: LiveTestnetProfileInput) => ({ ...v, anchor: { ...v.anchor, sdkCommit: "main" } })],
    ["mainnet rail", (v: LiveTestnetProfileInput) => ({ ...v, rail: { ...v.rail, chain: "base-mainnet" } })],
    ["unbounded attempts", (v: LiveTestnetProfileInput) => ({ ...v, effects: { ...v.effects, maxAttempts: 2 } })],
  ] as const) {
    test(`rejects ${name}`, () => {
      expect(() => admitExecutionProfile(mutate(structuredClone(LIVE_INPUT)) as LiveTestnetProfileInput))
        .toThrow();
    });
  }
});

import { describe, expect, test } from "bun:test";
import { paymentEvidenceLogicalAddress } from "../../src/protocol/settlement-address.ts";

describe("DACS-4 payment evidence logical addressing", () => {
  test("encodes the normative rail segment and optional resolution suffix", () => {
    const jobId = "01J8ME0SXKQ4T9V2RC5HJ6WX7D";
    expect(paymentEvidenceLogicalAddress(jobId, "evm-erc20:8453:USDC", 3)).toBe(
      "dacs4:payment:01J8ME0SXKQ4T9V2RC5HJ6WX7D:evm-erc20%3A8453%3AUSDC:3",
    );
    expect(paymentEvidenceLogicalAddress(jobId, "evm-erc20:8453:USDC", 3, true)).toBe(
      "dacs4:payment:01J8ME0SXKQ4T9V2RC5HJ6WX7D:evm-erc20%3A8453%3AUSDC:3:resolved",
    );
  });

  test.each([
    ["job", "demos-native:DEM", 0],
    ["01J8ME0SXKQ4T9V2RC5HJ6WX7D", "Demos:DEM", 0],
    ["01J8ME0SXKQ4T9V2RC5HJ6WX7D", "demos-native:DEM", -1],
    ["01J8ME0SXKQ4T9V2RC5HJ6WX7D", "demos-native:DEM", 1.5],
  ])("rejects malformed address inputs", (jobId, railId, phaseIndex) => {
    expect(() => paymentEvidenceLogicalAddress(jobId as string, railId as string, phaseIndex as number))
      .toThrow();
  });
});

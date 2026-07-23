import { describe, expect, test } from "bun:test";
import {
  encodeCf4Segment,
  listingLogicalAddress,
  parseListingLogicalAddress,
} from "../../src/protocol/logical-address.ts";

describe("DACS CF-4 logical addressing", () => {
  test("applies the normative worked-example encoding to a valid claim", () => {
    const address = `0x${"12".repeat(20)}`;
    const logical = listingLogicalAddress(
      `cci-xm:evm:mainnet:${address}`,
      "my-listing",
      3,
    );
    expect(logical).toBe(`dacs1:cci-xm%3Aevm%3Amainnet%3A${address}:my-listing:v3`);
    expect(parseListingLogicalAddress(logical)).toEqual({
      sellerPrimaryClaim: `cci-xm:evm:mainnet:${address}`,
      listingId: "my-listing",
      listingVersion: 3,
    });
  });

  test("encodes every reserved delimiter with uppercase hex", () => {
    expect(encodeCf4Segment("a:b?c&d=e%f"))
      .toBe("a%3Ab%3Fc%26d%3De%25f");
  });

  test("rejects ambiguous ids and invalid versions", () => {
    expect(() => listingLogicalAddress("did:demos:seller", "bad:id", 1)).toThrow();
    expect(() => listingLogicalAddress("did:demos:seller", "ok", 0)).toThrow();
    expect(() => parseListingLogicalAddress("dacs1:key%3aabcd:listing:v1")).toThrow(/CF-4/);
    expect(() => parseListingLogicalAddress("dacs1:key%3Aabcd:listing:v01")).toThrow(/CF-4/);
    expect(() => parseListingLogicalAddress("dacs1:key%20abcd:listing:v1")).toThrow(/CF-4/);
  });
});

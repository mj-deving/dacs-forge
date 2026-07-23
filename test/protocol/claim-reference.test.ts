import { describe, expect, test } from "bun:test";
import {
  ClaimReferenceError,
  canonicalizeClaimReference,
} from "../../src/protocol/claim-reference.ts";

describe("DACS ClaimReference canonicalization", () => {
  test("derives lowercase scheme and parameter-free CF-3 identity", () => {
    expect(canonicalizeClaimReference("DID:demos:buyer?z=2&a=1")).toEqual({
      canonicalReference: "did:demos:buyer?a=1&z=2",
      scheme: "did",
      identifier: "demos:buyer",
    });
    expect(canonicalizeClaimReference("cci-ethos:e\u0301").canonicalReference)
      .toBe("cci-ethos:é");
  });

  test("normalizes scheme-specific domain, key, and ERC-8004 identifiers", () => {
    expect(canonicalizeClaimReference("DOMAIN:Example.COM").canonicalReference)
      .toBe("domain:example.com");
    expect(canonicalizeClaimReference("domain:bücher.example").canonicalReference)
      .toBe("domain:xn--bcher-kva.example");
    expect(canonicalizeClaimReference("key:A0FF").canonicalReference).toBe("key:a0ff");
    expect(canonicalizeClaimReference(
      "erc8004:1:0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:42",
    ).canonicalReference).toBe(
      "erc8004:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:42",
    );
    expect(canonicalizeClaimReference("did:web:example.com:user%3a42").canonicalReference)
      .toBe("did:web:example.com:user%3A42");
  });

  test("rejects odd-length key identifiers that hex decoders would truncate", () => {
    const key = "ab".repeat(32);
    expect(Buffer.from(`${key}f`, "hex")).toEqual(Buffer.from(key, "hex"));
    expect(() => canonicalizeClaimReference(`key:${key}f`)).toThrow(/byte-aligned/);
  });

  test("validates supported DACS regulatory and CCI identity shapes", () => {
    expect(canonicalizeClaimReference("lei:5493001KJTIIGC8Y1R12").identifier)
      .toBe("5493001KJTIIGC8Y1R12");
    expect(canonicalizeClaimReference("finra-crd:12345").identifier).toBe("12345");
    expect(canonicalizeClaimReference("naics:541512").identifier).toBe("541512");
    expect(canonicalizeClaimReference(
      `cci-xm:demos:testnet:0x${"A".repeat(64)}`,
    ).identifier).toBe(`demos:testnet:0x${"a".repeat(64)}`);
    expect(canonicalizeClaimReference(
      "cci-xm:Solana:Devnet:11111111111111111111111111111111",
    ).identifier).toBe("solana:devnet:11111111111111111111111111111111");
  });

  test("parses every registered opaque or compound v0.1 scheme explicitly", () => {
    expect(canonicalizeClaimReference("cci-web2:GitHub:MJ-Deving").identifier)
      .toBe("github:MJ-Deving");
    expect(canonicalizeClaimReference("cci-web2:github:mj-deving").identifier)
      .toBe("github:mj-deving");
    expect(canonicalizeClaimReference("cci-web2:Discord:Bot#1234").identifier)
      .toBe("discord:Bot#1234");
    expect(canonicalizeClaimReference("cci-pqc:FALCON:AbC123").identifier)
      .toBe("falcon:AbC123");
    expect(canonicalizeClaimReference("cci-humanpassport:passport-42").identifier)
      .toBe("passport-42");
    expect(canonicalizeClaimReference("cci-ethos:profile-42").identifier)
      .toBe("profile-42");
    expect(canonicalizeClaimReference("stor-cred:ISO-27001:cert-42").identifier)
      .toBe("iso-27001:cert-42");
    expect(canonicalizeClaimReference(
      "substrate-validator-set:Demos-Mainnet:set-42",
    ).identifier).toBe("demos-mainnet:set-42");
    expect(canonicalizeClaimReference(
      "substrate-validator-set:demos-testnet:7",
    ).identifier).toBe("demos-testnet:7");
  });

  test("sorts parameters by Unicode code point and canonicalizes reserved escapes", () => {
    expect(canonicalizeClaimReference("did:demos:buyer?b=x%3ay&a=v%26w").canonicalReference)
      .toBe("did:demos:buyer?a=v%26w&b=x%3Ay");
    expect(canonicalizeClaimReference("did:demos:buyer?tag=b&tag=a").canonicalReference)
      .toBe("did:demos:buyer?tag=b&tag=a");
    expect(canonicalizeClaimReference("did:demos:buyer?a=%3a%25").canonicalReference)
      .toBe("did:demos:buyer?a=%3A%25");
  });

  test("rejects malformed references and parameter encoding", () => {
    for (const reference of [
      "",
      "did:",
      "_did:x",
      "did:x?",
      "did:x?a",
      "did:x?a=%ZZ",
      "did:x?a=%41",
      "did:x?a=%20",
      "did:x?a=%00",
      "did:UPPER:id",
      "did:method:",
      "domain:-bad.example",
      "lei:short",
      "finra-crd:0123",
      "naics:12345",
      "cci-web2:unknown:buyer",
      "cci-web2:github:a:b",
      "cci-web2:github:foo#bar",
      "cci-web2:github:a%20b",
      "cci-web2:github:a b",
      "cci-web2:telegram:mariusé",
      "cci-web2:telegram:marius\u202e",
      "cci-lei:5493001KJTIIGC8Y1R12",
      "cci-finra-crd:12345",
      "cci-sam-uei:ABCDEF123456",
      "cci-fedramp:moderate",
      "cci-naics:541512",
      "cci-cmmc:cert-42",
      "cci-ethos:\ud800",
      "substrate-validator-set:attacker:set-1",
      "cci-xm:solana:devnet:not_base58",
      `cci-xm:solana:devnet:${"1".repeat(4_096)}`,
      `did:method:${"a".repeat(4_096)}`,
      `did:demos:buyer?p=${":".repeat(4_000)}`,
      `erc8004:${"1".repeat(33)}:0x${"a".repeat(40)}:1`,
      `erc8004:1:0x${"a".repeat(40)}:${1n << 256n}`,
    ]) {
      expect(() => canonicalizeClaimReference(reference)).toThrow(ClaimReferenceError);
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../../src/cli/dacs.ts";
import {
  executeRegistrationCommand,
  type RegistrationAdapter,
  type RegistrationCommandInput,
} from "../../src/directory/registration-command.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  fixtureSignedListing,
  fixtureSigner,
  FIXTURE_NOW_MS,
} from "../fixtures/reference-listing.ts";

const NOW = 1_800_000_000_000;
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("explicit Directory registration gate", () => {
  test("registers only after operator authority and exact anchor read-back, then confirms Directory read-back", () => {
    const input = fixtureInput();
    const calls: string[] = [];
    const receipt = executeRegistrationCommand(input, adapter(input, calls));
    expect(calls).toEqual(["authorize", "anchor-read", "authorize", "register", "registration-read"]);
    expect(receipt).toEqual({
      schema: "dacs-directory-registration/v1",
      registrationId: "r1",
      listingId: input.listing.listingId,
      listingVersion: input.listing.listingVersion,
      contentHash: input.listing.contentHash,
      nativeAddress: input.listing.nativeAddress,
    });
  });

  test("performs zero registration writes when authority or anchor proof is absent, stale, or substituted", () => {
    const input = fixtureInput();
    for (const failure of [
      "authority", "revoked-after-anchor", "absent-anchor", "substituted-anchor", "substituted-identity", "expired",
    ] as const) {
      const calls: string[] = [];
      const candidate = failure === "expired"
        ? { ...input, operatorScope: { ...input.operatorScope, expiresAtMs: 0 } }
        : failure === "substituted-identity"
          ? { ...input, listing: { ...input.listing, listingId: "other-listing" } }
        : input;
      const candidateAdapter = adapter(input, calls,
        failure === "substituted-identity" ? undefined : failure);
      expect(() => executeRegistrationCommand(candidate, candidateAdapter)).toThrow();
      expect(calls).not.toContain("register");
      expect(calls).not.toContain("registration-read");
    }
  });

  test("does not report success until independent Directory read-back matches every Listing binding", () => {
    const input = fixtureInput();
    const calls: string[] = [];
    expect(() => executeRegistrationCommand(input, adapter(input, calls, "wrong-registration")))
      .toThrow(/read-back/);
    expect(calls).toEqual(["authorize", "anchor-read", "authorize", "register", "registration-read"]);
  });

  test("rejects forged signed Listing bytes even when the fixture anchor returns those exact bytes", () => {
    const input = fixtureInput();
    const document = JSON.parse(input.listing.canonicalJson) as Record<string, unknown>;
    const signature = document["signature"] as Record<string, unknown>;
    signature["value"] = `${signature["value"] as string}A`;
    const candidate = {
      ...input,
      listing: { ...input.listing, canonicalJson: canonicalize(document) },
    };
    const calls: string[] = [];
    expect(() => executeRegistrationCommand(candidate, adapter(candidate, calls)))
      .toThrow(/signature/i);
    expect(calls).toEqual([]);
  });

  test("rejects a markerless direct executor adapter before invoking any adapter method", () => {
    const input = fixtureInput();
    const calls: string[] = [];
    const marked = adapter(input, calls);
    const unmarked = {
      authorizeOperator: marked.authorizeOperator,
      readAnchor: marked.readAnchor,
      register: marked.register,
      readRegistration: marked.readRegistration,
    };
    expect(() => executeRegistrationCommand(input, unmarked as RegistrationAdapter))
      .toThrow(/fixture\/no-spend/);
    expect(calls).toEqual([]);
  });

  test("performs zero writes when authority expires during the final authorization callback", () => {
    const input = fixtureInput();
    const calls: string[] = [];
    const base = adapter(input, calls);
    const originalNow = Date.now;
    let authorizations = 0;
    const candidate: RegistrationAdapter = {
      ...base,
      authorizeOperator: () => {
        calls.push("authorize");
        authorizations += 1;
        if (authorizations === 2) Date.now = () => input.operatorScope.expiresAtMs;
        return true;
      },
    };
    try {
      expect(() => executeRegistrationCommand(input, candidate)).toThrow(/at submission/);
      expect(calls).toEqual(["authorize", "anchor-read", "authorize"]);
    } finally {
      Date.now = originalNow;
    }
  });

  test("keeps help and doctor read-only while exposing registration only through the explicit command", async () => {
    const readOnly = capture();
    expect(await runCli(["--help"], readOnly.io)).toBe(0);
    expect(await runCli(["doctor", "--json"], readOnly.io)).toBe(0);
    expect(readOnly.stdout()).not.toContain("dacs-directory-registration/v1");

    const root = await mkdtemp(join(tmpdir(), "dacs-register-cli-"));
    roots.push(root);
    const input = fixtureInput();
    const inputPath = join(root, "input.json");
    const adapterPath = join(root, "adapter.ts");
    await writeFile(inputPath, JSON.stringify(input));
    await writeFile(adapterPath, adapterModule(input));
    const explicit = capture();
    expect(await runCli(["register", "--input", inputPath, "--adapter", adapterPath], explicit.io))
      .toBe(0);
    expect(explicit.stderr()).toBe("");
    expect(JSON.parse(explicit.stdout())).toMatchObject({
      schema: "dacs-directory-registration/v1",
      registrationId: "r1",
    });

    const unmarkedPath = join(root, "unmarked-adapter.ts");
    await writeFile(unmarkedPath, adapterModule(input).replace('executionMode: "fixture-no-spend",\n    ', ""));
    const rejected = capture();
    expect(await runCli(["register", "--input", inputPath, "--adapter", unmarkedPath], rejected.io))
      .toBe(4);
    expect(rejected.stderr()).toContain("must declare fixture-no-spend mode");
  });
});

function fixtureInput(): RegistrationCommandInput {
  const signed = fixtureSignedListing();
  const listing = signed.listing;
  const canonicalJson = signed.canonicalJson;
  const signer = fixtureSigner();
  return Object.freeze({
    operatorCapability: "0".repeat(64),
    operatorScope: Object.freeze({
      instanceId: "instance-1",
      audience: "https://service.example",
      principal: "did:demos:operator",
      operation: "directory:register" as const,
      expiresAtMs: NOW + 60_000,
    }),
    listing: Object.freeze({
      sellerPrimaryClaim: signer.signer,
      listingId: listing["listingId"] as string,
      listingVersion: listing["listingVersion"] as number,
      contentHash: signed.contentHash,
      canonicalJson,
      logicalAddress: `dacs1:${encodeURIComponent(signer.signer)}:${listing["listingId"]}:v${listing["listingVersion"]}`,
      nativeAddress: `fixture://${listing["listingId"]}/v${listing["listingVersion"]}`,
      anchorTx: "fixture-anchor-1",
      anchorVerifiedAt: FIXTURE_NOW_MS,
      createdAt: "2027-01-15T08:00:00.000Z",
    }),
  });
}

function adapter(
  input: RegistrationCommandInput,
  calls: string[],
  failure?: "authority" | "revoked-after-anchor" | "absent-anchor" | "substituted-anchor" | "wrong-registration" | "expired",
): RegistrationAdapter {
  let authorizationCount = 0;
  return {
    executionMode: "fixture-no-spend",
    authorizeOperator: () => {
      calls.push("authorize");
      authorizationCount += 1;
      return failure !== "authority" && !(failure === "revoked-after-anchor" && authorizationCount > 1);
    },
    readAnchor: () => {
      calls.push("anchor-read");
      if (failure === "absent-anchor") return { disposition: "absent" };
      return {
        disposition: "verified",
        canonicalJson: input.listing.canonicalJson,
        contentHash: failure === "substituted-anchor" ? "1".repeat(64) : sha256Hex(input.listing.canonicalJson),
        anchorTx: input.listing.anchorTx,
      };
    },
    register: () => {
      calls.push("register");
      return { disposition: "submitted", registrationId: "r1" };
    },
    readRegistration: () => {
      calls.push("registration-read");
      return {
        disposition: "registered",
        listingId: input.listing.listingId,
        listingVersion: input.listing.listingVersion,
        contentHash: failure === "wrong-registration" ? "2".repeat(64) : input.listing.contentHash,
        nativeAddress: input.listing.nativeAddress,
      };
    },
  };
}

function adapterModule(input: RegistrationCommandInput): string {
  return `export default {
    executionMode: "fixture-no-spend",
    authorizeOperator: () => true,
    readAnchor: () => (${JSON.stringify({
      disposition: "verified",
      canonicalJson: input.listing.canonicalJson,
      contentHash: sha256Hex(input.listing.canonicalJson),
      anchorTx: input.listing.anchorTx,
    })}),
    register: () => ({ disposition: "submitted", registrationId: "r1" }),
    readRegistration: () => (${JSON.stringify({
      disposition: "registered",
      listingId: input.listing.listingId,
      listingVersion: input.listing.listingVersion,
      contentHash: input.listing.contentHash,
      nativeAddress: input.listing.nativeAddress,
    })}),
  };`;
}

function capture() {
  let stdout = "";
  let stderr = "";
  return {
    io: {
      stdout: (value: string) => { stdout += value; },
      stderr: (value: string) => { stderr += value; },
    },
    stdout: () => stdout,
    stderr: () => stderr,
  };
}

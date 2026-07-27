import { afterEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  readAuthorityCapabilityOutput,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { PartyAuthorityLifecycle } from "../../src/substrate/sqlite/party-authority-lifecycle.ts";

const NOW = 1_800_000_000_000;
const ADMIN = "key:administrator";
const RECOVERY = "key:recovery";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("capability custody", () => {
  test("persists only digests and confines raw bootstrap authority to its 0600 output", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-capability-custody-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite");
    const outputPath = join(root, "bootstrap.cap");
    const request = prepareAuthorityBootstrap({
      administratorKey: ADMIN,
      administratorOperations: ["capability:revoke"],
      administratorPrincipal: "did:demos:administrator",
      audience: "https://service.example",
      expiresAtMs: NOW + 60_000,
      instanceId: "instance-1",
      outputPath,
      recoveryKey: RECOVERY,
      requestedAtMs: NOW,
      storeBinding: authorityStoreBinding(databasePath),
    }, entropy());
    const bytes = authorityBootstrapSigningBytes(request);
    completeAuthorityBootstrap({
      request,
      administratorProof: sign(ADMIN, bytes),
      recoveryProof: sign(RECOVERY, bytes),
    }, options(databasePath));
    const token = readAuthorityCapabilityOutput(outputPath);
    const database = openDatabase(databasePath);
    const lifecycle = new PartyAuthorityLifecycle(database, {
      audience: "https://service.example",
      instanceId: "instance-1",
      keyCurrentness: currentness(),
      now: () => NOW,
      partyAuthority: { resolve: () => ({ disposition: "unavailable" as const }) },
      proofVerifier: { verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes) },
      randomBytes: entropy(),
    });
    expect(() => lifecycle.revoke({
      authorization: token,
      targetToken: token,
      requestedAtMs: NOW,
      proof: "wrong",
    })).toThrow(/proof is invalid/);
    try {
      lifecycle.authorize(token, {
        kind: "administrator",
        instanceId: "wrong-instance",
        audience: "https://service.example",
        principal: "did:demos:administrator",
        operations: ["capability:revoke"],
        expiresAtMs: NOW + 60_000,
        configuredKey: ADMIN,
      });
    } catch (error) {
      expect(String(error)).not.toContain(token);
    }
    lifecycle.close();
    database.close();

    for (const name of await readdir(root)) {
      const content = await readFile(join(root, name));
      if (name === "bootstrap.cap") expect(content.includes(Buffer.from(token))).toBe(true);
      else expect(content.includes(Buffer.from(token)), name).toBe(false);
    }
  });
});

function options(databasePath: string) {
  return {
    databasePath,
    keyCurrentness: currentness(),
    now: () => NOW,
    proofVerifier: { verify: ({ key, proof, signedBytes }: {
      key: string; proof: string; signedBytes: string;
    }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(),
  };
}

function currentness() {
  return { resolve: ({ keyClaim, checkedAt }: { keyClaim: string; checkedAt: number }) => ({
    disposition: "current" as const,
    currentClaim: keyClaim,
    recipeVersion: 1,
    checkedAt,
  }) };
}

function sign(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("hex");
}

function entropy(): (size: number) => Uint8Array {
  let value = 1n;
  return (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, value++);
    return bytes;
  };
}

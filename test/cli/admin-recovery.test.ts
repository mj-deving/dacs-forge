import { afterEach, describe, expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AdministratorCapabilityScope } from "../../src/http/capability-authority.ts";
import {
  acquireAuthorityServiceLease,
  authorityBootstrapSigningBytes,
  authorityRecoverySigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  readAuthorityCapabilityOutput,
  recoverAdministrator,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { PartyAuthorityLifecycle } from "../../src/substrate/sqlite/party-authority-lifecycle.ts";
import { MAX_ADMINISTRATOR_CAPABILITY_HISTORY } from "../../src/substrate/capability-limits.ts";

const NOW = 1_800_000_000_000;
const ADMIN = "key:administrator";
const REPLACEMENT = "key:administrator-replacement";
const RECOVERY = "key:recovery";
const INSTANCE = "instance-1";
const AUDIENCE = "https://service.example";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("offline administrator recovery", () => {
  test("runs recovery through the installed dacs entrypoint", async () => {
    const fixture = await bootstrapped();
    const inputPath = join(fixture.root, "recover.json");
    const adapterPath = join(fixture.root, "authority-adapter.ts");
    await writeFile(inputPath, JSON.stringify(signedRecovery(fixture.databasePath, fixture.newOutput)));
    await writeFile(adapterPath, adapterModule());
    const completed = Bun.spawnSync([
      resolve(import.meta.dir, "../../src/cli/dacs.ts"),
      "authority", "recover",
      "--input", inputPath,
      "--database", fixture.databasePath,
      "--adapter", adapterPath,
    ]);
    expect(completed.exitCode).toBe(0);
    expect(JSON.parse(completed.stdout.toString())).toMatchObject({
      schema: "dacs-authority-operation/v1",
      result: { instanceId: INSTANCE, generation: 2, outputPath: fixture.newOutput },
    });
    expect((await stat(fixture.newOutput)).mode & 0o777).toBe(0o600);
  });

  test("requires stopped service and atomically replaces every administrator", async () => {
    const fixture = await bootstrapped();
    const oldToken = readAuthorityCapabilityOutput(fixture.oldOutput);
    const recovery = signedRecovery(fixture.databasePath, fixture.newOutput);
    const lease = acquireAuthorityServiceLease(fixture.databasePath);
    expect(() => recoverAdministrator(recovery, options(fixture.databasePath)))
      .toThrow(/service is running/);
    lease.close();

    const result = recoverAdministrator(recovery, options(fixture.databasePath));
    expect(result).toEqual({ instanceId: INSTANCE, generation: 2, outputPath: fixture.newOutput });
    const newToken = readAuthorityCapabilityOutput(fixture.newOutput);
    expect((await stat(fixture.newOutput)).mode & 0o777).toBe(0o600);
    expect(newToken).not.toBe(oldToken);

    const database = openDatabase(fixture.databasePath);
    const lifecycle = authority(database);
    expect(lifecycle.authorize(oldToken, adminScope(ADMIN, NOW + 60_000))).toBe(false);
    expect(lifecycle.authorize(newToken, adminScope(REPLACEMENT, NOW + 120_000))).toBe(true);
    expect(database.query<{ active: bigint }, []>(`
      SELECT count(*) AS active FROM party_capabilities
      WHERE kind = 'administrator' AND state = 'active'
    `).get()?.active).toBe(1n);
    expect(database.query<{ generation: bigint }, []>(
      "SELECT generation FROM party_authority_instances",
    ).get()?.generation).toBe(2n);
    lifecycle.close();
    database.close();

    expect(() => recoverAdministrator(recovery, options(fixture.databasePath)))
      .toThrow(/generation does not match/);
  });

  test("reclaims bounded administrator history while recovering exactly one authority", async () => {
    const fixture = await bootstrapped();
    const oldToken = readAuthorityCapabilityOutput(fixture.oldOutput);
    const database = openDatabase(fixture.databasePath);
    const insert = database.query<never, { digest: string; index: number }>(`
      INSERT INTO party_capabilities (
        capability_digest, instance_id, audience, kind, principal, operations_json,
        expires_at_ms, configured_key, state, issued_at_ms, revoked_at_ms, generation
      ) VALUES (
        $digest, '${INSTANCE}', '${AUDIENCE}', 'administrator',
        'did:demos:historical-' || $index, '["administrator:rotate"]',
        ${NOW - 1}, 'key:historical-' || $index, 'revoked', ${NOW - 2}, ${NOW - 1}, 1
      )
    `);
    database.transaction(() => {
      for (let index = 1; index < MAX_ADMINISTRATOR_CAPABILITY_HISTORY; index += 1) {
        insert.run({ digest: digest(`historical-administrator-${index}`), index });
      }
    }).immediate();
    expect(database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM party_capabilities WHERE kind = 'administrator'
    `).get()?.count).toBe(BigInt(MAX_ADMINISTRATOR_CAPABILITY_HISTORY));
    database.close();

    recoverAdministrator(
      signedRecovery(fixture.databasePath, fixture.newOutput),
      options(fixture.databasePath),
    );
    const replacementToken = readAuthorityCapabilityOutput(fixture.newOutput);
    const reopened = openDatabase(fixture.databasePath);
    const lifecycle = authority(reopened);
    expect(lifecycle.authorize(oldToken, adminScope(ADMIN, NOW + 60_000))).toBe(false);
    expect(lifecycle.authorize(
      replacementToken,
      adminScope(REPLACEMENT, NOW + 120_000),
    )).toBe(true);
    expect(reopened.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM party_capabilities WHERE kind = 'administrator'
    `).get()?.count).toBe(1n);
    lifecycle.close();
    reopened.close();
  });

  test("rejects wrong proof without changing prior authority or writing output", async () => {
    const fixture = await bootstrapped();
    const recovery = signedRecovery(fixture.databasePath, fixture.newOutput);
    expect(() => recoverAdministrator(
      { ...recovery, administratorProof: "wrong" },
      options(fixture.databasePath),
    )).toThrow(/administrator proof is invalid/);
    expect(() => recoverAdministrator({ ...recovery, proof: "wrong" }, options(fixture.databasePath)))
      .toThrow(/proof is invalid/);
    const oldToken = readAuthorityCapabilityOutput(fixture.oldOutput);
    const database = openDatabase(fixture.databasePath);
    const lifecycle = authority(database);
    expect(lifecycle.authorize(oldToken, adminScope(ADMIN, NOW + 60_000))).toBe(true);
    lifecycle.close();
    database.close();
  });

  test("rejects an otherwise valid proof from a revoked recovery key", async () => {
    const fixture = await bootstrapped();
    const recovery = signedRecovery(fixture.databasePath, fixture.newOutput);
    expect(() => recoverAdministrator(recovery, options(fixture.databasePath, RECOVERY)))
      .toThrow(/not current/);
    const database = openDatabase(fixture.databasePath);
    expect(database.query<{ active: bigint }, []>(`
      SELECT count(*) AS active FROM party_capabilities
      WHERE kind = 'administrator' AND state = 'active'
    `).get()?.active).toBe(1n);
    database.close();
  });
});

async function bootstrapped() {
  const root = await mkdtemp(join(tmpdir(), "dacs-admin-recovery-"));
  roots.push(root);
  const databasePath = join(root, "state.sqlite");
  const oldOutput = join(root, "old-admin.cap");
  const newOutput = join(root, "new-admin.cap");
  const request = prepareAuthorityBootstrap({
    administratorKey: ADMIN,
    administratorOperations: ["administrator:rotate", "capability:revoke", "clone:rotate"],
    administratorPrincipal: "did:demos:administrator",
    audience: AUDIENCE,
    expiresAtMs: NOW + 60_000,
    instanceId: INSTANCE,
    outputPath: oldOutput,
    recoveryKey: RECOVERY,
    requestedAtMs: NOW,
    storeBinding: authorityStoreBinding(databasePath),
  }, entropy(1n));
  const bytes = authorityBootstrapSigningBytes(request);
  completeAuthorityBootstrap({
    request,
    administratorProof: sign(ADMIN, bytes),
    recoveryProof: sign(RECOVERY, bytes),
  }, options(databasePath));
  return { root, databasePath, oldOutput, newOutput };
}

function signedRecovery(databasePath: string, outputPath: string) {
  const request = {
    administratorKey: REPLACEMENT,
    administratorOperations: ["administrator:rotate", "capability:revoke", "clone:rotate"],
    administratorPrincipal: "did:demos:replacement",
    audience: AUDIENCE,
    expiresAtMs: NOW + 120_000,
    expectedGeneration: 1,
    instanceId: INSTANCE,
    nonce: "2".padStart(64, "0"),
    outputPath,
    requestedAtMs: NOW,
    storeBinding: authorityStoreBinding(databasePath),
  } as const;
  const bytes = authorityRecoverySigningBytes(request);
  return {
    request,
    administratorProof: sign(REPLACEMENT, bytes),
    proof: sign(RECOVERY, bytes),
  };
}

function authority(database: ReturnType<typeof openDatabase>) {
  return new PartyAuthorityLifecycle(database, {
    audience: AUDIENCE,
    instanceId: INSTANCE,
    keyCurrentness: currentness(),
    now: () => NOW,
    partyAuthority: { resolve: () => ({ disposition: "unavailable" as const }) },
    proofVerifier: { verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(50n),
  });
}

function adminScope(key: string, expiresAtMs: number): AdministratorCapabilityScope {
  return {
    kind: "administrator",
    instanceId: INSTANCE,
    audience: AUDIENCE,
    principal: key === ADMIN ? "did:demos:administrator" : "did:demos:replacement",
    operations: ["administrator:rotate", "capability:revoke", "clone:rotate"],
    expiresAtMs,
    configuredKey: key,
  };
}

function options(databasePath: string, revoked?: string) {
  return {
    databasePath,
    keyCurrentness: currentness(revoked),
    now: () => NOW,
    proofVerifier: { verify: ({ key, proof, signedBytes }: {
      key: string; proof: string; signedBytes: string;
    }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(10n),
  };
}

function currentness(revoked?: string) {
  return { resolve: ({ keyClaim, checkedAt }: { keyClaim: string; checkedAt: number }) =>
    keyClaim === revoked
      ? { disposition: "revoked" as const, currentClaim: "key:replacement", recipeVersion: 1, checkedAt }
      : { disposition: "current" as const, currentClaim: keyClaim, recipeVersion: 1, checkedAt } };
}

function sign(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("hex");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function entropy(initial: bigint): (size: number) => Uint8Array {
  let value = initial;
  return (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, value++);
    return bytes;
  };
}

function adapterModule(): string {
  return `import { createHmac } from "node:crypto";
let value = 10n;
export default {
  now: () => ${NOW},
  keyCurrentness: { resolve: ({ keyClaim, checkedAt }) => ({
    disposition: "current", currentClaim: keyClaim, recipeVersion: 1, checkedAt,
  }) },
  proofVerifier: { verify: ({ key, proof, signedBytes }) =>
    proof === createHmac("sha256", key).update(signedBytes).digest("hex") },
  randomBytes: (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, value++);
    return bytes;
  },
};\n`;
}

import { afterEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { chmod, link, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AdministratorCapabilityScope } from "../../src/http/capability-authority.ts";
import {
  acquireAuthorityServiceLease,
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  cloneRotationSigningBytes,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  readAuthorityCapabilityOutput,
  rotateCloneAuthority,
  type CloneRotationRequest,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { PartyAuthorityLifecycle } from "../../src/substrate/sqlite/party-authority-lifecycle.ts";

const NOW = 1_800_000_000_000;
const OLD_INSTANCE = "instance-source";
const NEW_INSTANCE = "instance-clone";
const AUDIENCE = "https://service.example";
const OLD_ADMIN = "key:old-admin";
const OLD_RECOVERY = "key:old-recovery";
const NEW_ADMIN = "key:new-admin";
const NEW_RECOVERY = "key:new-recovery";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("clone authority rotation", () => {
  test("requires stopped service and leaves exactly one clone administrator", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-clone-authority-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite");
    const sourceOutput = join(root, "source.cap");
    const cloneOutput = join(root, "clone.cap");
    bootstrap(databasePath, sourceOutput);
    const sourceToken = readAuthorityCapabilityOutput(sourceOutput);
    const request = cloneRequest(databasePath, sourceToken, cloneOutput);
    const signedBytes = cloneRotationSigningBytes(request);
    expect(cloneRotationSigningBytes({
      ...request,
      administratorCapability: "0".repeat(64),
    })).not.toBe(signedBytes);
    const signed = {
      ...request,
      administratorProof: sign(OLD_ADMIN, signedBytes),
      newAdministratorProof: sign(NEW_ADMIN, signedBytes),
      newRecoveryProof: sign(NEW_RECOVERY, signedBytes),
    };
    expect(() => rotateCloneAuthority(
      { ...signed, newAdministratorProof: "wrong" },
      options(databasePath),
    )).toThrow(/proofs are invalid/);

    const preparationDatabase = openDatabase(databasePath);
    preparationDatabase.query(`
      INSERT INTO admission_challenges (
        nonce, job_id, instance_id, audience, principal_ref, principal_scheme,
        principal_identifier, evidence_mode, client_nonce, client_idempotency_key,
        allocation_fingerprint, requested_at_ms, issued_at_ms, expires_at_ms, retain_until_ms
      ) VALUES (
        '11111111111111111111111111111111', '01J00000000000000000000009',
        '${OLD_INSTANCE}', '${AUDIENCE}', 'key:source', 'key', 'source', 'fixture',
        '22222222222222222222222222222222', 'clone-cleanup', '${"0".repeat(64)}',
        ${NOW}, ${NOW}, ${NOW + 1}, ${NOW + 1}
      )
    `).run();
    const preparationLifecycle = new PartyAuthorityLifecycle(preparationDatabase, {
      audience: AUDIENCE,
      instanceId: OLD_INSTANCE,
      keyCurrentness: currentness(),
      now: () => NOW,
      partyAuthority: { resolve: () => ({ disposition: "unavailable" as const }) },
      proofVerifier: { verify: ({ key, proof, signedBytes: bytes }) => proof === sign(key, bytes) },
      randomBytes: entropy(40n),
    });
    preparationLifecycle.prepareCapabilityReplacement();
    preparationLifecycle.close();
    preparationDatabase.close();

    const lease = acquireAuthorityServiceLease(databasePath);
    const aliasPath = join(root, "state-alias.sqlite");
    await symlink(databasePath, aliasPath);
    expect(() => acquireAuthorityServiceLease(aliasPath)).toThrow(/service is running/);
    const hardlinkPath = join(root, "state-hardlink.sqlite");
    await link(databasePath, hardlinkPath);
    expect(() => acquireAuthorityServiceLease(hardlinkPath)).toThrow(/hard-link aliases/);
    expect(() => lease.assertActive()).toThrow(/hard-link alias/);
    await rm(hardlinkPath);
    lease.assertActive();
    expect(() => rotateCloneAuthority(signed, options(databasePath)))
      .toThrow(/service is running/);
    lease.close();
    expect(rotateCloneAuthority(signed, options(databasePath))).toEqual({
      instanceId: NEW_INSTANCE,
      generation: 2,
      outputPath: cloneOutput,
    });

    const cloneToken = readAuthorityCapabilityOutput(cloneOutput);
    const database = openDatabase(databasePath);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capabilities WHERE state = 'active'",
    ).get()?.count).toBe(1n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capabilities",
    ).get()?.count).toBe(2n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capability_preparations",
    ).get()?.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(0n);
    expect(database.query<{ instanceId: string; recoveryKey: string }, []>(`
      SELECT instance_id AS instanceId, recovery_key AS recoveryKey FROM party_authority_instances
    `).get()).toEqual({ instanceId: NEW_INSTANCE, recoveryKey: NEW_RECOVERY });
    const lifecycle = new PartyAuthorityLifecycle(database, {
      audience: AUDIENCE,
      instanceId: NEW_INSTANCE,
      keyCurrentness: currentness(),
      now: () => NOW,
      partyAuthority: { resolve: () => ({ disposition: "unavailable" as const }) },
      proofVerifier: { verify: ({ key, proof, signedBytes: bytes }) => proof === sign(key, bytes) },
      randomBytes: entropy(50n),
    });
    expect(lifecycle.authorize(sourceToken, adminScope(OLD_INSTANCE, OLD_ADMIN))).toBe(false);
    expect(lifecycle.authorize(cloneToken, adminScope(NEW_INSTANCE, NEW_ADMIN))).toBe(true);
    lifecycle.close();
    database.close();

    expect(() => rotateCloneAuthority(signed, options(databasePath)))
      .toThrow(/source authority does not exist/);
  });

  test("runs clone rotation through the installed dacs entrypoint", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-clone-authority-cli-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite");
    const sourceOutput = join(root, "source.cap");
    const cloneOutput = join(root, "clone.cap");
    bootstrap(databasePath, sourceOutput);
    const request = cloneRequest(databasePath, readAuthorityCapabilityOutput(sourceOutput), cloneOutput);
    const signedBytes = cloneRotationSigningBytes(request);
    const inputPath = join(root, "clone-rotate.json");
    const adapterPath = join(root, "authority-adapter.ts");
    const executable = resolve(import.meta.dir, "../../src/cli/dacs.ts");
    await writeFile(inputPath, JSON.stringify({
      ...request,
      administratorProof: sign(OLD_ADMIN, signedBytes),
      newAdministratorProof: sign(NEW_ADMIN, signedBytes),
      newRecoveryProof: sign(NEW_RECOVERY, signedBytes),
    }), { mode: 0o644 });
    await writeFile(adapterPath, adapterModule());
    const rejected = Bun.spawnSync([
      executable,
      "authority", "clone-rotate",
      "--input", inputPath,
      "--database", databasePath,
      "--adapter", adapterPath,
    ]);
    expect(rejected.exitCode).toBe(2);
    expect(rejected.stderr.toString()).toContain("process-owned mode 0600");
    const oversizedPath = join(root, "oversized.json");
    await writeFile(oversizedPath, `{${"x".repeat(65_536)}`, { mode: 0o600 });
    expect(Bun.spawnSync([
      executable, "authority", "clone-rotate", "--input", oversizedPath,
      "--database", databasePath, "--adapter", adapterPath,
    ]).exitCode).toBe(2);
    const fifoPath = join(root, "authority-input.fifo");
    expect(Bun.spawnSync(["mkfifo", fifoPath]).exitCode).toBe(0);
    await chmod(fifoPath, 0o600);
    const fifoProcess = Bun.spawn([
      executable, "authority", "clone-rotate", "--input", fifoPath,
      "--database", databasePath, "--adapter", adapterPath,
    ]);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const fifoExit = await Promise.race([
      fifoProcess.exited,
      new Promise<number>((resolveTimeout) => {
        timeout = setTimeout(() => {
          fifoProcess.kill();
          resolveTimeout(-1);
        }, 1_000);
      }),
    ]);
    clearTimeout(timeout);
    if (fifoExit === -1) await fifoProcess.exited;
    expect(fifoExit).toBe(2);
    await chmod(inputPath, 0o600);
    const completed = Bun.spawnSync([
      executable,
      "authority", "clone-rotate",
      "--input", inputPath,
      "--database", databasePath,
      "--adapter", adapterPath,
    ]);
    expect(completed.exitCode).toBe(0);
    expect(JSON.parse(completed.stdout.toString())).toMatchObject({
      schema: "dacs-authority-operation/v1",
      result: { instanceId: NEW_INSTANCE, generation: 2, outputPath: cloneOutput },
    });
    expect(readAuthorityCapabilityOutput(cloneOutput)).toMatch(/^[0-9a-f]{64}$/);
  });

  test("refuses to split a populated source session from the rotated clone identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-clone-populated-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite");
    const sourceOutput = join(root, "source.cap");
    const cloneOutput = join(root, "clone.cap");
    bootstrap(databasePath, sourceOutput);
    const database = openDatabase(databasePath);
    database.query(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint, status, created_at
      ) VALUES (
        '${OLD_INSTANCE}', '${AUDIENCE}', '01J00000000000000000000008', 'fixture',
        '${"0".repeat(64)}', 'admitted', '2026-07-27T00:00:00.000Z'
      )
    `).run();
    database.close();
    const request = cloneRequest(databasePath, readAuthorityCapabilityOutput(sourceOutput), cloneOutput);
    const signedBytes = cloneRotationSigningBytes(request);
    expect(() => rotateCloneAuthority({
      ...request,
      administratorProof: sign(OLD_ADMIN, signedBytes),
      newAdministratorProof: sign(NEW_ADMIN, signedBytes),
      newRecoveryProof: sign(NEW_RECOVERY, signedBytes),
    }, options(databasePath))).toThrow(/unused source instance/);
  });
});

function bootstrap(databasePath: string, outputPath: string): void {
  const request = prepareAuthorityBootstrap({
    administratorKey: OLD_ADMIN,
    administratorOperations: ["clone:rotate", "capability:revoke"],
    administratorPrincipal: "did:demos:source-admin",
    audience: AUDIENCE,
    expiresAtMs: NOW + 60_000,
    instanceId: OLD_INSTANCE,
    outputPath,
    recoveryKey: OLD_RECOVERY,
    requestedAtMs: NOW,
    storeBinding: authorityStoreBinding(databasePath),
  }, entropy(1n));
  const bytes = authorityBootstrapSigningBytes(request);
  completeAuthorityBootstrap({
    request,
    administratorProof: sign(OLD_ADMIN, bytes),
    recoveryProof: sign(OLD_RECOVERY, bytes),
  }, options(databasePath));
}

function cloneRequest(
  databasePath: string,
  administratorCapability: string,
  outputPath: string,
): CloneRotationRequest {
  return {
    administratorProof: "pending",
    administratorCapability,
    audience: AUDIENCE,
    expiresAtMs: NOW + 120_000,
    newAdministratorKey: NEW_ADMIN,
    newAdministratorOperations: ["clone:rotate", "capability:revoke"],
    newAdministratorPrincipal: "did:demos:clone-admin",
    newAdministratorProof: "pending",
    newInstanceId: NEW_INSTANCE,
    newRecoveryKey: NEW_RECOVERY,
    newRecoveryProof: "pending",
    nonce: "3".padStart(64, "0"),
    oldInstanceId: OLD_INSTANCE,
    outputPath,
    requestedAtMs: NOW,
    storeBinding: authorityStoreBinding(databasePath),
  };
}

function adminScope(instanceId: string, key: string): AdministratorCapabilityScope {
  return {
    kind: "administrator",
    instanceId,
    audience: AUDIENCE,
    principal: key === OLD_ADMIN ? "did:demos:source-admin" : "did:demos:clone-admin",
    operations: ["capability:revoke", "clone:rotate"],
    expiresAtMs: key === OLD_ADMIN ? NOW + 60_000 : NOW + 120_000,
    configuredKey: key,
  };
}

function options(databasePath: string) {
  return {
    databasePath,
    keyCurrentness: currentness(),
    now: () => NOW,
    proofVerifier: { verify: ({ key, proof, signedBytes }: {
      key: string; proof: string; signedBytes: string;
    }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(10n),
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

import { afterEach, describe, expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AdministratorCapabilityScope } from "../../src/http/capability-authority.ts";
import {
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  readAuthorityCapabilityOutput,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  PartyAuthorityLifecycle,
  AdministratorSessionLimitError,
  CapabilityHistoryLimitError,
  CapabilityPreparationLimitError,
  administratorRotationSigningBytes,
  capabilityRenewalSigningBytes,
  capabilityRevocationSigningBytes,
} from "../../src/substrate/sqlite/party-authority-lifecycle.ts";
import { MAX_ADMINISTRATOR_CAPABILITY_HISTORY } from "../../src/substrate/capability-limits.ts";

const NOW = 1_800_000_000_000;
const INSTANCE = "instance-1";
const AUDIENCE = "https://service.example";
const ADMIN = "key:administrator";
const NEW_ADMIN = "key:replacement";
const RECOVERY = "key:recovery";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("capability lifecycle negative matrix", () => {
  test("rotates atomically and never permits revoking the last administrator", async () => {
    const fixture = await setup();
    const oldToken = readAuthorityCapabilityOutput(fixture.output);
    const database = openDatabase(fixture.databasePath);
    const lifecycle = authority(database);
    const replacementScope: AdministratorCapabilityScope = {
      kind: "administrator",
      instanceId: INSTANCE,
      audience: AUDIENCE,
      principal: "did:demos:replacement",
      operations: ["administrator:rotate", "capability:revoke", "session:inspect"],
      expiresAtMs: NOW + 120_000,
      configuredKey: NEW_ADMIN,
    };
    const replacementToken = lifecycle.prepareCapabilityReplacement();
    const signedRotationBytes = administratorRotationSigningBytes({
      authorizationDigest: digest(oldToken),
      replacementDigest: digest(replacementToken),
      replacementScope,
      requestedAtMs: NOW,
    });
    expect(() => lifecycle.rotateAdministrator({
      authorization: oldToken,
      expiresAtMs: replacementScope.expiresAtMs,
      newConfiguredKey: replacementScope.configuredKey,
      newKeyProof: sign(NEW_ADMIN, signedRotationBytes),
      newPrincipal: replacementScope.principal,
      operations: replacementScope.operations,
      proof: "wrong",
      replacementToken,
      requestedAtMs: NOW,
    })).toThrow(/proofs are invalid/);
    const excessiveScope = { ...replacementScope, expiresAtMs: NOW + 86_400_001 };
    const excessiveBytes = administratorRotationSigningBytes({
      authorizationDigest: digest(oldToken),
      replacementDigest: digest(replacementToken),
      replacementScope: excessiveScope,
      requestedAtMs: NOW,
    });
    expect(() => lifecycle.rotateAdministrator({
      authorization: oldToken,
      expiresAtMs: excessiveScope.expiresAtMs,
      newConfiguredKey: excessiveScope.configuredKey,
      newKeyProof: sign(NEW_ADMIN, excessiveBytes),
      newPrincipal: excessiveScope.principal,
      operations: excessiveScope.operations,
      proof: sign(ADMIN, excessiveBytes),
      replacementToken,
      requestedAtMs: NOW,
    })).toThrow(/within one day/);
    expect(() => lifecycle.rotateAdministrator({
      authorization: oldToken,
      expiresAtMs: replacementScope.expiresAtMs,
      newConfiguredKey: replacementScope.configuredKey,
      newKeyProof: "wrong",
      newPrincipal: replacementScope.principal,
      operations: replacementScope.operations,
      proof: sign(ADMIN, signedRotationBytes),
      replacementToken,
      requestedAtMs: NOW,
    })).toThrow(/proofs are invalid/);
    const replacement = lifecycle.rotateAdministrator({
      authorization: oldToken,
      expiresAtMs: replacementScope.expiresAtMs,
      newConfiguredKey: replacementScope.configuredKey,
      newKeyProof: sign(NEW_ADMIN, signedRotationBytes),
      newPrincipal: replacementScope.principal,
      operations: replacementScope.operations,
      proof: sign(ADMIN, signedRotationBytes),
      replacementToken,
      requestedAtMs: NOW,
    });
    expect(lifecycle.authorize(oldToken, adminScope(ADMIN, NOW + 60_000))).toBe(false);
    const { token: testToken } = replacement;
    expect(lifecycle.authorize(testToken, replacement.scope)).toBe(true);
    const testToken2 = lifecycle.prepareCapabilityReplacement();
    const renewalExpiry = NOW + 180_000;
    const excessiveRenewalExpiry = NOW + 86_400_001;
    expect(() => lifecycle.renew({
      token: testToken,
      replacementToken: testToken2,
      expiresAtMs: excessiveRenewalExpiry,
      requestedAtMs: NOW - 1_000,
      proof: sign(NEW_ADMIN, capabilityRenewalSigningBytes({
        tokenDigest: digest(testToken),
        replacementDigest: digest(testToken2),
        expiresAtMs: excessiveRenewalExpiry,
        requestedAtMs: NOW - 1_000,
      })),
    })).toThrow(/exceeds one day/);
    const renewed = lifecycle.renew({
      token: testToken,
      replacementToken: testToken2,
      expiresAtMs: renewalExpiry,
      requestedAtMs: NOW - 1_000,
      proof: sign(NEW_ADMIN, capabilityRenewalSigningBytes({
        tokenDigest: digest(testToken),
        replacementDigest: digest(testToken2),
        expiresAtMs: renewalExpiry,
        requestedAtMs: NOW - 1_000,
      })),
    });
    expect(renewed.token).toBe(testToken2);
    expect(lifecycle.authorize(testToken, replacement.scope)).toBe(false);
    expect(lifecycle.authorize(testToken2, renewed.scope)).toBe(true);
    const revokeBytes = capabilityRevocationSigningBytes({
      authorizationDigest: digest(testToken2),
      targetDigest: digest(testToken2),
      requestedAtMs: NOW,
    });
    expect(() => lifecycle.revoke({
      authorization: testToken2,
      targetToken: testToken2,
      requestedAtMs: NOW,
      proof: sign(NEW_ADMIN, revokeBytes),
    })).toThrow(/last administrator/);
    expect(lifecycle.authorize(testToken2, renewed.scope)).toBe(true);
    expect(database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM party_capabilities
      WHERE kind = 'administrator' AND state = 'active'
    `).get()?.count).toBe(1n);
    lifecycle.close();
    database.close();

    const reopened = openDatabase(fixture.databasePath);
    const restarted = authority(reopened);
    expect(restarted.authorize(testToken2, renewed.scope)).toBe(true);
    restarted.close();
    reopened.close();
  });

  test("rejects malformed, expired, wrong-instance, and wrong-operation scopes", async () => {
    const fixture = await setup();
    const token = readAuthorityCapabilityOutput(fixture.output);
    const database = openDatabase(fixture.databasePath);
    const lifecycle = authority(database);
    const scope = adminScope(ADMIN, NOW + 60_000);
    expect(lifecycle.authorize("not-a-capability", scope)).toBe(false);
    expect(lifecycle.authorize(token, { ...scope, instanceId: "other" })).toBe(false);
    expect(lifecycle.authorize(token, { ...scope, operations: ["unknown"] })).toBe(false);
    expect(lifecycle.authorize(token, { ...scope, expiresAtMs: NOW - 1 })).toBe(false);
    lifecycle.close();
    database.close();
  });

  test("fails closed when durable administrator history reaches its bound", async () => {
    const fixture = await setup();
    const oldToken = readAuthorityCapabilityOutput(fixture.output);
    const database = openDatabase(fixture.databasePath);
    const insert = database.query<never, { digest: string; principal: string; key: string }>(`
      INSERT INTO party_capabilities (
        capability_digest, instance_id, audience, kind, principal, operations_json,
        expires_at_ms, configured_key, state, issued_at_ms, revoked_at_ms, generation
      ) VALUES (
        $digest, '${INSTANCE}', '${AUDIENCE}', 'administrator', $principal,
        '["administrator:rotate"]', ${NOW - 1}, $key, 'revoked', ${NOW - 2}, ${NOW - 1}, 1
      )
    `);
    database.transaction(() => {
      for (let index = 1; index < MAX_ADMINISTRATOR_CAPABILITY_HISTORY; index += 1) {
        insert.run({
          digest: digest(`historical-administrator-${index}`),
          principal: `did:demos:historical-${index}`,
          key: `key:historical-${index}`,
        });
      }
    }).immediate();
    const lifecycle = authority(database);
    const replacementToken = lifecycle.prepareCapabilityReplacement();
    const replacementScope = adminScope(NEW_ADMIN, NOW + 120_000);
    const bytes = administratorRotationSigningBytes({
      authorizationDigest: digest(oldToken),
      replacementDigest: digest(replacementToken),
      replacementScope,
      requestedAtMs: NOW,
    });
    expect(() => lifecycle.rotateAdministrator({
      authorization: oldToken,
      expiresAtMs: replacementScope.expiresAtMs,
      newConfiguredKey: replacementScope.configuredKey,
      newKeyProof: sign(NEW_ADMIN, bytes),
      newPrincipal: replacementScope.principal,
      operations: replacementScope.operations,
      proof: sign(ADMIN, bytes),
      replacementToken,
      requestedAtMs: NOW,
    })).toThrow(CapabilityHistoryLimitError);
    expect(lifecycle.authorize(oldToken, adminScope(ADMIN, NOW + 60_000))).toBe(true);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capabilities",
    ).get()?.count).toBe(BigInt(MAX_ADMINISTRATOR_CAPABILITY_HISTORY));
    lifecycle.close();
    database.close();
  });

  test("does not count a revoked-key row as a usable replacement administrator", async () => {
    const fixture = await setup();
    const token = readAuthorityCapabilityOutput(fixture.output);
    const database = openDatabase(fixture.databasePath);
    database.query<never, { digest: string }>(`
      INSERT INTO party_capabilities (
        capability_digest, instance_id, audience, kind, principal, operations_json,
        expires_at_ms, configured_key, state, issued_at_ms, generation
      ) VALUES (
        $digest, '${INSTANCE}', '${AUDIENCE}', 'administrator', 'did:demos:stale',
        '["administrator:rotate","capability:revoke","session:inspect"]',
        ${NOW + 60_000}, '${NEW_ADMIN}', 'active', ${NOW}, 1
      )
    `).run({ digest: digest("stale-administrator") });
    const lifecycle = authority(database, NEW_ADMIN);
    const signed = capabilityRevocationSigningBytes({
      authorizationDigest: digest(token),
      targetDigest: digest(token),
      requestedAtMs: NOW,
    });
    expect(() => lifecycle.revoke({
      authorization: token,
      targetToken: token,
      requestedAtMs: NOW,
      proof: sign(ADMIN, signed),
    })).toThrow(/last administrator/);
    lifecycle.close();
    database.close();
  });

  test("bounds and expires unconsumed capability preparations", async () => {
    const fixture = await setup();
    const database = openDatabase(fixture.databasePath);
    let now = NOW;
    const lifecycle = authority(database, undefined, () => now);
    for (let index = 0; index < 256; index += 1) lifecycle.prepareCapabilityReplacement();
    expect(() => lifecycle.prepareCapabilityReplacement()).toThrow(CapabilityPreparationLimitError);
    now += 300_001;
    expect(lifecycle.prepareCapabilityReplacement()).toMatch(/^[0-9a-f]{64}$/);
    lifecycle.close();
    database.close();
  });

  test("bounds administrator session inspection before materializing the response", async () => {
    const fixture = await setup();
    const token = readAuthorityCapabilityOutput(fixture.output);
    const database = openDatabase(fixture.databasePath);
    const insert = database.query<never, { jobId: string }>(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint, status, created_at
      ) VALUES (
        '${INSTANCE}', '${AUDIENCE}', $jobId, 'fixture', '${"0".repeat(64)}',
        'admitted', '2026-07-27T00:00:00.000Z'
      )
    `);
    database.transaction(() => {
      for (let index = 0; index < 513; index += 1) {
        insert.run({ jobId: `01J${index.toString().padStart(23, "0")}` });
      }
    }).immediate();
    const lifecycle = authority(database);
    expect(() => lifecycle.listAdministratorSessions(token)).toThrow(AdministratorSessionLimitError);
    lifecycle.close();
    database.close();
  });
});

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dacs-capability-negative-"));
  roots.push(root);
  const databasePath = join(root, "state.sqlite");
  const output = join(root, "admin.cap");
  const request = prepareAuthorityBootstrap({
    administratorKey: ADMIN,
    administratorOperations: ["administrator:rotate", "capability:revoke", "session:inspect"],
    administratorPrincipal: "did:demos:administrator",
    audience: AUDIENCE,
    expiresAtMs: NOW + 60_000,
    instanceId: INSTANCE,
    outputPath: output,
    recoveryKey: RECOVERY,
    requestedAtMs: NOW,
    storeBinding: authorityStoreBinding(databasePath),
  }, entropy());
  const bytes = authorityBootstrapSigningBytes(request);
  completeAuthorityBootstrap({
    request,
    administratorProof: sign(ADMIN, bytes),
    recoveryProof: sign(RECOVERY, bytes),
  }, offlineOptions(databasePath));
  return { root, databasePath, output };
}

function authority(
  database: ReturnType<typeof openDatabase>,
  revokedKey?: string,
  now: () => number = () => NOW,
) {
  return new PartyAuthorityLifecycle(database, {
    audience: AUDIENCE,
    instanceId: INSTANCE,
    keyCurrentness: currentness(revokedKey),
    now,
    partyAuthority: { resolve: () => ({ disposition: "unavailable" as const }) },
    proofVerifier: { verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(),
  });
}

function adminScope(key: string, expiresAtMs: number): AdministratorCapabilityScope {
  return {
    kind: "administrator",
    instanceId: INSTANCE,
    audience: AUDIENCE,
    principal: "did:demos:administrator",
    operations: ["administrator:rotate", "capability:revoke", "session:inspect"],
    expiresAtMs,
    configuredKey: key,
  };
}

function offlineOptions(databasePath: string) {
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

function currentness(revokedKey?: string) {
  return { resolve: ({ keyClaim, checkedAt }: { keyClaim: string; checkedAt: number }) => ({
    disposition: keyClaim === revokedKey ? "revoked" as const : "current" as const,
    currentClaim: keyClaim === revokedKey ? ADMIN : keyClaim,
    recipeVersion: 1,
    checkedAt,
  }) };
}

function sign(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("hex");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function entropy(): (size: number) => Uint8Array {
  let value = 1n;
  return (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, value++);
    return bytes;
  };
}

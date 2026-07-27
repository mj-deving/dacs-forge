import { afterEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  acquireAuthorityServiceLease,
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  readAuthorityCapabilityOutput,
  type AuthorityFileStage,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";

const NOW = 1_800_000_000_000;
const ADMIN = "key:administrator";
const RECOVERY = "key:recovery";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("administrator bootstrap", () => {
  test("runs two-step bootstrap through the installed dacs entrypoint", async () => {
    const fixture = await setup();
    const prepareInput = join(fixture.root, "prepare.json");
    const completionInput = join(fixture.root, "complete.json");
    const adapterPath = join(fixture.root, "authority-adapter.ts");
    await writeFile(prepareInput, JSON.stringify({
      administratorKey: ADMIN,
      administratorOperations: ["administrator:rotate", "capability:revoke", "clone:rotate"],
      administratorPrincipal: "did:demos:administrator",
      audience: "https://service.example",
      expiresAtMs: NOW + 60_000,
      instanceId: "instance-1",
      outputPath: fixture.outputPath,
      recoveryKey: RECOVERY,
      requestedAtMs: NOW,
    }));
    await writeFile(adapterPath, adapterModule());
    const executable = resolve(import.meta.dir, "../../src/cli/dacs.ts");
    const prepared = Bun.spawnSync([
      executable, "authority", "bootstrap", "prepare", "--input", prepareInput,
      "--database", fixture.databasePath,
    ]);
    expect(prepared.exitCode).toBe(0);
    const document = JSON.parse(prepared.stdout.toString()) as {
      request: ReturnType<typeof prepareAuthorityBootstrap>;
      signingBytes: string;
    };
    expect(document.signingBytes).toBe(authorityBootstrapSigningBytes(document.request));
    await writeFile(completionInput, JSON.stringify({
      request: document.request,
      administratorProof: sign(ADMIN, document.signingBytes),
      recoveryProof: sign(RECOVERY, document.signingBytes),
    }));
    const completed = Bun.spawnSync([
      executable, "authority", "bootstrap", "complete",
      "--input", completionInput,
      "--database", fixture.databasePath,
      "--adapter", adapterPath,
    ]);
    expect(completed.exitCode).toBe(0);
    expect(JSON.parse(completed.stdout.toString())).toMatchObject({
      schema: "dacs-authority-operation/v1",
      result: { instanceId: "instance-1", generation: 1, outputPath: fixture.outputPath },
    });
    expect(readAuthorityCapabilityOutput(fixture.outputPath)).toMatch(/^[0-9a-f]{64}$/);
  });

  test.each([
    "after-create",
    "after-write",
    "after-file-fsync",
    "after-directory-fsync",
    "before-database-commit",
  ] as const)("does not initialize when %s fails", async (stage) => {
    const fixture = await setup();
    const completion = signedBootstrap(fixture.databasePath, fixture.outputPath);
    expect(() => completeAuthorityBootstrap(completion, options(fixture.databasePath, stage)))
      .toThrow(`fault:${stage}`);
    const database = openDatabase(fixture.databasePath);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_instances",
    ).get()?.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capabilities",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("keeps the durable output when failure arrives after database commit", async () => {
    const fixture = await setup();
    const completion = signedBootstrap(fixture.databasePath, fixture.outputPath);
    expect(() => completeAuthorityBootstrap(
      completion,
      options(fixture.databasePath, "after-database-commit"),
    )).toThrow("fault:after-database-commit");
    expect(readAuthorityCapabilityOutput(fixture.outputPath)).toMatch(/^[0-9a-f]{64}$/);
    expect((await stat(fixture.outputPath)).mode & 0o777).toBe(0o600);
    const database = openDatabase(fixture.databasePath);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_instances",
    ).get()?.count).toBe(1n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capabilities WHERE state = 'active'",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("uses one exclusive lease for online startup and offline mutation", async () => {
    const fixture = await setup();
    const completion = signedBootstrap(fixture.databasePath, fixture.outputPath);
    let observed = false;
    completeAuthorityBootstrap(completion, {
      ...options(fixture.databasePath),
      fault: (stage) => {
        if (stage !== "after-create") return;
        observed = true;
        expect(() => acquireAuthorityServiceLease(fixture.databasePath))
          .toThrow(/service is running/);
      },
    });
    expect(observed).toBe(true);
  });

  test.each([
    "after-create",
    "after-write",
    "after-file-fsync",
    "after-directory-fsync",
    "before-database-commit",
  ] as const)("reconciles interrupted output after real process crash at %s", async (stage) => {
    const fixture = await setup();
    const completion = signedBootstrap(fixture.databasePath, fixture.outputPath);
    const inputPath = join(fixture.root, "crash-input.json");
    await writeFile(inputPath, JSON.stringify(completion));
    const crashed = Bun.spawnSync([
      process.execPath,
      resolve(import.meta.dir, "../workers/authority-offline-crash-worker.ts"),
      inputPath,
      fixture.databasePath,
      stage,
      String(NOW + 1_000),
    ]);
    expect(crashed.exitCode).not.toBe(0);
    if (stage === "after-directory-fsync" || stage === "before-database-commit") {
      expect(readAuthorityCapabilityOutput(fixture.outputPath)).toMatch(/^[0-9a-f]{64}$/);
    } else {
      expect(() => readAuthorityCapabilityOutput(fixture.outputPath)).toThrow();
    }
    const before = openDatabase(fixture.databasePath);
    expect(before.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_instances",
    ).get()?.count).toBe(0n);
    before.close();

    completeAuthorityBootstrap(completion, {
      ...options(fixture.databasePath),
      now: () => NOW + 1_000,
    });
    const after = openDatabase(fixture.databasePath);
    expect(after.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_instances",
    ).get()?.count).toBe(1n);
    after.close();
  });

  test("rejects missing, wrong, reused-output, and relative output authority", async () => {
    const fixture = await setup();
    const completion = signedBootstrap(fixture.databasePath, fixture.outputPath);
    expect(() => completeAuthorityBootstrap(completion, options(join(fixture.root, "other.sqlite"))))
      .toThrow(/different store/);
    expect(() => completeAuthorityBootstrap({ ...completion, recoveryProof: "wrong" }, options(
      fixture.databasePath,
    ))).toThrow(/requires administrator and recovery proof/);
    completeAuthorityBootstrap(completion, options(fixture.databasePath));
    expect(() => completeAuthorityBootstrap(completion, options(fixture.databasePath)))
      .toThrow(/already initialized|EEXIST/);
    expect(() => prepareAuthorityBootstrap({
      ...completion.request,
      outputPath: "relative.cap",
    })).toThrow(/absolute/);
  });

  test("rejects an offline administrator scope above the aggregate byte bound", async () => {
    const fixture = await setup();
    const request = prepareAuthorityBootstrap({
      administratorKey: ADMIN,
      administratorOperations: [
        "a".repeat(4_096),
        "b".repeat(4_096),
        "c".repeat(4_096),
      ],
      administratorPrincipal: "did:demos:administrator",
      audience: "https://service.example",
      expiresAtMs: NOW + 60_000,
      instanceId: "instance-1",
      outputPath: fixture.outputPath,
      recoveryKey: RECOVERY,
      requestedAtMs: NOW,
      storeBinding: authorityStoreBinding(fixture.databasePath),
    }, entropy());
    const bytes = authorityBootstrapSigningBytes(request);
    expect(() => completeAuthorityBootstrap({
      request,
      administratorProof: sign(ADMIN, bytes),
      recoveryProof: sign(RECOVERY, bytes),
    }, options(fixture.databasePath))).toThrow(/aggregate byte bound/);
    expect(() => readAuthorityCapabilityOutput(fixture.outputPath)).toThrow();
    const database = openDatabase(fixture.databasePath);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_instances",
    ).get()?.count).toBe(0n);
    database.close();
  });
});

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dacs-admin-bootstrap-"));
  roots.push(root);
  return { root, databasePath: join(root, "state.sqlite"), outputPath: join(root, "admin.cap") };
}

function signedBootstrap(databasePath: string, outputPath: string) {
  const request = prepareAuthorityBootstrap({
    administratorKey: ADMIN,
    administratorOperations: ["administrator:rotate", "capability:revoke", "clone:rotate"],
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
  return {
    request,
    administratorProof: sign(ADMIN, bytes),
    recoveryProof: sign(RECOVERY, bytes),
  };
}

function options(databasePath: string, failure?: AuthorityFileStage) {
  return {
    databasePath,
    keyCurrentness: currentness(),
    now: () => NOW,
    proofVerifier: { verify: ({ key, proof, signedBytes }: {
      key: string; proof: string; signedBytes: string;
    }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(),
    ...(failure === undefined ? {} : { fault: (stage: AuthorityFileStage) => {
      if (stage === failure) throw new Error(`fault:${stage}`);
    } }),
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

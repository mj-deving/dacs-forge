import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  atomicExactLogicalSnapshotHash,
  atomicLogicalSnapshotHash,
} from "../fixtures/atomic-logical-snapshot.ts";
import {
  ATOMIC_MIGRATION_SCENARIOS,
  type AtomicMigrationScenario,
} from "../fixtures/atomic-migration-scenarios.ts";
import {
  killLinuxProcessTree,
  spawnInLinuxPidNamespace,
} from "../fixtures/linux-process-tree.ts";

const ROOT = join(import.meta.dir, "../..");
const WORKER = join(ROOT, "test/workers/atomic-migration-worker.ts");
const RAW_SNAPSHOT = join(ROOT, "test/workers/atomic-write-raw-snapshot.ts");
const SETUP_WORKER = join(ROOT, "test/workers/atomic-migration-setup.ts");
const VERIFIER = join(ROOT, "test/workers/atomic-write-verifier.ts");
const roots: string[] = [];

type MigrationPhase = "before-run" | "after-run" | "post-commit";

interface MigrationEvent {
  readonly api: string;
  readonly callSiteLine?: number;
  readonly inTransaction: boolean;
  readonly index: number;
  readonly kind: "migration-boundary" | "migration-observed";
  readonly phase: MigrationPhase | "after" | "before" | "post-commit";
  readonly sql: string;
  readonly sqlHash: string;
  readonly transactionMode: "autocommit" | "default" | "deferred" | "exclusive" | "immediate";
}

interface Verification {
  readonly kind: "atomic-write-verification";
  readonly preOpen: {
    readonly exactSnapshotHash: string;
    readonly exactTableHashes: Readonly<Record<string, string>>;
    readonly snapshotHash: string;
    readonly tableHashes: Readonly<Record<string, string>>;
    readonly schemaContractHash: string;
    readonly schemaHash: string;
    readonly schemaVersion: number;
    readonly tableCount: number;
  };
  readonly schemaHash: string;
  readonly snapshotHash: string;
  readonly tableHashes: Readonly<Record<string, string>>;
}

interface RawSnapshot {
  readonly exactSnapshotHash: string;
  readonly exactTableHashes: Readonly<Record<string, string>>;
  readonly schemaContractHash: string;
  readonly schemaHash: string;
  readonly snapshotHash: string;
  readonly tableHashes: Readonly<Record<string, string>>;
}

interface MigrationControl {
  readonly commitJournalMode: string;
  readonly commitSchemaHash: string;
  readonly finalJournalMode: string;
  readonly finalSchemaHash: string;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("exclusive schema migration interruption", () => {
  test("logical equality binds SQLite-owned persistent table contents", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-migration-sqlite-owned-"));
    roots.push(root);
    const database = new Database(join(root, "state.sqlite"), { strict: true });
    database.run("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)");
    database.run("CREATE INDEX sample_value ON sample(value)");
    database.run("INSERT INTO sample (value) VALUES ('alpha')");
    database.run("ANALYZE sample");
    const withStatistics = atomicLogicalSnapshotHash(database);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM sqlite_stat1").get()?.count)
      .toBeGreaterThan(0n);
    database.run("DELETE FROM sqlite_stat1");
    expect(atomicLogicalSnapshotHash(database)).not.toBe(withStatistics);
    database.close();
  });

  test("exact checkpoints preserve claim tokens while cross-run controls normalize them", () => {
    const database = new Database(":memory:", { strict: true });
    database.run("CREATE TABLE token_probe (claim_token TEXT NOT NULL)");
    database.run("INSERT INTO token_probe VALUES (?)", ["test-token-placeholder"]);
    const normalized = atomicLogicalSnapshotHash(database);
    const exact = atomicExactLogicalSnapshotHash(database);
    database.run("DELETE FROM token_probe");
    database.run("INSERT INTO token_probe VALUES (?)", ["test-auth-token"]);
    expect(atomicLogicalSnapshotHash(database)).toBe(normalized);
    expect(atomicExactLogicalSnapshotHash(database)).not.toBe(exact);
    database.close();
  });

  test("exact checkpoints distinguish SQLite integer, text, and blob storage classes", () => {
    const database = new Database(":memory:", { safeIntegers: true, strict: true });
    database.run("CREATE TABLE storage_probe (value)");
    database.run("INSERT INTO storage_probe VALUES (?)", [7n]);
    const integerHash = atomicExactLogicalSnapshotHash(database);
    database.run("DELETE FROM storage_probe");
    database.run("INSERT INTO storage_probe VALUES (?)", ["7"]);
    const integerTextHash = atomicExactLogicalSnapshotHash(database);
    expect(integerTextHash).not.toBe(integerHash);

    database.run("DELETE FROM storage_probe");
    database.run("INSERT INTO storage_probe VALUES (x'6162')");
    const blobHash = atomicExactLogicalSnapshotHash(database);
    database.run("DELETE FROM storage_probe");
    database.run("INSERT INTO storage_probe VALUES (?)", ["6162"]);
    expect(atomicExactLogicalSnapshotHash(database)).not.toBe(blobHash);
    database.close();
  });

  test("reopens an already-current database without manufacturing a migration-order failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-migration-current-reopen-"));
    roots.push(root);
    const path = join(root, "state.sqlite");
    openDatabase(path).close();
    const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, path], {
      cwd: ROOT,
      detached: true,
      writableRoots: [root],
      env: { ...process.env, DACS_MIGRATION_MODE: "observe" },
      stdout: "pipe",
      stderr: "pipe",
    });
    const { exitCode, stdout, stderr } = await collectChild(child, "current migration reopen", 20_000);
    expect(exitCode, stderr).toBe(0);
    expect(stdout).toContain('"kind":"migration-complete","migrationCount":0');
    expect(stdout).not.toContain('"kind":"migration-observed"');
  });

  test("rejects a migration boundary that does not match the requested index and phase", async () => {
    const stream = (event: Partial<MigrationEvent>) => new ReadableStream<Uint8Array>({
      start(controller) {
        const payload = {
          kind: "migration-boundary",
          api: "run",
          callSiteLine: 100,
          inTransaction: true,
          index: 4,
          phase: "before-run",
          sql: "CREATE TABLE example (id INTEGER)",
          transactionMode: "exclusive",
          ...event,
        } as const;
        controller.enqueue(new TextEncoder().encode(`${JSON.stringify({
          ...payload,
          sqlHash: event.sqlHash ?? sqlHash(payload.sql),
        })}\n`));
        controller.close();
      },
    });
    const neverExits = new Promise<number>(() => {});
    await expect(waitForBoundary(stream({ index: 3 }), neverExits, 4, "before-run"))
      .rejects.toThrow("expected 4/before-run, received 3/before-run");
    await expect(waitForBoundary(stream({ phase: "after-run" }), neverExits, 4, "before-run"))
      .rejects.toThrow("expected 4/before-run, received 4/after-run");
    const expected = {
      api: "run",
      callSiteLine: 100,
      sql: "CREATE TABLE example (id INTEGER)",
      sqlHash: sqlHash("CREATE TABLE example (id INTEGER)"),
    };
    await expect(waitForBoundary(stream({ api: "exec" }), neverExits, 4, "before-run", expected))
      .rejects.toThrow("content mismatch");
    await expect(waitForBoundary(stream({ sql: "DROP TABLE example" }), neverExits, 4, "before-run", expected))
      .rejects.toThrow("content mismatch");
    await expect(waitForBoundary(stream({ callSiteLine: 101 }), neverExits, 4, "before-run", expected))
      .rejects.toThrow("content mismatch");
    const encoded = new TextEncoder().encode(`${JSON.stringify({
      kind: "migration-boundary",
      ...expected,
      sqlHash: sqlHash(expected.sql),
      inTransaction: true,
      index: 4,
      phase: "before-run",
      transactionMode: "exclusive",
    })}\n`);
    const fragmented = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoded.slice(0, 19));
        controller.enqueue(encoded.slice(19));
        controller.close();
      },
    });
    expect((await waitForBoundary(fragmented, neverExits, 4, "before-run", expected)).api).toBe("run");
  });

  test("observes every SQLite mutation API and rejects writes outside the exclusive owner", async () => {
    for (const api of [
      "run", "exec",
      "query.run", "query.get", "query.all", "query.values", "query.raw", "query.iterate", "query.iterator",
      "prepare.run", "prepare.get", "prepare.all", "prepare.values", "prepare.raw", "prepare.iterate", "prepare.iterator",
    ] as const) {
      const observed = await observeApiProbe(api);
      expect(observed).toHaveLength(3);
      expect(observed.map(({ phase }) => phase)).toEqual(["before", "after", "post-commit"]);
      expect(observed.map(({ api: observedApi, index }) => ({ api: observedApi, index }))).toEqual([
        { api, index: 0 }, { api, index: 0 }, { api, index: 0 },
      ]);
      expect(observed.slice(0, 2).every(({ inTransaction }) => inTransaction)).toBe(true);
      expect(observed[2]?.inTransaction).toBe(false);
    }
    const boundRun = await observeApiProbe(
      "run-bindings",
      "exclusive",
      "INSERT INTO migration_api_probe (id) VALUES (?)",
    );
    expect(boundRun.map(({ phase }) => phase)).toEqual(["before", "after", "post-commit"]);
    const boundPrepare = await observeApiProbe("prepare-bindings");
    expect(boundPrepare.map(({ phase }) => phase)).toEqual(["before", "after", "post-commit"]);
    for (const phase of ["before-run", "after-run", "post-commit"] as const) {
      expect(await interruptPrepareBindingProbe(phase), phase).toBe(phase === "post-commit" ? 7 : null);
    }
    for (const api of [
      "query.iterate-close", "query.iterator-close",
      "prepare.iterate-close", "prepare.iterator-close",
    ] as const) {
      const observed = await observeApiProbe(api);
      expect(observed.map(({ phase }) => phase)).toEqual(["before", "after", "post-commit"]);
    }
    expect(await observeApiProbe("query.iterate-unconsumed")).toHaveLength(0);
    expect(await observeApiProbe("query.iterator-unconsumed")).toHaveLength(0);
    for (const transactionMode of ["autocommit", "default", "deferred", "immediate"] as const) {
      expect(await observeApiProbe("query.run", transactionMode)).toHaveLength(0);
    }
    for (const sql of [
      "WITH source AS (SELECT 1) INSERT INTO migration_api_probe SELECT * FROM source RETURNING id",
      "ANALYZE migration_api_probe",
      "PRAGMA application_id = 1",
      "PRAGMA main.optimize",
      "PRAGMA main.incremental_vacuum(1)",
    ]) {
      expect(await observeApiProbe("query.run", "immediate", sql)).toHaveLength(0);
    }
    for (const sql of [
      "SAVEPOINT nested",
      "ROLLBACK TO nested",
      "ROLLBACK TRANSACTION TO SAVEPOINT nested",
      "RELEASE SAVEPOINT nested",
      "BEGIN IMMEDIATE TRANSACTION",
      "COMMIT TRANSACTION",
      "END TRANSACTION",
      "SELECT 1; /* hidden */ SAVEPOINT nested",
      "SELECT '('; SAVEPOINT hidden",
      "SELECT '; SAVEPOINT quoted'; SAVEPOINT hidden",
    ]) {
      await expect(observeApiProbe("run", "exclusive", sql))
        .rejects.toThrow("SQL transaction control is forbidden");
    }
    await expect(observeApiProbe(
      "exec",
      "exclusive",
      "INSERT INTO migration_api_probe DEFAULT VALUES; INSERT INTO migration_api_probe DEFAULT VALUES",
    )).rejects.toThrow("exec SQL contains 2 mutations");
    await expect(observeApiProbe(
      "run",
      "exclusive",
      "INSERT INTO migration_api_probe DEFAULT VALUES; INSERT INTO migration_api_probe DEFAULT VALUES",
    )).rejects.toThrow("run SQL contains 2 mutations");
    for (const sql of ["PRAGMA journal_mode = WAL", "PRAGMA synchronous = FULL"]) {
      await expect(observeApiProbe("run", "exclusive", sql))
        .rejects.toThrow("before the exclusive migration commit");
      await expect(observeApiProbe("run", "exclusive", undefined, sql))
        .rejects.toThrow("before the exclusive migration commit");
    }
    for (const mode of ["control", "interrupt"] as const) {
      const result = await runRolledBackMigrationProbe(mode);
      expect(result.exitCode, result.stderr).toBe(0);
      expect(result.stdout).toContain('"kind":"migration-complete"');
      expect(result.stdout).not.toContain('"kind":"migration-boundary"');
      expect(result.stdout).not.toContain('"kind":"migration-control-commit"');
    }
    const rolledBackCompletion = await runRolledBackMigrationCompletionProbe();
    expect(rolledBackCompletion.exitCode).not.toBe(0);
    expect(rolledBackCompletion.stderr).toContain("before the exclusive migration commit");
    expect(rolledBackCompletion.stdout).not.toContain('"phase":"post-commit"');
  }, 15_000);

  test.each([...ATOMIC_MIGRATION_SCENARIOS])(
    "$id migration mutations are restartable before/after DDL and complete after commit",
    async (scenario) => {
    const observed = await observeMigration(scenario);
    const control = await runMigrationControl(scenario);
    const setupCheckpoint = await migrationSetupCheckpoint(scenario);
    expect(observed.length).toBeGreaterThan(0);
    expect(observed.every(({ inTransaction, transactionMode }) => inTransaction && transactionMode === "exclusive")).toBe(true);
    expect(observed.map(({ index }) => index)).toEqual(observed.map((_, index) => index));
    expect(observed.at(-1)?.sql).toBe("PRAGMA user_version = 20");
    expect(control.commitJournalMode).toBe(scenario.id === "fresh" ? "delete" : "wal");
    expect(control.finalJournalMode).toBe("wal");

    for (const observation of observed) {
      const before = await interruptAndVerify(scenario, observation, "before-run");
      const after = await interruptAndVerify(scenario, observation, "after-run");
      const committed = await interruptAndVerify(scenario, observation, "post-commit");

      expect(before.event.inTransaction).toBe(true);
      expect(after.event.inTransaction).toBe(true);
      expect(committed.event.inTransaction).toBe(false);
      expect(before.event.transactionMode).toBe("exclusive");
      expect(after.event.transactionMode).toBe("exclusive");
      expect(committed.event.transactionMode).toBe("exclusive");
      expect(before.verification.preOpen.schemaVersion).toBe(scenario.expectedSchemaVersion);
      expect(after.verification.preOpen.schemaVersion).toBe(scenario.expectedSchemaVersion);
      expect(before.verification.preOpen.tableCount).toBe(
        scenario.id === "fresh" ? 0 : after.verification.preOpen.tableCount,
      );
      expect(before.verification.preOpen.schemaContractHash).toBe(setupCheckpoint.schemaContractHash);
      expect(after.verification.preOpen.schemaContractHash).toBe(setupCheckpoint.schemaContractHash);
      expect(before.verification.preOpen.schemaHash).toBe(setupCheckpoint.schemaHash);
      expect(after.verification.preOpen.schemaHash).toBe(setupCheckpoint.schemaHash);
      expect(before.verification.preOpen.snapshotHash).toBe(setupCheckpoint.snapshotHash);
      expect(after.verification.preOpen.snapshotHash).toBe(setupCheckpoint.snapshotHash);
      expect(before.verification.preOpen.tableHashes).toEqual(setupCheckpoint.tableHashes);
      expect(after.verification.preOpen.tableHashes).toEqual(setupCheckpoint.tableHashes);
      expect(before.verification.preOpen.exactSnapshotHash).toBe(setupCheckpoint.exactSnapshotHash);
      expect(after.verification.preOpen.exactSnapshotHash).toBe(setupCheckpoint.exactSnapshotHash);
      expect(before.verification.preOpen.exactTableHashes).toEqual(setupCheckpoint.exactTableHashes);
      expect(after.verification.preOpen.exactTableHashes).toEqual(setupCheckpoint.exactTableHashes);
      expect(committed.verification.preOpen.schemaVersion).toBe(20);
      expect(committed.verification.preOpen.tableCount).toBeGreaterThan(0);
      expect(before.verification.preOpen.schemaContractHash).toBe(before.preKill.schemaContractHash);
      expect(after.verification.preOpen.schemaContractHash).toBe(after.preKill.schemaContractHash);
      expect(committed.verification.preOpen.schemaContractHash).toBe(committed.preKill.schemaContractHash);
      expect(before.verification.preOpen.schemaHash).toBe(before.preKill.schemaHash);
      expect(after.verification.preOpen.schemaHash).toBe(after.preKill.schemaHash);
      expect(committed.verification.preOpen.schemaHash).toBe(committed.preKill.schemaHash);
      expect(before.verification.preOpen.snapshotHash).toBe(before.preKill.snapshotHash);
      expect(after.verification.preOpen.snapshotHash).toBe(after.preKill.snapshotHash);
      expect(committed.verification.preOpen.snapshotHash).toBe(committed.preKill.snapshotHash);
      expect(before.verification.preOpen.tableHashes).toEqual(before.preKill.tableHashes);
      expect(after.verification.preOpen.tableHashes).toEqual(after.preKill.tableHashes);
      expect(committed.verification.preOpen.tableHashes).toEqual(committed.preKill.tableHashes);
      expect(before.verification.preOpen.exactSnapshotHash).toBe(before.preKill.exactSnapshotHash);
      expect(after.verification.preOpen.exactSnapshotHash).toBe(after.preKill.exactSnapshotHash);
      expect(committed.verification.preOpen.exactSnapshotHash).toBe(committed.preKill.exactSnapshotHash);
      expect(before.verification.preOpen.exactTableHashes).toEqual(before.preKill.exactTableHashes);
      expect(after.verification.preOpen.exactTableHashes).toEqual(after.preKill.exactTableHashes);
      expect(committed.verification.preOpen.exactTableHashes).toEqual(committed.preKill.exactTableHashes);
      expect(after.verification.preOpen.schemaHash).toBe(before.verification.preOpen.schemaHash);
      expect(committed.verification.preOpen.schemaHash).toBe(control.commitSchemaHash);
      expect(committed.verification.schemaHash).toBe(control.finalSchemaHash);
      expect(after.verification.snapshotHash).toBe(before.verification.snapshotHash);
      expect(committed.verification.snapshotHash).toBe(before.verification.snapshotHash);
    }
  }, 180_000);
});

async function observeApiProbe(
  api: string,
  transactionMode: "autocommit" | "default" | "deferred" | "exclusive" | "immediate" = "exclusive",
  sql?: string,
  postSql?: string,
): Promise<MigrationEvent[]> {
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-api-${api}-`));
  roots.push(root);
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, join(root, "state.sqlite")], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      DACS_MIGRATION_MODE: "observe",
      DACS_MIGRATION_PROBE_API: api,
      DACS_MIGRATION_PROBE_TRANSACTION_MODE: transactionMode,
      ...(sql === undefined ? {} : { DACS_MIGRATION_PROBE_SQL: sql }),
      ...(postSql === undefined ? {} : { DACS_MIGRATION_PROBE_POST_SQL: postSql }),
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(child, `migration API observer ${api}/${transactionMode}`, 20_000);
  if (transactionMode !== "exclusive") {
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain(`in ${transactionMode}, not migrate().exclusive()`);
    return [];
  }
  if (exitCode !== 0) throw new Error(`Migration API observer failed (${exitCode}): ${stderr}`);
  return stdout.trim().split("\n")
    .map((line) => JSON.parse(line) as MigrationEvent | { readonly kind: "migration-complete" })
    .filter((event): event is MigrationEvent => event.kind === "migration-observed");
}

async function interruptPrepareBindingProbe(phase: MigrationPhase): Promise<number | null> {
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-prepare-bindings-${phase}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      DACS_MIGRATION_MODE: "interrupt",
      DACS_MIGRATION_PHASE: phase,
      DACS_MIGRATION_TARGET_INDEX: "0",
      DACS_MIGRATION_PROBE_API: "prepare-bindings",
      DACS_MIGRATION_PROBE_TRANSACTION_MODE: "exclusive",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const stderrPromise = boundedStreamText(child.stderr);
  let boundaryError: unknown;
  try {
    const event = await waitForBoundary(child.stdout, child.exited, 0, phase, {
      api: "prepare.run",
      sql: "INSERT INTO migration_api_probe (id) VALUES (?) RETURNING id",
      sqlHash: sqlHash("INSERT INTO migration_api_probe (id) VALUES (?) RETURNING id"),
    });
    expect(event.api).toBe("prepare.run");
    expect(event.inTransaction).toBe(phase !== "post-commit");
  } catch (error) {
    boundaryError = error;
  } finally {
    killLinuxProcessTree(child);
  }
  const [exitCode, stderr] = await Promise.all([
    waitForExit(child, `migration prepare binding ${phase} after SIGKILL`, 5_000),
    stderrPromise,
  ]);
  if (boundaryError !== undefined) {
    const reason = boundaryError instanceof Error ? boundaryError.message : String(boundaryError);
    throw new Error(`${reason}\nchild stderr:\n${stderr}`);
  }
  if (exitCode === 0) throw new Error(`Migration prepare binding child exited before SIGKILL: ${stderr}`);
  const database = new Database(path, { readonly: true, strict: true });
  try {
    const exists = database.query<{ count: bigint }, []>(
      "SELECT COUNT(*) AS count FROM sqlite_schema WHERE type = 'table' AND name = 'migration_api_probe'",
    ).get()?.count ?? 0n;
    if (Number(exists) === 0) return null;
    return database.query<{ id: number }, []>("SELECT id FROM migration_api_probe").get()?.id ?? null;
  } finally {
    database.close();
  }
}

async function runRolledBackMigrationProbe(mode: "control" | "interrupt"): Promise<{
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}> {
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-rollback-${mode}-`));
  roots.push(root);
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, join(root, "state.sqlite")], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      DACS_MIGRATION_MODE: mode,
      DACS_MIGRATION_PHASE: "post-commit",
      DACS_MIGRATION_TARGET_INDEX: "0",
      DACS_MIGRATION_PROBE_API: "run",
      DACS_MIGRATION_PROBE_ROLLBACK: "1",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return collectChild(child, `rolled-back migration ${mode}`, 5_000);
}

async function runRolledBackMigrationCompletionProbe(): Promise<{
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "dacs-migration-rollback-completion-"));
  roots.push(root);
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, join(root, "state.sqlite")], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      DACS_MIGRATION_MODE: "observe",
      DACS_MIGRATION_PROBE_API: "run",
      DACS_MIGRATION_PROBE_ROLLBACK: "1",
      DACS_MIGRATION_PROBE_SQL: "PRAGMA user_version = 20",
      DACS_MIGRATION_PROBE_POST_SQL: "PRAGMA journal_mode = WAL",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return collectChild(child, "rolled-back migration completion", 5_000);
}

async function runMigrationControl(scenario: AtomicMigrationScenario): Promise<MigrationControl> {
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-control-${scenario.id}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  await setupMigrationScenario(path, scenario);
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: { ...process.env, DACS_MIGRATION_MODE: "control" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(child, "fresh migration control", 20_000);
  if (exitCode !== 0) throw new Error(`Migration control failed (${exitCode}): ${stderr}`);
  const events = stdout.trim().split("\n").map((line) => JSON.parse(line) as {
    readonly journalMode?: string;
    readonly kind: string;
    readonly schemaHash?: string;
  });
  const commitSchemaHash = events.find(({ kind }) => kind === "migration-control-commit")?.schemaHash;
  const finalSchemaHash = events.find(({ kind }) => kind === "migration-control-final")?.schemaHash;
  const commitJournalMode = events.find(({ kind }) => kind === "migration-control-commit")?.journalMode;
  const finalJournalMode = events.find(({ kind }) => kind === "migration-control-final")?.journalMode;
  if (commitSchemaHash === undefined || finalSchemaHash === undefined
    || commitJournalMode === undefined || finalJournalMode === undefined) {
    throw new Error(`Migration control omitted schema checkpoints: ${stdout}`);
  }
  return { commitJournalMode, commitSchemaHash, finalJournalMode, finalSchemaHash };
}

async function observeMigration(scenario: AtomicMigrationScenario): Promise<MigrationEvent[]> {
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-observe-${scenario.id}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  await setupMigrationScenario(path, scenario);
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: { ...process.env, DACS_MIGRATION_MODE: "observe" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(child, "fresh migration observer", 20_000);
  if (exitCode !== 0) throw new Error(`Migration observer failed (${exitCode}): ${stderr}`);
  return stdout.trim().split("\n")
    .map((line) => JSON.parse(line) as MigrationEvent | { readonly kind: "migration-complete" })
    .filter((event): event is MigrationEvent => event.kind === "migration-observed" && event.phase === "before");
}

async function interruptAndVerify(
  scenario: AtomicMigrationScenario,
  expected: MigrationEvent,
  phase: MigrationPhase,
): Promise<{
  readonly event: MigrationEvent;
  readonly preKill: RawSnapshot;
  readonly verification: Verification;
}> {
  const { index } = expected;
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-${scenario.id}-${index}-${phase}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  await setupMigrationScenario(path, scenario);
  const child = spawnInLinuxPidNamespace([process.execPath, "run", WORKER, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      DACS_MIGRATION_MODE: "interrupt",
      DACS_MIGRATION_PHASE: phase,
      DACS_MIGRATION_TARGET_INDEX: String(index),
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const stderrPromise = boundedStreamText(child.stderr);
  let event!: MigrationEvent;
  let exitCode = 0;
  let stderr = "";
  let preKill!: RawSnapshot;
  let boundaryError: unknown;
  try {
    event = await waitForBoundary(child.stdout, child.exited, index, phase, expected);
    preKill = await readRawSnapshot(
      await copyPausedMigrationDatabase(path, index, phase),
      `${index}/${phase}`,
    );
  } catch (error) {
    boundaryError = error;
  } finally {
    killLinuxProcessTree(child);
    [exitCode, stderr] = await Promise.all([
      waitForExit(child, `migration child ${index}/${phase} after SIGKILL`, 5_000),
      stderrPromise,
    ]);
  }
  if (boundaryError !== undefined) {
    const reason = boundaryError instanceof Error ? boundaryError.message : String(boundaryError);
    throw new Error(`${reason}\nchild stderr:\n${stderr}`);
  }
  if (exitCode === 0) throw new Error(`Migration child exited successfully instead of being killed: ${stderr}`);
  return { event, preKill, verification: await verifyInFreshProcess(path) };
}

async function setupMigrationScenario(path: string, scenario: AtomicMigrationScenario): Promise<void> {
  if (scenario.id === "fresh") return;
  const child = spawnInLinuxPidNamespace([process.execPath, "run", SETUP_WORKER, path, scenario.id], {
    cwd: ROOT,
    detached: true,
    writableRoots: [dirname(path)],
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(
    child,
    `migration setup ${scenario.id}`,
    20_000,
  );
  if (exitCode !== 0) throw new Error(`Migration setup ${scenario.id} failed (${exitCode}): ${stderr}\n${stdout}`);
}

async function migrationSetupCheckpoint(scenario: AtomicMigrationScenario): Promise<RawSnapshot> {
  const root = await mkdtemp(join(tmpdir(), `dacs-migration-setup-checkpoint-${scenario.id}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  if (scenario.id === "fresh") {
    const database = new Database(path, { safeIntegers: true, strict: true });
    database.close();
  } else await setupMigrationScenario(path, scenario);
  return readRawSnapshot(path, `setup/${scenario.id}`);
}

async function copyPausedMigrationDatabase(
  path: string,
  index: number,
  phase: MigrationPhase,
): Promise<string> {
  const snapshotRoot = await mkdtemp(join(tmpdir(), `dacs-migration-pre-kill-${index}-${phase}-`));
  roots.push(snapshotRoot);
  const snapshotPath = join(snapshotRoot, basename(path));
  await copyFile(path, snapshotPath);
  for (const suffix of ["-journal", "-wal"] as const) {
    try {
      await copyFile(`${path}${suffix}`, `${snapshotPath}${suffix}`);
    } catch (error) {
      if (typeof error !== "object" || error === null || !("code" in error) || error.code !== "ENOENT") throw error;
    }
  }
  return snapshotPath;
}

async function readRawSnapshot(path: string, context: string): Promise<RawSnapshot> {
  const child = spawnInLinuxPidNamespace([process.execPath, "run", RAW_SNAPSHOT, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [dirname(path)],
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(
    child,
    `migration raw snapshot ${context}`,
    20_000,
  );
  if (exitCode !== 0) throw new Error(`Migration raw snapshot failed (${exitCode}): ${stderr}`);
  const line = stdout.split("\n").find((entry) => entry.startsWith('{"kind":"atomic-write-raw-snapshot"'));
  if (line === undefined) throw new Error(`Migration raw snapshot emitted no result: ${stdout}`);
  return JSON.parse(line) as RawSnapshot;
}

async function waitForBoundary(
  stdout: ReadableStream<Uint8Array>,
  exited: Promise<number>,
  index: number,
  phase: MigrationPhase,
  expected?: Pick<MigrationEvent, "api" | "callSiteLine" | "sql" | "sqlHash">,
): Promise<MigrationEvent> {
  const reader = stdout.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = setTimeout(() => reader.cancel(`Timeout waiting for migration ${index}/${phase}`), 20_000);
  try {
    while (true) {
      const next = await Promise.race([
        reader.read(),
        exited.then((code) => ({ done: true as const, value: new Uint8Array(), code })),
      ]);
      if ("code" in next) throw new Error(`Migration child exited ${next.code} before ${index}/${phase}`);
      buffered += decoder.decode(next.value, { stream: !next.done });
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith('{"kind":"migration-boundary"')) continue;
        const event = JSON.parse(line) as MigrationEvent;
        if (event.index !== index || event.phase !== phase) {
          throw new Error(`Migration boundary mismatch: expected ${index}/${phase}, received ${event.index}/${event.phase}`);
        }
        if (expected !== undefined && (event.api !== expected.api
          || event.sqlHash !== expected.sqlHash
          || (expected.callSiteLine !== undefined && event.callSiteLine !== expected.callSiteLine))) {
          throw new Error(`Migration boundary content mismatch: expected ${expected.api}/${normalizeSql(expected.sql)}, received ${event.api}/${normalizeSql(event.sql)}`);
        }
        return event;
      }
      if (next.done) throw new Error(`Migration child closed before ${index}/${phase}: ${buffered}`);
    }
  } finally {
    clearTimeout(deadline);
    reader.releaseLock();
  }
}

function normalizeSql(sql: string): string {
  return sql.replace(/\s+/g, " ").trim();
}

function sqlHash(sql: string): string {
  return createHash("sha256").update(normalizeSql(sql)).digest("hex");
}

async function verifyInFreshProcess(path: string): Promise<Verification> {
  const child = spawnInLinuxPidNamespace([process.execPath, "run", VERIFIER, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [dirname(path)],
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(child, "migration verifier", 20_000);
  if (exitCode !== 0) throw new Error(`Migration verifier failed (${exitCode}): ${stderr}\n${stdout}`);
  const line = stdout.trim().split("\n").findLast((entry) => entry.startsWith('{"kind":"atomic-write-verification"'));
  if (line === undefined) throw new Error(`Migration verifier emitted no result: ${stdout}`);
  return JSON.parse(line) as Verification;
}

interface CapturedChild {
  readonly exited: Promise<number>;
  readonly pid: number;
  readonly stderr: ReadableStream<Uint8Array>;
  readonly stdout: ReadableStream<Uint8Array>;
  kill(signal?: NodeJS.Signals | number): void;
}

async function boundedStreamText(stream: ReadableStream<Uint8Array>, timeoutMs = 25_000): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let output = "";
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Child stream did not close within ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    while (true) {
      const next = await Promise.race([reader.read(), deadline]);
      if (next.done) return output + decoder.decode(new Uint8Array());
      output += decoder.decode(next.value, { stream: true });
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    reader.releaseLock();
  }
}

async function collectChild(
  child: CapturedChild,
  label: string,
  timeoutMs: number,
): Promise<{ readonly exitCode: number; readonly stderr: string; readonly stdout: string }> {
  const stdoutReader = child.stdout.getReader();
  const stderrReader = child.stderr.getReader();
  const drain = async (reader: { read(): Promise<{ readonly done: boolean; readonly value?: Uint8Array }> }) => {
    const decoder = new TextDecoder();
    let output = "";
    while (true) {
      const next = await reader.read();
      if (next.done) return output + decoder.decode(new Uint8Array());
      output += decoder.decode(next.value!, { stream: true });
    }
  };
  const completion = Promise.all([
    child.exited,
    drain(stdoutReader as unknown as Parameters<typeof drain>[0]),
    drain(stderrReader as unknown as Parameters<typeof drain>[0]),
  ] as const);
  const absoluteDeadline = performance.now() + timeoutMs;
  const cleanupReserveMs = Math.min(250, Math.max(10, Math.floor(timeoutMs * 0.9)));
  const executionBudgetMs = Math.max(0, timeoutMs - cleanupReserveMs);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = Symbol("timed-out");
  const completed = await Promise.race([
    completion,
    new Promise<typeof timedOut>((resolve) => {
      timer = setTimeout(() => resolve(timedOut), executionBudgetMs);
    }),
  ]);
  if (timer !== undefined) clearTimeout(timer);
  if (completed === timedOut) {
    killLinuxProcessTree(child);
    await Promise.allSettled([stdoutReader.cancel(), stderrReader.cancel()]);
    void completion.catch(() => {});
    const remainingMs = Math.max(1, Math.floor(absoluteDeadline - performance.now()));
    await waitForExit(child, `${label} after SIGKILL`, remainingMs);
    throw new Error(`${label} timed out after ${timeoutMs}ms`);
  }
  const [exitCode, stdout, stderr] = completed;
  return { exitCode, stdout, stderr };
}

async function waitForExit(child: CapturedChild, label: string, timeoutMs: number): Promise<number> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      child.exited,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(
          new Error(`${label} did not terminate within ${timeoutMs}ms; leaked pid=${child.pid}`),
        ), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

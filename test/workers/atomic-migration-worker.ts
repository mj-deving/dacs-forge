import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { atomicSchemaSnapshotHash } from "../fixtures/atomic-logical-snapshot.ts";
import {
  classifySqliteMutations,
  containsSqliteTransactionControl,
} from "../fixtures/sqlite-mutation-classifier.ts";
import { setupMigrationScenario } from "./atomic-migration-setup.ts";

const path = process.argv[2];
const mode = process.env["DACS_MIGRATION_MODE"];
const phase = process.env["DACS_MIGRATION_PHASE"];
const targetIndex = Number(process.env["DACS_MIGRATION_TARGET_INDEX"] ?? "-1");
const probeApi = process.env["DACS_MIGRATION_PROBE_API"];
const probeSql = process.env["DACS_MIGRATION_PROBE_SQL"];
const probePostSql = process.env["DACS_MIGRATION_PROBE_POST_SQL"];
const probeRollback = process.env["DACS_MIGRATION_PROBE_ROLLBACK"] === "1";
const probeTransactionMode = process.env["DACS_MIGRATION_PROBE_TRANSACTION_MODE"];
const setupScenario = process.env["DACS_MIGRATION_SETUP_SCENARIO"];
if (path === undefined || !["control", "observe", "interrupt"].includes(mode ?? "")) {
  throw new Error("Migration worker requires a database path and mode");
}
if (mode === "interrupt" && (!["before-run", "after-run", "post-commit"].includes(phase ?? "")
  || !Number.isSafeInteger(targetIndex) || targetIndex < 0)) {
  throw new Error("Migration interruption requires a valid phase and target index");
}
if (setupScenario !== undefined) {
  if (!["v8-current", "v9-current", "v12-no-orchestrator", "v18-current", "v18-no-vet-records", "v19-current"]
    .includes(setupScenario)) throw new Error(`Unknown migration setup scenario: ${setupScenario}`);
  setupMigrationScenario(path, setupScenario as Parameters<typeof setupMigrationScenario>[1]);
}

type RunFunction = (this: Database, sql: string, ...bindings: unknown[]) => unknown;
type QueryFunction = (this: Database, sql: string) => unknown;
type PrepareFunction = (this: Database, sql: string, ...bindings: unknown[]) => unknown;
type StatementExecutionFunction = (...bindings: unknown[]) => unknown;
type StatementIteratorFunction = (...bindings: unknown[]) => IterableIterator<unknown>;
interface InstrumentedStatement {
  all: StatementExecutionFunction;
  get: StatementExecutionFunction;
  iterate: StatementIteratorFunction;
  raw: StatementExecutionFunction;
  run: StatementExecutionFunction;
  values: StatementExecutionFunction;
  finalize(): void;
  [Symbol.iterator]: () => IterableIterator<unknown>;
}
type TransactionFunction = (this: Database, callback: (...args: unknown[]) => unknown) => TransactionHandle;
interface TransactionHandle {
  (...args: unknown[]): unknown;
  readonly default: (...args: unknown[]) => unknown;
  readonly deferred: (...args: unknown[]) => unknown;
  readonly immediate: (...args: unknown[]) => unknown;
  readonly exclusive: (...args: unknown[]) => unknown;
}
interface TransactionContext {
  readonly mode: "default" | "deferred" | "immediate" | "exclusive";
  sawMigrationCompletion: boolean;
}
interface PendingCommit {
  readonly api: string;
  readonly index: number;
  readonly sql: string;
  readonly transactions: readonly TransactionContext[];
}

const originalRun = Database.prototype.run as unknown as RunFunction;
const originalExec = Database.prototype.exec as unknown as RunFunction;
const originalQuery = Database.prototype.query as unknown as QueryFunction;
const originalPrepare = Database.prototype.prepare as unknown as PrepareFunction;
const originalTransaction = Database.prototype.transaction as unknown as TransactionFunction;
const pendingCommit = new WeakMap<Database, PendingCommit>();
const transactionContexts = new WeakMap<Database, TransactionContext[]>();
const migrationCommitted = new WeakSet<Database>();
const instrumentedStatements = new WeakSet<object>();
const activeIterators = new WeakMap<object, { readonly complete: () => void }>();
let migrationIndex = 0;
const migrationCallSiteLines = new Map<number, number>();
let emitted = false;
let queryConstructionDepth = 0;
let schemaVersionReadDepth = 0;
let transactionConstructionDepth = 0;

Database.prototype.run = function (this: Database, sql: string, ...bindings: unknown[]) {
  assertNoSqlTransactionControl(sql);
  assertSingleMutationSql(sql, "run");
  assertConnectionSetupOrder(this, sql);
  const index = beforeMutation(this, sql, "run");
  const result = originalRun.call(this, sql, ...bindings);
  afterMutation(this, sql, index, "run");
  return result;
} as typeof Database.prototype.run;

Database.prototype.exec = function (this: Database, sql: string) {
  assertNoSqlTransactionControl(sql);
  assertSingleMutationSql(sql, "exec");
  assertConnectionSetupOrder(this, sql);
  const index = beforeMutation(this, sql, "exec");
  const result = originalExec.call(this, sql);
  afterMutation(this, sql, index, "exec");
  return result;
} as typeof Database.prototype.exec;

Database.prototype.query = function (this: Database, sql: string) {
  if (schemaVersionReadDepth > 0) return originalQuery.call(this, sql) as ReturnType<typeof Database.prototype.query>;
  assertNoSqlTransactionControl(sql);
  assertSingleMutationSql(sql, "query");
  assertConnectionSetupOrder(this, sql);
  queryConstructionDepth += 1;
  try {
    return instrumentStatement(this, sql, originalQuery.call(this, sql), "query");
  } finally {
    queryConstructionDepth -= 1;
  }
} as typeof Database.prototype.query;

Database.prototype.prepare = function (this: Database, sql: string, ...bindings: unknown[]) {
  if (schemaVersionReadDepth > 0) {
    return originalPrepare.call(this, sql, ...bindings) as ReturnType<typeof Database.prototype.prepare>;
  }
  assertNoSqlTransactionControl(sql);
  assertSingleMutationSql(sql, "prepare");
  assertConnectionSetupOrder(this, sql);
  const statement = originalPrepare.call(this, sql, ...bindings);
  return queryConstructionDepth > 0 ? statement : instrumentStatement(this, sql, statement, "prepare");
} as typeof Database.prototype.prepare;

Database.prototype.transaction = function (this: Database, callback: (...args: unknown[]) => unknown) {
  const database = this;
  transactionConstructionDepth += 1;
  let transaction: TransactionHandle;
  try {
    transaction = originalTransaction.call(database, callback);
  } finally {
    transactionConstructionDepth -= 1;
  }
  const invoke = (method: keyof Pick<TransactionHandle, "default" | "deferred" | "immediate" | "exclusive">) =>
    (...args: unknown[]) => {
      const contexts = transactionContexts.get(database) ?? [];
      if (contexts.length === 0) transactionContexts.set(database, contexts);
      const context: TransactionContext = { mode: method, sawMigrationCompletion: false };
      contexts.push(context);
      let committed = false;
      try {
        const result = transaction[method](...args);
        committed = true;
        const parent = contexts.at(-2);
        if (parent !== undefined && context.sawMigrationCompletion) parent.sawMigrationCompletion = true;
        if (contexts[0] === context && context.sawMigrationCompletion
          && method === "exclusive" && !database.inTransaction) migrationCommitted.add(database);
        if (mode === "observe" && pendingCommit.has(database) && !database.inTransaction) {
          const pending = pendingCommit.get(database)!;
          assertPendingTransaction(pending, context);
          emit("migration-observed", database, pending.sql, pending.index, pending.api, "post-commit");
          pendingCommit.delete(database);
        }
        if (mode === "control" && pendingCommit.has(database) && !database.inTransaction) {
          assertPendingTransaction(pendingCommit.get(database)!, context);
          process.stdout.write(`${JSON.stringify({
            kind: "migration-control-commit",
            journalMode: currentJournalMode(database),
            schemaHash: atomicSchemaSnapshotHash(database),
          })}\n`);
          pendingCommit.delete(database);
        }
        if (mode === "interrupt" && phase === "post-commit"
          && pendingCommit.has(database) && !database.inTransaction) {
          const pending = pendingCommit.get(database)!;
          assertPendingTransaction(pending, context);
          stopAtBoundary(database, pending.sql, pending.index, pending.api);
        }
        return result;
      } finally {
        const pending = pendingCommit.get(database);
        if (!committed && pending?.transactions.includes(context)) pendingCommit.delete(database);
        contexts.pop();
      }
    };
  const wrapped = invoke("default") as TransactionHandle;
  Object.defineProperties(wrapped, {
    default: { value: wrapped },
    deferred: { value: invoke("deferred") },
    immediate: { value: invoke("immediate") },
    exclusive: { value: invoke("exclusive") },
  });
  return wrapped;
} as typeof Database.prototype.transaction;

if (probeApi !== undefined) {
  const database = new Database(path);
  const executeProbe = () => {
    originalRun.call(database, "CREATE TABLE migration_api_probe (id INTEGER PRIMARY KEY)");
    const sql = probeSql ?? "INSERT INTO migration_api_probe DEFAULT VALUES RETURNING id";
    if (probeApi === "run") database.run(probeSql ?? "INSERT INTO migration_api_probe DEFAULT VALUES");
    else if (probeApi === "run-bindings") database.run(
      probeSql ?? "INSERT INTO migration_api_probe (id) VALUES (?)",
      [7],
    );
    else if (probeApi === "exec") database.exec(probeSql ?? "INSERT INTO migration_api_probe DEFAULT VALUES");
    else if (probeApi?.startsWith("query.")) executeStatement(database.query(sql), probeApi.slice(6));
    else if (probeApi === "prepare-bindings") executeStatement(database.prepare(
      probeSql ?? "INSERT INTO migration_api_probe (id) VALUES (?) RETURNING id",
      [7],
    ), "run");
    else if (probeApi?.startsWith("prepare.")) executeStatement(database.prepare(sql), probeApi.slice(8));
    else throw new Error(`Unknown migration probe API: ${probeApi}`);
  };
  if (probeRollback) {
    database.transaction(() => {
      try {
        database.transaction(() => {
          executeProbe();
          throw new Error("intentional migration rollback");
        })();
      } catch (error) {
        if (!(error instanceof Error) || error.message !== "intentional migration rollback") throw error;
      }
      originalRun.call(database, "CREATE TABLE unrelated_commit (id INTEGER PRIMARY KEY)");
    }).exclusive();
  } else if (probeTransactionMode === "autocommit") executeProbe();
  else if (probeTransactionMode === "default") database.transaction(executeProbe)();
  else if (probeTransactionMode === "deferred") database.transaction(executeProbe).deferred();
  else if (probeTransactionMode === "immediate") database.transaction(executeProbe).immediate();
  else if (probeTransactionMode === undefined || probeTransactionMode === "exclusive") {
    database.transaction(executeProbe).exclusive();
  } else throw new Error(`Unknown migration probe transaction mode: ${probeTransactionMode}`);
  if (probePostSql !== undefined) database.run(probePostSql);
  if (probeApi === "run-bindings" || probeApi === "prepare-bindings") {
    const id = (originalQuery.call(database, "SELECT id FROM migration_api_probe") as {
      get(): { readonly id: number } | null;
    }).get()?.id;
    if (id !== 7) throw new Error(`Migration run binding was not preserved: ${id ?? "missing"}`);
  }
  if (probeApi.endsWith("-unconsumed")) {
    const count = (originalQuery.call(database, "SELECT COUNT(*) AS count FROM migration_api_probe") as {
      get(): { readonly count: bigint | number };
    }).get().count;
    if (Number(count) !== 0) throw new Error(`Unconsumed ${probeApi} executed ${count} mutation(s)`);
  }
  database.close();
} else {
  const database = openDatabase(path);
  if (mode === "control") {
    process.stdout.write(`${JSON.stringify({
      kind: "migration-control-final",
      journalMode: currentJournalMode(database),
      schemaHash: atomicSchemaSnapshotHash(database),
    })}\n`);
  }
  database.close();
}
process.stdout.write(`${JSON.stringify({ kind: "migration-complete", migrationCount: migrationIndex })}\n`);

function isMigrationMutation(database: Database, sql: string): boolean {
  return !isConnectionSetupPragma(database, sql) && classifySqliteMutations(sql).length > 0;
}

function instrumentStatement(database: Database, sql: string, value: unknown, api: "prepare" | "query"): unknown {
  const statement = value as InstrumentedStatement;
  if (!isMigrationMutation(database, sql)) return statement;
  if (instrumentedStatements.has(statement)) return statement;
  instrumentedStatements.add(statement);
  for (const method of ["all", "get", "raw", "run", "values"] as const) {
    const original = statement[method].bind(statement);
    statement[method] = (...bindings: unknown[]) => {
      const executionApi = `${api}.${method}`;
      const index = beforeMutation(database, sql, executionApi);
      const result = original(...bindings);
      afterMutation(database, sql, index, executionApi);
      return result;
    };
  }
  const originalIterate = statement.iterate.bind(statement);
  const originalIterator = statement[Symbol.iterator].bind(statement);
  const originalFinalize = statement.finalize.bind(statement);
  statement.iterate = (...bindings: unknown[]) => instrumentIterator(
    statement, database, sql, `${api}.iterate`, originalIterate(...bindings),
  );
  statement[Symbol.iterator] = () => instrumentIterator(
    statement, database, sql, `${api}.iterator`, originalIterator(),
  );
  statement.finalize = () => {
    const result = originalFinalize();
    activeIterators.get(statement)?.complete();
    return result;
  };
  return statement;
}

function executeStatement(value: unknown, method: string): void {
  const statement = value as InstrumentedStatement & Record<string, StatementExecutionFunction | undefined>;
  if (method === "iterate" || method === "iterator") {
    const iterator = method === "iterate" ? statement.iterate() : statement[Symbol.iterator]();
    while (!iterator.next().done) {
      // Exhaustion is the execution boundary for statements with RETURNING rows.
    }
    return;
  }
  if (method === "iterate-unconsumed" || method === "iterator-unconsumed") {
    if (method === "iterate-unconsumed") statement.iterate();
    else statement[Symbol.iterator]();
    return;
  }
  if (method === "iterate-close" || method === "iterator-close") {
    const iterator = method === "iterate-close" ? statement.iterate() : statement[Symbol.iterator]();
    const first = iterator.next();
    if (first.done) throw new Error(`${method} did not expose a partial RETURNING row`);
    statement.finalize();
    return;
  }
  const execute = statement[method];
  if (execute === undefined) throw new Error(`Unknown statement execution method: ${method}`);
  execute.call(statement);
}

function instrumentIterator(
  statement: object,
  database: Database,
  sql: string,
  api: string,
  iterator: IterableIterator<unknown>,
): IterableIterator<unknown> {
  return (function* () {
    const index = beforeMutation(database, sql, api);
    let complete = false;
    const finish = (): void => {
      if (complete) return;
      complete = true;
      activeIterators.delete(statement);
      afterMutation(database, sql, index, api);
    };
    if (activeIterators.has(statement)) throw new Error("Migration statement already has an active iterator");
    activeIterators.set(statement, { complete: finish });
    try {
      while (true) {
        const step = iterator.next();
        if (step.done) {
          finish();
          return step.value;
        }
        yield step.value;
      }
    } finally {
      if (!complete) {
        const step = iterator.return?.();
        if (step?.done === true) finish();
      }
    }
  })();
}

function isConnectionSetupPragma(database: Database, sql: string): boolean {
  const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
  if (/^pragma (?:busy_timeout = 5000|foreign_keys = on)$/.test(normalized)) return true;
  return (migrationCommitted.has(database) || hasCurrentSchemaVersion(database))
    && /^pragma (?:journal_mode = wal|synchronous = full)$/.test(normalized);
}

function assertConnectionSetupOrder(database: Database, sql: string): void {
  const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
  if (!migrationCommitted.has(database) && !hasCurrentSchemaVersion(database)
    && /^pragma (?:journal_mode = wal|synchronous = full)$/.test(normalized)) {
    throw new Error(`Connection setup occurred before the exclusive migration commit: ${normalized}`);
  }
}

function hasCurrentSchemaVersion(database: Database): boolean {
  schemaVersionReadDepth += 1;
  try {
    const row = (originalQuery.call(database, "PRAGMA user_version") as {
      get(): { readonly user_version: bigint | number } | null;
    }).get();
    return row !== null && Number(row.user_version) === 24;
  } finally {
    schemaVersionReadDepth -= 1;
  }
}

function assertSingleMutationSql(sql: string, api: string): void {
  const mutationCount = classifySqliteMutations(sql).length;
  if (mutationCount > 1) {
    throw new Error(`${api} SQL contains ${mutationCount} mutations; migration boundaries require one statement`);
  }
}

function assertNoSqlTransactionControl(sql: string): void {
  if (transactionConstructionDepth === 0 && containsSqliteTransactionControl(sql)) {
    throw new Error("Migration probes require Database.transaction ownership; SQL transaction control is forbidden");
  }
}

function beforeMutation(database: Database, sql: string, api: string): number {
  if (!isMigrationMutation(database, sql)) return -1;
  const index = migrationIndex++;
  if (probeApi === undefined) migrationCallSiteLines.set(index, migrationCallSiteLine());
  const transactions = transactionContexts.get(database) ?? [];
  const transactionMode = transactions[0]?.mode ?? "autocommit";
  if (/^pragma user_version = 24$/i.test(sql.replace(/\s+/g, " ").trim()) && transactions.length > 0) {
    transactions.at(-1)!.sawMigrationCompletion = true;
  }
  if (mode === "observe") {
    emit("migration-observed", database, sql, index, api, "before");
    if (transactionMode !== "exclusive") {
      throw new Error(`Migration mutation ${index} executed in ${transactionMode}, not migrate().exclusive()`);
    }
  }
  if ((mode === "control" || mode === "interrupt") && transactionMode !== "exclusive") {
    throw new Error(`Migration mutation ${index} executed in ${transactionMode}, not migrate().exclusive()`);
  }
  if (mode === "interrupt" && index === targetIndex && phase === "before-run") {
    stopAtBoundary(database, sql, index, api);
  }
  return index;
}

function afterMutation(database: Database, sql: string, index: number, api: string): void {
  if (index < 0) return;
  if (mode === "observe") {
    emit("migration-observed", database, sql, index, api, "after");
    pendingCommit.set(database, pending(database, api, index, sql));
    if (!database.inTransaction) {
      emit("migration-observed", database, sql, index, api, "post-commit");
      pendingCommit.delete(database);
    }
    return;
  }
  if (mode === "control") {
    pendingCommit.set(database, pending(database, api, index, sql));
    return;
  }
  if (mode !== "interrupt" || index !== targetIndex) return;
  if (phase === "after-run") stopAtBoundary(database, sql, index, api);
  if (phase === "post-commit") {
    pendingCommit.set(database, pending(database, api, index, sql));
    if (!database.inTransaction) stopAtBoundary(database, sql, index, api);
  }
}

function pending(database: Database, api: string, index: number, sql: string): PendingCommit {
  return Object.freeze({
    api,
    index,
    sql,
    transactions: Object.freeze([...(transactionContexts.get(database) ?? [])]),
  });
}

function assertPendingTransaction(pendingCommit: PendingCommit, committed: TransactionContext): void {
  if (pendingCommit.transactions[0] !== committed) {
    throw new Error("Pending migration mutation belongs to a different committed transaction");
  }
}

function stopAtBoundary(database: Database, sql: string, index: number, api: string): never {
  if (emitted) throw new Error(`Migration target ${index} executed more than once before termination`);
  emitted = true;
  emit("migration-boundary", database, sql, index, api);
  const gate = new Int32Array(new SharedArrayBuffer(4));
  while (true) Atomics.wait(gate, 0, 0);
}

function emit(
  kind: "migration-boundary" | "migration-observed",
  database: Database,
  sql: string,
  index: number,
  api: string,
  observedPhase?: "after" | "before" | "post-commit",
): void {
  process.stdout.write(`${JSON.stringify({
    kind,
    api,
    index,
    phase: mode === "observe" ? observedPhase : phase,
    inTransaction: database.inTransaction,
    transactionMode: transactionContexts.get(database)?.[0]?.mode ?? "autocommit",
    sql: sql.replace(/\s+/g, " ").trim().slice(0, 200),
    sqlHash: createHash("sha256").update(sql.replace(/\s+/g, " ").trim()).digest("hex"),
    callSiteLine: migrationCallSiteLines.get(index),
  })}\n`);
}

function migrationCallSiteLine(): number {
  for (const line of new Error().stack?.split("\n") ?? []) {
    const match = /\/src\/substrate\/sqlite\/database\.ts:(\d+):\d+/.exec(line);
    if (match?.[1] !== undefined) return Number(match[1]);
  }
  throw new Error("Migration mutation has no production database.ts callsite");
}

function currentJournalMode(database: Database): string {
  return (originalQuery.call(database, "PRAGMA journal_mode") as {
    get(): { readonly journal_mode: string } | null;
  }).get()?.journal_mode ?? "unknown";
}

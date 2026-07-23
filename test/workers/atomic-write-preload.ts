import { Database } from "bun:sqlite";
import {
  atomicLogicalSnapshotHash,
  atomicLogicalTableHashes,
  atomicSchemaContractHash,
  atomicSchemaSnapshotHash,
} from "../fixtures/atomic-logical-snapshot.ts";
import {
  containsSqliteTransactionControl,
  sqliteAtomicWriteMarkerIds,
} from "../fixtures/sqlite-mutation-classifier.ts";

const mode = process.env["DACS_ATOMIC_WRITE_MODE"] ?? "interrupt";
const target = process.env["DACS_ATOMIC_WRITE_TARGET"];
const phase = process.env["DACS_ATOMIC_WRITE_PHASE"];
if (!(["control", "interrupt", "observe"] as const).includes(mode as "control" | "interrupt" | "observe")) {
  throw new Error("Atomic-write preload requires a valid mode");
}
if ((mode === "interrupt" && (target === undefined
  || !["before-statement", "after-statement", "post-commit"].includes(phase ?? "")))
  || (mode === "control" && target === undefined)) {
  throw new Error("Atomic-write preload requires a target and valid phase");
}

type QueryFunction = (this: Database, sql: string) => unknown;
type PrepareFunction = (this: Database, sql: string, ...bindings: unknown[]) => unknown;
type DatabaseSqlFunction = (this: Database, sql: string, ...bindings: unknown[]) => unknown;
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

const originalQuery = Database.prototype.query as unknown as QueryFunction;
const originalPrepare = Database.prototype.prepare as unknown as PrepareFunction;
const originalDatabaseRun = Database.prototype.run as unknown as DatabaseSqlFunction;
const originalDatabaseExec = Database.prototype.exec as unknown as DatabaseSqlFunction;
const originalTransaction = Database.prototype.transaction as unknown as TransactionFunction;
interface TransactionContext {
  readonly callStack: readonly string[];
  readonly id: number;
  readonly mode: "default" | "deferred" | "immediate" | "exclusive";
  readonly startSnapshotHash: string;
  readonly startTableHashes: Readonly<Record<string, string>>;
}
const pendingCommit = new WeakMap<Database, {
  readonly api: string;
  readonly callStack: readonly string[];
  readonly sql: string;
  readonly transaction: TransactionContext | null;
}>();
const instrumentedStatements = new WeakSet<object>();
const activeIterators = new WeakMap<object, { readonly complete: () => void }>();
const transactionContexts = new WeakMap<Database, TransactionContext[]>();
let emitted = false;
let nextTransactionId = 1;
let queryConstructionDepth = 0;
let transactionConstructionDepth = 0;

Database.prototype.run = function (this: Database, sql: string, ...bindings: unknown[]) {
  assertNoSqlTransactionControl(sql);
  return executeMutation(this, sql, "run", () => originalDatabaseRun.call(this, sql, ...bindings));
} as typeof Database.prototype.run;

Database.prototype.exec = function (this: Database, sql: string, ...bindings: unknown[]) {
  assertNoSqlTransactionControl(sql);
  return executeMutation(this, sql, "exec", () => originalDatabaseExec.call(this, sql, ...bindings));
} as typeof Database.prototype.exec;

Database.prototype.prepare = function (this: Database, sql: string, ...bindings: unknown[]) {
  assertNoSqlTransactionControl(sql);
  const statement = originalPrepare.call(this, sql, ...bindings);
  return queryConstructionDepth > 0 ? statement : instrumentStatement(this, sql, statement, "prepare");
} as typeof Database.prototype.prepare;

Database.prototype.query = function (this: Database, sql: string) {
  assertNoSqlTransactionControl(sql);
  queryConstructionDepth += 1;
  try {
    return instrumentStatement(this, sql, originalQuery.call(this, sql), "query");
  } finally {
    queryConstructionDepth -= 1;
  }
} as typeof Database.prototype.query;

function instrumentStatement(database: Database, sql: string, value: unknown, api: "prepare" | "query"): unknown {
  const statement = value as InstrumentedStatement;
  if (siteIdFor(sql) === undefined || (mode !== "observe" && siteIdFor(sql) !== target)) return statement;
  if (instrumentedStatements.has(statement)) return statement;
  instrumentedStatements.add(statement);
  for (const method of ["all", "get", "raw", "run", "values"] as const) {
    const original = statement[method].bind(statement);
    statement[method] = (...bindings: unknown[]) => executeMutation(
      database,
      sql,
      `${api}.${method}`,
      () => original(...bindings),
    );
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

function instrumentIterator(
  statement: object,
  database: Database,
  sql: string,
  api: string,
  iterator: IterableIterator<unknown>,
): IterableIterator<unknown> {
  return (function* () {
    const context = beforeMutation(database, sql, api);
    if (context === undefined) {
      yield* iterator;
      return;
    }
    let complete = false;
    const finish = (): void => {
      if (complete) return;
      complete = true;
      activeIterators.delete(statement);
      afterMutation(database, sql, context);
    };
    if (activeIterators.has(statement)) throw new Error("Atomic-write statement already has an active iterator");
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

interface MutationContext {
  readonly api: string;
  readonly callStack: readonly string[];
  readonly siteId: string;
  readonly transaction: TransactionContext | null;
}

function executeMutation<T>(database: Database, sql: string, api: string, execute: () => T): T {
  const context = beforeMutation(database, sql, api);
  if (context === undefined) return execute();
  const result = execute();
  afterMutation(database, sql, context);
  return result;
}

function beforeMutation(database: Database, sql: string, api: string): MutationContext | undefined {
  const siteId = siteIdFor(sql);
  if (siteId === undefined || (mode !== "observe" && siteId !== target)) return undefined;
  const callStack = captureStack();
  const transaction = transactionContexts.get(database)?.[0] ?? null;
  if (mode === "interrupt" && phase === "before-statement") {
    stopAtBoundary(database, sql, siteId, api, callStack, transaction);
  }
  if (mode === "control") emitControlBefore(database, siteId, transaction);
  return { api, callStack, siteId, transaction };
}

function afterMutation(database: Database, sql: string, context: MutationContext): void {
  const { api, callStack, siteId, transaction } = context;
  if (mode === "observe") emitObservation(database, sql, siteId, api, callStack, transaction);
  if (mode === "control") {
    pendingCommit.set(database, { api, callStack, sql, transaction });
    if (!database.inTransaction) {
      emitControl(database, siteId, callStack, transaction);
      pendingCommit.delete(database);
    }
  }
  if (mode === "interrupt" && phase === "after-statement") {
    stopAtBoundary(database, sql, siteId, api, callStack, transaction);
  }
  if (mode === "interrupt" && phase === "post-commit") {
    pendingCommit.set(database, { api, callStack, sql, transaction });
    if (!database.inTransaction) stopAtBoundary(database, sql, siteId, api, callStack, transaction);
  }
}

function siteIdFor(sql: string): string | undefined {
  const ids = sqliteAtomicWriteMarkerIds(sql);
  return ids.length === 1 ? ids[0] : undefined;
}

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
      const context = contexts[0] ?? {
        callStack: captureStack(),
        id: nextTransactionId++,
        mode: method,
        startSnapshotHash: atomicLogicalSnapshotHash(database),
        startTableHashes: atomicLogicalTableHashes(database),
      };
      contexts.push(context);
      const pendingAtEntry = pendingCommit.get(database);
      let committed = false;
      try {
        const result = transaction[method](...args);
        committed = true;
        if (mode === "interrupt" && phase === "post-commit"
          && pendingCommit.has(database) && !database.inTransaction) {
          const pending = pendingCommit.get(database)!;
          if (pending.transaction !== context) {
            throw new Error("Pending atomic write belongs to a different committed transaction");
          }
          const pendingSiteId = siteIdFor(pending.sql);
          if (pendingSiteId === undefined) throw new Error("Pending atomic write lost its site marker");
          stopAtBoundary(database, pending.sql, pendingSiteId, pending.api, pending.callStack, pending.transaction);
        }
        if (mode === "control" && pendingCommit.has(database) && !database.inTransaction) {
          const pending = pendingCommit.get(database)!;
          if (pending.transaction !== context) {
            throw new Error("Pending atomic write belongs to a different committed transaction");
          }
          const pendingSiteId = siteIdFor(pending.sql);
          if (pendingSiteId === undefined) throw new Error("Pending atomic write lost its site marker");
          emitControl(database, pendingSiteId, pending.callStack, pending.transaction);
          pendingCommit.delete(database);
        }
        return result;
      } finally {
        const pending = pendingCommit.get(database);
        if (!committed && pending !== undefined && pending !== pendingAtEntry
          && pending.transaction === context) {
          if (pendingAtEntry === undefined) pendingCommit.delete(database);
          else pendingCommit.set(database, pendingAtEntry);
        }
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

function assertNoSqlTransactionControl(sql: string): void {
  if (transactionConstructionDepth === 0 && containsSqliteTransactionControl(sql)) {
    throw new Error("Atomic-write probes require Database.transaction ownership; SQL transaction control is forbidden");
  }
}

function stopAtBoundary(
  database: Database,
  sql: string,
  siteId: string,
  api: string,
  callStack = captureStack(),
  transaction = transactionContexts.get(database)?.[0] ?? null,
): never {
  if (emitted) throw new Error(`Atomic-write target ${target} executed more than once before termination`);
  emitted = true;
  process.stdout.write(`${JSON.stringify({
    kind: "atomic-write-boundary",
    api,
    target: siteId,
    phase,
    inTransaction: database.inTransaction,
    transactionId: transaction?.id ?? null,
    transactionMode: transaction?.mode ?? "autocommit",
    transactionCallStack: transaction?.callStack ?? [],
    callStack,
    sql: sql.replace(/\s+/g, " ").trim().slice(0, 160),
  })}\n`);
  const gate = new Int32Array(new SharedArrayBuffer(4));
  while (true) Atomics.wait(gate, 0, 0);
}

function emitObservation(
  database: Database,
  sql: string,
  siteId: string,
  api: string,
  callStack: readonly string[],
  transaction: TransactionContext | null,
): void {
  process.stdout.write(`${JSON.stringify({
    kind: "atomic-write-observation",
    api,
    target: siteId,
    inTransaction: database.inTransaction,
    transactionId: transaction?.id ?? null,
    transactionMode: transaction?.mode ?? "autocommit",
    transactionCallStack: transaction?.callStack ?? [],
    callStack,
    sql: sql.replace(/\s+/g, " ").trim().slice(0, 160),
  })}\n`);
}

function emitControl(
  database: Database,
  siteId: string,
  callStack: readonly string[],
  transaction: TransactionContext | null,
): void {
  if (emitted) return;
  emitted = true;
  process.stdout.write(`${JSON.stringify({
    kind: "atomic-write-control",
    target: siteId,
    snapshotHash: atomicLogicalSnapshotHash(database),
    tableHashes: atomicLogicalTableHashes(database),
    schemaContractHash: atomicSchemaContractHash(database),
    schemaHash: atomicSchemaSnapshotHash(database),
    transactionId: transaction?.id ?? null,
    transactionMode: transaction?.mode ?? "autocommit",
    transactionCallStack: transaction?.callStack ?? [],
    callStack,
  })}\n`);
}

function emitControlBefore(
  database: Database,
  siteId: string,
  transaction: TransactionContext | null,
): void {
  process.stdout.write(`${JSON.stringify({
    kind: "atomic-write-control-before",
    target: siteId,
    snapshotHash: atomicLogicalSnapshotHash(database),
    tableHashes: atomicLogicalTableHashes(database),
    oldSnapshotHash: transaction?.startSnapshotHash ?? atomicLogicalSnapshotHash(database),
    oldTableHashes: transaction?.startTableHashes ?? atomicLogicalTableHashes(database),
    schemaContractHash: atomicSchemaContractHash(database),
    schemaHash: atomicSchemaSnapshotHash(database),
  })}\n`);
}

function captureStack(): readonly string[] {
  return new Error().stack?.split("\n").slice(2, 42).map((line) => line.trim()) ?? [];
}

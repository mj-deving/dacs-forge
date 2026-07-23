import type { Database } from "bun:sqlite";

declare const exportedDatabase: Database;
declare let ambientDatabase: Database;
export const exportedBoundRun = exportedDatabase.run.bind(exportedDatabase);
export const { run: exportedDestructuredRun } = exportedDatabase;
export const exportedExactDatabase: Database = exportedDatabase;
declare function externalExactDatabaseSink(database: Database): void;
declare function externalContainerSink(value: unknown): void;
declare const externalCallable: { call(thisArg: Database): unknown };
declare const ambientWidenedExecutor: WidenedExecutor;
declare function externalCallbackRegistrar(callback: () => void): void;
const aliasedExportDatabase: Database = exportedDatabase;
function aliasedExportDatabaseGetter(): Database {
  return exportedDatabase;
}
function localExactDatabaseGetter(database: Database): Database {
  return database;
}
export { aliasedExportDatabase };
export { aliasedExportDatabaseGetter as default };

interface WidenedExecutor {
  run(sql: string): unknown;
}

interface WidenedHolder {
  db: WidenedExecutor;
}

ambientWidenedExecutor.run("UPDATE fixture SET value = 7");

function invokeWidened(executor: WidenedExecutor, sql: string): void {
  executor.run(sql);
}

function returnWidened(database: Database): WidenedExecutor {
  return database;
}

export function exerciseDatabaseReceiverForms(database: Database, sql: string): void {
  const aliased = database;
  aliased.run(sql);
  database["run"]("UPDATE fixture SET value = 1");
  const method = "run" as const;
  database[method](sql);
  const boundRun = database.run.bind(database);
  boundRun(sql);
}

export function returnExactDatabase(database: Database): Database {
  return database;
}

export const returnExactDatabaseArrow = (database: Database): Database => (database);

export function exerciseRejectedDatabaseMethodEscapes(
  database: Database,
  sql: string,
  method: "run",
  mixedMethod: "close" | "run",
  unionMethod: "query" | "run",
): void {
  const dynamicMethod: any = "run";
  // @ts-expect-error Adversarial non-literal key must fail closed in the scanner.
  database[dynamicMethod](sql);
  externalExactDatabaseSink(database);
  externalExactDatabaseSink(database as Database);
  externalExactDatabaseSink(<Database>database);
  externalExactDatabaseSink(database satisfies Database);
  externalContainerSink(localExactDatabaseGetter);
  ambientDatabase = database;
  externalCallable.call(database);
  database.run.call(database, sql);
  const escapedRun = database.run.bind(database);
  [sql].forEach(escapedRun as unknown as (value: string) => void);
  const { run: destructuredRun } = database;
  [sql].forEach(destructuredRun.bind(database) as unknown as (value: string) => void);
  const { ["run"]: computedRun } = database;
  [sql].forEach(computedRun.bind(database) as unknown as (value: string) => void);
  [sql].forEach(database[method].bind(database) as unknown as (value: string) => void);
  [sql].forEach(database[unionMethod].bind(database) as unknown as (value: string) => void);
  [sql].forEach(database[mixedMethod].bind(database) as unknown as (value: string) => void);
}

export function exerciseExternalWidenedReceiver(receiver: WidenedExecutor, sql: string): void {
  receiver.run(sql);
  receiver["run"](sql);
}

export function exerciseRejectedWidenedMethodEscapes(receiver: WidenedExecutor, sql: string): void {
  const extractedRun = receiver.run;
  [sql].forEach(extractedRun as (value: string) => void);
  const boundRun = receiver.run.bind(receiver);
  [sql].forEach(boundRun as (value: string) => void);
  const { run: destructuredRun } = receiver;
  [sql].forEach(destructuredRun.bind(receiver) as (value: string) => void);
}

function localWidenedCallback(receiver: WidenedExecutor, sql: string): void {
  receiver.run(sql);
}

externalCallbackRegistrar(() => localWidenedCallback(exportedDatabase, "UPDATE fixture SET value = 8"));

export class PublicDatabaseFieldHolder {
  database: Database = exportedDatabase;
}

export class PublicDatabaseParameterHolder {
  constructor(public readonly database: Database) {}
}

export class PrivateDatabaseFieldHolder {
  readonly #database: Database = exportedDatabase;

  close(): void {
    this.#database.close();
  }
}

export async function exerciseRejectedDatabaseContainers(database: Database): Promise<void> {
  externalContainerSink([database]);
  externalContainerSink(true ? database : exportedDatabase);
  externalContainerSink((externalContainerSink(undefined), database));
  externalContainerSink(await database);
}

export function exerciseRejectedDatabaseParameterBinding(
  { run, ["query"]: computedQuery }: Database,
  database: Database,
  sql: string,
): void {
  [sql].forEach(run.bind(database) as unknown as (value: string) => void);
  [sql].forEach(computedQuery.bind(database) as unknown as (value: string) => void);
}

export function exerciseRejectedDatabaseAssignmentBinding(database: Database, sql: string): void {
  let assignedRun: Database["run"];
  ({ run: assignedRun } = database);
  [sql].forEach(assignedRun.bind(database) as unknown as (value: string) => void);
  ({ ["run"]: assignedRun } = database);
}

export function exerciseRejectedWidenedDestructuring(
  { run: parameterRun }: WidenedExecutor,
  receiver: WidenedExecutor,
  sql: string,
): void {
  [sql].forEach(parameterRun as (value: string) => void);
  let assignedRun: WidenedExecutor["run"];
  ({ run: assignedRun } = receiver);
  [sql].forEach(assignedRun as (value: string) => void);
}

export function exerciseRejectedDatabaseReceiverWidening(database: Database, sql: string): void {
  const widened: WidenedExecutor = database;
  widened.run(sql);
  invokeWidened(database, sql);
  const asserted = database as WidenedExecutor;
  asserted.run(sql);
  const returned = returnWidened(database);
  returned.run(sql);
  const holder: WidenedHolder = { db: database };
  holder.db.run(sql);
  const shorthand: { database: WidenedExecutor } = { database };
  shorthand.database.run(sql);
}

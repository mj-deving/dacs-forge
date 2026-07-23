import type { Database } from "bun:sqlite";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";

export function atomicLogicalSnapshotHash(database: Database): string {
  return sha256Hex(canonicalize(atomicLogicalSnapshot(database, true)));
}

export function atomicLogicalTableHashes(database: Database): Readonly<Record<string, string>> {
  return tableHashes(atomicLogicalSnapshot(database, true));
}

export function atomicExactLogicalSnapshotHash(database: Database): string {
  return sha256Hex(canonicalize(atomicLogicalSnapshot(database, false)));
}

export function atomicExactLogicalTableHashes(database: Database): Readonly<Record<string, string>> {
  return tableHashes(atomicLogicalSnapshot(database, false));
}

function tableHashes(snapshot: Record<string, readonly Record<string, unknown>[]>): Readonly<Record<string, string>> {
  return Object.fromEntries(Object.entries(snapshot)
    .map(([table, rows]) => [table, sha256Hex(canonicalize(rows))]));
}

function atomicLogicalSnapshot(
  database: Database,
  normalizeClaimTokens: boolean,
): Record<string, readonly Record<string, unknown>[]> {
  const tableNames = database.query<{ name: string }, []>(`
    SELECT name FROM sqlite_schema
    WHERE type = 'table'
    ORDER BY name
  `).all().map(({ name }) => name);
  const result: Record<string, readonly Record<string, unknown>[]> = {};
  for (const table of tableNames) {
    const rows = database.query<Record<string, unknown>, []>(
      `SELECT * FROM "${table.replaceAll('"', '""')}"`,
    ).all();
    result[table] = rows.map((row) => normalizeRow(row, normalizeClaimTokens))
      .sort((left, right) => compareCanonicalRows(left, right));
  }
  return result;
}

export function atomicSchemaSnapshotHash(database: Database): string {
  return sha256Hex(canonicalize(atomicSchemaSnapshot(database)));
}

export function atomicSchemaContractHash(database: Database): string {
  const { pragmas, schema } = atomicSchemaSnapshot(database);
  const { freelistCount: _, pageCount: __, ...stablePragmas } = pragmas;
  return sha256Hex(canonicalize({
    pragmas: stablePragmas,
    schema: schema.map(({ rootPage: ___, ...entry }) => entry),
  }));
}

function atomicSchemaSnapshot(database: Database) {
  const schema = database.query<{
    name: string;
    rootPage: bigint;
    sql: string | null;
    tableName: string;
    type: string;
  }, []>(`
    SELECT type, name, tbl_name AS tableName, rootpage AS rootPage, sql
    FROM sqlite_schema
    ORDER BY type, name
  `).all().map(({ rootPage, ...row }) => ({ ...row, rootPage: rootPage.toString() }));
  const pragmas = {
    applicationId: Number(database.query<{ application_id: bigint }, []>(
      "PRAGMA application_id",
    ).get()?.application_id ?? 0n),
    autoVacuum: Number(database.query<{ auto_vacuum: bigint }, []>(
      "PRAGMA auto_vacuum",
    ).get()?.auto_vacuum ?? 0n),
    defaultCacheSize: Number(database.query<{ cache_size: bigint }, []>(
      "PRAGMA default_cache_size",
    ).get()?.cache_size ?? 0n),
    encoding: database.query<{ encoding: string },[]>("PRAGMA encoding").get()?.encoding ?? "",
    freelistCount: Number(database.query<{ freelist_count: bigint }, []>(
      "PRAGMA freelist_count",
    ).get()?.freelist_count ?? 0n),
    journalMode: database.query<{ journal_mode: string }, []>(
      "PRAGMA journal_mode",
    ).get()?.journal_mode ?? "",
    maxPageCount: Number(database.query<{ max_page_count: bigint }, []>(
      "PRAGMA max_page_count",
    ).get()?.max_page_count ?? 0n),
    pageCount: Number(database.query<{ page_count: bigint }, []>(
      "PRAGMA page_count",
    ).get()?.page_count ?? 0n),
    pageSize: Number(database.query<{ page_size: bigint }, []>(
      "PRAGMA page_size",
    ).get()?.page_size ?? 0n),
    schemaVersion: Number(database.query<{ schema_version: bigint }, []>(
      "PRAGMA schema_version",
    ).get()?.schema_version ?? 0n),
    userVersion: Number(database.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version ?? 0n),
  };
  return { pragmas, schema };
}

function compareCanonicalRows(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): number {
  const leftCanonical = canonicalize(left);
  const rightCanonical = canonicalize(right);
  return leftCanonical < rightCanonical ? -1 : leftCanonical > rightCanonical ? 1 : 0;
}

function normalizeRow(row: Record<string, unknown>, normalizeClaimTokens: boolean): Record<string, unknown> {
  return Object.fromEntries(Object.entries(row).map(([key, value]) => [key,
    normalizeClaimTokens && key === "claim_token" ? "<volatile-claim-token>"
      : typeof value === "bigint" ? { sqliteType: "integer", value: value.toString() }
      : value instanceof Uint8Array
        ? { sqliteType: "blob", value: Buffer.from(value).toString("hex") }
        : value,
  ]));
}

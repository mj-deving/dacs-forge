import type { Database } from "bun:sqlite";

declare function externalSink(value: unknown): void;

export function hideDatabaseSurface(database: Database): void {
  const opaque: unknown = database;
  externalSink(opaque);
}

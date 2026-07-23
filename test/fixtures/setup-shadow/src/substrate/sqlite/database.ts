import type { Database } from "bun:sqlite";

export function openDatabase(database: Database, migrate: (database: Database) => void): string | undefined {
  try {
    migrate(database);
    return enableWal(database);
  } catch (error) {
    throw error;
  }
}

function enableWal(database: Database): string | undefined {
  return database.query<{ journal_mode: string }, []>(
    "PRAGMA journal_mode = WAL",
  ).get()?.journal_mode;
}

function migrate(_database: Database): void {
  // This exact declaration is shadowed at the callsite and must not authorize WAL setup.
}

void migrate;

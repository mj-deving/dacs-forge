import type { Database } from "bun:sqlite";

export function openDatabase(database: Database): string | undefined {
  try {
    migrate(database);
    const journalMode = enableWal(database);
    void enableWal;
    return journalMode;
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
  // Typed setup-order fixture only.
}

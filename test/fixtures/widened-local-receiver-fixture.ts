import type { Database } from "bun:sqlite";

interface WidenedExecutor {
  run(sql: string): unknown;
}

export function retainLocally(database: Database): void {
  const local: WidenedExecutor = database;
  void local;
}

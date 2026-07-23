import type { Database } from "bun:sqlite";

interface WidenedExecutor {
  run(sql: string): unknown;
}

export function retainAssignment(database: Database): void {
  let local: WidenedExecutor;
  local = database;
  void local;
}

export class PrivateHolder {
  private readonly database: WidenedExecutor;

  constructor(database: Database) {
    this.database = database;
  }

  retain(): void {
    void this.database;
  }
}

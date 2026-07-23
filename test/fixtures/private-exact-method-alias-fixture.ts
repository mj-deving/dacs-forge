import type { Database } from "bun:sqlite";

export class PrivateMethodHolder {
  private run: Database["run"] | undefined;

  retain(database: Database): boolean {
    const { run } = database;
    this.run = run;
    return typeof this.run === "function";
  }
}

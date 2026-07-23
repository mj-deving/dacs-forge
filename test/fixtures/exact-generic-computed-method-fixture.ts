import type { Database } from "bun:sqlite";

declare const database: Database;
declare const sql: string;

export function invoke<K extends "prepare">(key: K): void {
  const prepare = database[key];
  prepare(sql);
}

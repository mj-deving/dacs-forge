import type { Database } from "bun:sqlite";

declare const database: Database;
declare const sql: string;

const literalKey: "prepare" = "prepare";
const { [literalKey]: literalPrepare } = database;
literalPrepare(sql);

export function invoke<K extends "prepare">(key: K): void {
  const { [key]: genericPrepare } = database;
  genericPrepare(sql);
}

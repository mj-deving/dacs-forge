import type { Database } from "bun:sqlite";

declare const database: Database;
const { run } = database;

export { run };

import type { Database } from "bun:sqlite";

declare const database: Database;
declare const sql: string;

const { run } = database;
(run as Database["run"])(sql);

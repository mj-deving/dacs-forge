import type { Database } from "bun:sqlite";

declare const database: Database;
declare const sql: string;

const boundRun = database.run.bind(database);
(boundRun!)(sql);

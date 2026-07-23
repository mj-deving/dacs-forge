import type { Database } from "bun:sqlite";

declare const database: Database;

(database.run)("UPDATE fixture SET value = 11");

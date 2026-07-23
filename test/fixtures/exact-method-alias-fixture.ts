import type { Database } from "bun:sqlite";

declare const database: Database;

const { run } = database;
const alias = run;
alias("UPDATE example SET value = 1");

const bound = database.run.bind(database);
const boundAlias = bound;
boundAlias("UPDATE example SET value = 2");

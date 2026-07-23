import { Database } from "bun:sqlite";

const path = process.argv[2];
const api = process.argv[3];
const sql = process.argv[4];
if (path === undefined || sql === undefined
  || !["exec", "prepare", "query", "run"].includes(api ?? "")) {
  throw new Error("Atomic-write transaction-control worker requires path, API, and SQL");
}

const database = new Database(path);
try {
  if (api === "exec") database.exec(sql);
  else if (api === "prepare") database.prepare(sql);
  else if (api === "query") database.query(sql);
  else database.run(sql);
} finally {
  database.close();
}

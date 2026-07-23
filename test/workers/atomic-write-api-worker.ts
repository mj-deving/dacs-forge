import { Database } from "bun:sqlite";

const path = process.argv[2];
const api = process.argv[3];
if (path === undefined || api === undefined) throw new Error("Atomic-write API worker requires path and API");

interface ProbeStatement {
  all(): unknown;
  get(): unknown;
  iterate(): IterableIterator<unknown>;
  raw(): unknown;
  run(): unknown;
  values(): unknown;
  finalize(): void;
  [Symbol.iterator](): IterableIterator<unknown>;
}

const database = new Database(path, { create: true, strict: true });
database.run("CREATE TABLE api_probe (id INTEGER PRIMARY KEY, api TEXT NOT NULL)");
const sql = api === "prepare.bindings"
  ? "/* atomic-write: api-probe */ INSERT INTO api_probe (api) VALUES (?) RETURNING id"
  : "/* atomic-write: api-probe */ INSERT INTO api_probe (api) VALUES ('probe') RETURNING id";

database.transaction(() => {
  if (api === "run") database.run("/* atomic-write: api-probe */ INSERT INTO api_probe (api) VALUES ('probe')");
  else if (api === "exec") database.exec("/* atomic-write: api-probe */ INSERT INTO api_probe (api) VALUES ('probe')");
  else {
    const [constructor, method] = api.split(".");
    const statement = (api === "prepare.bindings"
      ? database.prepare(sql, ["prepare-bound-value"])
      : constructor === "query" ? database.query(sql) : database.prepare(sql)) as unknown as ProbeStatement;
    if (api === "prepare.bindings") {
      statement.run();
      return;
    }
    if (method === "iterate" || method === "iterator"
      || method === "iterate-finalize" || method === "iterator-finalize") {
      const iterator = method.startsWith("iterate") ? statement.iterate() : statement[Symbol.iterator]();
      if (method.endsWith("-finalize")) {
        const first = iterator.next();
        if (first.done) throw new Error(`${api} did not expose a partial RETURNING row`);
        statement.finalize();
        return;
      }
      while (!iterator.next().done) {
        // Exhaustion completes the SQLite statement and is therefore the mutation boundary.
      }
    } else if (method === "all" || method === "get" || method === "raw"
      || method === "run" || method === "values") statement[method]();
    else throw new Error(`Unknown atomic-write statement API: ${api}`);
  }
}).immediate();

database.close();

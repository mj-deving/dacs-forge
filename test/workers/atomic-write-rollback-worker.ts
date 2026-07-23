import { Database } from "bun:sqlite";

const path = process.argv[2];
if (path === undefined) throw new Error("Atomic rollback worker requires a database path");
const scenario = process.argv[3] ?? "target-rollback";

const database = new Database(path, { create: true });
try {
  database.run("CREATE TABLE probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)");
  const target = database.query(`
    /* atomic-write: rollback-probe */
    INSERT INTO probe (id, value) VALUES (1, 'rolled-back')
  `);
  const nestedTarget = database.query(`
    /* atomic-write: rollback-probe */
    INSERT INTO probe (id, value) VALUES (2, 'nested-rollback')
  `);
  if (scenario === "target-rollback") {
    try {
      database.transaction(() => {
        target.run();
        throw new Error("intentional rollback");
      }).immediate();
    } catch (error) {
      if (!(error instanceof Error) || error.message !== "intentional rollback") throw error;
    }
    database.transaction(() => {
      database.run("INSERT INTO probe (id, value) VALUES (2, 'committed')");
    }).immediate();
  } else if (scenario === "outer-target-nested-rollback") {
    database.transaction(() => {
      target.run();
      try {
        database.transaction(() => {
          nestedTarget.run();
          throw new Error("intentional nested rollback");
        })();
      } catch (error) {
        if (!(error instanceof Error) || error.message !== "intentional nested rollback") throw error;
      }
    }).immediate();
  } else {
    throw new Error(`Unknown atomic rollback scenario: ${scenario}`);
  }
  process.stdout.write(`${JSON.stringify({ kind: "rollback-probe-complete" })}\n`);
} finally {
  database.close();
}

import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import type { AtomicMigrationScenario } from "../fixtures/atomic-migration-scenarios.ts";

export function setupMigrationScenario(
  path: string,
  scenario: Exclude<AtomicMigrationScenario["id"], "fresh">,
): void {
  const database = openDatabase(path);
  try {
    if (scenario === "v8-current") {
      database.run("PRAGMA user_version = 8");
    } else if (scenario === "v9-current") {
      database.run("PRAGMA user_version = 9");
    } else if (scenario === "v12-no-orchestrator") {
      database.run("ALTER TABLE fixture_commitments DROP COLUMN orchestrator_claim");
      database.run("PRAGMA user_version = 12");
    } else if (scenario === "v18-current") {
      database.run("PRAGMA user_version = 18");
    } else if (scenario === "v18-no-vet-records") {
      database.run("DROP TABLE fixture_vet_records");
      database.run("PRAGMA user_version = 18");
    } else {
      throw new Error(`Unknown migration setup scenario: ${scenario}`);
    }
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  const path = process.argv[2];
  const scenario = process.argv[3] as AtomicMigrationScenario["id"] | undefined;
  if (path === undefined || scenario === undefined || scenario === "fresh") {
    throw new Error("Migration setup requires a database path and non-fresh scenario");
  }
  setupMigrationScenario(path, scenario);
}

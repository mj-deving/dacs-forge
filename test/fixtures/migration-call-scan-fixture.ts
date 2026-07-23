import type { Database } from "bun:sqlite";

export function migrateFixture(database: Database, takeUpgradeOnlyBranch: boolean): void {
  let later = (): void => {};
  const apply = database.transaction(() => {
    migrateFixtureHelper(database);
    migrateExportedFixtureHelper(database);
    later = () => database.run("CREATE TABLE escaped_closure_migration (id INTEGER)");
  });
  if (takeUpgradeOnlyBranch) database.run("CREATE TABLE escaped_migration (id INTEGER)");
  apply.exclusive();
  if (takeUpgradeOnlyBranch) later();
}

function migrateFixtureHelper(database: Database): void {
  database.run("CREATE TABLE owned_migration (id INTEGER)");
}

export function migrateExportedFixtureHelper(database: Database): void {
  database.run("CREATE TABLE escaped_exported_migration (id INTEGER)");
}

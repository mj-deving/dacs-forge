export interface AtomicMigrationScenario {
  readonly id: "fresh" | "v8-current" | "v9-current" | "v12-no-orchestrator" | "v18-current"
    | "v18-no-vet-records" | "v19-current";
  readonly expectedSchemaVersion: number;
}

export const ATOMIC_MIGRATION_SCENARIOS: readonly AtomicMigrationScenario[] = Object.freeze([
  Object.freeze({ id: "fresh", expectedSchemaVersion: 0 }),
  Object.freeze({ id: "v8-current", expectedSchemaVersion: 8 }),
  Object.freeze({ id: "v9-current", expectedSchemaVersion: 9 }),
  Object.freeze({ id: "v12-no-orchestrator", expectedSchemaVersion: 12 }),
  Object.freeze({ id: "v18-current", expectedSchemaVersion: 18 }),
  Object.freeze({ id: "v18-no-vet-records", expectedSchemaVersion: 18 }),
  Object.freeze({ id: "v19-current", expectedSchemaVersion: 19 }),
]);

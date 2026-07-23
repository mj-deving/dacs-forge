import type { Database } from "bun:sqlite";

interface WidenedExecutor {
  run(sql: string): unknown;
}

declare const widenedExecutor: WidenedExecutor;
declare const key: keyof WidenedExecutor;
declare function externalSink(value: unknown): void;
let extracted: WidenedExecutor["run"];

({ [key]: extracted } = widenedExecutor);
externalSink(extracted);

type DatabaseTypeAnchor = Database;
declare const databaseTypeAnchor: DatabaseTypeAnchor;
void databaseTypeAnchor;

import type { Database } from "bun:sqlite";

interface WidenedExecutor {
  run(sql: string): unknown;
}

declare const widenedExecutor: WidenedExecutor;
declare function externalSink(value: unknown): void;
let extractedRun: WidenedExecutor["run"];

({ run: extractedRun } = widenedExecutor);
externalSink(extractedRun);

type DatabaseTypeAnchor = Database;
declare const databaseTypeAnchor: DatabaseTypeAnchor;
void databaseTypeAnchor;

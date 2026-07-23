import type { Database } from "bun:sqlite";

interface WidenedExecutor {
  run(sql: string): unknown;
}

declare const widenedExecutor: WidenedExecutor;
declare function externalSink(value: unknown): void;

const { run: { call } } = widenedExecutor;
externalSink(call);

type DatabaseTypeAnchor = Database;
declare const databaseTypeAnchor: DatabaseTypeAnchor;
void databaseTypeAnchor;

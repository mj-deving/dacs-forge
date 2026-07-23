import type { Database } from "bun:sqlite";

interface WidenedExecutor {
  run(sql: string): unknown;
}

declare function externalSink(value: unknown): void;

export function extractWidenedParameter({ run }: WidenedExecutor): void {
  externalSink(run);
}

type DatabaseTypeAnchor = Database;
declare const databaseTypeAnchor: DatabaseTypeAnchor;
void databaseTypeAnchor;

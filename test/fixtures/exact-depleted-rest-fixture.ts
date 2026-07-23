import type { Database } from "bun:sqlite";

declare function externalSink(value: unknown): void;

export function consumeDatabase({ run, exec, query, prepare, ...metadata }: Database): void {
  externalSink(run);
  externalSink(exec);
  externalSink(query);
  externalSink(prepare);
  externalSink(metadata);
}

interface PartialExecutor {
  exec: unknown;
  run(sql: string): unknown;
}

declare const executor: PartialExecutor;
declare function externalSink(value: unknown): void;

externalSink(executor.exec);

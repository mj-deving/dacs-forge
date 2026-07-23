interface DepletedRestExecutor {
  close(): void;
  run(sql: string): unknown;
}

declare const executor: DepletedRestExecutor;
declare function externalSink(value: unknown): void;

const { run, ...metadata } = executor;
externalSink(run);
externalSink(metadata);

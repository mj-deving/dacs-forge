interface WidenedExecutor {
  run(sql: string): unknown;
}

declare const executor: WidenedExecutor;
declare function externalSink(value: unknown): void;

const { ...rest } = executor;
externalSink(rest);

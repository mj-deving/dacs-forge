interface WidenedExecutor {
  close(): void;
  run(sql: string): unknown;
}

declare const executor: WidenedExecutor;
declare const key: "close" | "run";
declare function externalSink(value: unknown): void;
let extracted: unknown;

({ [key]: extracted } = executor);
externalSink(extracted);

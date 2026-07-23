interface WidenedExecutor {
  run(sql: string): unknown;
}

declare function externalSink(value: unknown): void;

export function extractUnresolved<K extends keyof WidenedExecutor>(executor: WidenedExecutor, key: K): void {
  let extracted: WidenedExecutor[K];
  ({ [key]: extracted } = executor);
  externalSink(extracted);
}

interface WidenedReceiver {
  run(sql: string): unknown;
}

declare const executor: WidenedReceiver;
declare function externalSink(value: unknown): void;

externalSink(executor);

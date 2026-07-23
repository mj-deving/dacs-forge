interface AssignmentRestExecutor {
  close(): void;
  run(sql: string): unknown;
}

declare const executor: AssignmentRestExecutor;
declare function externalSink(value: unknown): void;
let run: AssignmentRestExecutor["run"];
let metadata: Omit<AssignmentRestExecutor, "run">;

({ run, ...metadata } = executor);
externalSink(run);
externalSink(metadata);

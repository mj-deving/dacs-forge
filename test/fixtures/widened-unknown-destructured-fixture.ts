interface UnknownDestructuredExecutor {
  run: unknown;
}

declare const executor: UnknownDestructuredExecutor;
declare const sql: string;

const { run } = executor;
if (typeof run === "function") run(sql);

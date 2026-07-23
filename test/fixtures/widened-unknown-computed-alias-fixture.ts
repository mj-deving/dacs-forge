interface UnknownComputedExecutor {
  exec: unknown;
  run: unknown;
}

declare const executor: UnknownComputedExecutor;
declare const key: "exec" | "run";
declare const sql: string;

const { [key]: method } = executor;
if (typeof method === "function") method(sql);

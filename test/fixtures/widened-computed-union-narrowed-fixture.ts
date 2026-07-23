interface ComputedUnknownExecutor {
  exec: unknown;
  run: unknown;
}

declare const executor: ComputedUnknownExecutor;
declare const key: "exec" | "run";
declare const sql: string;

if (typeof executor[key] === "function") executor[key](sql);

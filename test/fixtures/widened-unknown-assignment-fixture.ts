interface UnknownAssignmentExecutor {
  run: unknown;
}

declare const executor: UnknownAssignmentExecutor;
declare const sql: string;
let run: unknown;

({ run } = executor);
if (typeof run === "function") run(sql);

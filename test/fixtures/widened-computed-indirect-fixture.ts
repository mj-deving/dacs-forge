interface UnknownExecutor {
  run: unknown;
}

declare const executor: UnknownExecutor;
declare const sql: string;

export function callMember({ run }: UnknownExecutor): void {
  if (typeof run === "function") run["call"](executor, sql);
}

export function applyMember({ run }: UnknownExecutor): void {
  if (typeof run === "function") run["apply"](executor, [sql]);
}

export function bindMember({ run }: UnknownExecutor): void {
  if (typeof run === "function") run["bind"](executor)(sql);
}

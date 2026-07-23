interface UnknownExecutor {
  run: unknown;
}

declare const receiver: UnknownExecutor;
declare const sql: string;

export function invoke<K extends "call">({ run }: UnknownExecutor, key: K): void {
  if (typeof run === "function") run[key](receiver, sql);
}

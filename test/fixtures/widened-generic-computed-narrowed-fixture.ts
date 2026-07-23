interface UnknownExecutor {
  run: unknown;
}

declare const sql: string;

export function invoke<K extends keyof UnknownExecutor>(receiver: UnknownExecutor, key: K): void {
  if (typeof receiver[key] === "function") receiver[key](sql);
}

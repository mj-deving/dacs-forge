interface UnknownExecutor {
  run: unknown;
}

declare const sql: string;

export function invoke<K extends keyof UnknownExecutor>(receiver: UnknownExecutor, key: K): void {
  const { [key]: method } = receiver;
  if (typeof method === "function") method(sql);
}

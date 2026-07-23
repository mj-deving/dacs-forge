interface UnknownExecutor {
  run: unknown;
}

declare const fallback: (sql: string) => unknown;
declare const flag: boolean;
declare const sql: string;

export function invoke(receiver: UnknownExecutor): void {
  const { run } = receiver;
  if (typeof run !== "function") return;
  const selected = flag ? run : fallback;
  selected(sql);
}

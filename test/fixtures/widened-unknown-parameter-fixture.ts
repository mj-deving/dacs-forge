interface UnknownParameterExecutor {
  run: unknown;
}

declare const sql: string;

export function execute({ run }: UnknownParameterExecutor): void {
  if (typeof run === "function") run(sql);
}

interface WidenedExecutor {
  run(sql: string): unknown;
}

export function executeGeneric<T extends WidenedExecutor>(executor: T): void {
  executor.run("UPDATE fixture SET value = 10");
}

interface OptionalExecutor {
  run?: (sql: string) => unknown;
}

declare const executor: OptionalExecutor;

executor.run?.("UPDATE fixture SET value = 12");

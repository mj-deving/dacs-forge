interface WidenedExecutor {
  run(sql: string): unknown;
}

declare const executor: WidenedExecutor;

executor.run("UPDATE fixture SET value = 9");

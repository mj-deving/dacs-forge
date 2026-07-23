interface NarrowedExecutor {
  run?: (sql: string) => unknown;
}

declare const executor: NarrowedExecutor;

if (executor.run !== undefined) executor.run("UPDATE fixture SET value = 13");

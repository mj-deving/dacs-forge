interface UnknownExecutor {
  run: unknown;
}

declare const executor: UnknownExecutor;

if (typeof executor.run === "function") executor.run("UPDATE fixture SET value = 14");

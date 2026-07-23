interface UnknownExecutor {
  run: unknown;
}

export let exportedRun: unknown;

export function transfer({ run }: UnknownExecutor): void {
  if (typeof run === "function") exportedRun = run;
}

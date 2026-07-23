interface UnknownExecutor {
  run: unknown;
}

export class PrivateNarrowedMethodHolder {
  private run: unknown;

  retain(receiver: UnknownExecutor): boolean {
    const { run } = receiver;
    if (typeof run === "function") this.run = run;
    return typeof this.run === "function";
  }
}

interface UnknownExecutor {
  run: unknown;
}

declare const sql: string;

export class PrivateIdentifierNarrowedAlias {
  #writer: unknown;

  invoke(receiver: UnknownExecutor): void {
    const { run } = receiver;
    if (typeof run === "function") this.#writer = run;
    if (typeof this.#writer === "function") this.#writer(sql);
  }
}

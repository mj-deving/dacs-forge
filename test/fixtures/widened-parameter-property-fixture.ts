interface WidenedExecutor {
  run(sql: string): unknown;
}

export class PublicHolder {
  constructor(public readonly executor: WidenedExecutor) {}
}

export class PrivateHolder {
  constructor(private readonly executor: WidenedExecutor) {}

  retain(): void {
    void this.executor;
  }
}

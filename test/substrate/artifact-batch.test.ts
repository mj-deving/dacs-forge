import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("atomic artifact batches", () => {
  test("rolls back every blob and kind when any batch entry fails", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-artifact-batch-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    database.run(`
      CREATE TRIGGER reject_receipt_kind
      BEFORE INSERT ON artifact_kinds
      WHEN NEW.kind = 'work-product-receipt'
      BEGIN
        SELECT RAISE(ABORT, 'injected receipt persistence failure');
      END
    `);
    const store = new ArtifactStore(database);

    expect(() => store.putBatch([
      { kind: "work-product:example", value: { output: "complete" } },
      { kind: "work-product-receipt", value: { receipt: "complete" } },
    ], "2026-07-17T08:00:00.000Z")).toThrow(/injected receipt persistence failure/);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()?.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifact_kinds",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("stores a complete batch idempotently", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-artifact-batch-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    const store = new ArtifactStore(database);
    const entries = [
      { kind: "work-product:example", value: { output: "complete" } },
      { kind: "work-product-receipt", value: { receipt: "complete" } },
    ] as const;
    const first = store.putBatch(entries, "2026-07-17T08:00:00.000Z");
    const replay = store.putBatch(entries, "2026-07-17T08:00:01.000Z");

    expect(first.map(({ contentHash }) => contentHash))
      .toEqual(replay.map(({ contentHash }) => contentHash));
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()?.count).toBe(2n);
    database.close();
  });

  test("allows direct artifact writes only inside a caller-owned transaction", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-artifact-batch-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    const store = new ArtifactStore(database);

    expect(() => store.putWithinTransaction(
      "work-product:example",
      { output: "complete" },
      "2026-07-17T08:00:00.000Z",
    )).toThrow(/requires an active SQLite transaction/);
    const transaction = database.transaction(() => {
      store.putWithinTransaction(
        "work-product:example",
        { output: "complete" },
        "2026-07-17T08:00:00.000Z",
      );
      throw new Error("forced caller rollback");
    });
    expect(() => transaction.immediate()).toThrow(/forced caller rollback/);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()?.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifact_kinds",
    ).get()?.count).toBe(0n);
    database.close();
  });
});

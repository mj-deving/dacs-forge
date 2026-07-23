import { Database } from "bun:sqlite";
import {
  atomicExactLogicalSnapshotHash,
  atomicExactLogicalTableHashes,
  atomicLogicalSnapshotHash,
  atomicLogicalTableHashes,
  atomicSchemaContractHash,
  atomicSchemaSnapshotHash,
} from "../fixtures/atomic-logical-snapshot.ts";

const path = process.argv[2];
if (path === undefined) throw new Error("Atomic-write raw snapshot requires a database path");

const database = new Database(path, { safeIntegers: true });
try {
  process.stdout.write(`${JSON.stringify({
    kind: "atomic-write-raw-snapshot",
    exactSnapshotHash: atomicExactLogicalSnapshotHash(database),
    exactTableHashes: atomicExactLogicalTableHashes(database),
    snapshotHash: atomicLogicalSnapshotHash(database),
    tableHashes: atomicLogicalTableHashes(database),
    schemaContractHash: atomicSchemaContractHash(database),
    schemaHash: atomicSchemaSnapshotHash(database),
  })}\n`);
} finally {
  database.close();
}

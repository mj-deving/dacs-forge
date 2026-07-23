import { constants } from "node:fs";
import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";

const writableRoot = process.argv[2];
const readOnlyPath = process.argv[3];
if (writableRoot === undefined || readOnlyPath === undefined) {
  throw new Error("Filesystem probe requires writable and read-only paths");
}

try {
  await access(readOnlyPath, constants.W_OK);
  throw new Error(`Read-only namespace path remained writable: ${readOnlyPath}`);
} catch (error) {
  if (error instanceof Error && error.message.startsWith("Read-only namespace path")) throw error;
}
await writeFile(join(writableRoot, "namespace-write-probe"), "bounded\n", { mode: 0o600 });

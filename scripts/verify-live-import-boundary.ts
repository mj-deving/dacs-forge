import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { OFFICIAL_DACS_SDK_COMMIT } from "../src/live/profile.ts";

const root = new URL("..", import.meta.url).pathname;
const violations: string[] = [];
for (const file of await typescriptFiles(join(root, "src"))) {
  const path = relative(root, file);
  const source = await readFile(file, "utf8");
  if (source.includes("@kynesyslabs/dacs")) violations.push(path);
}
const adapterSource = await readFile(join(root, "src/adapters/demos-sdk-listing.ts"), "utf8");
if (!adapterSource.includes("config.sdkCommit !== OFFICIAL_DACS_SDK_COMMIT")) {
  violations.push("optional Demos adapter does not enforce the exact SDK commit");
}
if (violations.length > 0) throw new Error(`Live SDK import boundary failed: ${violations.join(", ")}`);
console.log(`live import boundary: core/consumer/package clean; injected adapter pin ${OFFICIAL_DACS_SDK_COMMIT}`);

async function typescriptFiles(directory: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await typescriptFiles(path));
    else if (entry.isFile() && path.endsWith(".ts")) result.push(path);
  }
  return result;
}

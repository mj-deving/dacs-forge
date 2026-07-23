import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, normalize, resolve } from "node:path";
import { spawnSync } from "node:child_process";

type Entry = { path: string; sha256: string };
type Manifest = {
  schema: string;
  sourceCommit: string;
  scaffoldCommit: string;
  sourceFiles: Entry[];
  packagingFiles: Entry[];
  self: { path: string; digestIncluded: boolean };
};

const root = resolve(import.meta.dir, "..");
const manifestPath = "docs/SOURCE-PROVENANCE.json";
const manifest = JSON.parse(readFileSync(resolve(root, manifestPath), "utf8")) as Manifest;

function fail(message: string): never {
  throw new Error(`source provenance verification failed: ${message}`);
}

function sha256(bytes: Uint8Array): string {
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

if (manifest.schema !== "dacs-forge-source-provenance/v1") fail("unknown schema");
if (!/^[0-9a-f]{40}$/.test(manifest.sourceCommit)) fail("invalid source commit");
if (!/^[0-9a-f]{40}$/.test(manifest.scaffoldCommit)) fail("invalid scaffold commit");
if (manifest.self.path !== manifestPath || manifest.self.digestIncluded !== false) fail("invalid self rule");

const entries = [...manifest.sourceFiles, ...manifest.packagingFiles];
const declared = new Set<string>();
for (const entry of entries) {
  if (isAbsolute(entry.path) || normalize(entry.path) !== entry.path || entry.path.startsWith("../")) {
    fail(`unsafe path ${entry.path}`);
  }
  if (entry.path === manifestPath) fail("manifest must not digest itself");
  if (!/^[0-9a-f]{64}$/.test(entry.sha256)) fail(`invalid digest for ${entry.path}`);
  if (declared.has(entry.path)) fail(`duplicate path ${entry.path}`);
  declared.add(entry.path);

  const absolutePath = resolve(root, entry.path);
  if (lstatSync(absolutePath).isSymbolicLink()) fail(`symbolic link ${entry.path}`);
  if (sha256(readFileSync(absolutePath)) !== entry.sha256) fail(`digest mismatch ${entry.path}`);
}

const listed = spawnSync("git", ["ls-files", "-z"], { cwd: root });
if (listed.status !== 0) fail(`git ls-files exited ${listed.status}`);
const tracked = new Set(
  new TextDecoder().decode(listed.stdout).split("\0").filter((path) => path && path !== manifestPath),
);
for (const path of tracked) if (!declared.has(path)) fail(`undeclared tracked file ${path}`);
for (const path of declared) if (!tracked.has(path)) fail(`declared untracked file ${path}`);

console.log(`source provenance verified: ${manifest.sourceFiles.length} source, ${manifest.packagingFiles.length} packaging`);

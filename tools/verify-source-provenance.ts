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
  extensionScope: {
    exactPaths: string[];
    prefixes: string[];
    baselineFiles: Entry[];
  };
  self: { path: string; digestIncluded: boolean };
};

export type ProvenanceVerification = {
  sourceFiles: number;
  packagingFiles: number;
  extensionBaselines: number;
  trackedExtensions: number;
};

const DEFAULT_ROOT = resolve(import.meta.dir, "..");
const MANIFEST_PATH = "docs/SOURCE-PROVENANCE.json";
const EXTENSION_EXACT_PATHS = [
  "service/handler.ts",
  "service/input.schema.json",
  "service/output.schema.json",
  "service/service.config.ts",
] as const;
const EXTENSION_PREFIXES = ["service/fixtures/"] as const;

function fail(message: string): never {
  throw new Error(`source provenance verification failed: ${message}`);
}

function sha256(bytes: Uint8Array): string {
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

function assertSafePath(path: string): void {
  if (!path || isAbsolute(path) || normalize(path) !== path || path.startsWith("../")) {
    fail(`unsafe path ${path}`);
  }
}

function assertExactScope(actual: string[], expected: readonly string[], name: string): void {
  if (actual.length !== new Set(actual).size) fail(`duplicate ${name}`);
  if (actual.length !== expected.length || expected.some((path) => !actual.includes(path))) {
    fail(`invalid ${name}`);
  }
}

function isExtensionPath(path: string): boolean {
  return EXTENSION_EXACT_PATHS.includes(path as (typeof EXTENSION_EXACT_PATHS)[number])
    || EXTENSION_PREFIXES.some((prefix) => path.startsWith(prefix) && path.length > prefix.length);
}

function assertTrackedRegularFile(root: string, path: string): void {
  let status: ReturnType<typeof lstatSync>;
  try {
    status = lstatSync(resolve(root, path));
  } catch {
    fail(`missing file ${path}`);
  }
  if (status.isSymbolicLink()) fail(`symbolic link ${path}`);
  if (!status.isFile()) fail(`not a regular file ${path}`);
}

export function verifySourceProvenance(root = DEFAULT_ROOT): ProvenanceVerification {
  const manifest = JSON.parse(readFileSync(resolve(root, MANIFEST_PATH), "utf8")) as Manifest;

  if (manifest.schema !== "dacs-forge-source-provenance/v2") fail("unknown schema");
  if (!/^[0-9a-f]{40}$/.test(manifest.sourceCommit)) fail("invalid source commit");
  if (!/^[0-9a-f]{40}$/.test(manifest.scaffoldCommit)) fail("invalid scaffold commit");
  if (manifest.self.path !== MANIFEST_PATH || manifest.self.digestIncluded !== false) fail("invalid self rule");
  if (!manifest.extensionScope) fail("missing extension scope");

  assertExactScope(manifest.extensionScope.exactPaths, EXTENSION_EXACT_PATHS, "extension exact path");
  assertExactScope(manifest.extensionScope.prefixes, EXTENSION_PREFIXES, "extension prefix");

  const immutableEntries = [...manifest.sourceFiles, ...manifest.packagingFiles];
  const immutablePaths = new Set<string>();
  for (const entry of immutableEntries) {
    assertSafePath(entry.path);
    if (entry.path === MANIFEST_PATH) fail("manifest must not digest itself");
    if (isExtensionPath(entry.path)) fail(`extension path declared immutable ${entry.path}`);
    if (!/^[0-9a-f]{64}$/.test(entry.sha256)) fail(`invalid digest for ${entry.path}`);
    if (immutablePaths.has(entry.path)) fail(`duplicate path ${entry.path}`);
    immutablePaths.add(entry.path);

    assertTrackedRegularFile(root, entry.path);
    if (sha256(readFileSync(resolve(root, entry.path))) !== entry.sha256) fail(`digest mismatch ${entry.path}`);
  }

  const baselinePaths = new Set<string>();
  for (const entry of manifest.extensionScope.baselineFiles) {
    assertSafePath(entry.path);
    if (!isExtensionPath(entry.path)) fail(`baseline outside extension scope ${entry.path}`);
    if (!/^[0-9a-f]{64}$/.test(entry.sha256)) fail(`invalid baseline digest for ${entry.path}`);
    if (baselinePaths.has(entry.path)) fail(`duplicate baseline path ${entry.path}`);
    if (immutablePaths.has(entry.path)) fail(`path declared immutable and mutable ${entry.path}`);
    baselinePaths.add(entry.path);
  }
  for (const path of EXTENSION_EXACT_PATHS) {
    if (!baselinePaths.has(path)) fail(`missing extension baseline ${path}`);
  }

  const listed = spawnSync("git", ["ls-files", "-z"], { cwd: root });
  if (listed.status !== 0) fail(`git ls-files exited ${listed.status}`);
  const tracked = new Set(
    new TextDecoder().decode(listed.stdout).split("\0").filter((path) => path && path !== MANIFEST_PATH),
  );

  let trackedExtensions = 0;
  for (const path of tracked) {
    if (immutablePaths.has(path)) continue;
    if (!isExtensionPath(path)) fail(`undeclared tracked file ${path}`);
    assertTrackedRegularFile(root, path);
    trackedExtensions += 1;
  }
  for (const path of immutablePaths) if (!tracked.has(path)) fail(`declared untracked file ${path}`);
  for (const path of EXTENSION_EXACT_PATHS) {
    if (!tracked.has(path)) fail(`required extension untracked file ${path}`);
  }

  return {
    sourceFiles: manifest.sourceFiles.length,
    packagingFiles: manifest.packagingFiles.length,
    extensionBaselines: manifest.extensionScope.baselineFiles.length,
    trackedExtensions,
  };
}

if (import.meta.main) {
  const result = verifySourceProvenance();
  console.log(
    `source provenance verified: ${result.sourceFiles} source, ${result.packagingFiles} packaging, `
      + `${result.extensionBaselines} extension baselines, ${result.trackedExtensions} tracked extensions`,
  );
}

import { afterEach, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { verifySourceProvenance } from "../../tools/verify-source-provenance.ts";

type Entry = { path: string; sha256: string };
type FixtureManifest = {
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

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test("allows extension changes and added files inside the fixture extension prefix", () => {
  const root = createFixture();
  write(root, "service/handler.ts", "export default 'forked';\n");
  write(root, "service/fixtures/basic.ts", "export default 'changed fixture';\n");
  write(root, "service/fixtures/extra.ts", "export default 'new fixture';\n");
  git(root, "add", "service/fixtures/extra.ts");

  expect(verifySourceProvenance(root)).toEqual({
    sourceFiles: 1,
    packagingFiles: 0,
    extensionBaselines: 5,
    trackedExtensions: 6,
  });
});

test("allows replacing a historical fixture baseline inside the mutable prefix", () => {
  const root = createFixture();
  unlinkSync(join(root, "service/fixtures/basic.ts"));
  git(root, "rm", "service/fixtures/basic.ts");
  write(root, "service/fixtures/replacement.ts", "export default 'replacement fixture';\n");
  git(root, "add", "service/fixtures/replacement.ts");

  expect(verifySourceProvenance(root).trackedExtensions).toBe(5);
});

test("rejects immutable substrate drift", () => {
  const root = createFixture();
  write(root, "core.ts", "export const core = 'drift';\n");
  expect(() => verifySourceProvenance(root)).toThrow("digest mismatch core.ts");
});

test("rejects tracked files outside the fixed extension scope", () => {
  const root = createFixture();
  write(root, "extra.ts", "export {};\n");
  git(root, "add", "extra.ts");
  expect(() => verifySourceProvenance(root)).toThrow("undeclared tracked file extra.ts");
});

test("rejects a missing required extension baseline", () => {
  const root = createFixture();
  unlinkSync(join(root, "service/handler.ts"));
  expect(() => verifySourceProvenance(root)).toThrow("missing file service/handler.ts");
});

test("rejects a symbolic-link extension", () => {
  const root = createFixture();
  unlinkSync(join(root, "service/handler.ts"));
  symlinkSync("../core.ts", join(root, "service/handler.ts"));
  expect(() => verifySourceProvenance(root)).toThrow("symbolic link service/handler.ts");
});

test("rejects duplicate and widened extension declarations", () => {
  const duplicateRoot = createFixture();
  const duplicate = readManifest(duplicateRoot);
  duplicate.extensionScope.baselineFiles.push(duplicate.extensionScope.baselineFiles[0]!);
  writeManifest(duplicateRoot, duplicate);
  expect(() => verifySourceProvenance(duplicateRoot)).toThrow("duplicate baseline path");

  const widenedRoot = createFixture();
  const widened = readManifest(widenedRoot);
  widened.extensionScope.prefixes = ["service/"];
  writeManifest(widenedRoot, widened);
  expect(() => verifySourceProvenance(widenedRoot)).toThrow("invalid extension prefix");
});

function createFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "dacs-forge-provenance-"));
  roots.push(root);

  const files = new Map<string, string>([
    ["core.ts", "export const core = true;\n"],
    ["service/handler.ts", "export default 'base';\n"],
    ["service/input.schema.json", "{}\n"],
    ["service/output.schema.json", "{}\n"],
    ["service/service.config.ts", "export default {};\n"],
    ["service/fixtures/basic.ts", "export default 'fixture';\n"],
  ]);
  for (const [path, contents] of files) write(root, path, contents);

  const extensionPaths = [...files.keys()].filter((path) => path.startsWith("service/"));
  const manifest: FixtureManifest = {
    schema: "dacs-forge-source-provenance/v2",
    sourceCommit: "a".repeat(40),
    scaffoldCommit: "b".repeat(40),
    sourceFiles: [{ path: "core.ts", sha256: digest(files.get("core.ts")!) }],
    packagingFiles: [],
    extensionScope: {
      exactPaths: [
        "service/handler.ts",
        "service/input.schema.json",
        "service/output.schema.json",
        "service/service.config.ts",
      ],
      prefixes: ["service/fixtures/"],
      baselineFiles: extensionPaths.map((path) => ({ path, sha256: digest(files.get(path)!) })),
    },
    self: { path: "docs/SOURCE-PROVENANCE.json", digestIncluded: false },
  };
  writeManifest(root, manifest);
  git(root, "init", "-q");
  git(root, "add", ".");
  return root;
}

function readManifest(root: string): FixtureManifest {
  return JSON.parse(readFileSync(join(root, "docs/SOURCE-PROVENANCE.json"), "utf8")) as FixtureManifest;
}

function writeManifest(root: string, manifest: FixtureManifest): void {
  write(root, "docs/SOURCE-PROVENANCE.json", `${JSON.stringify(manifest, null, 2)}\n`);
}

function write(root: string, path: string, contents: string): void {
  const absolute = join(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, contents);
}

function digest(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function git(root: string, ...args: string[]): void {
  const result = spawnSync("git", args, { cwd: root });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} exited ${result.status}`);
}

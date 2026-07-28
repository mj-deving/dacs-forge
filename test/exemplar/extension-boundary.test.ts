import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { scanCriticalTree, verifyExtensionDelta } from "../../tools/exemplar-policy.ts";

const repositories: string[] = [];

function git(repository: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd: repository, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function write(repository: string, path: string, content: string): void {
  const absolute = join(repository, path);
  mkdirSync(join(absolute, ".."), { recursive: true });
  writeFileSync(absolute, content);
}

function commit(repository: string, message: string): string {
  git(repository, "add", "-A");
  git(repository, "commit", "-m", message);
  return git(repository, "rev-parse", "HEAD");
}

function commitTree(repository: string, tree: string, parent?: string): string {
  const result = spawnSync("git", ["commit-tree", tree, ...(parent ? ["-p", parent] : [])], {
    cwd: repository,
    encoding: "utf8",
    input: "synthetic\n",
  });
  if (result.status !== 0) throw new Error(`git commit-tree failed: ${result.stderr}`);
  return result.stdout.trim();
}

function fixtureRepository(): { readonly root: string; readonly base: string } {
  const root = mkdtempSync(join(tmpdir(), "dacs-exemplar-policy-"));
  repositories.push(root);
  git(root, "init", "-q");
  git(root, "config", "core.hooksPath", "/dev/null");
  git(root, "config", "user.email", "fixture@example.invalid");
  git(root, "config", "user.name", "Fixture");
  write(root, "service/handler.ts", "export const handler = () => ({ value: 'base' });\n");
  write(root, "service/input.schema.json", "{}\n");
  write(root, "service/output.schema.json", "{}\n");
  write(root, "service/service.config.ts", "export const service = 'base';\n");
  write(root, "service/fixtures/basic.ts", "export const fixture = 'base';\n");
  write(root, "src/protocol.ts", "export function protocol() { return 'ok'; }\n");
  write(root, "test/protocol.test.ts", "import { test } from 'bun:test'; test('ok', () => {});\n");
  write(root, "scripts/runtime.ts", "export const run = () => 1;\n");
  write(root, "Dockerfile", "FROM example.invalid/base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
  write(root, "package.json", "{\"private\":true}\n");
  return { root, base: commit(root, "base") };
}

afterEach(async () => {
  await Promise.all(repositories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("trusted-base exemplar policy", () => {
  test("accepts a regular-file service-logic plus fixture delta", async () => {
    const { root, base } = fixtureRepository();
    write(root, "service/handler.ts", "export const handler = () => ({ value: 'fork' });\n");
    write(root, "service/fixtures/basic.ts", "export const fixture = 'fork';\n");
    const tip = commit(root, "exemplar");
    expect(verifyExtensionDelta(root, base, tip)).toEqual([]);
    expect(await scanCriticalTree(root, tip)).toEqual([]);
  });

  test("rejects verifier or verifier-test bytes in the exemplar delta", () => {
    const { root, base } = fixtureRepository();
    write(root, "service/handler.ts", "export const handler = () => ({ value: 'fork' });\n");
    write(root, "service/fixtures/basic.ts", "export const fixture = 'fork';\n");
    write(root, "scripts/verify-exemplar-diff.ts", "console.log('self allowlist');\n");
    write(root, "test/exemplar/extension-boundary.test.ts", "export const weakened = true;\n");
    const tip = commit(root, "self-certifying exemplar");
    expect(verifyExtensionDelta(root, base, tip).map((finding) => finding.path)).toEqual([
      "scripts/verify-exemplar-diff.ts",
      "test/exemplar/extension-boundary.test.ts",
    ]);
  });

  test("rejects symlinked extension content", () => {
    const { root, base } = fixtureRepository();
    write(root, "service/handler.ts", "export const handler = () => ({ value: 'fork' });\n");
    symlinkSync("handler.ts", join(root, "service/fixtures/linked.ts"));
    const tip = commit(root, "linked exemplar");
    expect(verifyExtensionDelta(root, base, tip)).toContainEqual({
      kind: "boundary",
      path: "service/fixtures/linked.ts",
      detail: "extension path has forbidden mode 120000",
    });
  });

  test("rejects fixture formats outside the scanner surface", () => {
    const { root, base } = fixtureRepository();
    write(root, "service/handler.ts", "export const handler = () => ({ value: 'fork' });\n");
    write(root, "service/fixtures/bypass.tsx", "// marker hidden from the TypeScript scanner\n");
    const tip = commit(root, "unscanned fixture");
    expect(verifyExtensionDelta(root, base, tip)).toContainEqual({
      kind: "boundary",
      path: "service/fixtures/bypass.tsx",
      detail: "path is outside the declared extension surface",
    });
  });

  test("does not let replacement refs fabricate base ancestry", () => {
    const { root, base } = fixtureRepository();
    write(root, "service/handler.ts", "export const handler = () => ({ value: 'fork' });\n");
    write(root, "service/fixtures/basic.ts", "export const fixture = 'fork';\n");
    const normalTip = commit(root, "normal exemplar");
    const tree = git(root, "rev-parse", `${normalTip}^{tree}`);
    const unrelatedTip = commitTree(root, tree);
    const replacement = commitTree(root, tree, base);
    git(root, "replace", unrelatedTip, replacement);
    expect(verifyExtensionDelta(root, base, unrelatedTip)).toEqual([
      { kind: "boundary", path: ".", detail: "tip does not descend from exact base" },
    ]);
  });

  test("does not count executable-bit-only changes as fresh exemplar bytes", () => {
    const { root, base } = fixtureRepository();
    chmodSync(join(root, "service/handler.ts"), 0o755);
    chmodSync(join(root, "service/fixtures/basic.ts"), 0o755);
    const tip = commit(root, "mode-only exemplar");
    expect(verifyExtensionDelta(root, base, tip).map((finding) => finding.detail)).toEqual([
      "fresh exemplar must change service logic",
      "fresh exemplar must change schema or fixtures",
    ]);
  });

  test("kills marker, focused-test, and empty-export mutations", async () => {
    const { root } = fixtureRepository();
    write(root, "src/protocol.ts", "// TODO remove\nexport function protocol() {}\n");
    write(root, "test/protocol.test.ts", "import { test } from 'bun:test'; test.only('focused', () => {});\n");
    const tip = commit(root, "mutants");
    expect((await scanCriticalTree(root, tip)).map((finding) => finding.kind).sort()).toEqual([
      "empty-export",
      "marker",
      "test-focus",
    ]);
  });

  test("kills aliased and conditional Bun test mutations", async () => {
    const { root } = fixtureRepository();
    write(root, "test/protocol.test.ts", [
      "import { test as spec } from 'bun:test';",
      "spec.skip('aliased skip', () => {});",
      "spec.if(false)('conditional skip', () => {});",
      "",
    ].join("\n"));
    const tip = commit(root, "test modifiers");
    expect((await scanCriticalTree(root, tip)).filter((finding) => finding.kind === "test-focus")).toHaveLength(2);
  });

  test("kills aliased disabled Bun test roots", async () => {
    const { root } = fixtureRepository();
    write(root, "test/protocol.test.ts", [
      "import { xtest as check } from 'bun:test';",
      "check('disabled', () => {});",
      "",
    ].join("\n"));
    const tip = commit(root, "aliased disabled test");
    expect((await scanCriticalTree(root, tip)).filter((finding) => finding.kind === "test-focus")).toHaveLength(1);
  });

  test("kills direct and referenced default empty exports", async () => {
    const { root } = fixtureRepository();
    write(root, "src/protocol.ts", "export default () => {};\n");
    write(root, "src/another.ts", "const handler = () => {}; export default handler;\n");
    const tip = commit(root, "empty defaults");
    expect((await scanCriticalTree(root, tip)).filter((finding) => finding.kind === "empty-export")).toHaveLength(2);
  });

  test("kills parenthesized and satisfies-wrapped empty exports", async () => {
    const { root } = fixtureRepository();
    write(root, "src/protocol.ts", "export default (() => {});\n");
    write(root, "src/another.ts", "export const handler = ((() => {}) satisfies () => void);\n");
    const tip = commit(root, "wrapped empty exports");
    expect((await scanCriticalTree(root, tip)).filter((finding) => finding.kind === "empty-export")).toHaveLength(2);
  });

  test("kills wrapped references to local empty default exports", async () => {
    const { root } = fixtureRepository();
    write(root, "src/protocol.ts", "function handler() {}\nexport default (handler);\n");
    write(root, "src/as.ts", "function handler() {}\nexport default (handler as () => void);\n");
    write(root, "src/satisfies.ts", "function handler() {}\nexport default (handler satisfies () => void);\n");
    write(root, "src/non-null.ts", "function handler() {}\nexport default handler!;\n");
    const tip = commit(root, "wrapped default references");
    expect((await scanCriticalTree(root, tip)).filter((finding) => finding.kind === "empty-export")).toHaveLength(4);
  });

  test("requires distinct service logic and schema or fixture bytes", () => {
    const { root, base } = fixtureRepository();
    write(root, "service/service.config.ts", "export const service = 'renamed';\n");
    const tip = commit(root, "metadata only");
    expect(verifyExtensionDelta(root, base, tip).map((finding) => finding.detail)).toEqual([
      "fresh exemplar must change service logic",
      "fresh exemplar must change schema or fixtures",
    ]);
  });
});

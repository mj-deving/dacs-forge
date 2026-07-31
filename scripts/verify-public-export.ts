#!/usr/bin/env bun

import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import releaseManifest from "../release/release-manifest.json";

const FORBIDDEN_EXACT_PATHS = new Set(["AGENTS.md", "ISA.md"]);
const FORBIDDEN_PREFIXES = [[".", "beads/"].join(""), "Plans/", "Probes/", "evidence/"] as const;
const FORBIDDEN_PATH_SEGMENTS = new Set(["AGENTS.md", "ISA.md", [".", "beads"].join(""), "Plans", "Probes", "evidence"]);
const PUBLIC_EVIDENCE_PREFIXES = ["evidence/reviews/live-demos-profile/"] as const;
const FORBIDDEN_CONTENT = [
  { id: "local-home-path", pattern: new RegExp(["/", "home", "/", "mj", "/"].join("")) },
  { id: "private-bead-id", pattern: new RegExp(["DACS", "-standard-", "[a-z0-9]+(?:\\.[0-9]+)+"].join(""), "i") },
  { id: "goal-runtime-field", pattern: new RegExp(["goal", "_(?:id|thread_id)"].join("")) },
  { id: "worker-incarnation", pattern: new RegExp(["mj-deving", "@codex-"].join("")) },
  { id: "beads-path", pattern: new RegExp(["\\.", "beads", "\\/"].join("")) },
] as const;
const MAX_SCANNED_FILE_BYTES = 4 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function sha256(bytes: Uint8Array | string): string {
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

function gitBytes(root: string, args: readonly string[], maxBuffer = 16 * 1024 * 1024): Buffer {
  const result = spawnSync("git", args, { cwd: root, encoding: "buffer", maxBuffer });
  if (result.status !== 0 || result.error !== undefined) {
    throw new Error(`public export scan failed: git ${args[0] ?? "command"}`);
  }
  return result.stdout;
}

function decodeText(bytes: Uint8Array, surface: string): string {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch {
    throw new Error(`public export contains non-UTF-8 ${surface}`);
  }
}

function gitText(root: string, args: readonly string[]): string {
  return decodeText(gitBytes(root, args), `git ${args[0] ?? "output"}`);
}

export function isPublicPathAllowed(path: string): boolean {
  if (FORBIDDEN_EXACT_PATHS.has(path)) return false;
  const segments = path.split("/");
  const evidencePrefix = PUBLIC_EVIDENCE_PREFIXES.find((prefix) => path.startsWith(prefix));
  if (evidencePrefix !== undefined) {
    const suffix = path.slice(evidencePrefix.length);
    return suffix.length > 0
      && !suffix.split("/").some((segment) => segment.length === 0 || FORBIDDEN_PATH_SEGMENTS.has(segment));
  }
  return !FORBIDDEN_PREFIXES.some((prefix) => path.startsWith(prefix))
    && !segments.some((segment) => FORBIDDEN_PATH_SEGMENTS.has(segment));
}

function assertPublicPath(path: string, surface = path): void {
  if (!isPublicPathAllowed(path)) {
    throw new Error(`public export contains forbidden path: ${surface}`);
  }
  assertPublicText(path, `path name: ${surface}`);
}

function assertPublicText(text: string, surface: string): void {
  for (const rule of FORBIDDEN_CONTENT) {
    if (rule.pattern.test(text)) throw new Error(`public export contains ${rule.id}: ${surface}`);
  }
}

function verifyReachableHistory(root: string, historyBase: string): Readonly<{
  base: string;
  commits: number;
  blobs: number;
  inventorySha256: string;
}> {
  if (!/^[0-9a-f]{40}$/.test(historyBase)) throw new Error("public export history base is invalid");
  gitBytes(root, ["merge-base", "--is-ancestor", historyBase, "HEAD"]);
  const commits = gitText(root, ["rev-list", "--topo-order", "HEAD", `^${historyBase}`]).trim().split("\n").filter(Boolean);
  if (commits.length === 0) throw new Error("public export history range is empty");
  for (const commit of commits) {
    assertPublicText(decodeText(gitBytes(root, ["cat-file", "commit", commit]), `commit ${commit}`), `commit ${commit}`);
    const changedPaths = decodeText(
      gitBytes(root, ["diff-tree", "--root", "-m", "--no-commit-id", "--name-only", "-r", "-z", commit]),
      `paths for commit ${commit}`,
    ).split("\0").filter(Boolean);
    for (const path of changedPaths) assertPublicPath(path, `${path} at ${commit}`);
  }

  const objectIds = [...new Set(
    gitText(root, ["rev-list", "--objects", "HEAD", `^${historyBase}`])
      .split("\n")
      .map((line) => line.slice(0, 40))
      .filter((value) => /^[0-9a-f]{40}$/.test(value)),
  )].sort();
  const blobInventory: string[] = [];
  for (const objectId of objectIds) {
    if (gitText(root, ["cat-file", "-t", objectId]).trim() !== "blob") continue;
    const size = Number(gitText(root, ["cat-file", "-s", objectId]).trim());
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_SCANNED_FILE_BYTES) {
      throw new Error(`public export history blob exceeds scan bound: ${objectId}`);
    }
    const bytes = gitBytes(root, ["cat-file", "blob", objectId], MAX_SCANNED_FILE_BYTES + 1);
    assertPublicText(decodeText(bytes, `history blob ${objectId}`), `history blob ${objectId}`);
    blobInventory.push(`${objectId}\0${sha256(bytes)}`);
  }
  return Object.freeze({
    base: historyBase,
    commits: commits.length,
    blobs: blobInventory.length,
    inventorySha256: sha256([...commits, ...blobInventory].join("\n")),
  });
}

export function verifyPublicExport(root: string, historyBase?: string): Readonly<{
  schema: string;
  trackedFiles: number;
  inventorySha256: string;
  history: ReturnType<typeof verifyReachableHistory> | null;
}> {
  const paths = gitText(root, ["ls-files", "-z"]).split("\0").filter(Boolean).sort();
  const inventory: string[] = [];
  for (const path of paths) {
    assertPublicPath(path);
    const absolute = resolve(root, path);
    const status = lstatSync(absolute);
    if (!status.isFile() || status.isSymbolicLink()) throw new Error(`public export path is not a regular file: ${path}`);
    if (status.size > MAX_SCANNED_FILE_BYTES) throw new Error(`public export file exceeds scan bound: ${path}`);
    const bytes = readFileSync(absolute);
    const text = decodeText(bytes, `file: ${path}`);
    assertPublicText(text, path);
    inventory.push(`${path}\0${sha256(bytes)}`);
  }
  return Object.freeze({
    schema: "dacs-forge-public-export-verification/v2",
    trackedFiles: paths.length,
    inventorySha256: sha256(inventory.join("\n")),
    history: historyBase === undefined ? null : verifyReachableHistory(root, historyBase),
  });
}

if (import.meta.main) {
  console.log(JSON.stringify(verifyPublicExport(resolve(import.meta.dir, ".."), releaseManifest.sourceBinding.historyBase)));
}

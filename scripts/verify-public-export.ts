#!/usr/bin/env bun

import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const FORBIDDEN_EXACT_PATHS = new Set(["AGENTS.md", "ISA.md"]);
const FORBIDDEN_PREFIXES = [[".", "beads/"].join(""), "Plans/", "Probes/", "evidence/"] as const;
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

function trackedPaths(root: string): string[] {
  const result = spawnSync("git", ["ls-files", "-z"], { cwd: root, encoding: "buffer" });
  if (result.status !== 0) throw new Error("public export scan could not enumerate tracked files");
  return new TextDecoder().decode(result.stdout).split("\0").filter(Boolean).sort();
}

export function verifyPublicExport(root: string): Readonly<{ schema: string; trackedFiles: number; inventorySha256: string }> {
  const paths = trackedPaths(root);
  const inventory: string[] = [];
  for (const path of paths) {
    if (FORBIDDEN_EXACT_PATHS.has(path) || FORBIDDEN_PREFIXES.some((prefix) => path.startsWith(prefix))) {
      throw new Error(`public export contains forbidden path: ${path}`);
    }
    const absolute = resolve(root, path);
    const status = lstatSync(absolute);
    if (!status.isFile() || status.isSymbolicLink()) throw new Error(`public export path is not a regular file: ${path}`);
    if (status.size > MAX_SCANNED_FILE_BYTES) throw new Error(`public export file exceeds scan bound: ${path}`);
    const bytes = readFileSync(absolute);
    let text: string;
    try {
      text = UTF8_DECODER.decode(bytes);
    } catch {
      throw new Error(`public export contains a non-UTF-8 file: ${path}`);
    }
    for (const rule of FORBIDDEN_CONTENT) {
      if (rule.pattern.test(text)) throw new Error(`public export contains ${rule.id}: ${path}`);
    }
    inventory.push(`${path}\0${sha256(bytes)}`);
  }
  return Object.freeze({
    schema: "dacs-forge-public-export-verification/v1",
    trackedFiles: paths.length,
    inventorySha256: sha256(inventory.join("\n")),
  });
}

if (import.meta.main) console.log(JSON.stringify(verifyPublicExport(resolve(import.meta.dir, ".."))));

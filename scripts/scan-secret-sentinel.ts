#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { basename, isAbsolute, join } from "node:path";

const SENTINEL_ENV = "DACS_FORGE_SECRET_SENTINEL";
const MAX_FILES = 10_000;
const MAX_ENTRIES = 2_048;
const MAX_DEPTH = 64;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const SENTINEL_PATTERN = /^sentinel-[a-z0-9-]{1,32}-[0-9a-f]{32}$/;

interface ScanState {
  entriesScanned: number;
  filesScanned: number;
  filesWithMatches: Set<string>;
  pathsWithMatches: Set<string>;
  matches: number;
  scanFailures: number;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function variants(sentinel: string): readonly string[] {
  const bytes = Buffer.from(sentinel, "utf8");
  const base64 = bytes.toString("base64");
  const base64url = bytes.toString("base64url");
  return [
    sentinel,
    base64,
    base64.replace(/=+$/u, ""),
    base64url,
    `${base64url}${"=".repeat((4 - (base64url.length % 4)) % 4)}`,
  ];
}

function decodePercentEscapes(value: string): string {
  return value.replace(/%([0-9a-f]{2})/giu, (_match, pair: string) =>
    String.fromCharCode(Number.parseInt(pair, 16)));
}

function decodeJsonUnicodeEscapes(value: string): string {
  return value.replace(/\\u([0-9a-f]{4})/giu, (_match, digits: string) =>
    String.fromCharCode(Number.parseInt(digits, 16)));
}

function countMatches(value: string, needles: readonly string[]): number {
  let matches = 0;
  for (const needle of needles) {
    if (needle.length === 0) continue;
    let offset = 0;
    while (true) {
      const found = value.indexOf(needle, offset);
      if (found === -1) break;
      matches += 1;
      offset = found + Math.max(needle.length, 1);
    }
  }
  return matches;
}

function countEncodedMatches(value: string, sentinel: string, needles: readonly string[]): number {
  const hex = Buffer.from(sentinel, "utf8").toString("hex");
  return countMatches(value, needles)
    + countMatches(value.toLowerCase(), [hex])
    + countMatches(decodePercentEscapes(value), [sentinel])
    + countMatches(decodeJsonUnicodeEscapes(value), [sentinel]);
}

function scanPath(
  absolutePath: string,
  opaquePathId: string,
  sentinel: string,
  needles: readonly string[],
  state: ScanState,
  depth = 0,
): void {
  if (depth > MAX_DEPTH || state.entriesScanned >= MAX_ENTRIES) {
    state.scanFailures += 1;
    return;
  }
  state.entriesScanned += 1;
  const pathMatches = countEncodedMatches(basename(absolutePath), sentinel, needles);
  if (pathMatches > 0) {
    state.pathsWithMatches.add(opaquePathId);
    state.matches += pathMatches;
  }
  let metadata: ReturnType<typeof lstatSync>;
  try {
    metadata = lstatSync(absolutePath);
  } catch {
    state.scanFailures += 1;
    return;
  }
  if (metadata.isSymbolicLink()) {
    state.scanFailures += 1;
    return;
  }
  if (metadata.isDirectory()) {
    let entries: string[];
    try {
      entries = readdirSync(absolutePath).sort();
    } catch {
      state.scanFailures += 1;
      return;
    }
    if (entries.length > MAX_ENTRIES - state.entriesScanned) {
      state.scanFailures += 1;
      return;
    }
    for (const entry of entries) {
      scanPath(
        join(absolutePath, entry),
        `${opaquePathId}/${digest(entry)}`,
        sentinel,
        needles,
        state,
        depth + 1,
      );
    }
    return;
  }
  if (state.filesScanned >= MAX_FILES) {
    state.scanFailures += 1;
    return;
  }
  if (!metadata.isFile() || metadata.size > MAX_FILE_BYTES) {
    state.scanFailures += 1;
    return;
  }

  state.filesScanned += 1;
  let bytes: Buffer;
  try {
    bytes = readFileSync(absolutePath);
  } catch {
    state.scanFailures += 1;
    return;
  }
  const contentMatches = countEncodedMatches(bytes.toString("utf8"), sentinel, needles);
  if (contentMatches > 0) {
    state.filesWithMatches.add(opaquePathId);
    state.matches += contentMatches;
  }
}

function emitReport(
  sentinelDigest: string,
  state: ScanState,
  result: "accepted" | "rejected" | "invalid",
): void {
  process.stdout.write(`${JSON.stringify({
    schema: "dacs-forge-secret-boundary/v1",
    sentinelSha256: sentinelDigest,
    result,
    rootsScanned: result === "invalid" ? 0 : 1,
    entriesScanned: state.entriesScanned,
    filesScanned: state.filesScanned,
    filesWithMatches: state.filesWithMatches.size,
    pathsWithMatches: state.pathsWithMatches.size,
    matches: state.matches,
    scanFailures: state.scanFailures,
  })}\n`);
}

function invalid(): never {
  emitReport("unavailable", {
    entriesScanned: 0,
    filesScanned: 0,
    filesWithMatches: new Set(),
    pathsWithMatches: new Set(),
    matches: 0,
    scanFailures: 1,
  }, "invalid");
  process.exit(2);
}

const sentinel = process.env[SENTINEL_ENV];
const args = Bun.argv.slice(2);
if (typeof sentinel !== "string" || !SENTINEL_PATTERN.test(sentinel)
  || args.length !== 2 || args[0] !== "--root" || !isAbsolute(args[1] ?? "")) {
  invalid();
}

const state: ScanState = {
  entriesScanned: 0,
  filesScanned: 0,
  filesWithMatches: new Set(),
  pathsWithMatches: new Set(),
  matches: 0,
  scanFailures: 0,
};
scanPath(args[1]!, "root", sentinel, variants(sentinel), state);
const accepted = state.matches === 0 && state.scanFailures === 0;
emitReport(digest(sentinel), state, accepted ? "accepted" : "rejected");
process.exit(accepted ? 0 : 1);

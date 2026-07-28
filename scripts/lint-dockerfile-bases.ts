#!/usr/bin/env bun

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const DIGEST_PIN = /@sha256:[0-9a-f]{64}$/;

export type DockerfileBase = Readonly<{
  line: number;
  reference: string;
}>;

export function dockerfileBases(source: string): readonly DockerfileBase[] {
  const logicalLines = source.replaceAll(/\\\r?\n/g, " ").split(/\r?\n/);
  const aliases = new Set<string>();
  const bases: DockerfileBase[] = [];

  for (const [index, line] of logicalLines.entries()) {
    const match = /^\s*FROM\s+(.+?)\s*$/i.exec(line);
    if (!match) continue;
    const tokens = match[1]!.split(/\s+/).filter(Boolean);
    while (tokens[0]?.startsWith("--")) tokens.shift();
    const reference = tokens.shift();
    if (!reference) throw new Error(`Dockerfile FROM at line ${index + 1} has no image reference`);
    const referencesExistingStage = aliases.has(reference.toLowerCase());
    const asIndex = tokens.findIndex((token) => token.toUpperCase() === "AS");
    if (asIndex >= 0 && tokens[asIndex + 1]) aliases.add(tokens[asIndex + 1]!.toLowerCase());
    if (!referencesExistingStage) bases.push({ line: index + 1, reference });
  }
  if (bases.length === 0) throw new Error("Dockerfile contains no external FROM reference");
  return bases;
}

export function verifyDockerfileBases(path: string): readonly DockerfileBase[] {
  const bases = dockerfileBases(readFileSync(path, "utf8"));
  const mutable = bases.filter(({ reference }) => !DIGEST_PIN.test(reference));
  if (mutable.length > 0) {
    throw new Error(`tag-only Dockerfile base: ${mutable.map(({ line, reference }) => `${line}:${reference}`).join(", ")}`);
  }
  return bases;
}

if (import.meta.main) {
  const path = resolve(process.argv[2] ?? resolve(import.meta.dir, "..", "Dockerfile"));
  const bases = verifyDockerfileBases(path);
  console.log(`Dockerfile bases verified: ${bases.map(({ reference }) => reference).join(", ")}`);
}

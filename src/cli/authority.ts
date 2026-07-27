import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  recoverAdministrator,
  rotateCloneAuthority,
  type OfflineAuthorityOptions,
} from "../substrate/authority-offline.ts";

const MAX_INPUT_BYTES = 65_536;

export interface AuthorityCliIO {
  readonly stdout: (value: string) => void;
  readonly stderr: (value: string) => void;
}

export interface AuthorityCliAdapter {
  readonly keyCurrentness: OfflineAuthorityOptions["keyCurrentness"];
  readonly proofVerifier: OfflineAuthorityOptions["proofVerifier"];
  readonly now?: OfflineAuthorityOptions["now"];
  readonly randomBytes?: OfflineAuthorityOptions["randomBytes"];
}

export const AUTHORITY_USAGE = `Usage:
  dacs authority bootstrap prepare --input <absolute-json-file> --database <absolute-sqlite-file>
  dacs authority bootstrap complete --input <absolute-json-file> --database <absolute-sqlite-file> --adapter <absolute-module>
  dacs authority recover --input <absolute-json-file> --database <absolute-sqlite-file> --adapter <absolute-module>
  dacs authority clone-rotate --input <absolute-json-file> --database <absolute-sqlite-file> --adapter <absolute-module>`;

export async function runAuthorityCli(
  args: readonly string[],
  io: AuthorityCliIO,
): Promise<number> {
  try {
    if (args.includes("--help") || args.includes("-h")) {
      io.stdout(`${AUTHORITY_USAGE}\n`);
      return 0;
    }
    const command = commandName(args);
    const flags = parseFlags(args.slice(command.consumed));
    const input = readJson(flags["input"], command.name === "clone-rotate");
    if (command.name === "bootstrap-prepare") {
      requireExactFlags(flags, ["database", "input"]);
      const databasePath = absolutePath(flags["database"]!, "--database");
      const request = prepareAuthorityBootstrap(Object.assign(
        Object.create(null) as Record<string, unknown>,
        input,
        { storeBinding: authorityStoreBinding(databasePath) },
      ) as never);
      io.stdout(`${JSON.stringify({
        schema: "dacs-authority-bootstrap-request/v1",
        request,
        signingBytes: authorityBootstrapSigningBytes(request),
      })}\n`);
      return 0;
    }
    requireExactFlags(flags, ["adapter", "database", "input"]);
    const adapter = await loadAdapter(flags["adapter"]!);
    const options: OfflineAuthorityOptions = {
      databasePath: absolutePath(flags["database"]!, "--database"),
      keyCurrentness: adapter.keyCurrentness,
      proofVerifier: adapter.proofVerifier,
      ...(adapter.now === undefined ? {} : { now: adapter.now }),
      ...(adapter.randomBytes === undefined ? {} : { randomBytes: adapter.randomBytes }),
    };
    const result = command.name === "bootstrap-complete"
      ? completeAuthorityBootstrap(input as never, options)
      : command.name === "recover"
        ? recoverAdministrator(input as never, options)
        : rotateCloneAuthority(input as never, options);
    io.stdout(`${JSON.stringify({ schema: "dacs-authority-operation/v1", result })}\n`);
    return 0;
  } catch (error) {
    const usage = error instanceof AuthorityCliUsageError;
    const message = error instanceof Error && error.message.length <= 1_024
      ? error.message : "Unexpected authority command failure";
    io.stderr(`dacs: ${usage ? "" : "authority error: "}${message}\n`);
    if (usage) io.stderr("Run 'dacs authority --help' for usage.\n");
    return usage ? 2 : 4;
  }
}

class AuthorityCliUsageError extends Error {}

function commandName(args: readonly string[]): Readonly<{
  readonly name: "bootstrap-prepare" | "bootstrap-complete" | "recover" | "clone-rotate";
  readonly consumed: number;
}> {
  if (args[0] === "bootstrap" && args[1] === "prepare") {
    return { name: "bootstrap-prepare", consumed: 2 };
  }
  if (args[0] === "bootstrap" && args[1] === "complete") {
    return { name: "bootstrap-complete", consumed: 2 };
  }
  if (args[0] === "recover") return { name: "recover", consumed: 1 };
  if (args[0] === "clone-rotate") return { name: "clone-rotate", consumed: 1 };
  throw new AuthorityCliUsageError("Unknown authority command");
}

function parseFlags(args: readonly string[]): Record<string, string> {
  const flags: Record<string, string> = Object.create(null) as Record<string, string>;
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (name === undefined || value === undefined || !name.startsWith("--")
      || value.startsWith("--")) throw new AuthorityCliUsageError("Authority flags require values");
    const key = name.slice(2);
    if (!/^[a-z]+$/.test(key) || Object.hasOwn(flags, key)) {
      throw new AuthorityCliUsageError(`Invalid or repeated authority flag: ${name}`);
    }
    flags[key] = value;
  }
  return flags;
}

function requireExactFlags(flags: Record<string, string>, expected: readonly string[]): void {
  const actual = Object.keys(flags).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new AuthorityCliUsageError(`Expected flags: ${wanted.map((key) => `--${key}`).join(", ")}`);
  }
}

function absolutePath(path: string, flag: string): string {
  if (!isAbsolute(path) || path.length > 4_096) {
    throw new AuthorityCliUsageError(`${flag} must be a bounded absolute path`);
  }
  return resolve(path);
}

function readJson(path: string | undefined, sensitive = false): unknown {
  if (path === undefined) throw new AuthorityCliUsageError("--input is required");
  const resolved = absolutePath(path, "--input");
  let descriptor: number;
  try {
    descriptor = openSync(
      resolved,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
  } catch {
    throw new AuthorityCliUsageError("Authority input must be a non-symlink regular JSON file");
  }
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) throw new AuthorityCliUsageError("Authority input must be a regular JSON file");
    const processUid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (sensitive && (processUid === undefined || metadata.uid !== processUid
      || (metadata.mode & 0o777) !== 0o600)) {
      throw new AuthorityCliUsageError("Sensitive authority input must be process-owned mode 0600");
    }
    const bytes = Buffer.allocUnsafe(MAX_INPUT_BYTES + 1);
    let length = 0;
    while (length < bytes.byteLength) {
      const read = readSync(descriptor, bytes, length, bytes.byteLength - length, null);
      if (read === 0) break;
      length += read;
    }
    if (length < 2 || length > MAX_INPUT_BYTES) {
      throw new AuthorityCliUsageError("Authority input must be bounded JSON");
    }
    return JSON.parse(bytes.subarray(0, length).toString("utf8")) as unknown;
  } finally {
    closeSync(descriptor);
  }
}

async function loadAdapter(path: string): Promise<AuthorityCliAdapter> {
  const resolved = absolutePath(path, "--adapter");
  const imported = await import(pathToFileURL(resolved).href) as { default?: unknown };
  const adapter = imported.default;
  if (adapter === null || typeof adapter !== "object"
    || typeof (adapter as AuthorityCliAdapter).keyCurrentness?.resolve !== "function"
    || typeof (adapter as AuthorityCliAdapter).proofVerifier?.verify !== "function") {
    throw new Error("Authority adapter must export keyCurrentness and proofVerifier");
  }
  return adapter as AuthorityCliAdapter;
}

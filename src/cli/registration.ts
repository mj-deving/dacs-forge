import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  executeRegistrationCommand,
  type RegistrationAdapter,
  type RegistrationCommandInput,
} from "../directory/registration-command.ts";

const MAX_INPUT_BYTES = 262_144;

export interface RegistrationCliIO {
  readonly stdout: (value: string) => void;
  readonly stderr: (value: string) => void;
}

export const REGISTRATION_USAGE = `Usage:
  dacs register --input <absolute-json-file> --adapter <absolute-module>`;

export async function runRegistrationCli(
  args: readonly string[],
  io: RegistrationCliIO,
): Promise<number> {
  try {
    if (args.includes("--help") || args.includes("-h")) {
      io.stdout(`${REGISTRATION_USAGE}\n`);
      return 0;
    }
    const flags = parseFlags(args);
    requireExactFlags(flags, ["adapter", "input"]);
    const input = readJson(flags["input"]!) as RegistrationCommandInput;
    const adapter = await loadAdapter(flags["adapter"]!);
    const receipt = executeRegistrationCommand(input, adapter);
    io.stdout(`${JSON.stringify(receipt)}\n`);
    return 0;
  } catch (error) {
    const usage = error instanceof RegistrationCliUsageError;
    const message = error instanceof Error && error.message.length <= 1_024
      ? error.message : "Unexpected registration command failure";
    io.stderr(`dacs: ${usage ? "" : "registration error: "}${message}\n`);
    if (usage) io.stderr("Run 'dacs register --help' for usage.\n");
    return usage ? 2 : 4;
  }
}

class RegistrationCliUsageError extends Error {}

function parseFlags(args: readonly string[]): Record<string, string> {
  const flags: Record<string, string> = Object.create(null) as Record<string, string>;
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (name === undefined || value === undefined || !name.startsWith("--")
      || value.startsWith("--")) throw new RegistrationCliUsageError("Registration flags require values");
    const key = name.slice(2);
    if (!/^[a-z]+$/.test(key) || Object.hasOwn(flags, key)) {
      throw new RegistrationCliUsageError("Invalid or repeated registration flag");
    }
    flags[key] = value;
  }
  return flags;
}

function requireExactFlags(flags: Record<string, string>, expected: readonly string[]): void {
  const actual = Object.keys(flags).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new RegistrationCliUsageError(`Expected flags: ${wanted.map((key) => `--${key}`).join(", ")}`);
  }
}

function absolutePath(path: string, flag: string): string {
  if (!isAbsolute(path) || path.length > 4_096) {
    throw new RegistrationCliUsageError(`${flag} must be a bounded absolute path`);
  }
  return resolve(path);
}

function readJson(path: string | undefined): unknown {
  if (path === undefined) throw new RegistrationCliUsageError("--input is required");
  const resolved = absolutePath(path, "--input");
  let descriptor: number;
  try {
    descriptor = openSync(resolved, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    throw new RegistrationCliUsageError("Registration input must be a non-symlink regular JSON file");
  }
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) throw new RegistrationCliUsageError("Registration input must be a regular JSON file");
    const bytes = Buffer.allocUnsafe(MAX_INPUT_BYTES + 1);
    let length = 0;
    while (length < bytes.byteLength) {
      const read = readSync(descriptor, bytes, length, bytes.byteLength - length, null);
      if (read === 0) break;
      length += read;
    }
    if (length < 2 || length > MAX_INPUT_BYTES) {
      throw new RegistrationCliUsageError("Registration input must be bounded JSON");
    }
    return JSON.parse(bytes.subarray(0, length).toString("utf8")) as unknown;
  } finally {
    closeSync(descriptor);
  }
}

async function loadAdapter(path: string): Promise<RegistrationAdapter> {
  const resolved = absolutePath(path, "--adapter");
  const imported = await import(pathToFileURL(resolved).href) as { default?: unknown };
  const adapter = imported.default;
  if (adapter === null || typeof adapter !== "object"
    || (adapter as Partial<RegistrationAdapter>).executionMode !== "fixture-no-spend"
    || typeof (adapter as RegistrationAdapter).authorizeOperator !== "function"
    || typeof (adapter as RegistrationAdapter).readAnchor !== "function"
    || typeof (adapter as RegistrationAdapter).register !== "function"
    || typeof (adapter as RegistrationAdapter).readRegistration !== "function") {
    throw new Error("Registration adapter must declare fixture-no-spend mode and export authorizeOperator, readAnchor, register, and readRegistration");
  }
  return adapter as RegistrationAdapter;
}

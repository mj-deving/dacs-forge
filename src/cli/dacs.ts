#!/usr/bin/env bun

import { types as utilTypes } from "node:util";
import { parseEvidenceMode, type EvidenceMode } from "../core/evidence-mode.ts";
import {
  assertDoctorReport,
  doctorPackageVersion,
  runDoctor,
  serializeDoctorReport,
  type DoctorReport,
} from "../readiness/doctor.ts";
import { runAuthorityCli } from "./authority.ts";
import { runRegistrationCli } from "./registration.ts";

export interface CliIO {
  readonly stdout: (value: string) => void;
  readonly stderr: (value: string) => void;
}

export interface CliEnvironment {
  readonly NO_COLOR?: string;
  readonly TERM?: string;
  readonly [key: string]: string | undefined;
}

export const USAGE = `Usage:
  dacs --help
  dacs --version
  dacs doctor [--json] [--no-input] [--no-color] [--evidence-mode <fixture|local-chain|live>]
  dacs authority <bootstrap|recover|clone-rotate> [options]
  dacs register --input <absolute-json-file> --adapter <absolute-module>
`;

const intrinsicGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const intrinsicOwnKeys = Reflect.ownKeys;
const intrinsicDefineProperty = Object.defineProperty;
const intrinsicFreeze = Object.freeze;
const intrinsicHasOwn = Object.hasOwn;
const intrinsicIsProxy = utilTypes.isProxy;
const intrinsicIsArray = Array.isArray;
const intrinsicIsSafeInteger = Number.isSafeInteger;
const intrinsicStartsWith = String.prototype.startsWith;
const intrinsicTrimEnd = String.prototype.trimEnd;
const intrinsicCharCodeAt = String.prototype.charCodeAt;
const intrinsicSlice = String.prototype.slice;
const intrinsicApply = Reflect.apply;
const intrinsicWeakSetAdd = WeakSet.prototype.add;
const intrinsicWeakSetHas = WeakSet.prototype.has;
const IntrinsicTypeError = TypeError;
const IntrinsicString = String;
const usageErrors = new WeakSet<object>();
const MAX_ARGUMENT_LENGTH = 4096;
const MAX_ARGUMENT_TOTAL = 16_384;
const MAX_EXTERNAL_MESSAGE_LENGTH = 1024;

class UsageError extends Error {
  override readonly name = "UsageError";

  constructor(message: string) {
    super(message);
    intrinsicApply(intrinsicWeakSetAdd, usageErrors, [this]);
  }
}

function isUsageError(value: unknown): boolean {
  return value !== null && (typeof value === "object" || typeof value === "function")
    && intrinsicApply(intrinsicWeakSetHas, usageErrors, [value]) === true;
}

function ownStringDataProperty(value: unknown, key: string): string | undefined {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return undefined;
  if (intrinsicIsProxy(value)) return undefined;
  try {
    const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && intrinsicHasOwn(descriptor, "value")
      && typeof descriptor.value === "string" ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function startsWith(value: string, prefix: string): boolean {
  return intrinsicApply(intrinsicStartsWith, value, [prefix]) as boolean;
}

function trimEnd(value: string): string {
  return intrinsicApply(intrinsicTrimEnd, value, []) as string;
}

function safeThrowableMessage(value: unknown): string {
  const message = ownStringDataProperty(value, "message");
  if (message === undefined || message.length > MAX_EXTERNAL_MESSAGE_LENGTH) {
    return "Unexpected doctor failure";
  }
  let normalized = "";
  for (let index = 0; index < message.length; index += 1) {
    const code = intrinsicApply(intrinsicCharCodeAt, message, [index]) as number;
    normalized += code <= 0x1f || (code >= 0x7f && code <= 0x9f)
      ? " " : intrinsicApply(intrinsicSlice, message, [index, index + 1]) as string;
  }
  return normalized;
}

function ownCallableDataProperty(value: unknown, key: string): (text: string) => void {
  if (value === null || typeof value !== "object" || intrinsicIsProxy(value)) {
    throw new IntrinsicTypeError("CLI IO must be a plain object");
  }
  const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !intrinsicHasOwn(descriptor, "value")
    || typeof descriptor.value !== "function" || intrinsicIsProxy(descriptor.value)) {
    throw new IntrinsicTypeError(`CLI ${key} must be an own non-proxy function`);
  }
  return descriptor.value as (text: string) => void;
}

function snapshotCliIo(value: CliIO): CliIO {
  return intrinsicFreeze({
    stdout: ownCallableDataProperty(value, "stdout"),
    stderr: ownCallableDataProperty(value, "stderr"),
  });
}

function snapshotCliArgs(value: readonly string[]): readonly string[] {
  if (!intrinsicIsArray(value) || intrinsicIsProxy(value)) {
    throw new IntrinsicTypeError("CLI arguments must be an array");
  }
  const lengthDescriptor = intrinsicGetOwnPropertyDescriptor(value, "length");
  const length = lengthDescriptor !== undefined && intrinsicHasOwn(lengthDescriptor, "value")
    ? lengthDescriptor.value : undefined;
  if (typeof length !== "number" || !intrinsicIsSafeInteger(length) || length < 0 || length > 128
    || intrinsicOwnKeys(value).length !== length + 1) {
    throw new IntrinsicTypeError("CLI arguments must be a dense bounded array");
  }
  const snapshot: string[] = [];
  let totalLength = 0;
  for (let index = 0; index < length; index += 1) {
    const descriptor = intrinsicGetOwnPropertyDescriptor(value, IntrinsicString(index));
    if (descriptor === undefined || !intrinsicHasOwn(descriptor, "value")
      || typeof descriptor.value !== "string") {
      throw new IntrinsicTypeError("CLI arguments must contain own string data properties");
    }
    if (descriptor.value.length > MAX_ARGUMENT_LENGTH) {
      throw new UsageError("CLI argument exceeds 4096 characters");
    }
    totalLength += descriptor.value.length;
    if (totalLength > MAX_ARGUMENT_TOTAL) {
      throw new UsageError("CLI arguments exceed 16384 total characters");
    }
    intrinsicDefineProperty(snapshot, IntrinsicString(index), {
      configurable: true,
      enumerable: true,
      value: descriptor.value,
      writable: true,
    });
  }
  return intrinsicFreeze(snapshot);
}

function includes(values: readonly string[], expected: string): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === expected) return true;
  }
  return false;
}

function tail(values: readonly string[]): readonly string[] {
  const result: string[] = [];
  for (let index = 1; index < values.length; index += 1) {
    intrinsicDefineProperty(result, IntrinsicString(index - 1), {
      configurable: true,
      enumerable: true,
      value: values[index],
      writable: true,
    });
  }
  return intrinsicFreeze(result);
}

function writeLine(write: (value: string) => void, value: string): void {
  intrinsicApply(write, undefined, [`${value}\n`]);
}

function bestEffortWriteLine(write: (value: string) => void, value: string): void {
  try {
    writeLine(write, value);
  } catch {
    // A diagnostic writer must not turn a handled CLI failure into a rejection.
  }
}

function readFlagValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || startsWith(value, "-")) throw new UsageError(`${flag} requires a value`);
  return value;
}

function parseDoctorArgs(args: readonly string[]): {
  readonly json: boolean;
  readonly evidenceMode: EvidenceMode;
} {
  let json = false;
  let evidenceMode: EvidenceMode = "fixture";
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--json") json = true;
    else if (arg === "--no-input" || arg === "--no-color") continue;
    else if (arg === "--evidence-mode") {
      try {
        evidenceMode = parseEvidenceMode(readFlagValue(args, index, arg));
      } catch {
        throw new UsageError("Invalid evidence mode; expected fixture | local-chain | live");
      }
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      throw new UsageError(trimEnd(USAGE));
    } else {
      throw new UsageError("Unknown doctor option");
    }
  }
  return intrinsicFreeze({ json, evidenceMode });
}

function formatDoctor(report: DoctorReport): string {
  const lines = [
    `DACS doctor: ${report.ready ? "ready" : "not ready"}`,
    `evidence mode: ${report.evidenceMode}`,
  ];
  for (const item of report.checks) {
    lines.push(`${item.status.padEnd(14)} ${item.id}${item.reason ? `: ${item.reason}` : ""}`);
  }
  return lines.join("\n");
}

export async function runCli(
  args: readonly string[],
  io: CliIO,
  _environment: CliEnvironment = process.env,
): Promise<number> {
  let writers: CliIO;
  try {
    writers = snapshotCliIo(io);
  } catch {
    return 4;
  }
  try {
    const snapshot = snapshotCliArgs(args);
    if (includes(snapshot, "--help") || includes(snapshot, "-h") || snapshot[0] === "help") {
      writeLine(writers.stdout, trimEnd(USAGE));
      return 0;
    }
    if (snapshot.length === 1 && snapshot[0] === "--version") {
      writeLine(writers.stdout, doctorPackageVersion());
      return 0;
    }
    if (snapshot[0] === "authority") {
      return runAuthorityCli(tail(snapshot), writers);
    }
    if (snapshot[0] === "register") {
      return runRegistrationCli(tail(snapshot), writers);
    }
    if (snapshot[0] !== "doctor") {
      throw new UsageError(snapshot.length === 0
        ? "A command is required" : "Unknown command");
    }
    const parsed = parseDoctorArgs(tail(snapshot));
    const report = runDoctor({ evidenceMode: parsed.evidenceMode });
    assertDoctorReport(report);
    writeLine(writers.stdout, parsed.json ? serializeDoctorReport(report) : formatDoctor(report));
    return report.exitCode;
  } catch (error) {
    const message = safeThrowableMessage(error);
    if (isUsageError(error)) {
      bestEffortWriteLine(writers.stderr, `dacs: ${message}`);
      if (!startsWith(message, "Usage:")) {
        bestEffortWriteLine(writers.stderr, "Run 'dacs --help' for usage.");
      }
      return 2;
    }
    bestEffortWriteLine(writers.stderr, `dacs: internal error: ${message}`);
    return 4;
  }
}

if (import.meta.main) {
  process.exitCode = await runCli(Bun.argv.slice(2), {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
  });
}

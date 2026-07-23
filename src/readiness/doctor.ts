import packageMetadataJson from "../../package.json" with { type: "json" };
import { Buffer } from "node:buffer";
import { types as utilTypes } from "node:util";
import { EVIDENCE_MODES, parseEvidenceMode, type EvidenceMode } from "../core/evidence-mode.ts";
import {
  DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
  isPreparedDirectorySchemaDriftProbe,
} from "./directory-schema-drift.ts";

export const DOCTOR_SCHEMA = "dacs-doctor/v1" as const;
const DOCTOR_STATUS_VALUES = Object.freeze([
  "passed",
  "failed",
  "blocked",
  "not-run",
  "not-applicable",
] as const);
export const DOCTOR_STATUSES = Object.freeze([...DOCTOR_STATUS_VALUES]);

export type DoctorStatus = (typeof DOCTOR_STATUS_VALUES)[number];
export type ProtocolDisposition = "pass" | "fail" | "indeterminate" | "error";

export interface DoctorCheck {
  readonly id: string;
  readonly required: boolean;
  readonly status: DoctorStatus;
  readonly protocolDisposition?: ProtocolDisposition;
  readonly evidenceMode: EvidenceMode;
  readonly sourceRef: string;
  readonly observed: Readonly<Record<string, boolean | number | string>>;
  readonly reason?: string;
}

export interface DoctorReport {
  readonly schema: typeof DOCTOR_SCHEMA;
  readonly service: "dacs-forge";
  readonly version: string;
  readonly generatedAt: string;
  readonly evidenceMode: EvidenceMode;
  readonly ready: boolean;
  readonly exitCode: 0 | 3 | 4 | 5;
  readonly checks: readonly DoctorCheck[];
}

export interface DoctorProbe {
  readonly id: string;
  readonly required: boolean;
  readonly run: () => DoctorCheck;
}

export interface DoctorOptions {
  readonly evidenceMode?: EvidenceMode;
  readonly now?: () => string;
  readonly probes?: readonly DoctorProbe[];
  readonly sensitiveValues?: readonly string[];
}

interface PackageMetadata {
  readonly name?: unknown;
  readonly version?: unknown;
  readonly private?: unknown;
  readonly type?: unknown;
  readonly packageManager?: unknown;
  readonly engines?: Readonly<Record<string, unknown>>;
  readonly bin?: Readonly<Record<string, unknown>>;
}

const intrinsicDefineProperty = Object.defineProperty;
const IntrinsicError = Error;
const TypeError = globalThis.TypeError;
const IntrinsicString = String;
const intrinsicStringFromCodePoint = String.fromCodePoint;
const intrinsicObjectPrototype = Object.prototype;
const intrinsicArrayPrototype = Array.prototype;
const intrinsicArrayUnscopables = Array.prototype[Symbol.unscopables] as object;
const intrinsicStringPrototype = String.prototype;
const intrinsicNumberPrototype = Number.prototype;
const intrinsicBooleanPrototype = Boolean.prototype;
const intrinsicFunctionPrototype = Function.prototype;
const intrinsicRegExpPrototype = RegExp.prototype;
const intrinsicArrayIteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]()) as object;
const intrinsicStringIteratorPrototype = Object.getPrototypeOf(""[Symbol.iterator]()) as object;
const intrinsicRegExpStringIteratorPrototype = Object.getPrototypeOf("".matchAll(/x/g)) as object;
const intrinsicIteratorPrototype = Object.getPrototypeOf(intrinsicArrayIteratorPrototype) as object;
const intrinsicObjectToString = Object.prototype.toString;
const intrinsicObjectValueOf = Object.prototype.valueOf;
const intrinsicObjectIs = Object.is;
const intrinsicArrayToString = Array.prototype.toString;
const intrinsicArrayIterator = Array.prototype[Symbol.iterator];
const intrinsicEntries = Object.entries;
const intrinsicFreeze = Object.freeze;
const intrinsicGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const intrinsicGetPrototypeOf = Object.getPrototypeOf;
const intrinsicSetPrototypeOf = Object.setPrototypeOf;
const intrinsicHasOwn = Object.hasOwn;
const intrinsicIsFinite = Number.isFinite;
const intrinsicIsProxy = utilTypes.isProxy;
const intrinsicKeys = Object.keys;
const intrinsicOwnKeys = Reflect.ownKeys;
const intrinsicValues = Object.values;
const intrinsicBufferByteLength = Buffer.byteLength;

const EXPECTED_BUN_VERSION = "1.3.9";
const MAX_REPORT_WIRE_BYTES = 16_384;
const CORE_CHECK_IDS = intrinsicFreeze([
  "runtime.bun",
  "package.contract",
  "execution.read-only",
  "binding.live-resolution",
  "registration.directory",
  "transport.http",
  "conformance.external-rig",
]);
const intrinsicApply = Reflect.apply;
const intrinsicArrayEvery = intrinsicArrayPrototype.every;
const intrinsicArrayIncludes = intrinsicArrayPrototype.includes;
const intrinsicArrayJoin = intrinsicArrayPrototype.join;
const intrinsicArraySome = intrinsicArrayPrototype.some;
const intrinsicArraySort = intrinsicArrayPrototype.sort;
const intrinsicIsArray = Array.isArray;
const IntrinsicDate = Date;
const intrinsicDateToISOString = Date.prototype.toISOString;
const intrinsicRegExpExec = RegExp.prototype.exec;
const intrinsicStringCharCodeAt = String.prototype.charCodeAt;
const intrinsicStringIncludes = String.prototype.includes;
const intrinsicStringIndexOf = String.prototype.indexOf;
const intrinsicStringSlice = String.prototype.slice;
const intrinsicInspectCustom = Symbol.for("nodejs.util.inspect.custom");
const intrinsicSymbolToPrimitive = Symbol.toPrimitive;
const intrinsicSymbolToStringTag = Symbol.toStringTag;
const intrinsicSymbolIterator = Symbol.iterator;
const intrinsicSymbolAsyncIterator = Symbol.asyncIterator;
const stringifyJson = JSON.stringify;

interface CapturedPrototypeSurface {
  readonly prototype: object;
  readonly parent: object | null;
  readonly keys: readonly PropertyKey[];
  readonly descriptors: readonly PropertyDescriptor[];
}

function capturePrototypeSurface(prototype: object): CapturedPrototypeSurface {
  const keys = intrinsicOwnKeys(prototype);
  const capturedKeys: PropertyKey[] = [];
  const descriptors: PropertyDescriptor[] = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    const descriptor = intrinsicGetOwnPropertyDescriptor(prototype, key)!;
    appendArray(capturedKeys, key);
    appendArray(descriptors, intrinsicFreeze({ ...descriptor }));
  }
  return intrinsicFreeze({
    prototype,
    parent: intrinsicGetPrototypeOf(prototype) as object | null,
    keys: intrinsicFreeze(capturedKeys),
    descriptors: intrinsicFreeze(descriptors),
  });
}

const CAPTURED_OUTPUT_PROTOTYPES = intrinsicFreeze([
  capturePrototypeSurface(intrinsicObjectPrototype),
  capturePrototypeSurface(intrinsicArrayPrototype),
  capturePrototypeSurface(intrinsicArrayUnscopables),
  capturePrototypeSurface(intrinsicStringPrototype),
  capturePrototypeSurface(intrinsicNumberPrototype),
  capturePrototypeSurface(intrinsicBooleanPrototype),
  capturePrototypeSurface(intrinsicArrayIteratorPrototype),
  capturePrototypeSurface(intrinsicStringIteratorPrototype),
  capturePrototypeSurface(intrinsicIteratorPrototype),
  capturePrototypeSurface(intrinsicRegExpStringIteratorPrototype),
  capturePrototypeSurface(Object),
  capturePrototypeSurface(Array),
  capturePrototypeSurface(String),
  capturePrototypeSurface(Number),
  capturePrototypeSurface(Boolean),
  capturePrototypeSurface(RegExp),
  capturePrototypeSurface(Function),
  capturePrototypeSurface(intrinsicFunctionPrototype),
  capturePrototypeSurface(intrinsicRegExpPrototype),
]);

function captureCallableDescriptorSurfaces(
  surfaces: readonly CapturedPrototypeSurface[],
): readonly CapturedPrototypeSurface[] {
  const callables: Function[] = [];
  const captured: CapturedPrototypeSurface[] = [];
  for (let surfaceIndex = 0; surfaceIndex < surfaces.length; surfaceIndex += 1) {
    const descriptors = surfaces[surfaceIndex]!.descriptors;
    for (let descriptorIndex = 0; descriptorIndex < descriptors.length; descriptorIndex += 1) {
      const descriptor = descriptors[descriptorIndex]!;
      const candidates = intrinsicHasOwn(descriptor, "value")
        ? [descriptor.value] : [descriptor.get, descriptor.set];
      for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
        const candidate = candidates[candidateIndex];
        if (typeof candidate !== "function") continue;
        let seen = false;
        for (let index = 0; index < callables.length; index += 1) {
          if (callables[index] === candidate) {
            seen = true;
            break;
          }
        }
        if (seen) continue;
        appendArray(callables, candidate);
        appendArray(captured, capturePrototypeSurface(candidate));
      }
    }
  }
  return intrinsicFreeze(captured);
}

const CAPTURED_OUTPUT_CALLABLES = captureCallableDescriptorSurfaces(CAPTURED_OUTPUT_PROTOTYPES);

const CAPTURED_PACKAGE_METADATA: PackageMetadata = intrinsicFreeze({
  name: packageMetadataJson.name,
  version: packageMetadataJson.version,
  private: packageMetadataJson.private,
  type: packageMetadataJson.type,
  packageManager: packageMetadataJson.packageManager,
  engines: intrinsicFreeze({ bun: packageMetadataJson.engines?.bun }),
  bin: intrinsicFreeze({ dacs: packageMetadataJson.bin?.dacs }),
});
const CAPTURED_BUN_VERSION = Bun.version;

function appendArray<T>(values: T[], value: T): number {
  intrinsicDefineProperty(values, IntrinsicString(values.length), {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
  return values.length;
}

function arrayEvery<T>(values: readonly T[], predicate: (value: T, index: number) => boolean): boolean {
  return intrinsicApply(intrinsicArrayEvery, values, [predicate]) as boolean;
}

function arrayIncludes<T>(values: readonly T[], value: T): boolean {
  return intrinsicApply(intrinsicArrayIncludes, values, [value]) as boolean;
}

function arrayJoin(values: readonly string[], separator: string): string {
  return intrinsicApply(intrinsicArrayJoin, values, [separator]) as string;
}

function arraySome<T>(values: readonly T[], predicate: (value: T, index: number) => boolean): boolean {
  return intrinsicApply(intrinsicArraySome, values, [predicate]) as boolean;
}

function arraySort<T>(values: T[], compare?: (left: T, right: T) => number): T[] {
  return intrinsicApply(intrinsicArraySort, values, compare === undefined ? [] : [compare]) as T[];
}

function stringIncludes(value: string, search: string): boolean {
  return intrinsicApply(intrinsicStringIncludes, value, [search]) as boolean;
}

function sliceString(value: string, start: number, end?: number): string {
  return intrinsicApply(
    intrinsicStringSlice,
    value,
    end === undefined ? [start] : [start, end],
  ) as string;
}

function stringIndexOf(value: string, search: string, start: number): number {
  return intrinsicApply(intrinsicStringIndexOf, value, [search, start]) as number;
}

function regexMatches(pattern: RegExp, value: string): boolean {
  return intrinsicApply(intrinsicRegExpExec, pattern, [value]) !== null;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string"
    || !regexMatches(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, value)) return false;
  try {
    const parsed = new IntrinsicDate(value);
    return intrinsicApply(intrinsicDateToISOString, parsed, []) === value;
  } catch {
    return false;
  }
}

function hasPrototypeProperty(value: object, key: PropertyKey): boolean {
  let current: object | null = value;
  while (current !== null) {
    if (intrinsicIsProxy(current)) return true;
    if (intrinsicGetOwnPropertyDescriptor(current, key) !== undefined) return true;
    current = intrinsicGetPrototypeOf(current) as object | null;
  }
  return false;
}

function hasSerializationHook(value: object): boolean {
  return hasPrototypeProperty(value, "toJSON");
}

function sameDescriptor(actual: PropertyDescriptor, expected: PropertyDescriptor): boolean {
  if (actual.configurable !== expected.configurable || actual.enumerable !== expected.enumerable) {
    return false;
  }
  if (intrinsicHasOwn(expected, "value")) {
    return intrinsicHasOwn(actual, "value") && intrinsicObjectIs(actual.value, expected.value)
      && actual.writable === expected.writable;
  }
  return !intrinsicHasOwn(actual, "value")
    && actual.get === expected.get && actual.set === expected.set;
}

function capturedSurfacesSafe(surfaces: readonly CapturedPrototypeSurface[]): boolean {
  for (let surfaceIndex = 0; surfaceIndex < surfaces.length;
    surfaceIndex += 1) {
    const surface = surfaces[surfaceIndex]!;
    if (intrinsicIsProxy(surface.prototype)
      || intrinsicGetPrototypeOf(surface.prototype) !== surface.parent) return false;
    const keys = intrinsicOwnKeys(surface.prototype);
    if (keys.length !== surface.keys.length) return false;
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      if (keys[keyIndex] !== surface.keys[keyIndex]) return false;
      const descriptor = intrinsicGetOwnPropertyDescriptor(surface.prototype, keys[keyIndex]!);
      if (descriptor === undefined
        || !sameDescriptor(descriptor, surface.descriptors[keyIndex]!)) return false;
    }
  }
  return true;
}

function outputPrototypeChainSafe(value: object): boolean {
  if (!capturedSurfacesSafe(CAPTURED_OUTPUT_PROTOTYPES)
    || !capturedSurfacesSafe(CAPTURED_OUTPUT_CALLABLES)) return false;
  let current = intrinsicGetPrototypeOf(value) as object | null;
  while (current !== null) {
    if ((current !== intrinsicObjectPrototype && current !== intrinsicArrayPrototype)
      || intrinsicIsProxy(current)
      || intrinsicGetOwnPropertyDescriptor(current, "toJSON") !== undefined
      || intrinsicGetOwnPropertyDescriptor(current, "then") !== undefined
      || intrinsicGetOwnPropertyDescriptor(current, intrinsicInspectCustom) !== undefined
      || intrinsicGetOwnPropertyDescriptor(current, intrinsicSymbolToPrimitive) !== undefined
      || intrinsicGetOwnPropertyDescriptor(current, intrinsicSymbolToStringTag) !== undefined) {
      return false;
    }
    if (current === intrinsicObjectPrototype) {
      if (optionalOwnDataProperty(current, "toString") !== intrinsicObjectToString
        || optionalOwnDataProperty(current, "valueOf") !== intrinsicObjectValueOf
        || intrinsicGetPrototypeOf(current) !== null) return false;
    } else if (optionalOwnDataProperty(current, "toString") !== intrinsicArrayToString
      || intrinsicGetOwnPropertyDescriptor(current, "valueOf") !== undefined
      || optionalOwnDataProperty(current, intrinsicSymbolIterator) !== intrinsicArrayIterator
      || intrinsicGetPrototypeOf(current) !== intrinsicObjectPrototype) return false;
    current = intrinsicGetPrototypeOf(current) as object | null;
  }
  return true;
}

function exactKeys(value: object, keys: readonly string[]): boolean {
  if (intrinsicIsProxy(value) || intrinsicGetPrototypeOf(value) !== intrinsicObjectPrototype
    || hasSerializationHook(value)) return false;
  const ownKeys = intrinsicOwnKeys(value);
  if (arraySome(ownKeys, (key) => typeof key !== "string")) return false;
  const actual = arraySort(ownKeys as string[]);
  const expected: string[] = [];
  for (let index = 0; index < keys.length; index += 1) appendArray(expected, keys[index]!);
  arraySort(expected);
  return actual.length === expected.length
    && arrayEvery(actual, (key, index) => {
      const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
      return key === expected[index] && descriptor?.enumerable === true
        && intrinsicHasOwn(descriptor, "value");
    });
}

function plainDataRecord(value: object): boolean {
  if (intrinsicIsProxy(value) || intrinsicGetPrototypeOf(value) !== intrinsicObjectPrototype
    || hasSerializationHook(value)) return false;
  return arrayEvery(intrinsicOwnKeys(value), (key) => {
    const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
    return typeof key === "string" && descriptor?.enumerable === true
      && intrinsicHasOwn(descriptor, "value");
  });
}

function validDoctorId(value: unknown): value is string {
  return typeof value === "string" && value.length <= 128
    && regexMatches(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/, value);
}

interface ReportBudget {
  remaining: number;
}

function textWireCost(value: string): number {
  return intrinsicApply(intrinsicBufferByteLength, Buffer, [value, "utf8"]) as number;
}

function consumeCheckBudget(input: DoctorCheck, budget: ReportBudget): void {
  let cost = 256;
  cost += 2 * (textWireCost(input.id) + textWireCost(input.status)
    + textWireCost(input.evidenceMode) + textWireCost(input.sourceRef));
  const reason = optionalOwnDataProperty(input, "reason");
  const disposition = optionalOwnDataProperty(input, "protocolDisposition");
  if (typeof reason === "string") cost += 2 * textWireCost(reason);
  if (typeof disposition === "string") cost += 2 * textWireCost(disposition);
  const keys = intrinsicKeys(input.observed);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    cost += 16 + (2 * textWireCost(key));
    const entry = input.observed[key];
    if (typeof entry === "string") cost += 2 * textWireCost(entry);
    else if (typeof entry === "number") cost += 32;
    else cost += 5;
  }
  if (cost > budget.remaining) throw new TypeError("Doctor report exceeds the 16 KiB wire budget");
  budget.remaining -= cost;
}

function check(input: DoctorCheck, budget?: ReportBudget): DoctorCheck {
  if (!plainDataRecord(input)) throw new TypeError("Doctor check contains accessor fields");
  const reason = optionalOwnDataProperty(input, "reason");
  const protocolDisposition = optionalOwnDataProperty(input, "protocolDisposition");
  const hasReason = intrinsicHasOwn(input, "reason");
  const hasProtocolDisposition = intrinsicHasOwn(input, "protocolDisposition");
  const allowedKeys = ["id", "required", "status"];
  if (intrinsicHasOwn(input, "protocolDisposition")) appendArray(allowedKeys, "protocolDisposition");
  const trailingKeys = ["evidenceMode", "sourceRef", "observed"];
  for (let index = 0; index < trailingKeys.length; index += 1) {
    appendArray(allowedKeys, trailingKeys[index]!);
  }
  if (intrinsicHasOwn(input, "reason")) appendArray(allowedKeys, "reason");
  if (!exactKeys(input, allowedKeys)) {
    throw new TypeError("Doctor check contains unknown fields");
  }
  if (!validDoctorId(input.id)) {
    throw new TypeError("Doctor check id is invalid");
  }
  if (typeof input.required !== "boolean") {
    throw new TypeError(`Doctor check ${input.id} required flag is invalid`);
  }
  if (typeof input.status !== "string" || !arrayIncludes(DOCTOR_STATUS_VALUES, input.status)) {
    throw new TypeError("Doctor check status is invalid");
  }
  if (typeof input.evidenceMode !== "string" || !arrayIncludes(EVIDENCE_MODES, input.evidenceMode)) {
    throw new TypeError(`Doctor check ${input.id} evidence mode is invalid`);
  }
  if (typeof input.sourceRef !== "string" || input.sourceRef.length < 1
    || input.sourceRef.length > 512 || regexMatches(/[\u0000-\u001f\u007f-\u009f]/, input.sourceRef)) {
    throw new TypeError(`Doctor check ${input.id} source reference is invalid`);
  }
  if (hasReason && (typeof reason !== "string"
      || reason.length < 1 || reason.length > 1024
      || regexMatches(/[\u0000-\u001f\u007f-\u009f]/, reason))) {
    throw new TypeError(`Doctor check ${input.id} reason is invalid`);
  }
  if (hasProtocolDisposition
    && typeof protocolDisposition !== "string") {
    throw new TypeError(`Doctor check ${input.id} protocol disposition is invalid`);
  }
  if (protocolDisposition !== undefined
    && !arrayIncludes(["pass", "fail", "indeterminate", "error"], protocolDisposition)) {
    throw new TypeError(`Doctor check ${input.id} protocol disposition is invalid`);
  }
  if ((input.status === "blocked" || input.status === "not-run"
      || input.status === "not-applicable") && !reason) {
    throw new TypeError(`Doctor check ${input.id} requires a reason`);
  }
  if (input.required && input.status === "not-applicable") {
    throw new TypeError(`Required doctor check ${input.id} cannot be not-applicable`);
  }
  const validDisposition = protocolDisposition === undefined
    || (input.status === "passed" && protocolDisposition === "pass")
    || (input.status === "failed"
      && (protocolDisposition === "fail" || protocolDisposition === "error"))
    || (input.status === "blocked"
      && (protocolDisposition === "indeterminate" || protocolDisposition === "error"))
    || (input.status === "not-run" && protocolDisposition === "error");
  if (!validDisposition) {
    throw new TypeError(`Doctor check ${input.id} status and disposition contradict`);
  }
  if (input.observed === null || typeof input.observed !== "object"
    || intrinsicIsArray(input.observed) || !plainDataRecord(input.observed)
    || intrinsicKeys(input.observed).length > 256
    || arraySome(intrinsicKeys(input.observed), (key) => key.length < 1 || key.length > 128
      || regexMatches(/[\u0000-\u001f\u007f-\u009f]/, key))
    || arraySome(intrinsicValues(input.observed), (entry) => {
      if (typeof entry === "string") {
        return entry.length > 2048 || regexMatches(/[\u0000-\u001f\u007f-\u009f]/, entry);
      }
      return (typeof entry !== "number" || !intrinsicIsFinite(entry)
          || intrinsicObjectIs(entry, -0))
        && typeof entry !== "boolean";
    })) {
    throw new TypeError(`Doctor check ${input.id} has an invalid observed value`);
  }
  if (budget !== undefined) consumeCheckBudget(input, budget);
  return intrinsicFreeze({
    ...input,
    observed: intrinsicFreeze({ ...input.observed }),
  });
}

function packageMetadata(): PackageMetadata {
  return CAPTURED_PACKAGE_METADATA;
}

function packageVersion(metadata: PackageMetadata): string {
  if (typeof metadata.version !== "string" || metadata.version.length === 0) {
    throw new TypeError("Package version is unavailable");
  }
  return metadata.version;
}

export function doctorPackageVersion(): string {
  return packageVersion(packageMetadata());
}

function packageCheck(metadata: PackageMetadata, evidenceMode: EvidenceMode): DoctorCheck {
  const valid = metadata.name === "dacs-forge"
    && metadata.private === true
    && metadata.type === "module"
    && metadata.packageManager === `bun@${EXPECTED_BUN_VERSION}`
    && metadata.engines?.["bun"] === EXPECTED_BUN_VERSION
    && metadata.bin?.["dacs"] === "./src/cli/dacs.ts";
  return check({
    id: "package.contract",
    required: true,
    status: valid ? "passed" : "failed",
    protocolDisposition: valid ? "pass" : "fail",
    evidenceMode,
    sourceRef: "package.json",
    observed: {
      packageName: typeof metadata.name === "string" ? metadata.name : "invalid",
      packageManager: typeof metadata.packageManager === "string"
        ? metadata.packageManager : "invalid",
      binDeclared: metadata.bin?.["dacs"] === "./src/cli/dacs.ts",
    },
    ...(valid ? {} : { reason: "Installed package metadata does not match the pinned CLI contract" }),
  });
}

function runtimeCheck(evidenceMode: EvidenceMode): DoctorCheck {
  const version = CAPTURED_BUN_VERSION;
  const valid = version === EXPECTED_BUN_VERSION;
  return check({
    id: "runtime.bun",
    required: true,
    status: valid ? "passed" : "failed",
    protocolDisposition: valid ? "pass" : "fail",
    evidenceMode,
    sourceRef: "runtime:Bun.version",
    observed: { version, required: EXPECTED_BUN_VERSION },
    ...(valid ? {} : { reason: `Bun ${EXPECTED_BUN_VERSION} is required` }),
  });
}

function coreChecks(evidenceMode: EvidenceMode): readonly DoctorCheck[] {
  return [
    check({
      id: "execution.read-only",
      required: true,
      status: "passed",
      protocolDisposition: "pass",
      evidenceMode,
      sourceRef: "src/readiness/doctor.ts",
      observed: { liveEffects: 0, registrationCommands: 0 },
    }),
    check({
      id: "binding.live-resolution",
      required: evidenceMode !== "fixture",
      status: evidenceMode === "fixture" ? "not-applicable" : "blocked",
      ...(evidenceMode === "fixture" ? {} : { protocolDisposition: "indeterminate" as const }),
      evidenceMode,
      sourceRef: "DACS-Standard#242",
      observed: { resolverConfigured: false },
      reason: evidenceMode === "fixture"
        ? "Live logical/native binding is outside fixture execution"
        : "No authoritative live logical/native binding resolver is configured",
    }),
    check({
      id: "registration.directory",
      required: false,
      status: "not-applicable",
      evidenceMode,
      sourceRef: "operator-action:directory-registration",
      observed: { attempted: false },
      reason: "Directory registration is a separate explicit operator action",
    }),
    check({
      id: "transport.http",
      required: false,
      status: "not-applicable",
      evidenceMode,
      sourceRef: "ISA:ISC-23",
      observed: { serverConfigured: false },
      reason: "HTTP transport is not part of the isolated Doctor Core",
    }),
    check({
      id: "conformance.external-rig",
      required: true,
      status: "blocked",
      protocolDisposition: "indeterminate",
      evidenceMode,
      sourceRef: "ISA:ISC-34.1",
      observed: { acceptedRigPinned: false },
      reason: "No externally accepted conformance-rig release is pinned",
    }),
  ];
}

function redactText(value: string, sensitiveValues: readonly string[]): string {
  let redacted = value;
  const normalized: string[] = [];
  for (let index = 0; index < sensitiveValues.length; index += 1) {
    const item = sensitiveValues[index]!;
    if (item.length === 0) continue;
    if (!arrayIncludes(normalized, item)) appendArray(normalized, item);
  }
  arraySort(normalized, (left, right) => right.length - left.length);
  let changed = true;
  while (changed) {
    changed = false;
    for (let index = 0; index < normalized.length; index += 1) {
      const sensitive = normalized[index]!;
      if (!stringIncludes(redacted, sensitive)) continue;
      const chunks: string[] = [];
      let cursor = 0;
      while (cursor <= redacted.length) {
        const match = stringIndexOf(redacted, sensitive, cursor);
        if (match < 0) {
          appendArray(chunks, sliceString(redacted, cursor));
          break;
        }
        appendArray(chunks, sliceString(redacted, cursor, match));
        cursor = match + sensitive.length;
      }
      redacted = arrayJoin(chunks, "");
      changed = true;
    }
  }
  return redacted;
}

function safeToken(sensitiveValues: readonly string[], seed = 0): string {
  const candidates = ["masked", "hidden", "doctor-failure", "x"];
  if (seed === 0) {
    for (let index = 0; index < candidates.length; index += 1) {
      const candidate = candidates[index]!;
      if (arrayEvery(sensitiveValues, (sensitive) => !stringIncludes(candidate, sensitive)
        && !stringIncludes(stringifyJson(candidate), sensitive))) return candidate;
    }
  }
  for (let offset = seed; offset < seed + 6400; offset += 1) {
    const candidate = intrinsicStringFromCodePoint(0xe000 + (offset % 6400));
    if (arrayEvery(sensitiveValues, (sensitive) => !stringIncludes(candidate, sensitive)
      && !stringIncludes(stringifyJson(candidate), sensitive))) return candidate;
  }
  throw new TypeError("Unable to allocate a safe redaction token");
}

function normalizedText(value: string): string {
  const characters: string[] = [];
  let cursor = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = intrinsicApply(intrinsicStringCharCodeAt, value, [index]) as number;
    if (code > 0x1f && (code < 0x7f || code > 0x9f)) continue;
    appendArray(characters, sliceString(value, cursor, index));
    appendArray(characters, " ");
    cursor = index + 1;
  }
  appendArray(characters, sliceString(value, cursor));
  return arrayJoin(characters, "");
}

function boundedText(value: string, maximum: number): string {
  return value.length <= maximum ? value : sliceString(value, 0, maximum);
}

function redactBoundedText(
  value: string,
  sensitiveValues: readonly string[],
  maximum: number,
  requireNonempty = false,
): string {
  const redacted = boundedText(redactText(normalizedText(value), sensitiveValues), maximum);
  const nonempty = requireNonempty && redacted.length === 0 ? safeToken(sensitiveValues) : redacted;
  return arraySome(sensitiveValues, (sensitive) => stringIncludes(stringifyJson(nonempty), sensitive))
    ? safeToken(sensitiveValues) : nonempty;
}

function redactCheck(input: DoctorCheck, sensitiveValues: readonly string[]): DoctorCheck {
  if (arrayIncludes(CORE_CHECK_IDS, input.id)) return input;
  const reason = optionalOwnDataProperty(input, "reason");
  const observed: Record<string, boolean | number | string> = {};
  const entries = intrinsicEntries(input.observed);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]!;
    const key = entry[0];
    const value = entry[1];
    const candidate = redactBoundedText(key, sensitiveValues, 128);
    let redactedKey = candidate;
    let suffix = index;
    while (redactedKey.length === 0 || intrinsicHasOwn(observed, redactedKey)) {
      redactedKey = safeToken(sensitiveValues, suffix);
      suffix += 1;
    }
    intrinsicDefineProperty(observed, redactedKey, {
      configurable: true,
      enumerable: true,
      value: (() => {
        const serialized = IntrinsicString(value);
        const redacted = redactBoundedText(serialized, sensitiveValues, 2048);
        if (input.id === "internal.tool" && key === "completed" && value === false) return false;
        return sensitiveValues.length === 0 && redacted === serialized ? value : redacted;
      })(),
      writable: true,
    });
  }
  return check({
    ...input,
    sourceRef: arrayIncludes(CORE_CHECK_IDS, input.id) || input.id === "internal.tool"
      ? input.sourceRef : redactBoundedText(input.sourceRef, sensitiveValues, 512, true),
    observed,
    ...(reason === undefined
      ? {} : { reason: redactBoundedText(reason as string, sensitiveValues, 1024, true) }),
  });
}

function errorReason(error: unknown, sensitiveValues: readonly string[]): string {
  let raw = "Unknown Doctor failure";
  if (typeof error === "string") {
    raw = error;
  } else if ((typeof error === "object" && error !== null) || typeof error === "function") {
    if (!intrinsicIsProxy(error)) {
      const descriptor = intrinsicGetOwnPropertyDescriptor(error, "message");
      if (descriptor !== undefined && intrinsicHasOwn(descriptor, "value")
        && typeof descriptor.value === "string") raw = descriptor.value;
    }
  }
  if (raw.length > 4096) return safeToken(sensitiveValues);
  return redactBoundedText(raw, sensitiveValues, 1024, true);
}

function denseDataArray(value: unknown, maximum: number): readonly unknown[] | null {
  if (!intrinsicIsArray(value) || intrinsicIsProxy(value)
    || intrinsicGetPrototypeOf(value) !== intrinsicArrayPrototype || hasSerializationHook(value)
    || value.length > maximum) return null;
  const expectedKeys = ["length"];
  for (let index = 0; index < value.length; index += 1) {
    appendArray(expectedKeys, IntrinsicString(index));
  }
  arraySort(expectedKeys);
  const actualKeys = intrinsicOwnKeys(value);
  if (arraySome(actualKeys, (key) => typeof key !== "string")
    || arraySome(arraySort(actualKeys as string[]), (key, index) => key !== expectedKeys[index])
    || actualKeys.length !== expectedKeys.length) return null;
  const snapshot: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = intrinsicGetOwnPropertyDescriptor(value, IntrinsicString(index));
    if (descriptor === undefined || !intrinsicHasOwn(descriptor, "value")) return null;
    appendArray(snapshot, descriptor.value);
  }
  return intrinsicFreeze(snapshot);
}

function ownDataProperty(value: object, key: string): unknown {
  const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !intrinsicHasOwn(descriptor, "value")) {
    throw new TypeError(`Doctor probe ${key} must be an own data property`);
  }
  return descriptor.value;
}

function optionalOwnDataProperty(value: object, key: PropertyKey): unknown {
  const descriptor = intrinsicGetOwnPropertyDescriptor(value, key);
  return descriptor !== undefined && intrinsicHasOwn(descriptor, "value")
    ? descriptor.value : undefined;
}

function detachedRejection(message = ""): Error {
  const rejection = new IntrinsicError();
  const safeText = () => message;
  const rejectSerialization = () => {
    throw rejection;
  };
  intrinsicSetPrototypeOf(safeText, null);
  intrinsicSetPrototypeOf(rejectSerialization, null);
  intrinsicFreeze(safeText);
  intrinsicFreeze(rejectSerialization);
  intrinsicDefineProperty(rejection, "name", { configurable: true, value: "", writable: true });
  intrinsicDefineProperty(rejection, "message", { configurable: true, value: message, writable: true });
  intrinsicDefineProperty(rejection, "stack", { configurable: true, value: "", writable: true });
  intrinsicDefineProperty(rejection, "toJSON", {
    configurable: true,
    value: rejectSerialization,
  });
  intrinsicDefineProperty(rejection, "then", { configurable: true, value: undefined });
  intrinsicDefineProperty(rejection, intrinsicSymbolIterator, {
    configurable: true,
    value: undefined,
  });
  intrinsicDefineProperty(rejection, intrinsicSymbolAsyncIterator, {
    configurable: true,
    value: undefined,
  });
  intrinsicDefineProperty(rejection, intrinsicSymbolToStringTag, {
    configurable: true,
    get: rejectSerialization,
  });
  intrinsicDefineProperty(rejection, "toString", { configurable: true, value: safeText });
  intrinsicDefineProperty(rejection, "valueOf", { configurable: true, value: safeText });
  intrinsicDefineProperty(rejection, intrinsicInspectCustom, {
    configurable: true,
    value: safeText,
  });
  intrinsicDefineProperty(rejection, intrinsicSymbolToPrimitive, {
    configurable: true,
    value: safeText,
  });
  intrinsicSetPrototypeOf(rejection, null);
  return intrinsicFreeze(rejection);
}

function emptyRejection(): Error {
  return detachedRejection();
}

function diagnosticRejection(error: unknown): Error {
  if (error !== null && (typeof error === "object" || typeof error === "function")) {
    const descriptor = intrinsicGetOwnPropertyDescriptor(error, "message");
    if (descriptor !== undefined && intrinsicHasOwn(descriptor, "value")
      && typeof descriptor.value === "string") {
      return detachedRejection(descriptor.value);
    }
  }
  return detachedRejection("Doctor report validation failed");
}

function internalFailureCheck(
  evidenceMode: EvidenceMode,
  error: unknown,
  sensitiveValues: readonly string[],
): DoctorCheck {
  try {
    return check({
      id: "internal.tool",
      required: true,
      status: "failed",
      protocolDisposition: "error",
      evidenceMode,
      sourceRef: "doctor:internal",
      observed: { completed: false },
      reason: errorReason(error, sensitiveValues),
    });
  } catch {
    throw emptyRejection();
  }
}

function sensitiveValuesOption(value: unknown): {
  readonly valid: boolean;
  readonly values: readonly string[];
  readonly unsafe?: boolean;
} {
  if (value === undefined) return { valid: true, values: [] };
  const rawValues = denseDataArray(value, 256);
  if (rawValues === null) return { valid: false, values: [], unsafe: intrinsicIsArray(value) };
  const values: string[] = [];
  let totalLength = 0;
  for (let index = 0; index < rawValues.length; index += 1) {
    const item = rawValues[index];
    if (typeof item === "string" && stringIncludes(item, "\"")) {
      return { valid: false, values: intrinsicFreeze(values), unsafe: true };
    }
    if (typeof item !== "string" || item.length === 0 || item.length > 4096) {
      return { valid: false, values };
    }
    totalLength += item.length;
    if (totalLength > 65_536) return { valid: false, values };
    appendArray(values, item);
  }
  return { valid: true, values: intrinsicFreeze(values) };
}

function assertUniqueCheckIds(checks: readonly DoctorCheck[]): void {
  const ids: string[] = [];
  for (let index = 0; index < checks.length; index += 1) {
    const item = checks[index]!;
    if (arrayIncludes(ids, item.id)) throw new TypeError(`Duplicate Doctor check id: ${item.id}`);
    appendArray(ids, item.id);
  }
}

function equivalentObserved(
  actual: Readonly<Record<string, boolean | number | string>>,
  expected: Readonly<Record<string, boolean | number | string>>,
): boolean {
  const actualKeys = arraySort(intrinsicKeys(actual));
  const expectedKeys = arraySort(intrinsicKeys(expected));
  return actualKeys.length === expectedKeys.length
    && arrayEvery(actualKeys, (key, index) => key === expectedKeys[index]
      && intrinsicObjectIs(actual[key], expected[key]));
}

function equivalentCheck(actual: DoctorCheck, expected: DoctorCheck): boolean {
  return actual.id === expected.id
    && actual.required === expected.required
    && actual.status === expected.status
    && intrinsicHasOwn(actual, "protocolDisposition")
      === intrinsicHasOwn(expected, "protocolDisposition")
    && optionalOwnDataProperty(actual, "protocolDisposition")
      === optionalOwnDataProperty(expected, "protocolDisposition")
    && actual.evidenceMode === expected.evidenceMode
    && actual.sourceRef === expected.sourceRef
    && intrinsicHasOwn(actual, "reason") === intrinsicHasOwn(expected, "reason")
    && optionalOwnDataProperty(actual, "reason") === optionalOwnDataProperty(expected, "reason")
    && equivalentObserved(actual.observed, expected.observed);
}

function assertCoreChecks(checks: readonly DoctorCheck[], evidenceMode: EvidenceMode): void {
  const containsInternal = arraySome(checks, (item) => item.id === "internal.tool");
  const internalCheck = checks[0];
  const internalDisposition = internalCheck === undefined
    ? undefined : optionalOwnDataProperty(internalCheck, "protocolDisposition");
  const internalReason = internalCheck === undefined
    ? undefined : optionalOwnDataProperty(internalCheck, "reason");
  const internal = checks.length === 1 && internalCheck?.id === "internal.tool"
    && internalCheck.required === true && internalCheck.status === "failed"
    && intrinsicHasOwn(internalCheck, "protocolDisposition") && internalDisposition === "error"
    && internalCheck.evidenceMode === evidenceMode
    && internalCheck.sourceRef === "doctor:internal"
    && exactKeys(internalCheck.observed, ["completed"])
    && internalCheck.observed["completed"] === false
    && intrinsicHasOwn(internalCheck, "reason")
    && typeof internalReason === "string" && internalReason.length > 0
    && doctorExitCode(checks) === 4;
  if (internal) return;
  if (containsInternal) {
    throw new TypeError("internal.tool is valid only as the sole internal-error check");
  }
  const expectedChecks: DoctorCheck[] = [];
  appendArray(expectedChecks, runtimeCheck(evidenceMode));
  appendArray(expectedChecks, packageCheck(CAPTURED_PACKAGE_METADATA, evidenceMode));
  const remaining = coreChecks(evidenceMode);
  for (let index = 0; index < remaining.length; index += 1) {
    appendArray(expectedChecks, remaining[index]!);
  }
  for (let index = 0; index < expectedChecks.length; index += 1) {
    const expected = expectedChecks[index]!;
    const actual = checks[index];
    if (actual === undefined) {
      throw new TypeError(`Doctor report requires exactly one ${expected.id} check`);
    }
    if (!equivalentCheck(actual, expected)) {
      throw new TypeError(`Doctor check ${expected.id} does not match canonical evidence`);
    }
  }
}

export function doctorExitCode(checks: readonly DoctorCheck[]): 0 | 3 | 4 | 5 {
  if (arraySome(checks, (item) => item.id === "internal.tool" && item.required
      && item.status === "failed" && item.protocolDisposition === "error")) return 4;
  if (arraySome(checks, (item) => item.required
      && (item.status === "failed" || item.status === "not-run"))) return 3;
  if (arraySome(checks, (item) => item.required && item.status === "blocked")) return 5;
  return 0;
}

export function runDoctor(options: DoctorOptions = {}): DoctorReport {
  let evidenceMode: EvidenceMode = "fixture";
  let normalizedOptions: DoctorOptions = {};
  let sensitiveOption: ReturnType<typeof sensitiveValuesOption> = { valid: true, values: [] };
  const reportBudget: ReportBudget = { remaining: MAX_REPORT_WIRE_BYTES };
  try {
    if (options === null || typeof options !== "object" || intrinsicIsArray(options)
      || intrinsicIsProxy(options) || intrinsicGetPrototypeOf(options) !== intrinsicObjectPrototype) {
      throw new TypeError("Doctor options must be an object");
    }
    const allowed = ["evidenceMode", "now", "probes", "sensitiveValues"];
    const snapshot: Record<string, unknown> = {};
    const optionKeys = intrinsicOwnKeys(options);
    for (let index = 0; index < optionKeys.length; index += 1) {
      const key = optionKeys[index]!;
      if (typeof key !== "string" || !arrayIncludes(allowed, key)) {
        throw new TypeError("Unknown Doctor option");
      }
      const descriptor = intrinsicGetOwnPropertyDescriptor(options, key);
      if (descriptor === undefined || !intrinsicHasOwn(descriptor, "value")
        || !descriptor.enumerable) {
        throw new TypeError("Doctor options must use own enumerable data properties");
      }
      intrinsicDefineProperty(snapshot, key, {
        configurable: true,
        enumerable: true,
        value: descriptor.value,
        writable: true,
      });
    }
    normalizedOptions = intrinsicFreeze(snapshot) as DoctorOptions;
    sensitiveOption = sensitiveValuesOption(optionalOwnDataProperty(snapshot, "sensitiveValues"));
  } catch {
    throw emptyRejection();
  }
  const sensitiveValues = sensitiveOption.values;
  if (sensitiveOption.unsafe || !sensitiveOption.valid) throw emptyRejection();
  const metadata = packageMetadata();
  let checks: DoctorCheck[];
  const version = packageVersion(metadata);
  let generatedAt = intrinsicApply(intrinsicDateToISOString, new IntrinsicDate(), []) as string;
  try {
    const requestedMode = optionalOwnDataProperty(normalizedOptions, "evidenceMode");
    evidenceMode = parseEvidenceMode(requestedMode === undefined ? "fixture" : requestedMode);
    const probesOption = optionalOwnDataProperty(normalizedOptions, "probes");
    const rawProbes = probesOption === undefined ? intrinsicFreeze([]) : denseDataArray(probesOption, 256);
    if (rawProbes === null) {
      throw new TypeError("Doctor probes option must be an array");
    }
    const probeSnapshots: Array<{
      readonly id: string;
      readonly required: boolean;
      readonly run: () => unknown;
    }> = [];
    const probeIds: string[] = [];
    for (let index = 0; index < rawProbes.length; index += 1) {
      const probe = rawProbes[index];
      if (probe === null || typeof probe !== "object" || intrinsicIsArray(probe)
        || !exactKeys(probe, ["id", "required", "run"])) {
        throw new TypeError("Doctor probe must be an object");
      }
      const probeId = ownDataProperty(probe, "id");
      const probeRequired = ownDataProperty(probe, "required");
      const probeRun = ownDataProperty(probe, "run");
      if (!validDoctorId(probeId) || typeof probeRequired !== "boolean"
        || typeof probeRun !== "function" || intrinsicIsProxy(probeRun)) {
        throw new TypeError("Doctor probe identity or requirement is invalid");
      }
      if (probeId === "internal.tool" || arrayIncludes(CORE_CHECK_IDS, probeId)) {
        throw new TypeError(`Doctor probe id ${probeId} is reserved`);
      }
      if (probeId === DIRECTORY_SCHEMA_DRIFT_CHECK_ID
        && !isPreparedDirectorySchemaDriftProbe(probe)) {
        throw new TypeError(`Doctor probe id ${probeId} requires a prepared Directory probe`);
      }
      if (arrayIncludes(probeIds, probeId)) {
        throw new TypeError(`Duplicate Doctor probe id: ${probeId}`);
      }
      if (arraySome(sensitiveValues, (sensitive) => stringIncludes(probeId, sensitive))) {
        throw new TypeError("Doctor probe id contains a configured sensitive value");
      }
      appendArray(probeIds, probeId);
      appendArray(probeSnapshots, intrinsicFreeze({
        id: probeId,
        required: probeRequired,
        run: () => intrinsicApply(probeRun, probe, []),
      }));
    }
    const nowOption = optionalOwnDataProperty(normalizedOptions, "now");
    if (nowOption !== undefined && typeof nowOption !== "function") {
      throw new TypeError("Doctor now option must be a function");
    }
    const observedAt: unknown = nowOption === undefined ? generatedAt : nowOption();
    if (!canonicalTimestamp(observedAt)) {
      throw new TypeError("Doctor timestamp is not canonical RFC 3339 UTC");
    }
    generatedAt = observedAt;
    checks = [runtimeCheck(evidenceMode), packageCheck(metadata, evidenceMode)];
    const core = coreChecks(evidenceMode);
    for (let index = 0; index < core.length; index += 1) appendArray(checks, core[index]!);
    for (let index = 0; index < checks.length; index += 1) {
      consumeCheckBudget(checks[index]!, reportBudget);
    }
    for (let index = 0; index < probeSnapshots.length; index += 1) {
      const probe = probeSnapshots[index]!;
      const result = check(probe.run() as DoctorCheck, reportBudget);
      if (result.id !== probe.id || result.required !== probe.required
        || result.evidenceMode !== evidenceMode) {
        throw new TypeError(
          `Doctor probe ${probe.id} changed its declared identity, requirement, or evidence mode`,
        );
      }
      appendArray(checks, result);
    }
  } catch (error) {
    checks = [internalFailureCheck(evidenceMode, error, sensitiveValues)];
  }
  let sanitized: readonly DoctorCheck[];
  try {
    const redacted: DoctorCheck[] = [];
    for (let index = 0; index < checks.length; index += 1) {
      appendArray(redacted, redactCheck(checks[index]!, sensitiveValues));
    }
    sanitized = intrinsicFreeze(redacted);
    assertUniqueCheckIds(sanitized);
  } catch (error) {
    sanitized = intrinsicFreeze([internalFailureCheck(evidenceMode, error, sensitiveValues)]);
  }
  const exitCode = doctorExitCode(sanitized);
  const report = intrinsicFreeze({
    schema: DOCTOR_SCHEMA,
    service: "dacs-forge",
    version,
    generatedAt,
    evidenceMode,
    ready: exitCode === 0,
    exitCode,
    checks: sanitized,
  });
  try {
    assertDoctorReport(report);
  } catch (error) {
    if (sensitiveValues.length > 0) throw emptyRejection();
    throw diagnosticRejection(error);
  }
  const encoded = serializeDoctorReport(report);
  if (textWireCost(encoded) > MAX_REPORT_WIRE_BYTES) {
    if (sensitiveValues.length > 0) throw emptyRejection();
    throw detachedRejection("Doctor report exceeds the 16 KiB wire budget");
  }
  if (arraySome(sensitiveValues, (sensitive) => stringIncludes(encoded, sensitive))) {
    throw emptyRejection();
  }
  if (hasPrototypeProperty(report, "then")) throw emptyRejection();
  return report;
}

export function assertDoctorReport(value: unknown): asserts value is DoctorReport {
  if (value === null || typeof value !== "object" || intrinsicIsArray(value)
    || !plainDataRecord(value)) {
    throw new TypeError("Doctor report must be an object");
  }
  const report = value as Record<string, unknown>;
  if (!exactKeys(report, [
    "schema", "service", "version", "generatedAt", "evidenceMode", "ready", "exitCode", "checks",
  ])) {
    throw new TypeError("Doctor report shape is invalid");
  }
  const rawChecks = denseDataArray(report["checks"], 263);
  if (report["schema"] !== DOCTOR_SCHEMA || report["service"] !== "dacs-forge"
    || typeof report["version"] !== "string" || report["version"].length < 1
    || report["version"].length > 128 || regexMatches(/[\u0000-\u001f\u007f-\u009f]/, report["version"])
    || report["version"] !== CAPTURED_PACKAGE_METADATA.version
    || typeof report["generatedAt"] !== "string"
    || !canonicalTimestamp(report["generatedAt"])
    || typeof report["evidenceMode"] !== "string"
    || !arrayIncludes(EVIDENCE_MODES, report["evidenceMode"] as EvidenceMode)
    || typeof report["ready"] !== "boolean" || typeof report["exitCode"] !== "number"
    || !arrayIncludes([0, 3, 4, 5], report["exitCode"])
    || rawChecks === null) {
    throw new TypeError("Doctor report shape is invalid");
  }
  const reportBudget: ReportBudget = { remaining: MAX_REPORT_WIRE_BYTES };
  for (let index = 0; index < rawChecks.length; index += 1) {
    const rawCheck = rawChecks[index];
    if (rawCheck === null || typeof rawCheck !== "object" || intrinsicIsArray(rawCheck)) {
      throw new TypeError("Doctor check must be an object");
    }
    const item = rawCheck as Record<string, unknown>;
    if (!plainDataRecord(item)) throw new TypeError("Doctor check shape is invalid");
    const allowed = intrinsicHasOwn(item, "protocolDisposition")
      ? ["id", "required", "status", "protocolDisposition", "evidenceMode", "sourceRef", "observed", "reason"]
      : ["id", "required", "status", "evidenceMode", "sourceRef", "observed", "reason"];
    if (!intrinsicHasOwn(item, "reason")) {
      allowed.length -= 1;
    }
    if (!exactKeys(item, allowed) || item["evidenceMode"] !== report["evidenceMode"]) {
      throw new TypeError("Doctor check shape is invalid");
    }
    try {
      check(item as unknown as DoctorCheck, reportBudget);
    } catch (error) {
      throw new TypeError("Doctor check shape is invalid", { cause: error });
    }
  }
  const checks = rawChecks as DoctorCheck[];
  if (!outputPrototypeChainSafe(report) || !outputPrototypeChainSafe(rawChecks)) {
    throw new TypeError("Doctor report prototype chain is unsafe");
  }
  for (let index = 0; index < checks.length; index += 1) {
    if (!outputPrototypeChainSafe(checks[index]!)
      || !outputPrototypeChainSafe(checks[index]!.observed)) {
      throw new TypeError("Doctor report prototype chain is unsafe");
    }
  }
  assertUniqueCheckIds(checks);
  assertCoreChecks(checks, report["evidenceMode"] as EvidenceMode);
  const expectedExitCode = doctorExitCode(checks);
  if (report["exitCode"] !== expectedExitCode || report["ready"] !== (expectedExitCode === 0)) {
    throw new TypeError("Doctor report readiness or exit code contradicts its checks");
  }
}

export function serializeDoctorReport(report: DoctorReport): string {
  assertDoctorReport(report);
  const encoded = stringifyJson(report);
  if (textWireCost(encoded) > MAX_REPORT_WIRE_BYTES) {
    throw new TypeError("Doctor report exceeds the 16 KiB wire budget");
  }
  return encoded;
}

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | CanonicalJsonValue[]
  | { readonly [key: string]: CanonicalJsonValue | undefined };

export class CanonicalizationError extends Error {
  override readonly name = "CanonicalizationError";
}

const MAX_NESTING_DEPTH = 64;

export function canonicalize(value: unknown): string {
  return serialize(value, new Set<object>(), 0);
}

export function deepFreezeJson<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) deepFreezeJson(value[index]);
  } else {
    for (const key of Object.keys(value)) {
      deepFreezeJson((value as Record<string, unknown>)[key]);
    }
  }
  return Object.isFrozen(value) ? value : Object.freeze(value);
}

export function withoutFields<T extends Record<string, unknown>>(
  document: T,
  ...fields: readonly [string, ...string[]]
): Record<string, unknown> {
  const omitted = new Set(fields);
  return Object.fromEntries(
    Object.entries(document).filter(([key]) => !omitted.has(key)),
  );
}

function serialize(value: unknown, ancestors: Set<object>, depth: number): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return serializeNumber(value);
    case "string":
      return serializeString(value);
    case "object": {
      if (depth >= MAX_NESTING_DEPTH) {
        throw new CanonicalizationError(
          `JCS: nesting depth exceeds ${MAX_NESTING_DEPTH}`,
        );
      }
      return withCycleGuard(value, ancestors, () =>
        Array.isArray(value)
          ? serializeArray(value, ancestors, depth + 1)
          : serializeObject(value, ancestors, depth + 1),
      );
    }
    default:
      throw new CanonicalizationError(`JCS: unsupported value type "${typeof value}"`);
  }
}

function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError("JCS: non-finite number");
  }
  if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
    throw new CanonicalizationError(
      `JCS (DACS CORE B.2): JSON number ${value} exceeds the safe-integer range`,
    );
  }
  return JSON.stringify(value);
}

function serializeString(value: string): string {
  const normalized = normalizeString(value);
  let output = '"';

  for (const character of normalized) {
    switch (character) {
      case '"': output += '\\"'; break;
      case "\\": output += "\\\\"; break;
      case "\b": output += "\\b"; break;
      case "\f": output += "\\f"; break;
      case "\n": output += "\\n"; break;
      case "\r": output += "\\r"; break;
      case "\t": output += "\\t"; break;
      default: {
        const codePoint = character.codePointAt(0);
        if (codePoint === undefined) {
          throw new CanonicalizationError("JCS: invalid empty code point");
        }
        output += codePoint < 0x20
          ? `\\u${codePoint.toString(16).padStart(4, "0")}`
          : character;
      }
    }
  }

  return `${output}"`;
}

function normalizeString(value: string): string {
  assertNoLoneSurrogates(value);
  return value.normalize("NFC");
}

function assertNoLoneSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalizationError("JCS: lone high surrogate");
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new CanonicalizationError("JCS: lone low surrogate");
    }
  }
}

function serializeArray(
  value: readonly unknown[],
  ancestors: Set<object>,
  childDepth: number,
): string {
  const entries: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      throw new CanonicalizationError(`JCS: sparse array entry at index ${index}`);
    }
    entries.push(serialize(value[index], ancestors, childDepth));
  }
  return `[${entries.join(",")}]`;
}

function serializeObject(
  value: object,
  ancestors: Set<object>,
  childDepth: number,
): string {
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new CanonicalizationError("JCS: only plain JSON objects are supported");
  }

  const normalizedEntries = new Map<string, unknown>();
  for (const [rawKey, entry] of Object.entries(value)) {
    if (entry === undefined) continue;
    const key = normalizeString(rawKey);
    if (normalizedEntries.has(key)) {
      throw new CanonicalizationError(`JCS (CF-1): NFC key collision for "${key}"`);
    }
    normalizedEntries.set(key, entry);
  }

  const members = [...normalizedEntries.entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, entry]) => `${serializeString(key)}:${serialize(entry, ancestors, childDepth)}`);
  return `{${members.join(",")}}`;
}

function withCycleGuard<T>(
  value: object,
  ancestors: Set<object>,
  operation: () => T,
): T {
  if (ancestors.has(value)) {
    throw new CanonicalizationError("JCS: cyclic structure");
  }
  ancestors.add(value);
  try {
    return operation();
  } finally {
    ancestors.delete(value);
  }
}

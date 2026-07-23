export class ConsumerCanonicalizationError extends Error {
  override readonly name = "ConsumerCanonicalizationError";
}

const MAX_DEPTH = 64;

export function consumerCanonicalize(value: unknown): string {
  return encode(value, [], 0);
}

function encode(value: unknown, parents: readonly object[], depth: number): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return quote(normalize(value));
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new ConsumerCanonicalizationError("DACS JSON number is outside the finite safe-integer range");
    }
    return String(Object.is(value, -0) ? 0 : value);
  }
  if (typeof value !== "object") {
    throw new ConsumerCanonicalizationError(`Unsupported JSON type: ${typeof value}`);
  }
  if (depth >= MAX_DEPTH) throw new ConsumerCanonicalizationError("Maximum nesting exceeded");
  if (parents.includes(value)) throw new ConsumerCanonicalizationError("Cyclic JSON value");
  const lineage = [...parents, value];

  if (Array.isArray(value)) {
    const encoded: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        throw new ConsumerCanonicalizationError(`Sparse array entry: ${index}`);
      }
      encoded.push(encode(value[index], lineage, depth + 1));
    }
    return `[${encoded.join(",")}]`;
  }

  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ConsumerCanonicalizationError("Expected a plain JSON object");
  }
  const entries = new Map<string, unknown>();
  for (const key of Object.keys(value)) {
    const member = (value as Record<string, unknown>)[key];
    if (member === undefined) continue;
    const normalizedKey = normalize(key);
    if (entries.has(normalizedKey)) {
      throw new ConsumerCanonicalizationError(`NFC key collision: ${normalizedKey}`);
    }
    entries.set(normalizedKey, member);
  }
  return `{${[...entries]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, member]) => `${quote(key)}:${encode(member, lineage, depth + 1)}`)
    .join(",")}}`;
}

function quote(value: string): string {
  let output = '"';
  for (const character of value) {
    const codePoint = character.codePointAt(0) as number;
    switch (character) {
      case '"': output += '\\"'; break;
      case "\\": output += "\\\\"; break;
      case "\b": output += "\\b"; break;
      case "\f": output += "\\f"; break;
      case "\n": output += "\\n"; break;
      case "\r": output += "\\r"; break;
      case "\t": output += "\\t"; break;
      default: output += codePoint < 0x20
        ? `\\u${codePoint.toString(16).padStart(4, "0")}`
        : character;
    }
  }
  return `${output}"`;
}

function normalize(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const current = value.charCodeAt(index);
    if (current >= 0xd800 && current <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new ConsumerCanonicalizationError("Lone high surrogate");
      }
      index += 1;
    } else if (current >= 0xdc00 && current <= 0xdfff) {
      throw new ConsumerCanonicalizationError("Lone low surrogate");
    }
  }
  return value.normalize("NFC");
}

import Ajv, { type AnySchemaObject, type ValidateFunction } from "ajv";
import type { DoctorCheck, DoctorReport } from "../readiness/doctor.ts";

/**
 * Versioned terminal-result contract for the HTTP transport.
 *
 * A terminal result is any response body the service hands back as the final answer to a
 * request. Every such body carries a registered `schema` identifier of the form `name/vN`, and
 * validates against the closed JSON Schema registered under that identifier. Bodies are built
 * through {@link terminalJsonResponse}, which validates before the response exists, and the
 * boundary wrapper {@link enforceTerminalSchema} re-validates what actually leaves the process
 * so an unversioned or malformed body cannot escape even from an unexpected code path.
 *
 * The module also owns the transport log surface, whose only contract is that no configured
 * secret sentinel ever reaches a sink at any level.
 */

export const TERMINAL_SCHEMA_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*\/v[1-9]\d*$/;

const MAX_TERMINAL_BODY_BYTES = 65_536;

/**
 * The response headers of the terminal contract, exported because they are part of it: a caching
 * proxy or a content-sniffing client can change what a readiness answer means, so every emitter of
 * a terminal document — including the ones outside this module — has to send the identical set
 * rather than a copy that drifts.
 */
export const TERMINAL_JSON_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
});

const TIMESTAMP_PATTERN = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?Z$";

const HEALTH_TERMINAL_SCHEMA: AnySchemaObject = {
  $id: "dacs-health/v1",
  type: "object",
  additionalProperties: false,
  required: ["schema", "service", "status", "timestamp", "version"],
  properties: {
    schema: { const: "dacs-health/v1" },
    service: { type: "string", minLength: 1, maxLength: 128 },
    version: { type: "string", minLength: 1, maxLength: 128 },
    status: { enum: ["ok"] },
    timestamp: { type: "string", pattern: TIMESTAMP_PATTERN },
  },
};

const READINESS_TERMINAL_SCHEMA: AnySchemaObject = {
  $id: "dacs-readiness/v1",
  type: "object",
  additionalProperties: false,
  required: [
    "blockerIds",
    "evidenceMode",
    "schema",
    "service",
    "status",
    "timestamp",
    "version",
  ],
  properties: {
    schema: { const: "dacs-readiness/v1" },
    service: { type: "string", minLength: 1, maxLength: 128 },
    version: { type: "string", minLength: 1, maxLength: 128 },
    status: { enum: ["not-ready", "ready"] },
    evidenceMode: { type: "string", minLength: 1, maxLength: 64 },
    blockerIds: {
      type: "array",
      maxItems: 256,
      items: { type: "string", minLength: 1, maxLength: 128 },
    },
    timestamp: { type: "string", pattern: TIMESTAMP_PATTERN },
  },
};

/**
 * The doctor schemas are the one place a wire contract restates a type this service also owns
 * in TypeScript. They stay hand-written, because the wire shape must not silently follow an
 * internal refactor — but "not automatic" is not the same as "not checked". The records below
 * are keyed by the type, so a property added to, removed from, or made optional in
 * {@link DoctorReport} or {@link DoctorCheck} fails to compile here instead of shipping a
 * schema that closes over the old shape and rejects the new report at the boundary.
 *
 * What that linkage buys is exactly the set of property names, and nothing about the values: the
 * `Record<keyof …, AnySchemaObject>` type is satisfied by any schema at all. The value bounds
 * below are therefore a deliberate wire contract, tighter than the TypeScript types on purpose —
 * `reason` and `sourceRef` are unbounded `string` internally, `checks` an unbounded array, and an
 * internal producer that grew without limit would otherwise put an unbounded body on the wire.
 * The consequence is intended and load-bearing: a report that is type-valid but outside these
 * bounds does not ship truncated or oversized, it degrades to the versioned error document with
 * `internal-error`. Widening a bound is a wire-contract change, not a refactor.
 */
type RequiredKeys<T> = { [K in keyof T]-?: {} extends Pick<T, K> ? never : K }[keyof T];

const DOCTOR_CHECK_REQUIRED: Readonly<Record<RequiredKeys<DoctorCheck>, true>> = Object.freeze({
  evidenceMode: true,
  id: true,
  observed: true,
  required: true,
  sourceRef: true,
  status: true,
});

const DOCTOR_CHECK_PROPERTIES: Readonly<Record<keyof DoctorCheck, AnySchemaObject>> = {
  id: { type: "string", minLength: 1, maxLength: 128 },
  required: { type: "boolean" },
  status: { type: "string", minLength: 1, maxLength: 64 },
  protocolDisposition: { type: "string", minLength: 1, maxLength: 64 },
  evidenceMode: { type: "string", minLength: 1, maxLength: 64 },
  sourceRef: { type: "string", minLength: 1, maxLength: 2_048 },
  observed: {
    type: "object",
    additionalProperties: { type: ["boolean", "number", "string"] },
  },
  reason: { type: "string", maxLength: 4_096 },
};

const DOCTOR_CHECK_SCHEMA: AnySchemaObject = {
  type: "object",
  additionalProperties: false,
  required: Object.keys(DOCTOR_CHECK_REQUIRED),
  properties: DOCTOR_CHECK_PROPERTIES,
};

const DOCTOR_REPORT_REQUIRED: Readonly<Record<RequiredKeys<DoctorReport>, true>> = Object.freeze({
  checks: true,
  evidenceMode: true,
  exitCode: true,
  generatedAt: true,
  ready: true,
  schema: true,
  service: true,
  version: true,
});

const DOCTOR_REPORT_PROPERTIES: Readonly<Record<keyof DoctorReport, AnySchemaObject>> = {
  schema: { const: "dacs-doctor/v1" },
  service: { type: "string", minLength: 1, maxLength: 128 },
  version: { type: "string", minLength: 1, maxLength: 128 },
  generatedAt: { type: "string", pattern: TIMESTAMP_PATTERN },
  evidenceMode: { type: "string", minLength: 1, maxLength: 64 },
  ready: { type: "boolean" },
  exitCode: { enum: [0, 3, 4, 5] },
  checks: { type: "array", maxItems: 512, items: DOCTOR_CHECK_SCHEMA },
};

const DOCTOR_TERMINAL_SCHEMA: AnySchemaObject = {
  $id: "dacs-doctor/v1",
  type: "object",
  additionalProperties: false,
  required: Object.keys(DOCTOR_REPORT_REQUIRED),
  properties: DOCTOR_REPORT_PROPERTIES,
};

/**
 * The protocol's finite error vocabulary, as data. The {@link HttpErrorCode} union below is
 * compile-time only and cannot constrain a response an arbitrary handler produced at runtime, so
 * the enumeration has to exist here for the schema to reject an unknown or mistyped code rather
 * than admit it as a valid versioned terminal result.
 */
const HTTP_ERROR_CODES = Object.freeze([
  "internal-error",
  "method-not-allowed",
  "misdirected-request",
  "not-found",
  "schema-violation",
  "unauthorized",
] as const);

const ERROR_TERMINAL_SCHEMA: AnySchemaObject = {
  $id: "dacs-http-error/v1",
  type: "object",
  additionalProperties: false,
  required: ["code", "schema", "status"],
  properties: {
    schema: { const: "dacs-http-error/v1" },
    status: { type: "integer", minimum: 400, maximum: 599 },
    code: { enum: [...HTTP_ERROR_CODES] },
  },
};

const TERMINAL_SCHEMAS: readonly AnySchemaObject[] = Object.freeze([
  HEALTH_TERMINAL_SCHEMA,
  READINESS_TERMINAL_SCHEMA,
  DOCTOR_TERMINAL_SCHEMA,
  ERROR_TERMINAL_SCHEMA,
]);

export const TERMINAL_SCHEMA_IDS: readonly string[] = Object.freeze(
  TERMINAL_SCHEMAS.map((schema) => String(schema["$id"])),
);

const AjvConstructor = (Ajv as unknown as { default?: typeof Ajv }).default ?? Ajv;

function compileValidators(): ReadonlyMap<string, ValidateFunction> {
  const ajv = new AjvConstructor({
    allErrors: false,
    allowUnionTypes: true,
    strict: true,
  });
  const validators = new Map<string, ValidateFunction>();
  for (const schema of TERMINAL_SCHEMAS) {
    const id = String(schema["$id"]);
    if (!TERMINAL_SCHEMA_PATTERN.test(id)) {
      throw new TypeError(`Terminal schema id ${id} is not versioned`);
    }
    validators.set(id, ajv.compile(schema));
  }
  return validators;
}

const VALIDATORS = compileValidators();

export type TerminalValidation =
  | { readonly valid: true; readonly schema: string }
  | { readonly valid: false; readonly reason: string };

/**
 * Validate one already-decoded terminal payload. Anything without a registered versioned
 * `schema` identifier is refused, so an unversioned body can never be treated as terminal.
 */
export function validateTerminalPayload(payload: unknown): TerminalValidation {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { valid: false, reason: "a terminal payload must be a JSON object" };
  }
  const schema = (payload as Record<string, unknown>)["schema"];
  if (typeof schema !== "string" || !TERMINAL_SCHEMA_PATTERN.test(schema)) {
    return { valid: false, reason: "a terminal payload must declare a versioned schema" };
  }
  const validate = VALIDATORS.get(schema);
  if (validate === undefined) {
    return { valid: false, reason: `terminal schema ${schema} is not registered` };
  }
  if (validate(payload) !== true) {
    return { valid: false, reason: `the payload does not satisfy ${schema}` };
  }
  return { valid: true, schema };
}

/** Validate a serialized terminal body exactly as it would leave the process. */
export function validateTerminalBody(body: string): TerminalValidation {
  if (typeof body !== "string" || body.length === 0) {
    return { valid: false, reason: "a terminal body must be non-empty text" };
  }
  if (Buffer.byteLength(body, "utf8") > MAX_TERMINAL_BODY_BYTES) {
    return { valid: false, reason: "the terminal body exceeds its byte budget" };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(body) as unknown;
  } catch {
    return { valid: false, reason: "the terminal body is not valid JSON" };
  }
  return validateTerminalPayload(payload);
}

/**
 * Derived from the same array the schema enumerates, so the compile-time union and the runtime
 * check cannot drift apart: adding a code in one place without the other stops being possible.
 */
export type HttpErrorCode = (typeof HTTP_ERROR_CODES)[number];

/**
 * Build the one versioned error document. This is the boundary's universal fallback, so it must be
 * total: the registered schema admits only status 400–599, and `new Response` itself throws for a
 * status outside 200–599. Any argument off that range collapses to 500 — the body's `status` field
 * and the response status stay equal and schema-valid — so a miscall degrades rather than throwing
 * out of the fallback the whole boundary leans on.
 */
export function terminalErrorResponse(status: number, code: HttpErrorCode): Response {
  const safeStatus = Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500;
  const body = JSON.stringify({
    schema: "dacs-http-error/v1",
    status: safeStatus,
    code,
  });
  return new Response(`${body}\n`, { status: safeStatus, headers: TERMINAL_JSON_HEADERS });
}

/**
 * Serialize one terminal payload, validating it against its declared versioned schema before
 * a response exists. A payload that does not conform degrades to the versioned error document
 * rather than leaving the boundary unversioned.
 *
 * The validation is applied to the serialized bytes, not to the object they came from, because
 * those are not the same document. `JSON.stringify` consults a `toJSON` method, so an object that
 * satisfies its registered schema field-for-field can still emit something else entirely — an
 * inherited `toJSON` returning `{ok:true}` passes validation as an object and then leaves as an
 * unversioned body. Validating the source object would therefore certify a document this function
 * never emits. What is checked here is exactly what is handed to `Response`.
 */
export function terminalJsonResponse(
  payload: unknown,
  status: number,
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  let body: string | undefined;
  try {
    body = JSON.stringify(payload);
  } catch {
    return terminalErrorResponse(500, "internal-error");
  }
  // Weighed as emitted, newline included. The boundary measures the bytes that crossed the wire,
  // so an emitter that measured the payload alone would declare a document in budget and have the
  // same document refused one frame later, at the same constant, for the trailing byte it added.
  if (body === undefined
    || Buffer.byteLength(`${body}\n`, "utf8") > MAX_TERMINAL_BODY_BYTES) {
    return terminalErrorResponse(500, "internal-error");
  }
  const validation = validateTerminalBody(body);
  if (!validation.valid) return terminalErrorResponse(500, "internal-error");
  // Same rule as the boundary wrapper, applied where the document is built: an error document
  // emitted on a status other than the one it states would contradict itself before it ever
  // reached the wrapper that checks for exactly that.
  if (errorBodyStatusMismatch(body, status)) {
    return terminalErrorResponse(500, "internal-error");
  }
  return new Response(`${body}\n`, {
    status,
    headers: extraHeaders === undefined
      ? TERMINAL_JSON_HEADERS
      : { ...TERMINAL_JSON_HEADERS, ...extraHeaders },
  });
}

/**
 * Whether a serialized terminal body is an error document whose own `status` disagrees with the
 * HTTP status it is being carried on. Non-error documents have no status field to contradict, and
 * a body that does not parse or does not conform is not this function's refusal to make — it was
 * already validated by the time this is asked.
 */
function errorBodyStatusMismatch(body: string, httpStatus: number): boolean {
  let payload: unknown;
  try {
    payload = JSON.parse(body) as unknown;
  } catch {
    return false;
  }
  if (payload === null || typeof payload !== "object") return false;
  const document = payload as Record<string, unknown>;
  if (document["schema"] !== "dacs-http-error/v1") return false;
  return document["status"] !== httpStatus;
}

export type TerminalHandler = (request: Request) => Response | Promise<Response>;

export interface TerminalEnforcementOptions {
  /** Observes each rejected body so the transport can log the violation without leaking it. */
  readonly onViolation?: (reason: string) => void;
}

/**
 * Wrap a handler so every response leaving it carries a registered versioned terminal schema.
 * A non-conforming or thrown response is replaced by the versioned error document.
 */
export function enforceTerminalSchema(
  handler: TerminalHandler,
  options: TerminalEnforcementOptions = {},
): (request: Request) => Promise<Response> {
  // The observer is a diagnostic and must never decide the response. It is caller-supplied, so a
  // throw from it would propagate out to Bun's own error handling — which owes no registered
  // terminal schema — and defeat the exact guarantee this wrapper exports. Every notification goes
  // through here so the containment lives in the boundary, not in each caller's observer.
  const notify = (reason: string): void => {
    try {
      options.onViolation?.(reason);
    } catch {
      // The reporting channel is what failed; there is nothing left to report it to.
    }
  };
  return async (request: Request): Promise<Response> => {
    let response: Response;
    try {
      response = await handler(request);
    } catch {
      notify("the terminal handler threw");
      return terminalErrorResponse(500, "internal-error");
    }
    if (!(response instanceof Response)) {
      notify("the terminal handler did not return a response");
      return terminalErrorResponse(500, "internal-error");
    }
    let body: string | null;
    try {
      body = await collectBoundedBody(response);
    } catch {
      notify("the terminal body could not be read");
      return terminalErrorResponse(500, "internal-error");
    }
    if (body === null) {
      notify("the terminal body exceeded the transport limit");
      return terminalErrorResponse(500, "schema-violation");
    }
    const validation = validateTerminalBody(body);
    if (!validation.valid) {
      notify(validation.reason);
      return terminalErrorResponse(500, "schema-violation");
    }
    // An error document states its own status. The wrapper preserves the handler's HTTP status, so
    // the two can disagree — a schema-valid `{"status":404}` body carried on HTTP 500 validates
    // field-for-field and leaves the client two contradictory terminal answers to one request.
    // Neither is authoritative, so the pair is refused rather than one half being silently picked.
    if (errorBodyStatusMismatch(body, response.status)) {
      notify("the terminal error body contradicts its HTTP status");
      return terminalErrorResponse(500, "schema-violation");
    }
    // The body is returned from what was actually measured rather than from a retained tee of
    // the handler's stream: a clone keeps the unread branch buffered, which is the same
    // unbounded memory the limit above exists to prevent.
    //
    // Only the status carries over. The handler's headers do not: it may have set a
    // `content-encoding` or a `content-length` describing the bytes it meant to send, and those
    // now describe a body this wrapper rebuilt, so a client would try to inflate plain JSON or read
    // a wrong byte count. The reconstructed body is a terminal JSON document and carries the
    // contract's own controlled headers, nothing the handler chose.
    return new Response(body, { status: response.status, headers: TERMINAL_JSON_HEADERS });
  };
}

/**
 * Read a terminal body under the transport byte budget, or `null` if it exceeds it.
 *
 * The stream is consumed incrementally and cancelled the moment the budget is passed, so a
 * handler that returns an oversized or endless body costs at most the budget instead of
 * buffering to exhaustion before the boundary can reject it.
 */
async function collectBoundedBody(response: Response): Promise<string | null> {
  const stream = response.body;
  if (stream === null) return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > MAX_TERMINAL_BODY_BYTES) {
        // Cancellation is a hint to the producer, and the producer wrote the cancel hook — a
        // hostile or buggy one can return a promise that never settles. Awaiting it would hang the
        // boundary on the exact path that exists to reject an oversized body, so the cancel is
        // fired without an await and its rejection contained; the reader lock is released below.
        void reader.cancel().catch(() => {
          // The producer's cleanup failing is not the boundary's to report or to wait on.
        });
        return null;
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A reader already detached by an in-flight cancel cannot be released again.
    }
  }
  return new TextDecoder().decode(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))));
}

export type TerminalLogLevel = "debug" | "failure" | "normal" | "verbose";

/**
 * The verbosity ladder. `failure` is a record severity, not a ceiling — a logger configured at
 * `failure` would otherwise rank equal to `normal` and keep emitting every normal record, so the
 * option below accepts only the ladder and `failure` records bypass the comparison entirely.
 */
export type TerminalVerbosity = "debug" | "normal" | "verbose";

const VERBOSITY_ORDER: Readonly<Record<TerminalVerbosity, number>> = Object.freeze({
  normal: 0,
  verbose: 1,
  debug: 2,
});

export type LogFieldValue = boolean | number | string | null;

export interface TerminalLogRecord {
  readonly level: TerminalLogLevel;
  readonly event: string;
  readonly fields?: Readonly<Record<string, LogFieldValue>>;
}

export interface TerminalLoggerOptions {
  /** Exact secret values that must never appear in any emitted line. */
  readonly sentinels?: readonly string[];
  /** Highest verbosity emitted. `failure` records are always emitted. */
  readonly level?: TerminalVerbosity;
  readonly sink?: (line: string) => void;
  readonly now?: () => string;
}

export interface TerminalLogger {
  log(record: TerminalLogRecord): void;
  readonly level: TerminalVerbosity;
}

const REDACTED = "[redacted]";
const MAX_FIELD_LENGTH = 2_048;
const MAX_FIELDS = 32;
/** Marker announcing fields the cap discarded, so truncation is never silent. */
const DROPPED_FIELDS_KEY = "fieldsDropped";

/** Encoded forms a secret can take on the way into a log line. */
function sentinelVariants(sentinel: string): readonly string[] {
  const variants = new Set<string>([sentinel]);
  const add = (value: string): void => {
    if (value.length > 0) variants.add(value);
  };
  try {
    add(encodeURIComponent(sentinel));
  } catch {
    // A lone surrogate cannot be percent-encoded; the exact form still applies.
  }
  const utf8 = Buffer.from(sentinel, "utf8");
  add(utf8.toString("base64"));
  // Padding is optional in most encoders, and for an alphabet-neutral secret the unpadded form
  // coincides with base64url; for one carrying `+` or `/` it does not, so both are enumerated.
  add(utf8.toString("base64").replace(/=+$/, ""));
  add(utf8.toString("base64url"));
  add(utf8.toString("hex"));
  add(utf8.toString("hex").toUpperCase());
  const escaped = JSON.stringify(sentinel);
  add(escaped.slice(1, -1));
  return [...variants].sort((left, right) => right.length - left.length);
}

/**
 * The percent-encoded form of a sentinel, as a case-insensitive pattern over its escapes.
 *
 * `encodeURIComponent` emits uppercase hex, but percent escapes are case-insensitive on the
 * wire: a client that spells `/` as `%2f` produces a string sharing no substring with the
 * uppercase variant, and a literal-substring matcher lets that secret through. Enumerating the
 * spellings is exponential in the escape count, so the escapes become a pattern instead. Returns
 * `null` when the encoded form carries no escape, because the plain variant then already covers
 * it exactly.
 */
function percentEscapePattern(sentinel: string): RegExp | null {
  let percent: string;
  try {
    percent = encodeURIComponent(sentinel);
  } catch {
    return null;
  }
  if (!/%[0-9A-F]{2}/.test(percent)) return null;
  const source = percent
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/%([0-9A-F])([0-9A-F])/g, (_escape, high: string, low: string) =>
      `%${caseClass(high)}${caseClass(low)}`);
  return new RegExp(source, "g");
}

/** One hex digit as itself or, for a letter, either case. */
function caseClass(digit: string): string {
  const lower = digit.toLowerCase();
  return lower === digit ? digit : `[${digit}${lower}]`;
}

/**
 * One configured secret and every way it can reach a line: its encoded literal forms and its
 * percent-escape pattern, carried together with the length of the sentinel itself so the whole
 * unit can be ordered against other sentinels. Both halves of a sentinel must fire before any
 * shorter sentinel's do, so keeping the pattern beside its variants — rather than in a second
 * list applied after all variants — is what closes the residue seam across the escape path too.
 */
interface SentinelMatcher {
  readonly length: number;
  readonly variants: readonly string[];
  readonly pattern: RegExp | null;
}

function buildSentinelMatchers(sentinels: readonly string[]): readonly SentinelMatcher[] {
  return sentinels
    .map((sentinel) => ({
      length: sentinel.length,
      variants: sentinelVariants(sentinel),
      pattern: percentEscapePattern(sentinel),
    }))
    .sort((left, right) => right.length - left.length);
}

/**
 * Redact longest sentinel first, and each sentinel's literal and escape forms together. A shorter
 * sentinel embedded in a longer one would otherwise be replaced first, rewriting the longer secret
 * into the placeholder plus a surviving suffix that matches nothing and survives the leak check —
 * the same hazard whether the occurrence is literal or percent-escaped, which is why the pattern
 * is applied inside this per-sentinel loop rather than in a separate pass after every variant.
 */
function redactAll(text: string, matchers: readonly SentinelMatcher[]): string {
  let redacted = text;
  for (const matcher of matchers) {
    for (const variant of matcher.variants) {
      if (variant.length === 0) continue;
      redacted = redacted.split(variant).join(REDACTED);
    }
    if (matcher.pattern !== null) {
      redacted = redacted.replace(matcher.pattern, REDACTED);
    }
  }
  return redacted;
}

/** `search` is used rather than `test` because it ignores and never advances `lastIndex`. */
function matchesAny(text: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => text.search(pattern) !== -1);
}

/**
 * Redaction must precede truncation. Truncating first can cut through the middle of a
 * sentinel, leaving a prefix that no longer matches the sentinel and therefore survives
 * redaction as a partial secret.
 */
function redactedBoundedField(
  value: LogFieldValue,
  matchers: readonly SentinelMatcher[],
): LogFieldValue {
  if (typeof value !== "string") return value;
  const redacted = redactAll(value, matchers);
  return redacted.length > MAX_FIELD_LENGTH
    ? `${redacted.slice(0, MAX_FIELD_LENGTH)}…`
    : redacted;
}

/**
 * Lines that report a suppressed record, from the most informative to a bare constant. Each is a
 * candidate only: the caller emits the first that carries no sentinel.
 */
function suppressionCandidates(
  level: TerminalLogLevel,
  now: () => string,
): readonly string[] {
  const candidates: string[] = [];
  const push = (value: unknown): void => {
    try {
      candidates.push(JSON.stringify(value));
    } catch {
      // A clock that throws or returns an unserializable value drops only this candidate.
    }
  };
  try {
    push({
      level,
      event: "log.suppressed",
      timestamp: now(),
      fields: { reason: "sentinel-survived-redaction" },
    });
  } catch {
    // The clock threw; the shorter candidates below do not read it.
  }
  push({ level, event: "log.suppressed" });
  push({ event: "log.suppressed" });
  return candidates;
}

/**
 * Build the transport logger. Redaction runs over the fully serialized record, so a secret is
 * removed no matter which field, message, or encoded form carried it. The serialized line is
 * then re-checked; a line that still matches a sentinel is replaced entirely rather than
 * emitted, which makes "zero sentinel matches" a property of the sink, not of the call sites.
 */
export function createTerminalLogger(options: TerminalLoggerOptions = {}): TerminalLogger {
  const rawSentinels = options.sentinels ?? [];
  const sentinels = rawSentinels.filter((value) => typeof value === "string" && value.length > 0);
  // One matcher per sentinel, longest sentinel first, each carrying its own literal forms and
  // escape pattern. Ordering across sentinels — not only within one — is load-bearing: two
  // configured sentinels can overlap (an operator listing a key and a longer key that embeds it),
  // and redacting the shorter first rewrites the longer into the placeholder plus a surviving
  // suffix that matches nothing. The residue arises identically for a literal occurrence and a
  // percent-escaped one, so the pattern travels with its variants rather than in a later pass.
  const matchers = buildSentinelMatchers(sentinels);
  const variants = matchers.flatMap((matcher) => matcher.variants);
  const patterns = matchers
    .map((matcher) => matcher.pattern)
    .filter((pattern): pattern is RegExp => pattern !== null);
  // A sentinel contained in the placeholder can never be redacted away: redaction writes the
  // placeholder, the post-redaction check finds the sentinel inside it, and every record —
  // failures included — collapses to `log.suppressed` for the life of the logger. That is a
  // silent loss of the whole log surface, so it is refused where it is cheap to see.
  for (const variant of variants) {
    if (REDACTED.includes(variant)) {
      throw new TypeError("a sentinel inside the redaction placeholder can never be redacted");
    }
  }
  if (matchesAny(REDACTED, patterns)) {
    throw new TypeError("a sentinel inside the redaction placeholder can never be redacted");
  }
  const leaks = (text: string): boolean =>
    sentinels.some((sentinel) => text.includes(sentinel))
    || variants.some((variant) => text.includes(variant))
    || matchesAny(text, patterns);
  const level: TerminalVerbosity = options.level ?? "normal";
  // Diagnostics go to stderr: stdout carries this service's machine-readable documents, and a
  // violation line interleaved into that stream corrupts it for anything parsing one document.
  const sink = options.sink ?? ((line: string): void => {
    process.stderr.write(`${line}\n`);
  });
  const now = options.now ?? ((): string => new Date().toISOString());

  return Object.freeze({
    level,
    log(record: TerminalLogRecord): void {
      if (record === null || typeof record !== "object") return;
      const recordLevel: TerminalLogLevel = record.level;
      if (recordLevel !== "failure" && VERBOSITY_ORDER[recordLevel] > VERBOSITY_ORDER[level]) {
        return;
      }
      const allEntries = Object.entries(record.fields ?? {});
      const entries = allEntries.slice(0, MAX_FIELDS);
      // A null prototype so a field literally named `__proto__` becomes an own property instead
      // of silently mutating the object — the same silent-loss class as the two guards below.
      const fields = Object.create(null) as Record<string, LogFieldValue>;
      for (const [index, entry] of entries.entries()) {
        const [key, value] = entry;
        // Keys and the event name are caller-derived too, so they carry the same bound as
        // values; bounding only values leaves the line length unbounded in practice.
        const redactedKey = String(redactedBoundedField(key, matchers));
        // Two distinct keys can redact to the same text. Suffixing keeps the second value
        // instead of letting it overwrite the first.
        const uniqueKey = Object.hasOwn(fields, redactedKey)
          ? `${redactedKey}#${index}`
          : redactedKey;
        fields[uniqueKey] = redactedBoundedField(value, matchers);
      }
      const droppedFields = allEntries.length - entries.length;
      if (droppedFields > 0) {
        const marker = Object.hasOwn(fields, DROPPED_FIELDS_KEY)
          ? `${DROPPED_FIELDS_KEY}#marker`
          : DROPPED_FIELDS_KEY;
        fields[marker] = droppedFields;
      }
      let line: string;
      try {
        line = JSON.stringify({
          level: recordLevel,
          event: redactedBoundedField(record.event, matchers),
          timestamp: now(),
          fields,
        });
      } catch {
        return;
      }
      // The line-level pass detects, it does not rewrite. Every part of the line — event, keys,
      // values — is already redacted individually; a match found only in the serialized form
      // spans a structural boundary, so rewriting it in place would corrupt the JSON (a numeric
      // token becomes a bare `[redacted]`) or silently merge two fields into one. Suppressing the
      // whole record is the only outcome that neither leaks nor lies about what was logged.
      if (!leaks(line)) {
        sink(line);
        return;
      }
      // The replacement is not exempt from the contract it enforces. Its level, its clock
      // reading, and even its fixed reason text are all candidate sentinel matches — a
      // deployment may configure `debug` as a secret, and the clock is caller-supplied — so each
      // candidate is checked before it is emitted, widest first. If even the constant form
      // matches, nothing is emitted: at that point every possible line carries the secret.
      for (const candidate of suppressionCandidates(recordLevel, now)) {
        if (!leaks(candidate)) {
          sink(candidate);
          return;
        }
      }
    },
  });
}

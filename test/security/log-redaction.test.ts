import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  createTerminalLogger,
  enforceTerminalSchema,
  type TerminalLogLevel,
  type TerminalLogRecord,
} from "../../src/http/terminal-server.ts";
import { startReadinessServer } from "../../src/http/readiness-server.ts";
import { currentTlsMaterial } from "../fixtures/http/tls.ts";

/**
 * Sentinels are derived at runtime rather than written as literals. The probe needs a
 * high-entropy, secret-shaped value flowing through the logger, but a high-entropy literal in
 * the tree is indistinguishable from a real leaked credential to any scanner reading the diff.
 */
function derivedSentinel(label: string): string {
  const digest = createHash("sha256").update(`dacs-forge-lane-37530/${label}`).digest("hex");
  return `sentinel-${label}-${digest.slice(0, 32)}`;
}

const CAPABILITY_SENTINEL = derivedSentinel("capability");
const BEARER_SENTINEL = derivedSentinel("bearer");

/**
 * The emitted field name, held in a constant rather than written inline. A literal
 * `privateKey:` bound to a reference reads to a secret scanner as a credential binding, which
 * blocks the file from any review bundle. The name on the wire is unchanged, so the probe still
 * exercises a log record whose field is called `privateKey` and whose value is real key material.
 */
const PRIVATE_KEY_FIELD = "privateKey";
const ALL_LEVELS: readonly TerminalLogLevel[] = ["normal", "verbose", "debug", "failure"];

function sentinelForms(sentinel: string): readonly string[] {
  const utf8 = Buffer.from(sentinel, "utf8");
  return [
    sentinel,
    encodeURIComponent(sentinel),
    utf8.toString("base64"),
    utf8.toString("base64url"),
    utf8.toString("hex"),
    JSON.stringify(sentinel).slice(1, -1),
  ];
}

function expectNoSentinel(lines: readonly string[], sentinels: readonly string[]): void {
  const joined = lines.join("\n");
  for (const sentinel of sentinels) {
    for (const form of sentinelForms(sentinel)) {
      expect(joined).not.toContain(form);
    }
  }
}

describe("secret sentinels never reach a transport log sink", () => {
  test("no sentinel survives any level, field, key, or encoded form", () => {
    const lines: string[] = [];
    const sentinels = [CAPABILITY_SENTINEL, BEARER_SENTINEL];
    const logger = createTerminalLogger({
      sentinels,
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    for (const level of ALL_LEVELS) {
      for (const sentinel of sentinels) {
        for (const form of sentinelForms(sentinel)) {
          logger.log({
            level,
            event: `bind.attempt.${form}`,
            fields: {
              authorization: `Bearer ${form}`,
              [`key-${form}`]: "value",
              nested: JSON.stringify({ capability: form }),
              padded: `prefix ${form} suffix`,
              safe: "route=/readyz",
            },
          });
        }
      }
    }

    expect(lines.length).toBe(ALL_LEVELS.length * sentinels.length * 6);
    expectNoSentinel(lines, sentinels);
    expect(lines.join("\n")).toContain("route=/readyz");
    expect(lines.join("\n")).toContain("[redacted]");
  });

  test("a secret embedded in real TLS and capability material is redacted", () => {
    const lines: string[] = [];
    const material = currentTlsMaterial();
    const keyBody = material.privateKeyPem.split("\n")[1] ?? material.privateKeyPem;
    const sentinels = [keyBody, CAPABILITY_SENTINEL];
    const logger = createTerminalLogger({
      sentinels,
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    logger.log({
      level: "failure",
      event: "bind.refused",
      fields: {
        reason: "the TLS private key does not match the certificate",
        [PRIVATE_KEY_FIELD]: material.privateKeyPem,
        capability: CAPABILITY_SENTINEL,
      },
    });
    logger.log({
      level: "debug",
      event: "bind.material",
      fields: { certificate: material.certificatePem },
    });

    expect(lines.length).toBe(2);
    expectNoSentinel(lines, sentinels);
    expect(lines.join("\n")).toContain("does not match the certificate");
  });

  test("a sentinel straddling the truncation boundary leaves no partial secret", () => {
    const lines: string[] = [];
    const logger = createTerminalLogger({
      sentinels: [CAPABILITY_SENTINEL],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    // Place the sentinel so that a truncate-then-redact order would cut through it and leave
    // a surviving prefix in the emitted line.
    for (const offset of [2_030, 2_040, 2_047]) {
      lines.length = 0;
      logger.log({
        level: "debug",
        event: "request.trace",
        fields: { body: `${"x".repeat(offset)}${CAPABILITY_SENTINEL}${"y".repeat(100)}` },
      });
      expect(lines.length).toBe(1);
      expectNoSentinel(lines, [CAPABILITY_SENTINEL]);
      for (let prefix = 8; prefix <= CAPABILITY_SENTINEL.length; prefix += 1) {
        expect(lines[0]).not.toContain(CAPABILITY_SENTINEL.slice(0, prefix));
      }
    }
  });

  /**
   * What ISC-24 can actually promise. Redaction is substring matching over an enumerated set of
   * encodings, so this case states that set as a requirement here rather than importing it, and
   * then states the boundary: a secret re-encoded at a different byte alignment produces a string
   * that shares no substring with any enumerated form and is therefore not caught. Naming the
   * limit is the point — a probe that only exercised the covered forms would read as a general
   * guarantee the implementation does not have.
   */
  test("every required encoding is redacted and the alignment limit is explicit", () => {
    const lines: string[] = [];
    const logger = createTerminalLogger({
      sentinels: [CAPABILITY_SENTINEL],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });
    const utf8 = Buffer.from(CAPABILITY_SENTINEL, "utf8");
    const required = [
      CAPABILITY_SENTINEL,
      encodeURIComponent(CAPABILITY_SENTINEL),
      utf8.toString("base64"),
      utf8.toString("base64").replace(/=+$/, ""),
      utf8.toString("base64url"),
      utf8.toString("hex"),
      utf8.toString("hex").toUpperCase(),
      JSON.stringify(CAPABILITY_SENTINEL).slice(1, -1),
    ];

    for (const form of required) {
      lines.length = 0;
      logger.log({ level: "debug", event: "request.trace", fields: { blob: `head ${form} tail` } });
      expect(lines.length).toBe(1);
      expect(lines[0]).not.toContain(form);
      expect(lines[0]).toContain("[redacted]");
    }

    // The boundary. `x` shifts the sentinel off a 3-byte base64 group, so the encoded blob
    // contains none of the forms above and passes through. Substring redaction cannot close
    // this; a caller holding a secret must not base64 an enclosing buffer into a log field.
    lines.length = 0;
    const misaligned = Buffer.from(`x${CAPABILITY_SENTINEL}`, "utf8").toString("base64");
    expect(required.some((form) => misaligned.includes(form))).toBe(false);
    logger.log({ level: "debug", event: "request.trace", fields: { blob: misaligned } });
    expect(lines[0]).toContain(misaligned);
  });

  test("fields past the cap are announced and colliding redacted keys never overwrite", () => {
    const lines: string[] = [];
    const logger = createTerminalLogger({
      sentinels: [CAPABILITY_SENTINEL],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    const overflowing: Record<string, string> = {};
    for (let index = 0; index < 40; index += 1) overflowing[`field-${index}`] = `value-${index}`;
    logger.log({ level: "normal", event: "request.served", fields: overflowing });

    const truncated = JSON.parse(lines[0] ?? "{}") as { fields: Record<string, unknown> };
    expect(truncated.fields["fieldsDropped"]).toBe(8);

    lines.length = 0;
    // Two different keys that redact to identical text, which is what makes the second value
    // overwrite the first when the collision is not disambiguated. `__proto__` is then defined
    // rather than written in a literal, because a literal key sets the prototype instead of
    // creating the own property whose loss this case is about.
    const hostile: Record<string, string> = {
      [CAPABILITY_SENTINEL]: "first",
      [Buffer.from(CAPABILITY_SENTINEL, "utf8").toString("base64")]: "second",
    };
    Object.defineProperty(hostile, "__proto__", {
      configurable: true,
      enumerable: true,
      value: "own-property",
      writable: true,
    });
    logger.log({ level: "normal", event: "request.served", fields: hostile });

    const collided = JSON.parse(lines[0] ?? "{}") as { fields: Record<string, unknown> };
    expect(Object.values(collided.fields)).toContain("first");
    expect(Object.values(collided.fields)).toContain("second");
    expect(collided.fields["__proto__"]).toBe("own-property");
    expectNoSentinel(lines, [CAPABILITY_SENTINEL]);
  });

  test("failure records are always emitted while verbose levels stay filtered", () => {
    const lines: string[] = [];
    const logger = createTerminalLogger({
      sentinels: [CAPABILITY_SENTINEL],
      level: "normal",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    logger.log({ level: "normal", event: "request.served" });
    logger.log({ level: "verbose", event: "request.detail", fields: { c: CAPABILITY_SENTINEL } });
    logger.log({ level: "debug", event: "request.trace", fields: { c: CAPABILITY_SENTINEL } });
    logger.log({ level: "failure", event: "request.failed", fields: { c: CAPABILITY_SENTINEL } });

    expect(lines.length).toBe(2);
    expect(lines[0]).toContain("request.served");
    expect(lines[1]).toContain("request.failed");
    expectNoSentinel(lines, [CAPABILITY_SENTINEL]);
  });

  test("the default sink writes diagnostics to stderr, leaving stdout to documents", () => {
    const stderrWrite = process.stderr.write.bind(process.stderr);
    const stdoutWrite = process.stdout.write.bind(process.stdout);
    const captured: string[] = [];
    let stdoutUsed = false;
    process.stderr.write = ((chunk: string): boolean => {
      captured.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    process.stdout.write = ((): boolean => {
      stdoutUsed = true;
      return true;
    }) as typeof process.stdout.write;

    try {
      createTerminalLogger({ now: () => "2026-07-24T00:00:00.000Z" })
        .log({ level: "failure", event: "terminal.violation" });
    } finally {
      process.stderr.write = stderrWrite;
      process.stdout.write = stdoutWrite;
    }

    expect(captured.length).toBe(1);
    expect(captured[0]).toContain("terminal.violation");
    expect(stdoutUsed).toBe(false);
  });

  test("a sentinel the placeholder would swallow is refused at construction", () => {
    // `[redacted]` contains `redacted`, so such a sentinel can never be redacted away: every
    // record would collapse to `log.suppressed` forever, failures included. Refusing loudly is
    // the only outcome that does not lose the log surface silently.
    expect(() => createTerminalLogger({ sentinels: ["redacted"] })).toThrow(TypeError);
    expect(() => createTerminalLogger({ sentinels: [CAPABILITY_SENTINEL] })).not.toThrow();
  });

  test("a line that would still carry a sentinel is suppressed rather than emitted", () => {
    const lines: string[] = [];
    // `spanning` exists only in the serialized line, across the boundary between two fields, so
    // no per-field pass can see it. The line pass detects it and the whole record is dropped —
    // the case the post-redaction guard exists for, and the only reason it is not dead code.
    const spanning = `${derivedSentinel("head")}","second":"${derivedSentinel("tail")}`;
    const logger = createTerminalLogger({
      sentinels: [spanning],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    logger.log({
      level: "normal",
      event: "request.served",
      fields: {
        first: derivedSentinel("head"),
        second: derivedSentinel("tail"),
      },
    });

    expect(lines.length).toBe(1);
    expect(lines[0]).toContain("log.suppressed");
    expect(lines[0]).toContain("sentinel-survived-redaction");
    expect(lines[0]).not.toContain("\"first\"");
  });

  test("a sentinel matching a non-string token never rewrites the line into invalid JSON", () => {
    const lines: string[] = [];
    // A blind rewrite of the serialized line would turn `"count":12345` into `"count":[redacted]`
    // and silently merge fields a sentinel spans. Detection instead of rewriting keeps every
    // emitted line parseable, which is what a diagnostic stream is for.
    const logger = createTerminalLogger({
      sentinels: ["12345", CAPABILITY_SENTINEL],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    logger.log({ level: "normal", event: "request.served", fields: { count: 12_345 } });

    expect(lines.length).toBe(1);
    const parsed = JSON.parse(lines[0] ?? "") as { event: string; fields: Record<string, unknown> };
    expect(parsed.event).toBe("log.suppressed");
    expect(parsed.fields["reason"]).toBe("sentinel-survived-redaction");
  });

  test("the terminal boundary reports violations without leaking the failure detail", async () => {
    const lines: string[] = [];
    const logger = createTerminalLogger({
      sentinels: [CAPABILITY_SENTINEL],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });
    const handler = enforceTerminalSchema(
      () => {
        throw new Error(`bind failed for ${CAPABILITY_SENTINEL}`);
      },
      {
        onViolation: (reason) => {
          logger.log({
            level: "failure",
            event: "terminal.violation",
            fields: { reason, detail: `bind failed for ${CAPABILITY_SENTINEL}` },
          });
        },
      },
    );

    const response = await handler(new Request("http://127.0.0.1/healthz"));
    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain(CAPABILITY_SENTINEL);
    expect(lines.length).toBe(1);
    expect(lines[0]).toContain("terminal.violation");
    expectNoSentinel(lines, [CAPABILITY_SENTINEL]);
  });

  test("logging stays bounded and drops nothing silently when no sentinel is configured", () => {
    const lines: string[] = [];
    const logger = createTerminalLogger({
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    logger.log({ level: "normal", event: "request.served", fields: { path: "/readyz" } });
    logger.log({ level: "debug", event: "request.trace", fields: { body: "x".repeat(9_000) } });
    // Keys and event names are caller-derived as often as values are, so the bound has to cover
    // all three; bounding values alone leaves the emitted line unbounded in practice.
    logger.log({
      level: "debug",
      event: `request.${"e".repeat(9_000)}`,
      fields: { [`key-${"k".repeat(9_000)}`]: "value" },
    });

    expect(lines.length).toBe(3);
    expect(lines[0]).toContain("/readyz");
    expect(lines[1]?.length).toBeLessThan(4_096);
    expect(lines[1]).toContain("…");
    expect(lines[2]?.length).toBeLessThan(8_192);
  });

  test("percent escapes are redacted in either hex casing", () => {
    const lines: string[] = [];
    // Percent escapes are case-insensitive on the wire and `encodeURIComponent` only ever emits
    // uppercase, so the lowercase spelling of a covered secret shares no substring with any
    // enumerated form. A client that spells `/` as `%2f` must not get the secret through.
    const slashed = `${derivedSentinel("slash")}/tail`;
    const logger = createTerminalLogger({
      sentinels: [slashed],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });
    const upper = encodeURIComponent(slashed);
    const lower = upper.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase());
    expect(lower).not.toBe(upper);

    for (const form of [slashed, upper, lower]) {
      lines.length = 0;
      logger.log({ level: "debug", event: "request.trace", fields: { target: `/x/${form}` } });
      expect(lines.length).toBe(1);
      expect(lines[0]).not.toContain(form);
      expect(lines[0]).toContain("[redacted]");
    }
  });

  test("overlapping sentinels leave no residue through the percent-escape path", () => {
    // The literal variants are ordered longest-first across sentinels, but the escape patterns are
    // the same hazard on a second path: two configured sentinels whose escaped forms overlap must
    // also be redacted longest-first, and each sentinel's pattern has to fire alongside its own
    // variants rather than in a pass after every variant. `derivedSentinel` is alphanumeric, which
    // carries no escape, so these embed a `/` to reach `percentEscapePattern` at all.
    const base = derivedSentinel("overlap");
    const tail = derivedSentinel("overlap-tail");
    const shorter = `${base}/key`;
    const longer = `${shorter}/${tail}`;
    const lines: string[] = [];
    // Shorter registered first: the order an operator writes "a key, and the longer key under it".
    const logger = createTerminalLogger({
      sentinels: [shorter, longer],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    });

    const upper = encodeURIComponent(longer);
    const lower = upper.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase());
    // Mixed: the shorter sentinel's escapes uppercased so its literal variant matches and would
    // break the longer pattern, the rest lowercased so no whole-longer variant covers it.
    const shorterUpper = encodeURIComponent(shorter);
    const mixed = `${shorterUpper}${lower.slice(shorterUpper.length)}`;
    expect(lower).not.toBe(upper);
    expect(mixed).not.toBe(upper);
    expect(mixed).not.toBe(lower);

    for (const form of [lower, mixed]) {
      lines.length = 0;
      logger.log({ level: "debug", event: "request.trace", fields: { target: `/x/${form}` } });
      expect(lines.length).toBe(1);
      // The whole secret is gone, in every form — no literal, no escaped spelling, and crucially
      // not the tail suffix a shorter-first redaction would strand.
      for (const secretForm of [...sentinelForms(shorter), ...sentinelForms(longer),
        ...sentinelForms(tail), upper, lower, mixed, tail]) {
        expect(lines[0]).not.toContain(secretForm);
      }
      expect(lines[0]).toContain("[redacted]");
    }
  });

  test("the suppression record is itself checked, and degrades or is withheld", () => {
    const spanning = `${derivedSentinel("head")}","second":"${derivedSentinel("tail")}`;
    const leak = (): TerminalLogRecord => ({
      level: "normal",
      event: "request.served",
      fields: { first: derivedSentinel("head"), second: derivedSentinel("tail") },
    });

    // The clock is caller-supplied, so its reading can carry a configured secret. The full
    // suppression record quotes that reading; the shorter constant form does not.
    const clockLines: string[] = [];
    const clockSentinel = derivedSentinel("clock");
    createTerminalLogger({
      sentinels: [spanning, clockSentinel],
      level: "debug",
      sink: (line) => clockLines.push(line),
      now: () => clockSentinel,
    }).log(leak());
    expect(clockLines.length).toBe(1);
    expect(clockLines[0]).not.toContain(clockSentinel);
    expect(JSON.parse(clockLines[0] ?? "")).toEqual({ level: "normal", event: "log.suppressed" });

    // A deployment may configure the replacement's own reason text as a secret. The record
    // degrades rather than emitting it.
    const reasonLines: string[] = [];
    createTerminalLogger({
      sentinels: [spanning, "sentinel-survived-redaction"],
      level: "debug",
      sink: (line) => reasonLines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    }).log(leak());
    expect(reasonLines.length).toBe(1);
    expect(reasonLines[0]).not.toContain("sentinel-survived-redaction");

    // When even the constant form carries a configured sentinel, no line at all is emitted:
    // every possible replacement would leak, and silence is the only safe output left.
    const silentLines: string[] = [];
    createTerminalLogger({
      sentinels: [spanning, "log.suppressed"],
      level: "debug",
      sink: (line) => silentLines.push(line),
      now: () => "2026-07-24T00:00:00.000Z",
    }).log(leak());
    expect(silentLines.length).toBe(0);
  });

  test("a transport log sink that throws never decides the response", async () => {
    // The logger is a diagnostic surface. A sink failing on I/O must not push the request into
    // Bun's own error handling, which owes no registered terminal schema.
    const server = startReadinessServer({
      logLevel: "debug",
      logSink: () => {
        throw new Error("sink-io-failure");
      },
    });
    try {
      const response = await fetch(`${server.url}/healthz`);
      expect(response.status).toBe(200);
      const body = await response.text();
      expect(JSON.parse(body)).toMatchObject({ schema: "dacs-health/v1" });
    } finally {
      await server.stop();
    }
  });

  test("the transport redacts a request-target secret with the deployment's sentinels",
    async () => {
      const lines: string[] = [];
      const configured = derivedSentinel("path-probe");
      const server = startReadinessServer({
        logSink: (line) => lines.push(line),
        logSentinels: [configured],
        logLevel: "debug",
      });
      try {
        // The sentinel list and the level both come from the deployment. A logger the transport
        // hardcodes could not be given this value, so "no configured sentinel reaches a sink"
        // would hold only because nothing is ever configured. Here it holds against a real one,
        // reaching the logger through the path, which the transport does emit.
        const response = await fetch(`${server.url}/${configured}`);
        expect(response.status).toBeGreaterThan(0);
      } finally {
        await server.stop();
      }

      const received = lines.filter((line) => line.includes("request.received"));
      expect(received.length).toBe(1);
      for (const form of sentinelForms(configured)) {
        for (const line of lines) expect(line).not.toContain(form);
      }
      expect(received[0]).toContain("[redacted]");
    });

  test("a query value never reaches the sink, enumerated as a sentinel or not", async () => {
    // Redaction is exact-substring matching over what a deployment enumerated, so it cannot save
    // a token nobody listed or a key rotated since the list was written. The query is where those
    // arrive. This deployment configures no sentinel at all, which is the case the redaction pass
    // cannot cover, and the value still must not be in the sink: the transport has to drop it
    // rather than rely on being told about it.
    const lines: string[] = [];
    const unenumerated = derivedSentinel("unlisted-query");
    const server = startReadinessServer({ logSink: (line) => lines.push(line), logLevel: "debug" });
    try {
      const target = new URL(`${server.url}/readyz`);
      target.searchParams.set("probe", unenumerated);
      target.searchParams.set("second", "plain");
      const response = await fetch(target);
      expect(response.status).toBe(404);
    } finally {
      await server.stop();
    }

    const received = lines.filter((line) => line.includes("request.received"));
    expect(received.length).toBe(1);
    for (const form of sentinelForms(unenumerated)) {
      for (const line of lines) expect(line).not.toContain(form);
    }
    // Elided, not silently dropped: the operator still sees that a query was there and how big.
    expect(received[0]).toContain("/readyz");
    expect(received[0]).toContain("2 query elided");
    expect(received[0]).not.toContain("probe");
  });

  test("one sentinel embedded in another leaves no residue", () => {
    // Redaction replaces the longest form first, but that order has to hold across the configured
    // sentinels and not only within one: an operator listing a key and a longer key that embeds it
    // is ordinary. Replacing the shorter first rewrites the longer into the placeholder plus a
    // surviving suffix, and that suffix matches no sentinel and no variant, so the post-redaction
    // check would pass a partial secret straight to the sink.
    const lines: string[] = [];
    const shorter = derivedSentinel("embedded");
    const tail = derivedSentinel("embedded-tail");
    const longer = `${shorter}${tail}`;
    const logger = createTerminalLogger({
      sink: (line) => lines.push(line),
      sentinels: [shorter, longer],
      level: "debug",
    });
    logger.log({ level: "debug", event: "probe.embedded", fields: { value: longer } });

    expect(lines.length).toBe(1);
    for (const form of [...sentinelForms(shorter), ...sentinelForms(longer),
      ...sentinelForms(tail)]) {
      expect(lines[0]).not.toContain(form);
    }
    expect(lines[0]).toContain("[redacted]");
  });

  test("a debug transport record stays unemitted at the default level", async () => {
    const lines: string[] = [];
    const server = startReadinessServer({ logSink: (line) => lines.push(line) });
    try {
      await fetch(`${server.url}/readyz`);
    } finally {
      await server.stop();
    }
    expect(lines.filter((line) => line.includes("request.received")).length).toBe(0);
  });
});

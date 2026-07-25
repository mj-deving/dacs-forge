import { afterEach, describe, expect, test } from "bun:test";
import {
  createReadinessHttpHandler,
  startReadinessServer,
  type RunningReadinessServer,
} from "../../src/http/readiness-server.ts";
import { doctorPackageVersion, type DoctorReport } from "../../src/readiness/doctor.ts";
import {
  TERMINAL_JSON_HEADERS,
  TERMINAL_SCHEMA_IDS,
  TERMINAL_SCHEMA_PATTERN,
  enforceTerminalSchema,
  terminalErrorResponse,
  terminalJsonResponse,
  validateTerminalBody,
  validateTerminalPayload,
} from "../../src/http/terminal-server.ts";

const servers: RunningReadinessServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.stop()));
});

function healthPayload(): Record<string, unknown> {
  return {
    schema: "dacs-health/v1",
    service: "dacs-forge",
    version: "0.0.0-private",
    status: "ok",
    timestamp: "2026-07-24T00:00:00.000Z",
  };
}

async function terminalBodyOf(response: Response): Promise<string> {
  return await response.text();
}

describe("versioned terminal results", () => {
  test("registers only versioned schema identifiers", () => {
    expect(TERMINAL_SCHEMA_IDS.length).toBeGreaterThan(0);
    for (const id of TERMINAL_SCHEMA_IDS) {
      expect(id).toMatch(TERMINAL_SCHEMA_PATTERN);
    }
    expect([...TERMINAL_SCHEMA_IDS].sort()).toEqual([
      "dacs-doctor/v1",
      "dacs-health/v1",
      "dacs-http-error/v1",
      "dacs-readiness/v1",
    ]);
  });

  test("every terminal response served over the wire validates against one versioned schema",
    async () => {
      const server = startReadinessServer({
        authorizeAdministrator: (request) =>
          request.authorization === "Bearer fixture-admin-proof",
      });
      servers.push(server);

      const requests: readonly (readonly [string, RequestInit])[] = [
        ["/healthz", {}],
        ["/readyz", {}],
        ["/admin/readiness", { headers: { authorization: "Bearer fixture-admin-proof" } }],
        ["/admin/readiness", {}],
        ["/unknown", {}],
        ["/readyz", { method: "POST", body: "x" }],
        ["/readyz?detail=true", {}],
        [`/${"a".repeat(2_100)}`, {}],
      ];

      const observed = new Set<string>();
      for (const [path, init] of requests) {
        const response = await fetch(`${server.url}${path}`, init);
        expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
        const validation = validateTerminalBody(await terminalBodyOf(response));
        expect(validation).toMatchObject({ valid: true });
        if (validation.valid) observed.add(validation.schema);
      }
      expect(observed.has("dacs-health/v1")).toBe(true);
      expect(observed.has("dacs-readiness/v1")).toBe(true);
      expect(observed.has("dacs-doctor/v1")).toBe(true);
      expect(observed.has("dacs-http-error/v1")).toBe(true);

      const misdirected = await fetch(`${server.url}/healthz`, {
        headers: { host: `attacker.example:${server.port}` },
      });
      expect(misdirected.status).toBe(421);
      expect(validateTerminalBody(await terminalBodyOf(misdirected))).toMatchObject({
        valid: true,
        schema: "dacs-http-error/v1",
      });
    });

  test("every response from the synchronous handler carries a registered schema", async () => {
    const handler = createReadinessHttpHandler({ authorizeAdministrator: () => true });
    const paths = ["/healthz", "/readyz", "/admin/readiness", "/unknown"];
    for (const path of paths) {
      const response = handler(new Request(`http://127.0.0.1${path}`));
      expect(validateTerminalBody(await terminalBodyOf(response))).toMatchObject({ valid: true });
    }
  });

  test("refuses payloads that are unversioned, unregistered, or non-conforming", () => {
    expect(validateTerminalPayload(healthPayload())).toMatchObject({
      valid: true,
      schema: "dacs-health/v1",
    });
    expect(validateTerminalPayload({ ...healthPayload(), schema: "dacs-health" }))
      .toMatchObject({ valid: false });
    expect(validateTerminalPayload({ ...healthPayload(), schema: "dacs-health/v2" }))
      .toMatchObject({ valid: false });
    expect(validateTerminalPayload({ ...healthPayload(), extra: true }))
      .toMatchObject({ valid: false });
    expect(validateTerminalPayload({ ...healthPayload(), status: "degraded" }))
      .toMatchObject({ valid: false });
    expect(validateTerminalPayload({ ...healthPayload(), timestamp: "yesterday" }))
      .toMatchObject({ valid: false });
    for (const value of [null, undefined, 7, "text", [healthPayload()]]) {
      expect(validateTerminalPayload(value)).toMatchObject({ valid: false });
    }
  });

  test("refuses bodies that are not versioned terminal JSON", () => {
    expect(validateTerminalBody("")).toMatchObject({ valid: false });
    expect(validateTerminalBody("{")).toMatchObject({ valid: false });
    expect(validateTerminalBody(JSON.stringify({ ok: true }))).toMatchObject({ valid: false });
    expect(validateTerminalBody(JSON.stringify(healthPayload()))).toMatchObject({ valid: true });
    expect(validateTerminalBody(`${JSON.stringify(healthPayload())}\n`))
      .toMatchObject({ valid: true });
  });

  test("serializes a conforming payload and degrades a non-conforming one", async () => {
    const ok = terminalJsonResponse(healthPayload(), 200);
    expect(ok.status).toBe(200);
    expect(ok.headers.get("cache-control")).toBe("no-store");
    expect(ok.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await terminalBodyOf(ok)).toBe(`${JSON.stringify(healthPayload())}\n`);

    const degraded = terminalJsonResponse({ schema: "unregistered/v1" }, 200);
    expect(degraded.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(degraded))).toEqual({
      schema: "dacs-http-error/v1",
      status: 500,
      code: "internal-error",
    });

    // Serialization runs before validation, because the document that matters is the one emitted.
    // A cyclic payload therefore throws inside `JSON.stringify` and is caught there — reachable
    // defence, not decoration — and it would also have failed validation as an extra property.
    const cyclic: Record<string, unknown> = { ...healthPayload() };
    cyclic["self"] = cyclic;
    const rejected = terminalJsonResponse(cyclic, 200);
    expect(rejected.status).toBe(500);
    expect(validateTerminalPayload(cyclic)).toMatchObject({ valid: false });
  });

  test("what is validated is the document emitted, not the object it came from", async () => {
    // `JSON.stringify` consults `toJSON`, so an object can satisfy its registered schema
    // field-for-field and still serialize to something else entirely. Validating the source object
    // would certify a document the boundary never emits: this payload passed validation as an
    // object and left as an unversioned `{"ok":true}` with status 200.
    class SubstitutingHealth {
      readonly schema = "dacs-health/v1";
      readonly service = "dacs-template";
      readonly version = doctorPackageVersion();
      readonly status = "ok";
      readonly timestamp = "2026-01-01T00:00:00.000Z";
      toJSON(): unknown {
        return { ok: true };
      }
    }
    const substituted = new SubstitutingHealth();
    // The source object is schema-valid on its own fields, which is exactly why checking it is not
    // enough — the inherited method is not an own property and no schema can see it.
    expect(validateTerminalPayload({ ...substituted })).toMatchObject({ valid: true });

    const response = terminalJsonResponse(substituted, 200);
    expect(response.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(response))).toEqual({
      schema: "dacs-http-error/v1",
      status: 500,
      code: "internal-error",
    });
  });

  test("the doctor wire bounds are the boundary's own, and refuse rather than truncate", () => {
    // The type/schema linkage pins property names only — `Record<keyof DoctorCheck, …>` admits any
    // schema per value — so these bounds are a deliberate wire contract, not a restatement of the
    // types: `reason` and `sourceRef` are unbounded `string`, `checks` an unbounded array. On the
    // in-process path `assertDoctorReport` is stricter still (1 KiB and 512 bytes), so these are
    // the gate for a document that did not come from `runDoctor` — a fixture doctor, a future
    // producer, a report crossing a process. Asserted here, at the layer that owns them, and the
    // consequence is a refusal: the boundary emits the versioned error, never a trimmed report.
    const bounded = (check: Record<string, unknown>, count = 1): Record<string, unknown> => ({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: doctorPackageVersion(),
      generatedAt: "2026-07-24T00:00:00.000Z",
      evidenceMode: "fixture",
      ready: true,
      exitCode: 0,
      checks: Array.from({ length: count }, () => check),
    });
    const conforming = {
      id: "probe.wire.bound",
      required: false,
      status: "passed",
      evidenceMode: "fixture",
      sourceRef: "docs/READINESS.md",
      observed: { size: 1 },
      reason: "r".repeat(4_096),
    };

    expect(validateTerminalPayload(bounded(conforming))).toMatchObject({ valid: true });
    for (const outside of [
      { ...conforming, reason: "r".repeat(4_097) },
      { ...conforming, sourceRef: `docs/${"r".repeat(2_045)}` },
    ]) {
      expect(validateTerminalPayload(bounded(outside))).toMatchObject({ valid: false });
      expect(terminalJsonResponse(bounded(outside), 200).status).toBe(500);
    }
    const lean = { ...conforming, reason: "r" };
    expect(validateTerminalPayload(bounded(lean, 512))).toMatchObject({ valid: true });
    expect(validateTerminalPayload(bounded(lean, 513))).toMatchObject({ valid: false });
  });

  test("one byte budget governs a terminal document, and it is the boundary's", () => {
    // The readiness emitters delegate here, so this is the only budget a terminal document meets.
    // A second, smaller one at a caller would refuse a body this one serves, which is the same
    // response being valid or not depending on which emitter produced it.
    const sized = (bytes: number): DoctorReport => ({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: doctorPackageVersion(),
      generatedAt: "2026-07-24T00:00:00.000Z",
      evidenceMode: "fixture",
      ready: true,
      exitCode: 0,
      checks: Array.from({ length: Math.ceil(bytes / 4_096) }, (_unused, index) => ({
        id: `probe.budget.${index}`,
        required: false,
        status: "passed" as const,
        evidenceMode: "fixture" as const,
        sourceRef: "docs/READINESS.md",
        observed: { size: index },
        reason: "r".repeat(4_000),
      })),
    });

    // Sized to the byte by tuning one check's `reason`, which is plain ASCII in the encoding, so
    // a character added is a byte added.
    const exactly = (bytes: number): DoctorReport => {
      const withTail = (tail: number): DoctorReport => {
        const base = sized(61_440);
        return {
          ...base,
          checks: [...base.checks, {
            id: "probe.budget.tail",
            required: false,
            status: "passed" as const,
            evidenceMode: "fixture" as const,
            sourceRef: "docs/READINESS.md",
            observed: { size: 0 },
            reason: "r".repeat(tail),
          }],
        };
      };
      let tail = 2_048;
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const measured = Buffer.byteLength(JSON.stringify(withTail(tail)), "utf8");
        if (measured === bytes) return withTail(tail);
        tail += bytes - measured;
        if (tail < 0 || tail > 4_096) break;
      }
      throw new Error(`could not size a report to exactly ${bytes} bytes`);
    };

    const admitted = sized(24_576);
    const admittedBytes = Buffer.byteLength(JSON.stringify(admitted), "utf8");
    expect(admittedBytes).toBeGreaterThan(16_384);
    expect(admittedBytes).toBeLessThan(65_536);
    expect(terminalJsonResponse(admitted, 200).status).toBe(200);

    const refused = sized(69_632);
    expect(Buffer.byteLength(JSON.stringify(refused), "utf8")).toBeGreaterThan(65_536);
    expect(terminalJsonResponse(refused, 200).status).toBe(500);

    // The budget is one number applied to one thing: the bytes that cross the wire, newline
    // included. A payload serializing to exactly 65 536 bytes emits 65 537 and must be refused
    // here, because the boundary measures the emitted body against the identical constant and
    // would otherwise reject a document the emitter had just declared in budget.
    const atLimit = exactly(65_536);
    expect(Buffer.byteLength(JSON.stringify(atLimit), "utf8")).toBe(65_536);
    expect(validateTerminalPayload(atLimit)).toMatchObject({ valid: true });
    expect(terminalJsonResponse(atLimit, 200).status).toBe(500);

    const underLimit = exactly(65_535);
    expect(Buffer.byteLength(JSON.stringify(underLimit), "utf8")).toBe(65_535);
    expect(terminalJsonResponse(underLimit, 200).status).toBe(200);
  });

  test("the authenticated diagnostic body carries the contract's own headers", async () => {
    const server = startReadinessServer({
      authorizeAdministrator: (request) => request.authorization === "Bearer fixture-admin-proof",
    });
    servers.push(server);

    const detailed = await fetch(`${server.url}/admin/readiness`, {
      headers: { authorization: "Bearer fixture-admin-proof" },
    });
    void await detailed.text();
    const health = await fetch(`${server.url}/healthz`);
    void await health.text();

    // Asserted against the exported set rather than against literals, so a local copy that drifts
    // on this path — the one where a cached or sniffed answer is worst — fails here.
    for (const [header, value] of Object.entries(TERMINAL_JSON_HEADERS)) {
      expect(detailed.headers.get(header)).toBe(value);
      expect(health.headers.get(header)).toBe(value);
    }
  });

  test("an oversized doctor report degrades to a versioned error document", async () => {
    // A fixture report of this size cannot reach the wire at all, and the reason is worth being
    // exact about: `doctorReport` runs `assertDoctorReport`, which refuses these checks on shape
    // and on canonical evidence long before `serializeDoctorReport` would weigh them against its
    // 16 KiB budget. Either way the handler's outer catch turns the throw into the versioned error
    // document, which is what this pins — the boundary never has to reject an oversized body.
    const bulky = (): DoctorReport => ({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: doctorPackageVersion(),
      generatedAt: "2026-07-24T00:00:00.000Z",
      evidenceMode: "fixture",
      ready: true,
      exitCode: 0,
      checks: Array.from({ length: 64 }, (_unused, index) => ({
        id: `probe.bulk.${index}`,
        required: false,
        status: "passed" as const,
        evidenceMode: "fixture" as const,
        sourceRef: "docs/READINESS.md",
        observed: { size: index },
        reason: "r".repeat(4_000),
      })),
    });

    const server = startReadinessServer({
      authorizeAdministrator: (request) => request.authorization === "Bearer fixture-admin-proof",
      doctor: bulky,
    });
    servers.push(server);

    const response = await fetch(`${server.url}/admin/readiness`, {
      headers: { authorization: "Bearer fixture-admin-proof" },
    });
    expect(response.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(response))).toEqual({
      schema: "dacs-http-error/v1",
      status: 500,
      code: "internal-error",
    });
  });

  test("the boundary replaces an unversioned or thrown response with a versioned document",
    async () => {
      const violations: string[] = [];
      const record = (reason: string): void => {
        violations.push(reason);
      };

      const unversioned = enforceTerminalSchema(
        () => new Response("{\"ok\":true}\n", { status: 200 }),
        { onViolation: record },
      );
      const unversionedResponse = await unversioned(new Request("http://127.0.0.1/healthz"));
      expect(unversionedResponse.status).toBe(500);
      expect(JSON.parse(await terminalBodyOf(unversionedResponse))).toEqual({
        schema: "dacs-http-error/v1",
        status: 500,
        code: "schema-violation",
      });

      const thrown = enforceTerminalSchema(() => {
        throw new Error("handler-secret-detail");
      }, { onViolation: record });
      const thrownResponse = await thrown(new Request("http://127.0.0.1/healthz"));
      expect(thrownResponse.status).toBe(500);
      const thrownBody = await terminalBodyOf(thrownResponse);
      expect(thrownBody).not.toContain("handler-secret-detail");
      expect(validateTerminalBody(thrownBody)).toMatchObject({ valid: true });

      const nonResponse = enforceTerminalSchema(
        (() => "not a response") as unknown as () => Response,
        { onViolation: record },
      );
      expect((await nonResponse(new Request("http://127.0.0.1/healthz"))).status).toBe(500);

      const passthrough = enforceTerminalSchema(() => terminalJsonResponse(healthPayload(), 200));
      const passed = await passthrough(new Request("http://127.0.0.1/healthz"));
      expect(passed.status).toBe(200);
      expect(validateTerminalBody(await terminalBodyOf(passed))).toMatchObject({ valid: true });

      // The observer is a diagnostic and is caller-supplied: one that throws must not decide the
      // response. Without containment its throw propagates to Bun's own error handling, which owes
      // no registered schema — the exact failure this wrapper exists to prevent. Every violation
      // path is exercised so the containment is proven at the boundary, not in the observer.
      const thrower = (): never => {
        throw new Error("observer-detail-secret");
      };
      const guarded = [
        enforceTerminalSchema((): Response => {
          throw new Error("inner");
        }, { onViolation: thrower }),
        enforceTerminalSchema(
          (() => "not a response") as unknown as () => Response,
          { onViolation: thrower },
        ),
        enforceTerminalSchema(
          () => new Response("{\"ok\":true}\n", { status: 200 }),
          { onViolation: thrower },
        ),
      ];
      for (const handler of guarded) {
        const guardedResponse = await handler(new Request("http://127.0.0.1/healthz"));
        expect(guardedResponse.status).toBe(500);
        const guardedBody = await terminalBodyOf(guardedResponse);
        expect(guardedBody).not.toContain("observer-detail-secret");
        expect(validateTerminalBody(guardedBody)).toMatchObject({ valid: true });
      }

      expect(violations.length).toBe(3);
    });

  test("an oversized or endless handler body is bounded and cancelled at the boundary",
    async () => {
      // The limit has to hold while reading, not after. A handler that streams forever would
      // otherwise buffer without end before the boundary ever got to reject it, so this asserts
      // both the versioned refusal and that the stream was actually cancelled.
      const violations: string[] = [];
      let cancelled = false;
      // Bounded at 32 chunks rather than truly endless: it still exceeds the 64 KiB budget by
      // four times, and an unbounded producer inside a shared test process would starve the
      // event loop for every later file if the cancellation it asserts ever regressed.
      let produced = 0;
      const oversized = new ReadableStream<Uint8Array>({
        pull(controller) {
          produced += 1;
          if (produced > 32) {
            controller.close();
            return;
          }
          controller.enqueue(new Uint8Array(8_192));
        },
        cancel() {
          cancelled = true;
        },
      });

      const guarded = enforceTerminalSchema(
        () => new Response(oversized, { status: 200 }),
        { onViolation: (reason): void => { violations.push(reason); } },
      );
      const response = await guarded(new Request("http://127.0.0.1/healthz"));
      expect(response.status).toBe(500);
      expect(JSON.parse(await terminalBodyOf(response))).toEqual({
        schema: "dacs-http-error/v1",
        status: 500,
        code: "schema-violation",
      });
      expect(cancelled).toBe(true);
      // Cancelled at the budget, not after draining what the producer had to offer.
      expect(produced).toBeLessThan(32);
      expect(violations).toEqual(["the terminal body exceeded the transport limit"]);

      // A conforming body still passes through unchanged, headers and status included.
      const passed = await enforceTerminalSchema(
        () => terminalJsonResponse(healthPayload(), 200),
      )(new Request("http://127.0.0.1/healthz"));
      expect(passed.status).toBe(200);
      expect(passed.headers.get("cache-control")).toBe("no-store");
      expect(await terminalBodyOf(passed)).toBe(`${JSON.stringify(healthPayload())}\n`);
    });

  test("the versioned error document covers every terminal error code", async () => {
    const codes = [
      "internal-error",
      "method-not-allowed",
      "misdirected-request",
      "not-found",
      "schema-violation",
      "unauthorized",
    ] as const;
    for (const code of codes) {
      const response = terminalErrorResponse(500, code);
      const validation = validateTerminalBody(await terminalBodyOf(response));
      expect(validation).toMatchObject({ valid: true, schema: "dacs-http-error/v1" });
    }
  });

  test("an error code outside the registered set is a violation, not a new code", async () => {
    // `code` was once any string, so a document could carry a value no client knows while
    // validating perfectly. The enum is the contract clients read: anything outside it is a
    // violation, and the boundary must replace it rather than forward an unreadable failure.
    for (const code of ["", "database-down", "INTERNAL-ERROR", "internal error", "unauthorised"]) {
      const body = `${JSON.stringify({ schema: "dacs-http-error/v1", status: 500, code })}\n`;
      expect(validateTerminalBody(body)).toMatchObject({ valid: false });
    }
    // The builder refuses to emit one, degrading to a document that is in contract.
    const built = terminalJsonResponse(
      { schema: "dacs-http-error/v1", status: 503, code: "database-down" },
      503,
    );
    expect(built.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(built))).toEqual({
      schema: "dacs-http-error/v1",
      status: 500,
      code: "internal-error",
    });
    // And a handler that emits one directly is replaced at the boundary.
    const violations: string[] = [];
    const guarded = enforceTerminalSchema(
      () => new Response(
        `${JSON.stringify({ schema: "dacs-http-error/v1", status: 503, code: "database-down" })}\n`,
        { status: 503, headers: TERMINAL_JSON_HEADERS },
      ),
      { onViolation: (reason): void => { violations.push(reason); } },
    );
    const response = await guarded(new Request("http://127.0.0.1/healthz"));
    expect(response.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(response))).toEqual({
      schema: "dacs-http-error/v1",
      status: 500,
      code: "schema-violation",
    });
    expect(violations.length).toBe(1);
  });

  test("an error document must agree with the HTTP status that carries it", async () => {
    // Both fields are individually in contract, so a 200 carrying `{"status":503}` validates
    // against the schema while telling two different stories: a client reading the status sees
    // success and a client reading the body sees failure. Which one is believed decides whether a
    // failed request is retried, so the disagreement is refused rather than served.
    const errorBody = (status: number): string =>
      `${JSON.stringify({ schema: "dacs-http-error/v1", status, code: "internal-error" })}\n`;
    const violations: string[] = [];
    const guarded = enforceTerminalSchema(
      () => new Response(errorBody(503), { status: 200, headers: TERMINAL_JSON_HEADERS }),
      { onViolation: (reason): void => { violations.push(reason); } },
    );
    const response = await guarded(new Request("http://127.0.0.1/healthz"));
    expect(response.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(response))).toEqual({
      schema: "dacs-http-error/v1",
      status: 500,
      code: "schema-violation",
    });
    expect(violations).toEqual(["the terminal error body contradicts its HTTP status"]);

    // Agreement passes through untouched, so the check is about the disagreement and not about
    // error documents reaching the boundary at all.
    const agreeing = await enforceTerminalSchema(
      () => new Response(errorBody(503), { status: 503, headers: TERMINAL_JSON_HEADERS }),
    )(new Request("http://127.0.0.1/healthz"));
    expect(agreeing.status).toBe(503);
    expect(JSON.parse(await terminalBodyOf(agreeing))).toMatchObject({ status: 503 });

    // The builder cannot emit a disagreement either, so the guarantee does not depend on which
    // path produced the document.
    const disagreeingBuild = { schema: "dacs-http-error/v1", status: 503, code: "internal-error" };
    expect(terminalJsonResponse(disagreeingBuild, 200).status).toBe(500);
    expect(terminalErrorResponse(503, "internal-error").status).toBe(503);
    // A payload whose schema is not the error document is unaffected: `status` is not its field,
    // and a health document that happened to carry one must not be read as an HTTP status.
    const health = terminalJsonResponse({ ...healthPayload(), status: "ok" }, 200);
    expect(health.status).toBe(200);
  });

  test("the fallback is total: any out-of-contract status collapses to a valid 500", async () => {
    // `terminalErrorResponse` is the boundary's universal fallback, so it must never throw and
    // never emit a body outside its own schema. A 200 would produce a body whose `status` field
    // violates the 400–599 schema; a value past the Response range would throw from the
    // constructor. Both degrade to 500, body and response status agreeing.
    for (const status of [200, 100, 0, 600, 700, -1, 1.5, Number.NaN]) {
      const response = terminalErrorResponse(status, "internal-error");
      expect(response.status).toBe(500);
      const parsed = JSON.parse(await terminalBodyOf(response)) as { status: number };
      expect(parsed.status).toBe(500);
      expect(validateTerminalBody(`${JSON.stringify(parsed)}\n`)).toMatchObject({ valid: true });
    }
    // A status already in contract is preserved exactly.
    expect(terminalErrorResponse(503, "internal-error").status).toBe(503);
  });

  test("the boundary reissues its own headers and drops the handler's framing", async () => {
    // The wrapper rebuilds the body, so representation and framing headers the handler set now
    // describe bytes that no longer exist: a `content-encoding: gzip` would have the client inflate
    // plain JSON, a stale `content-length` would truncate it. The reconstructed terminal document
    // carries the contract's controlled headers and nothing the handler chose.
    const handler = enforceTerminalSchema(() => new Response(
      `${JSON.stringify(healthPayload())}\n`,
      {
        status: 200,
        headers: {
          "content-type": "text/plain",
          "content-encoding": "gzip",
          "content-length": "999999",
          "x-handler-chosen": "leak",
        },
      },
    ));
    const response = await handler(new Request("http://127.0.0.1/healthz"));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-encoding")).toBeNull();
    expect(response.headers.get("x-handler-chosen")).toBeNull();
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(validateTerminalBody(await terminalBodyOf(response))).toMatchObject({ valid: true });
  });

  test("a stream whose cancel hook never settles cannot hang the boundary", async () => {
    // Cancellation is the producer's cleanup, and the producer wrote it. If the boundary awaited a
    // cancel hook that never resolves, an oversized body would hang the request forever on the very
    // path meant to reject it. The versioned refusal must arrive without waiting on that hook.
    let produced = 0;
    const wedged = new ReadableStream<Uint8Array>({
      pull(controller) {
        produced += 1;
        if (produced > 32) {
          controller.close();
          return;
        }
        controller.enqueue(new Uint8Array(8_192));
      },
      cancel() {
        return new Promise<void>(() => {
          // Never settles: a hostile or buggy producer's cleanup that the boundary must not await.
        });
      },
    });
    const handler = enforceTerminalSchema(() => new Response(wedged, { status: 200 }));
    const decided = handler(new Request("http://127.0.0.1/healthz"));
    const timeout = new Promise<"timeout">((resolve) => {
      setTimeout(() => { resolve("timeout"); }, 2_000);
    });
    const outcome = await Promise.race([decided.then(() => "decided" as const), timeout]);
    expect(outcome).toBe("decided");
    const response = await decided;
    expect(response.status).toBe(500);
    expect(JSON.parse(await terminalBodyOf(response))).toMatchObject({ code: "schema-violation" });
  });

  test("HEAD carries no terminal body by HTTP definition and is refused as a method", async () => {
    // The transport answers GET only; every non-GET is 405. HTTP also forbids a body on a HEAD
    // response, and Bun strips it, so the "every response over the wire validates as terminal JSON"
    // invariant is scoped to transmitted GET bodies. This pins both halves: HEAD is 405 with an
    // empty wire body, and the GET of the same path does carry a validating terminal document.
    const server = startReadinessServer({
      authorizeAdministrator: (request) => request.authorization === "Bearer fixture-admin-proof",
    });
    servers.push(server);

    for (const path of ["/healthz", "/readyz", "/admin/readiness"]) {
      const head = await fetch(`${server.url}${path}`, { method: "HEAD" });
      expect(head.status).toBe(405);
      expect((await head.text()).length).toBe(0);

      const get = await fetch(`${server.url}${path}`);
      const body = await get.text();
      expect(body.length).toBeGreaterThan(0);
      expect(validateTerminalBody(body)).toMatchObject({ valid: true });
    }
  });
});

import { describe, expect, test } from "bun:test";
import { runDoctor, serializeDoctorReport, type DoctorCheck } from "../../src/readiness/doctor.ts";
import {
  DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
  DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
  prepareDirectorySchemaDriftProbe,
  type DirectorySchemaReadResponse,
} from "../../src/readiness/directory-schema-drift.ts";
import {
  LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
  PINNED_LISTING_SUMMARY_SCHEMA_JSON,
} from "../../src/protocol/directory-summary-schema.ts";

const MATCH_RESPONSE = Object.freeze({
  finalUrl: DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
  status: 200,
  contentType: "application/json; charset=utf-8",
  body: new TextEncoder().encode(PINNED_LISTING_SUMMARY_SCHEMA_JSON),
});

describe("Directory ListingSummary schema-drift Doctor probe", () => {
  test("reports an exact pinned match without changing readiness authority", async () => {
    let calls = 0;
    const probe = await prepareDirectorySchemaDriftProbe({
      evidenceMode: "fixture",
      readCurrentSchema: async (url) => {
        calls += 1;
        expect(url).toBe(DIRECTORY_LISTING_SUMMARY_SCHEMA_URL);
        return MATCH_RESPONSE;
      },
    });
    const report = runDoctor({ probes: [probe] });
    const check = report.checks.find((item) => item.id === DIRECTORY_SCHEMA_DRIFT_CHECK_ID);

    expect(calls).toBe(1);
    expect(check).toMatchObject({
      required: false,
      status: "passed",
      protocolDisposition: "pass",
      sourceRef: DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
      observed: {
        disposition: "match",
        pinnedSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
        currentSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
        schemaBytes: 1672,
        httpStatus: 200,
      },
    });
    expect(report.exitCode).toBe(0);
    expect(report.ready).toBe(true);
  });

  test("reports a valid schema mismatch as a non-gating drift advisory", async () => {
    const schema = JSON.parse(PINNED_LISTING_SUMMARY_SCHEMA_JSON) as Record<string, unknown>;
    schema["title"] = "Changed Directory schema";
    const body = new TextEncoder().encode(JSON.stringify(schema));
    const probe = await prepareDirectorySchemaDriftProbe({
      evidenceMode: "fixture",
      readCurrentSchema: async () => ({ ...MATCH_RESPONSE, body }),
    });
    const report = runDoctor({ probes: [probe] });
    const check = report.checks.find((item) => item.id === DIRECTORY_SCHEMA_DRIFT_CHECK_ID);

    expect(check).toMatchObject({
      required: false,
      status: "blocked",
      protocolDisposition: "indeterminate",
      observed: {
        disposition: "drift",
        pinnedSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
        schemaBytes: body.byteLength,
        httpStatus: 200,
      },
      reason: "Current Directory ListingSummary schema differs from the pinned compatibility schema",
    });
    expect(check?.observed["currentSha256"]).not.toBe(LIVE_LISTING_SUMMARY_SCHEMA_SHA256);
    expect(report.exitCode).toBe(0);
    expect(report.ready).toBe(true);
  });

  test("keeps unavailable and malformed reads blocked, indeterminate, and body-safe", async () => {
    const sourceBodyMarker = "untrusted-schema-body-marker";
    const cases = [
      {
        disposition: "unavailable",
        reader: async () => { throw new Error(`network ${sourceBodyMarker}`); },
      },
      {
        disposition: "unavailable",
        reader: async () => ({
          ...MATCH_RESPONSE,
          status: 503,
          body: new TextEncoder().encode(sourceBodyMarker),
        }),
      },
      {
        disposition: "invalid",
        reader: async () => ({
          ...MATCH_RESPONSE,
          body: new TextEncoder().encode(`{\"marker\":\"${sourceBodyMarker}`),
        }),
      },
      {
        disposition: "invalid",
        reader: async () => ({
          ...MATCH_RESPONSE,
          body: new TextEncoder().encode(
            `{\"type\":\"not-a-json-schema-type\",\"marker\":\"${sourceBodyMarker}\"}`,
          ),
        }),
      },
      {
        disposition: "invalid",
        reader: async () => ({
          ...MATCH_RESPONSE,
          contentType: "text/html",
          body: new TextEncoder().encode(sourceBodyMarker),
        }),
      },
      {
        disposition: "invalid",
        reader: async () => ({
          ...MATCH_RESPONSE,
          finalUrl: "https://example.invalid/schema.json",
          body: new TextEncoder().encode(sourceBodyMarker),
        }),
      },
      {
        disposition: "invalid",
        reader: async () => ({
          ...MATCH_RESPONSE,
          contentType: "application/json; definitely-not-a-parameter",
        }),
      },
      {
        disposition: "invalid",
        reader: async () => ({ ...MATCH_RESPONSE, contentType: "application/json\r\n" }),
      },
      {
        disposition: "invalid",
        reader: async () => ({ ...MATCH_RESPONSE, contentType: "application/json\u00a0" }),
      },
    ] as const;

    for (const sample of cases) {
      const probe = await prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: sample.reader as () => Promise<DirectorySchemaReadResponse>,
      });
      const report = runDoctor({ probes: [probe] });
      const redactedReport = runDoctor({ probes: [probe], sensitiveValues: [sourceBodyMarker] });
      const check = report.checks.find((item) => item.id === DIRECTORY_SCHEMA_DRIFT_CHECK_ID);
      expect(check).toMatchObject({
        required: false,
        status: "blocked",
        protocolDisposition: "indeterminate",
        observed: { disposition: sample.disposition },
      });
      expect(serializeDoctorReport(report)).not.toContain(sourceBodyMarker);
      expect(serializeDoctorReport(redactedReport)).not.toContain(sourceBodyMarker);
    }
  });

  test("default Doctor performs no Directory read and official probe identity cannot be forged", () => {
    let calls = 0;
    const unusedReader = async (): Promise<DirectorySchemaReadResponse> => {
      calls += 1;
      return MATCH_RESPONSE;
    };
    void unusedReader;

    const offline = runDoctor();
    expect(calls).toBe(0);
    expect(offline.checks.some((item) => item.id === DIRECTORY_SCHEMA_DRIFT_CHECK_ID)).toBe(false);

    const forged: DoctorCheck = {
      id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
      required: false,
      status: "passed",
      protocolDisposition: "pass",
      evidenceMode: "fixture",
      sourceRef: DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
      observed: { disposition: "match" },
    };
    const report = runDoctor({
      probes: [{ id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID, required: false, run: () => forged }],
    });
    expect(report.checks).toHaveLength(1);
    expect(report.checks[0]).toMatchObject({
      id: "internal.tool",
      status: "failed",
      protocolDisposition: "error",
    });
  });

  test("rejects oversized and structurally hostile adapter responses without executing accessors", async () => {
    let accessed = false;
    const hostile = Object.defineProperty({}, "body", {
      enumerable: true,
      get() {
        accessed = true;
        return PINNED_LISTING_SUMMARY_SCHEMA_JSON;
      },
    });
    Object.assign(hostile, {
      finalUrl: DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
      status: 200,
      contentType: "application/json",
    });
    const probes = await Promise.all([
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => hostile as DirectorySchemaReadResponse,
      }),
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => ({
          ...MATCH_RESPONSE,
          body: new Uint8Array(65_537).fill(0x78),
        }),
      }),
    ]);

    for (const probe of probes) {
      const check = runDoctor({ probes: [probe] }).checks.at(-1);
      expect(check).toMatchObject({
        id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
        status: "blocked",
        observed: { disposition: "invalid" },
      });
    }
    expect(accessed).toBe(false);
  });

  test("separates reader rejection from invalid resolved responses before body copying", async () => {
    const throwingResponse = new Proxy({}, {
      getPrototypeOf() {
        throw new Error("resolved response trap");
      },
    });
    const [readerFailure, invalidResolved, unavailableHttp] = await Promise.all([
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => { throw new Error("reader failed"); },
      }),
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => throwingResponse as DirectorySchemaReadResponse,
      }),
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => ({
          ...MATCH_RESPONSE,
          status: 503,
          body: new Uint8Array(1_000_000),
        }),
      }),
    ]);

    expect(runDoctor({ probes: [readerFailure] }).checks.at(-1)?.observed["disposition"])
      .toBe("unavailable");
    expect(runDoctor({ probes: [invalidResolved] }).checks.at(-1)?.observed["disposition"])
      .toBe("invalid");
    expect(runDoctor({ probes: [unavailableHttp] }).checks.at(-1)).toMatchObject({
      status: "blocked",
      observed: { disposition: "unavailable", httpStatus: 503 },
    });
  });

  test("rejects a Proxy that spoofs the Uint8Array prototype before size or copy", async () => {
    let iteratorRead = false;
    const spoofedBody = new Proxy({}, {
      getPrototypeOf: () => Uint8Array.prototype,
      get(_target, key) {
        if (key === "byteLength") return 1;
        if (key === Symbol.iterator) {
          iteratorRead = true;
          return function* unbounded() {
            while (true) yield 0x78;
          };
        }
        return undefined;
      },
    });
    const probe = await prepareDirectorySchemaDriftProbe({
      evidenceMode: "fixture",
      readCurrentSchema: async () => ({
        ...MATCH_RESPONSE,
        body: spoofedBody as Uint8Array,
      }),
    });

    expect(runDoctor({ probes: [probe] }).checks.at(-1)).toMatchObject({
      status: "blocked",
      observed: { disposition: "invalid" },
    });
    expect(iteratorRead).toBe(false);
  });

  test("hashes raw response bytes, compiles candidates, and accepts boolean JSON Schema drift", async () => {
    const pinned = MATCH_RESPONSE.body;
    const bomPrefixed = new Uint8Array(pinned.byteLength + 3);
    bomPrefixed.set([0xef, 0xbb, 0xbf]);
    bomPrefixed.set(pinned, 3);
    const invalidPattern = new TextEncoder().encode('{"type":"string","pattern":"["}');
    const booleanSchema = new TextEncoder().encode("true");

    const [bomProbe, invalidPatternProbe, booleanProbe] = await Promise.all([
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => ({ ...MATCH_RESPONSE, body: bomPrefixed }),
      }),
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => ({ ...MATCH_RESPONSE, body: invalidPattern }),
      }),
      prepareDirectorySchemaDriftProbe({
        evidenceMode: "fixture",
        readCurrentSchema: async () => ({ ...MATCH_RESPONSE, body: booleanSchema }),
      }),
    ]);

    expect(runDoctor({ probes: [bomProbe] }).checks.at(-1)).toMatchObject({
      status: "blocked",
      observed: { disposition: "drift", schemaBytes: pinned.byteLength + 3 },
    });
    expect(runDoctor({ probes: [invalidPatternProbe] }).checks.at(-1)).toMatchObject({
      status: "blocked",
      observed: { disposition: "invalid" },
    });
    expect(runDoctor({ probes: [booleanProbe] }).checks.at(-1)).toMatchObject({
      status: "blocked",
      observed: { disposition: "drift" },
    });
  });

  test("snapshots evidence mode and reader before awaiting mutable caller options", async () => {
    let release!: () => void;
    const wait = new Promise<void>((resolve) => { release = resolve; });
    const options = {
      evidenceMode: "fixture" as const,
      readCurrentSchema: async () => {
        await wait;
        return MATCH_RESPONSE;
      },
    };
    const pending = prepareDirectorySchemaDriftProbe(options);
    Object.defineProperty(options, "evidenceMode", {
      enumerable: true,
      get() {
        throw new Error("late options accessor executed");
      },
    });
    Object.defineProperty(options, "readCurrentSchema", {
      enumerable: true,
      value: async () => { throw new Error("late reader executed"); },
    });
    release();

    const probe = await pending;
    expect(runDoctor({ probes: [probe] }).checks.at(-1)).toMatchObject({
      id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
      evidenceMode: "fixture",
      status: "passed",
      observed: { disposition: "match" },
    });
  });
});

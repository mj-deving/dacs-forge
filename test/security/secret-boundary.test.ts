import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runCli } from "../../src/cli/dacs.ts";
import { createTerminalLogger } from "../../src/http/terminal-server.ts";
import { runDoctor, serializeDoctorReport } from "../../src/readiness/doctor.ts";

const roots: string[] = [];
const scanner = resolve(import.meta.dir, "../../scripts/scan-secret-sentinel.ts");

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true });
});

function sentinel(label: string): string {
  const digest = createHash("sha256").update(`dacs-forge-secret-boundary/${label}`).digest("hex");
  return `sentinel-${label}-${digest.slice(0, 32)}`;
}

function boundaryValue(): string {
  return process.env["DACS_FORGE_SECRET_SENTINEL"] ?? sentinel("default");
}

function forms(secret: string): readonly string[] {
  const bytes = Buffer.from(secret, "utf8");
  return [
    secret,
    encodeURIComponent(secret),
    bytes.toString("base64"),
    bytes.toString("base64url"),
    bytes.toString("hex"),
    JSON.stringify(secret).slice(1, -1),
  ];
}

function percentEncoded(secret: string): string {
  return [...Buffer.from(secret, "utf8")]
    .map((byte, index) => `%${byte.toString(16)[index % 2 === 0 ? "toUpperCase" : "toLowerCase"]()}`)
    .join("");
}

function mixedJsonUnicode(secret: string): string {
  return [...secret].map((character, index) => index % 2 === 0
    ? `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
    : character).join("");
}

function expectAbsent(text: string, secret: string): void {
  expect(forms(secret).some((form) => text.includes(form))).toBe(false);
}

function capture(): {
  readonly io: { stdout: (value: string) => void; stderr: (value: string) => void };
  readonly value: () => string;
} {
  let value = "";
  return {
    io: {
      stdout: (chunk) => { value += chunk; },
      stderr: (chunk) => { value += chunk; },
    },
    value: () => value,
  };
}

function runScanner(root: string, secret: string): ReturnType<typeof Bun.spawnSync> {
  return Bun.spawnSync({
    cmd: [process.execPath, "run", scanner, "--root", root],
    env: { ...process.env, DACS_FORGE_SECRET_SENTINEL: secret },
    stdout: "pipe",
    stderr: "pipe",
  });
}

function processOutput(value: Uint8Array | undefined): string {
  return value === undefined ? "" : Buffer.from(value).toString("utf8");
}

describe("terminal secret boundary", () => {
  test("keeps failure diagnostics free of the boundary marker", () => {
    const secret = boundaryValue();
    let diagnostic = "";
    try {
      expectAbsent(`leak=${secret}`, secret);
    } catch (error) {
      diagnostic = error instanceof Error ? error.message : "non-error failure";
    }
    expect(diagnostic.length).toBeGreaterThan(0);
    expectAbsent(diagnostic, secret);
  });

  test("never reflects argv values through any CLI router", async () => {
    const secret = boundaryValue();
    const probes = [
      [secret],
      ["doctor", `--${secret}`],
      ["authority", "recover", `--${secret}`, "value"],
      ["register", `--${secret}`, "value"],
    ];
    for (const args of probes) {
      const output = capture();
      expect(await runCli(args, output.io)).not.toBe(0);
      expectAbsent(output.value(), secret);
    }
  });

  test("reports a clean bounded artifact root without emitting the sentinel", () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-secret-clean-"));
    roots.push(root);
    mkdirSync(join(root, "reports"));
    writeFileSync(join(root, "reports", "doctor.json"), '{"ready":false}\n');

    const secret = boundaryValue();
    const result = runScanner(root, secret);
    expect(result.exitCode).toBe(0);
    expect(processOutput(result.stderr).length).toBe(0);
    expectAbsent(processOutput(result.stdout), secret);
    const report = JSON.parse(processOutput(result.stdout)) as Record<string, unknown>;
    expect(report["schema"]).toBe("dacs-forge-secret-boundary/v1");
    expect(report["matches"]).toBe(0);
    expect(report["filesScanned"]).toBe(1);
  });

  test("rejects a path-unsafe marker without emitting it", () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-secret-invalid-marker-"));
    roots.push(root);
    const marker = `sentinel-${"x".repeat(33)}-${"a".repeat(32)}`;
    const result = runScanner(root, marker);
    expect(result.exitCode).toBe(2);
    expect(processOutput(result.stderr).length).toBe(0);
    const output = processOutput(result.stdout);
    expectAbsent(output, marker);
    expect(JSON.parse(output)).toMatchObject({ result: "invalid", scanFailures: 1 });
  });

  test("redacts the sentinel from logs, readiness reports, snapshots, and scanner output", () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-secret-surfaces-"));
    roots.push(root);
    const secret = boundaryValue();
    const lines: string[] = [];
    const logger = createTerminalLogger({
      sentinels: [secret],
      level: "debug",
      sink: (line) => lines.push(line),
      now: () => "2026-07-29T00:00:00.000Z",
    });
    logger.log({
      level: "failure",
      event: `request.${secret}`,
      fields: { authorization: `Bearer ${secret}`, detail: JSON.stringify({ secret }) },
    });
    const report = runDoctor({
      sensitiveValues: [secret],
      probes: [{
        id: "probe.secret-boundary",
        required: true,
        run: () => ({
          id: "probe.secret-boundary",
          required: true,
          status: "failed",
          evidenceMode: "fixture",
          sourceRef: `fixture:${secret}`,
          observed: { detail: secret },
          reason: `failed with ${secret}`,
        }),
      }],
    });
    const serialized = serializeDoctorReport(report);
    const combined = `${lines.join("\n")}\n${serialized}\n`;
    expectAbsent(combined, secret);

    mkdirSync(join(root, "snapshots"));
    mkdirSync(join(root, "ci"));
    writeFileSync(join(root, "snapshots", "transport.snap"), `${lines.join("\n")}\n`);
    writeFileSync(join(root, "ci", "doctor-report.json"), `${serialized}\n`);
    const result = runScanner(root, secret);
    expect(result.exitCode).toBe(0);
    expect(processOutput(result.stderr).length).toBe(0);
    expectAbsent(processOutput(result.stdout), secret);
    expect(JSON.parse(processOutput(result.stdout))).toMatchObject({
      result: "accepted",
      matches: 0,
      filesScanned: 2,
    });
  });

  test("detects raw, encoded, filename, snapshot, and CI leaks without re-emitting them", () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-secret-leak-"));
    roots.push(root);
    const secret = boundaryValue();
    mkdirSync(join(root, "snapshots"));
    mkdirSync(join(root, "ci"));
    writeFileSync(join(root, "snapshots", `${secret}.snap`), forms(secret).join("\n"));
    writeFileSync(join(root, "ci", "test-output.txt"), `failure=${secret}\n`);

    const result = runScanner(root, secret);
    expect(result.exitCode).toBe(1);
    expect(processOutput(result.stderr).length).toBe(0);
    const output = processOutput(result.stdout);
    expectAbsent(output, secret);
    const report = JSON.parse(output) as Record<string, unknown>;
    expect(report["matches"]).toBeGreaterThanOrEqual(7);
    expect(report["filesWithMatches"]).toBe(2);
    expect(report["result"]).toBe("rejected");
  });

  test("rejects leaks in conventionally excluded subtrees and equivalent encodings", () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-secret-equivalent-"));
    roots.push(root);
    const secret = boundaryValue();
    const bytes = Buffer.from(secret, "utf8");
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, "node_modules"));
    const mixedHex = [...bytes.toString("hex")].map((character, index) =>
      index % 2 === 0 ? character.toUpperCase() : character).join("");
    writeFileSync(join(root, ".git", "report"), mixedHex);
    writeFileSync(join(root, "node_modules", "output.log"), [
      bytes.toString("base64").replace(/=+$/u, ""),
      percentEncoded(secret),
      mixedJsonUnicode(secret),
    ].join("\n"));

    const result = runScanner(root, secret);
    expect(result.exitCode).toBe(1);
    expect(processOutput(result.stderr).length).toBe(0);
    const output = processOutput(result.stdout);
    expectAbsent(output, secret);
    expect(JSON.parse(output)).toMatchObject({
      result: "rejected",
      filesWithMatches: 2,
      scanFailures: 0,
    });
  });

  test("rejects empty secret-named directories and traversal-budget overflow", () => {
    const secret = boundaryValue();
    const namedRoot = mkdtempSync(join(tmpdir(), "dacs-secret-directory-"));
    roots.push(namedRoot);
    mkdirSync(join(namedRoot, percentEncoded(secret)));
    const namedResult = runScanner(namedRoot, secret);
    expect(namedResult.exitCode).toBe(1);
    expect(JSON.parse(processOutput(namedResult.stdout))).toMatchObject({
      result: "rejected",
      pathsWithMatches: 1,
      scanFailures: 0,
    });

    const broadRoot = mkdtempSync(join(tmpdir(), "dacs-secret-broad-"));
    roots.push(broadRoot);
    for (let index = 0; index < 2_048; index += 1) {
      mkdirSync(join(broadRoot, `entry-${index.toString().padStart(4, "0")}`));
    }
    const broadResult = runScanner(broadRoot, secret);
    expect(broadResult.exitCode).toBe(1);
    expect(JSON.parse(processOutput(broadResult.stdout))).toMatchObject({
      result: "rejected",
      scanFailures: 1,
      matches: 0,
    });
  });
});

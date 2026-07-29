import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runCli } from "../../src/cli/dacs.ts";

const roots: string[] = [];
const COLD_INSTALL_TIMEOUT_MS = 60_000;
const FROZEN_INSTALL_TIMEOUT_MS = 30_000;
const CLI_PROCESS_TIMEOUT_MS = 5_000;
const PACKAGE_MANAGER_SYMLINK_TEST_TIMEOUT_MS =
  COLD_INSTALL_TIMEOUT_MS + FROZEN_INSTALL_TIMEOUT_MS + (4 * CLI_PROCESS_TIMEOUT_MS) + 5_000;

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true });
});

function capture(): {
  readonly io: { stdout: (value: string) => void; stderr: (value: string) => void };
  readonly stdout: () => string;
  readonly stderr: () => string;
} {
  let stdout = "";
  let stderr = "";
  return {
    io: {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
    },
    stdout: () => stdout,
    stderr: () => stderr,
  };
}

describe("dacs executable", () => {
  test("provides stable help, version, usage errors, and no-input behavior", async () => {
    for (const args of [["--help"], ["-h"], ["help"]]) {
      const output = capture();
      expect(await runCli(args, output.io)).toBe(0);
      expect(output.stdout()).toStartWith("Usage:\n  dacs --help");
      expect(output.stderr()).toBe("");
    }
    const version = capture();
    expect(await runCli(["--version"], version.io)).toBe(0);
    expect(version.stdout()).toBe("0.1.0-preview.1\n");

    const absent = capture();
    expect(await runCli([], absent.io)).toBe(2);
    expect(absent.stdout()).toBe("");
    expect(absent.stderr()).toContain("A command is required");

    const noInput = capture();
    expect(await runCli(["doctor", "--no-input", "--json"], noInput.io)).toBe(5);
    expect(noInput.stderr()).toBe("");
    expect(() => JSON.parse(noInput.stdout())).not.toThrow();
  });

  test("writes exactly one JSON document to stdout and diagnostics only to stderr", async () => {
    const output = capture();
    const exitCode = await runCli(["doctor", "--json"], output.io);
    expect(exitCode).toBe(5);
    expect(output.stderr()).toBe("");
    expect(output.stdout().split("\n")).toHaveLength(2);
    const report = JSON.parse(output.stdout()) as Record<string, unknown>;
    expect(report["schema"]).toBe("dacs-doctor/v1");
    expect(report["exitCode"]).toBe(exitCode);
  });

  test("rejects argument accessors before they can queue prototype mutation", async () => {
    const output = capture();
    const originalMap = Array.prototype.map;
    let queued = false;
    const args = ["doctor", "--json"];
    Object.defineProperty(args, "1", {
      configurable: true,
      enumerable: true,
      get: () => {
        if (!queued) {
          queued = true;
          queueMicrotask(() => {
            Array.prototype.map = (() => []) as unknown as typeof Array.prototype.map;
          });
        }
        return "--json";
      },
    });

    expect(await runCli(args, output.io)).toBe(4);
    await Promise.resolve();
    Array.prototype.map = originalMap;
    expect(output.stdout()).toBe("");
    expect(output.stderr()).toBe("dacs: internal error: CLI arguments must contain own string data properties\n");
  });

  test("snapshots dense CLI arguments without executing accessors or mutable array methods", async () => {
    const output = capture();
    const originalIncludes = Array.prototype.includes;
    let getterRuns = 0;
    let replacementRuns = 0;
    const args = ["doctor", "--json"];
    Object.defineProperty(args, "0", {
      configurable: true,
      enumerable: true,
      get: () => {
        getterRuns += 1;
        Array.prototype.includes = (() => {
          replacementRuns += 1;
          return true;
        }) as typeof Array.prototype.includes;
        return "doctor";
      },
    });
    try {
      expect(await runCli(args, output.io)).toBe(4);
    } finally {
      Array.prototype.includes = originalIncludes;
    }
    expect(getterRuns).toBe(0);
    expect(replacementRuns).toBe(0);
    expect(output.stdout()).toBe("");
    expect(output.stderr()).toContain("CLI arguments must contain own string data properties");

    const oversized = capture();
    expect(await runCli(["doctor", "x".repeat(4097)], oversized.io)).toBe(2);
    expect(oversized.stderr()).toContain("CLI argument exceeds 4096 characters");

    const aggregate = capture();
    expect(await runCli([
      "doctor",
      "a".repeat(4096),
      "b".repeat(4096),
      "c".repeat(4096),
      "d".repeat(4096),
    ], aggregate.io)).toBe(2);
    expect(aggregate.stderr()).toContain("CLI arguments exceed 16384 total characters");
  });

  test("does not execute caller-controlled error accessors or instanceof hooks", async () => {
    const output = capture();
    const hasInstanceDescriptor = Object.getOwnPropertyDescriptor(Error, Symbol.hasInstance);
    let messageReads = 0;
    let hasInstanceRuns = 0;
    const thrown = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(thrown, "message", {
      get: () => {
        messageReads += 1;
        throw new Error("message accessor ran");
      },
    });
    const hostileIo = {
      stdout: () => { throw thrown; },
      stderr: output.io.stderr,
    };

    let exitCode: number;
    try {
      Object.defineProperty(Error, Symbol.hasInstance, {
        configurable: true,
        value: () => {
          hasInstanceRuns += 1;
          throw new Error("instanceof hook ran");
        },
      });
      exitCode = await runCli(["--help"], hostileIo);
    } finally {
      if (hasInstanceDescriptor === undefined) delete (Error as { [Symbol.hasInstance]?: unknown })[Symbol.hasInstance];
      else Object.defineProperty(Error, Symbol.hasInstance, hasInstanceDescriptor);
    }

    expect(exitCode).toBe(4);
    expect(messageReads).toBe(0);
    expect(hasInstanceRuns).toBe(0);
    expect(output.stdout()).toBe("");
    expect(output.stderr()).toBe("dacs: internal error: Unexpected doctor failure\n");

    const proxyOutput = capture();
    let descriptorTraps = 0;
    const proxyError = new Proxy({}, {
      getOwnPropertyDescriptor: () => {
        descriptorTraps += 1;
        throw new Error("descriptor trap ran");
      },
    });
    expect(await runCli(["--help"], {
      stdout: () => { throw proxyError; },
      stderr: proxyOutput.io.stderr,
    })).toBe(4);
    expect(descriptorTraps).toBe(0);
    expect(proxyOutput.stderr()).toBe("dacs: internal error: Unexpected doctor failure\n");

    const spoofedOutput = capture();
    expect(await runCli(["--help"], {
      stdout: () => { throw { name: "UsageError", message: "Usage: forged" }; },
      stderr: spoofedOutput.io.stderr,
    })).toBe(4);
    expect(spoofedOutput.stderr()).toBe("dacs: internal error: Usage: forged\n");

    const controlledOutput = capture();
    expect(await runCli(["--help"], {
      stdout: () => { throw { message: "forged\nline\u001b[31m" }; },
      stderr: controlledOutput.io.stderr,
    })).toBe(4);
    expect(controlledOutput.stderr()).not.toContain("\u001b");
    expect(controlledOutput.stderr().split("\n")).toHaveLength(2);
    expect(controlledOutput.stderr()).toBe("dacs: internal error: forged line [31m\n");

    const oversizedMessage = capture();
    expect(await runCli(["--help"], {
      stdout: () => { throw { message: "x".repeat(1025) }; },
      stderr: oversizedMessage.io.stderr,
    })).toBe(4);
    expect(oversizedMessage.stderr()).toBe("dacs: internal error: Unexpected doctor failure\n");

    expect(await runCli(["--help"], {
      stdout: () => { throw new Error("stdout failed"); },
      stderr: () => { throw new Error("stderr failed"); },
    })).toBe(4);
  });

  test("NO_COLOR, TERM=dumb, and --no-color preserve unstyled data", async () => {
    const baseline = capture();
    const noColor = capture();
    const dumb = capture();
    await runCli(["doctor"], baseline.io, {});
    await runCli(["doctor", "--no-color"], noColor.io, { NO_COLOR: "1" });
    await runCli(["doctor"], dumb.io, { TERM: "dumb" });
    expect(noColor.stdout().replaceAll("--no-color", "")).toBe(baseline.stdout());
    expect(dumb.stdout()).toBe(baseline.stdout());
    expect(baseline.stdout()).not.toMatch(/\x1b\[/);
  });

  test("runs through the declared package-manager symlink", async () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-doctor-install-"));
    roots.push(root);
    const packageRoot = resolve(import.meta.dir, "../..");
    await Bun.write(join(root, "package.json"), JSON.stringify({
      private: true,
      dependencies: { "dacs-forge": `file:${packageRoot}` },
    }));
    const installEnvironment = {
      ...process.env,
      BUN_INSTALL_CACHE_DIR: join(root, ".bun-cache"),
    };
    const initialInstall = Bun.spawnSync(["bun", "install"], {
      cwd: root,
      env: installEnvironment,
      stdout: "pipe",
      stderr: "pipe",
      timeout: COLD_INSTALL_TIMEOUT_MS,
    });
    expect(initialInstall.exitCode).toBe(0);
    rmSync(join(root, "node_modules"), { force: true, recursive: true });
    const install = Bun.spawnSync(["bun", "install", "--frozen-lockfile"], {
      cwd: root,
      env: installEnvironment,
      stdout: "pipe",
      stderr: "pipe",
      timeout: FROZEN_INSTALL_TIMEOUT_MS,
    });
    expect(install.exitCode).toBe(0);
    const executable = join(root, "node_modules/.bin/dacs");
    for (const command of [join(packageRoot, "src/cli/dacs.ts"), executable]) {
      const help = Bun.spawnSync([command, "--help"], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
        timeout: CLI_PROCESS_TIMEOUT_MS,
      });
      expect(help.exitCode).toBe(0);
      expect(help.stdout.toString()).toContain("dacs doctor");
      expect(help.stderr.toString()).toBe("");
      const version = Bun.spawnSync([command, "--version"], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
        timeout: CLI_PROCESS_TIMEOUT_MS,
      });
      expect(version.exitCode).toBe(0);
      expect(version.stdout.toString()).toBe("0.1.0-preview.1\n");
      expect(version.stderr.toString()).toBe("");
    }
  }, PACKAGE_MANAGER_SYMLINK_TEST_TIMEOUT_MS);

  test("preserves package metadata through the generated dist bundle", () => {
    const root = mkdtempSync(join(tmpdir(), "dacs-doctor-dist-"));
    roots.push(root);
    const packageRoot = resolve(import.meta.dir, "../..");
    const build = Bun.spawnSync([
      "bun", "build", join(packageRoot, "src/index.ts"),
      "--outfile", join(root, "index.js"), "--target", "bun", "--packages", "external",
    ], { cwd: packageRoot, stdout: "pipe", stderr: "pipe" });
    expect(build.exitCode).toBe(0);
    const smoke = Bun.spawnSync([
      "bun", "-e",
      `const m = await import(${JSON.stringify(join(root, "index.js"))});`
        + `if (m.doctorPackageVersion() !== "0.1.0-preview.1") process.exit(10);`
        + `const r = m.runDoctor(); if (r.exitCode !== 5) process.exit(11);`
        + `if (JSON.parse(m.serializeDoctorReport(r)).exitCode !== 5) process.exit(12);`,
    ], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(smoke.exitCode).toBe(0);
    expect(smoke.stderr.toString()).toBe("");
  });
});

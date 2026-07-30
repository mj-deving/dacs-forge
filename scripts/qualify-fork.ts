#!/usr/bin/env bun

import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import releaseManifest from "../release/release-manifest.json" with { type: "json" };
import {
  assertTrustedVerifierCheckout,
  formatFindings,
  scanCriticalTree,
  verifyExtensionDelta,
} from "../tools/exemplar-policy.ts";
import { verifyDirectorySupply } from "./verify-directory-supply.ts";
import { rigInventory } from "./verify-release-manifest.ts";

type JsonObject = Record<string, unknown>;

const QUALIFICATION_EFFECT_KEYS = [
  "public", "release", "registration", "deployment", "payment", "transfer", "spend", "liveValue",
] as const;

const FULL_RIG = ["bun", "run", "verify:product-seal-candidate"] as const;
const DOCTOR = [
  "bun", "src/cli/dacs.ts", "doctor", "--json", "--no-input", "--no-color", "--evidence-mode", "fixture",
] as const;

interface CommandReceipt {
  readonly command: string;
  readonly exitCode: 0;
  readonly stdoutSha256: string;
  readonly stderrSha256: string;
}

function object(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value as JsonObject;
}

function sha256(bytes: string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function git(repository: string, args: readonly string[]): string {
  const result = spawnSync("git", args, {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, GIT_NO_LAZY_FETCH: "1", GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

function trustedEnvironment(): Readonly<Record<string, string>> {
  const path = process.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin";
  const home = process.env["HOME"] ?? "/tmp";
  return Object.freeze({
    HOME: home,
    PATH: path,
    NO_COLOR: "1",
    TERM: "dumb",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    DACS_FORGE_SECRET_SENTINEL: `sentinel-seal-${randomBytes(16).toString("hex")}`,
    ...(process.env["DOCKER_HOST"] === undefined ? {} : { DOCKER_HOST: process.env["DOCKER_HOST"] }),
  });
}

function runTrustedCommand(repository: string, command: readonly string[]): CommandReceipt & { readonly stdout: string } {
  const result = spawnSync(command[0]!, command.slice(1), {
    cwd: repository,
    encoding: "utf8",
    env: trustedEnvironment(),
    maxBuffer: 64 * 1024 * 1024,
  });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  if (result.status !== 0) {
    throw new Error(`${command.join(" ")} failed (${result.status}): ${stderr.slice(-2_000)}`);
  }
  return Object.freeze({
    command: command.join(" "),
    exitCode: 0 as const,
    stdout,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr),
  });
}

function commandReceipt(result: CommandReceipt & { readonly stdout: string }): CommandReceipt {
  return Object.freeze({
    command: result.command,
    exitCode: result.exitCode,
    stdoutSha256: result.stdoutSha256,
    stderrSha256: result.stderrSha256,
  });
}

function exactClone(source: string, revision: string, destination: string): void {
  if (!/^[0-9a-f]{40}$/.test(revision)
    || git(source, ["rev-parse", "--verify", `${revision}^{commit}`]) !== revision) {
    throw new Error("qualification clone requires an exact local commit");
  }
  const clone = spawnSync("git", [
    "clone", "--local", "--no-hardlinks", "--no-tags", "--no-checkout", "--", source, destination,
  ], {
    encoding: "utf8",
    env: { ...process.env, GIT_NO_LAZY_FETCH: "1", GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (clone.status !== 0) throw new Error(`exact local clone failed: ${clone.stderr.trim()}`);
  git(destination, ["config", "core.hooksPath", "/dev/null"]);
  git(destination, ["checkout", "--detach", revision]);
  if (git(destination, ["rev-parse", "HEAD"]) !== revision
    || git(destination, ["status", "--porcelain=v1"]) !== "") {
    throw new Error("exact qualification clone did not materialize the requested commit cleanly");
  }
}

export function assertExactEffectsRecord(value: unknown): Readonly<Record<string, false>> {
  const effects = object(value, "qualification effects");
  if (JSON.stringify(Object.keys(effects).sort()) !== JSON.stringify([...QUALIFICATION_EFFECT_KEYS].sort())) {
    throw new Error("qualification effects keys are incomplete or unexpected");
  }
  for (const key of QUALIFICATION_EFFECT_KEYS) {
    if (effects[key] !== false) throw new Error(`qualification effects.${key} is not false`);
  }
  return effects as Readonly<Record<string, false>>;
}

function validateDoctor(stdout: string): Readonly<JsonObject> {
  const report = object(JSON.parse(stdout.trim()), "fixture Doctor report");
  if (report["schema"] !== "dacs-doctor/v1" || report["evidenceMode"] !== "fixture"
    || report["ready"] !== true || report["exitCode"] !== 0) {
    throw new Error("trusted fixture Doctor did not report ready");
  }
  const checks = report["checks"];
  if (!Array.isArray(checks)) throw new Error("trusted fixture Doctor checks are invalid");
  const external = object(checks.find((entry) => object(entry, "Doctor check")["id"] === "conformance.external-rig"), "external rig check");
  const observed = object(external["observed"], "external rig observation");
  if (external["required"] !== true || external["status"] !== "passed"
    || external["protocolDisposition"] !== "pass" || observed["acceptedRigPinned"] !== true
    || observed["profile"] !== "v0.4"
    || observed["commit"] !== "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091") {
    throw new Error("trusted fixture Doctor did not consume the pinned DACS v0.4 rig");
  }
  const execution = object(checks.find((entry) => object(entry, "Doctor check")["id"] === "execution.read-only"), "execution check");
  const effects = object(execution["observed"], "Doctor effects");
  if (JSON.stringify(Object.keys(effects).sort()) !== JSON.stringify(["liveEffects", "registrationCommands"].sort())
    || effects["liveEffects"] !== 0 || effects["registrationCommands"] !== 0) {
    throw new Error("trusted fixture Doctor effects are incomplete or nonzero");
  }
  return report;
}

function rigDefinition(root: string): string {
  const manifest = object(releaseManifest, "release manifest");
  const rig = object(manifest["rig"], "release rig");
  const definition = object(rig["definition"], "release rig definition");
  const expected = rigInventory(root);
  if (definition["inventorySha256"] !== expected) {
    throw new Error("release manifest does not pin the current trusted rig");
  }
  return expected;
}

export async function qualifyFork(input: {
  readonly trustedRoot: string;
  readonly forkRepository: string;
  readonly baseCommit: string;
  readonly tipCommit: string;
}): Promise<Readonly<JsonObject>> {
  assertTrustedVerifierCheckout(input.trustedRoot, input.baseCommit);
  if (git(input.trustedRoot, ["status", "--porcelain=v1"]) !== "") {
    throw new Error("trusted fork qualification checkout must be clean");
  }
  if (!/^[0-9a-f]{40}$/.test(input.tipCommit)
    || git(input.forkRepository, ["rev-parse", "--verify", `${input.tipCommit}^{commit}`]) !== input.tipCommit) {
    throw new Error("fork qualification source does not contain the exact tip");
  }
  const findings = verifyExtensionDelta(input.forkRepository, input.baseCommit, input.tipCommit);
  if (findings.length > 0) throw new Error(`fork boundary rejected:\n${formatFindings(findings)}`);
  const criticalFindings = await scanCriticalTree(input.forkRepository, input.tipCommit);
  if (criticalFindings.length > 0) {
    throw new Error(`fork critical scan rejected:\n${formatFindings(criticalFindings)}`);
  }
  const expectedRig = rigDefinition(input.trustedRoot);
  const temporaryRoot = mkdtempSync(join(tmpdir(), "dacs-forge-fork-qualification-"));
  const baseClone = join(temporaryRoot, "base");
  const forkClone = join(temporaryRoot, "fork");
  try {
    exactClone(input.trustedRoot, input.baseCommit, baseClone);
    exactClone(input.forkRepository, input.tipCommit, forkClone);
    const directory = await verifyDirectorySupply({
      trustedRoot: baseClone,
      baseCommit: input.baseCommit,
      forkRepository: forkClone,
      forkTip: input.tipCommit,
    });
    const baseDoctor = runTrustedCommand(baseClone, DOCTOR);
    const forkDoctor = runTrustedCommand(forkClone, DOCTOR);
    validateDoctor(baseDoctor.stdout);
    validateDoctor(forkDoctor.stdout);
    const baseRig = runTrustedCommand(baseClone, FULL_RIG);
    const forkRig = runTrustedCommand(forkClone, FULL_RIG);
    const effects = assertExactEffectsRecord({
      public: false,
      release: false,
      registration: false,
      deployment: false,
      payment: false,
      transfer: false,
      spend: false,
      liveValue: false,
    });
    return Object.freeze({
      schema: "dacs-forge-fork-qualification/v1",
      baseCommit: input.baseCommit,
      tipCommit: input.tipCommit,
      tipTree: git(forkClone, ["rev-parse", `${input.tipCommit}^{tree}`]),
      changedPaths: git(forkClone, [
        "diff", "--no-renames", "--name-only", input.baseCommit, input.tipCommit, "--",
      ]).split("\n").filter(Boolean),
      acceptedRig: Object.freeze({
        kind: "trusted-dacs-forge-candidate-rig",
        definitionSha256: expectedRig,
        dacsProfile: "v0.4",
        dacsCommit: "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
        forkModified: false,
      }),
      execution: Object.freeze({
        materialization: "fresh-local-no-hardlinks-exact-commits",
        baseDoctor: commandReceipt(baseDoctor),
        forkDoctor: commandReceipt(forkDoctor),
        baseRig: commandReceipt(baseRig),
        forkRig: commandReceipt(forkRig),
        directorySupplySha256: sha256(JSON.stringify(directory)),
      }),
      qualification: "pass",
      effects,
    });
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function option(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? undefined : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

if (import.meta.main) {
  const trustedRoot = resolve(import.meta.dir, "..");
  const result = await qualifyFork({
    trustedRoot,
    forkRepository: resolve(option("--repository")),
    baseCommit: option("--base"),
    tipCommit: option("--tip"),
  });
  console.log(JSON.stringify(result));
}

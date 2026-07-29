#!/usr/bin/env bun

import { resolve } from "node:path";
import type { ContainerFixtureReceipt } from "./container-fixture-runtime.ts";

const root = resolve(import.meta.dir, "..");
const suffix = `${process.pid}-${Date.now()}`;
const image = `dacs-forge:verify-${suffix}`;
const runContainer = `dacs-forge-run-${suffix}`;
const composeProject = `dacsforge${process.pid}`;
const path = Bun.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin";
const home = Bun.env["HOME"] ?? "/tmp";
const boundaryMarker = Bun.env["DACS_FORGE_SECRET_SENTINEL"];
const boundaryMarkerPattern = /^sentinel-[a-z0-9-]{1,32}-[0-9a-f]{32}$/;
const baseEnvironment = Object.freeze({
  HOME: home,
  PATH: path,
  ...(boundaryMarker === undefined ? {} : { DACS_FORGE_SECRET_SENTINEL: boundaryMarker }),
});
const composeEnvironment = Object.freeze({
  ...baseEnvironment,
  DACS_FORGE_IMAGE: image,
});

interface CommandOptions {
  readonly allowFailure?: boolean;
  readonly env?: Readonly<Record<string, string>>;
}

function command(args: readonly string[], options: CommandOptions = {}): string {
  const result = Bun.spawnSync([...args], {
    cwd: root,
    env: options.env ?? baseEnvironment,
    stderr: "pipe",
    stdout: "pipe",
  });
  const stdout = result.stdout.toString("utf8");
  if (result.exitCode !== 0 && !options.allowFailure) {
    throw new Error(`${args.join(" ")} failed (${result.exitCode})`);
  }
  return stdout;
}

export function parseContainerFixtureReceipt(output: string): ContainerFixtureReceipt {
  const line = output.trim().split("\n").findLast((candidate) => {
    try {
      return (JSON.parse(candidate) as { schema?: unknown }).schema === "dacs-container-fixture/v1";
    } catch {
      return false;
    }
  });
  if (line === undefined) throw new Error("Container fixture receipt is missing");
  const parsed = JSON.parse(line) as Record<string, unknown>;
  const expected = {
    schema: "dacs-container-fixture/v1",
    evidenceMode: "fixture",
    lifecycle: "verified",
    tests: [
      "test/runtime/service-runtime.test.ts",
      "test/e2e/full-handshake.test.ts",
      "test/security/secret-boundary.test.ts",
    ],
    effects: {
      analytics: 0,
      liveAnchors: 0,
      liveBroadcasts: 0,
      liveRegistrations: 0,
      liveTransfers: 0,
      liveWrites: 0,
      telemetry: 0,
    },
  } satisfies ContainerFixtureReceipt;
  if (JSON.stringify(parsed) !== JSON.stringify(expected)) {
    throw new Error("Container fixture receipt does not prove the bounded no-live-effect contract");
  }
  return parsed as unknown as ContainerFixtureReceipt;
}

function health(container: string): Readonly<Record<string, string>> {
  const output = command([
    "docker", "exec", container,
    "bun", "run", "./scripts/container-fixture-runtime.ts", "health",
  ]).trim();
  const parsed = JSON.parse(output) as Record<string, unknown>;
  const expected = Object.freeze({
    schema: "dacs-health/v1",
    service: "dacs-forge",
    status: "ok",
    version: "0.0.0-private",
  });
  if (JSON.stringify(parsed) !== JSON.stringify(expected)) {
    throw new Error("Container returned an unexpected normalized health contract");
  }
  return expected;
}

function assertNoExternalNetwork(container: string): void {
  const output = command(["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container]);
  const networks = JSON.parse(output) as Record<string, Record<string, unknown>>;
  if (Object.keys(networks).length !== 1 || networks["none"] === undefined
    || networks["none"]["Gateway"] !== "" || networks["none"]["IPAddress"] !== "") {
    throw new Error("Container has an external network path");
  }
}

async function waitHealthy(container: string): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const state = command(["docker", "inspect", "--format", "{{.State.Health.Status}}", container]).trim();
    if (state === "healthy") return;
    if (state === "unhealthy") throw new Error("Container became unhealthy");
    await Bun.sleep(500);
  }
  throw new Error("Container did not become healthy within 30 seconds");
}

function removeRunContainer(): void {
  command(["docker", "rm", "--force", runContainer], { allowFailure: true });
}

function composeDown(allowFailure = false): void {
  command([
    "docker", "compose", "--project-name", composeProject,
    "down", "--timeout", "5", "--remove-orphans",
  ], { allowFailure, env: composeEnvironment });
}

async function verify(): Promise<void> {
  if (typeof boundaryMarker !== "string" || !boundaryMarkerPattern.test(boundaryMarker)) {
    throw new Error("Container fixture verification requires a valid boundary marker");
  }
  command(["docker", "version", "--format", "{{.Server.Version}}"]);
  const composeVersion = command(["docker", "compose", "version", "--short"]).trim();
  const startedAt = performance.now();
  command(["docker", "build", "--pull", "--no-cache", "--tag", image, "."]);

  const selfTestStartedAt = performance.now();
  const selfTestReceipt = parseContainerFixtureReceipt(command([
    "docker", "run", "--rm",
    "--env", "DACS_FORGE_SECRET_SENTINEL",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/runtime:rw,noexec,nosuid,nodev,uid=1000,gid=1000,mode=0700",
    image, "self-test",
  ]));
  const selfTestMs = performance.now() - selfTestStartedAt;

  command([
    "docker", "run", "--detach", "--name", runContainer,
    "--env", "DACS_FORGE_SECRET_SENTINEL",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/runtime:rw,noexec,nosuid,nodev,uid=1000,gid=1000,mode=0700",
    image, "serve",
  ]);
  await waitHealthy(runContainer);
  const runUid = Number(command(["docker", "exec", runContainer, "id", "-u"]).trim());
  if (!Number.isInteger(runUid) || runUid === 0) throw new Error("docker run process is root");
  assertNoExternalNetwork(runContainer);
  const runHealth = health(runContainer);
  parseContainerFixtureReceipt(command(["docker", "logs", runContainer]));
  const stopStartedAt = performance.now();
  command(["docker", "stop", "--timeout", "5", runContainer]);
  const stopMs = performance.now() - stopStartedAt;
  if (stopMs >= 5_000) throw new Error("docker run shutdown exceeded five seconds");
  removeRunContainer();

  command([
    "docker", "compose", "--project-name", composeProject,
    "up", "--detach", "--no-build", "--wait", "--wait-timeout", "60",
  ], { env: composeEnvironment });
  const composeContainer = command([
    "docker", "compose", "--project-name", composeProject,
    "ps", "--quiet", "forge",
  ], { env: composeEnvironment }).trim();
  if (composeContainer.length === 0) throw new Error("Compose container is missing");
  const composeUid = Number(command(["docker", "exec", composeContainer, "id", "-u"]).trim());
  if (!Number.isInteger(composeUid) || composeUid === 0) throw new Error("Compose process is root");
  assertNoExternalNetwork(composeContainer);
  const composeHealth = health(composeContainer);
  if (JSON.stringify(composeHealth) !== JSON.stringify(runHealth)) {
    throw new Error("Compose and docker run health contracts differ");
  }
  const composeStopStartedAt = performance.now();
  composeDown();
  const composeStopMs = performance.now() - composeStopStartedAt;
  if (composeStopMs >= 5_000) throw new Error("Compose shutdown exceeded five seconds");
  const remainingComposeContainers = command([
    "docker", "compose", "--project-name", composeProject,
    "ps", "--all", "--quiet",
  ], { env: composeEnvironment }).trim();
  if (remainingComposeContainers.length !== 0) {
    throw new Error("Compose shutdown left a container behind");
  }

  const elapsedMs = performance.now() - startedAt;
  if (elapsedMs >= 300_000) throw new Error("Cold local build and runtime verification exceeded 300 seconds");
  console.log(JSON.stringify({
    schema: "dacs-container-fixture-verification/v1",
    composeVersion,
    composeShutdownMs: Math.round(composeStopMs),
    elapsedMs: Math.round(elapsedMs),
    health: runHealth,
    image,
    networkMode: "none",
    selfTestMs: Math.round(selfTestMs),
    selfTestReceipt,
    shutdownMs: Math.round(stopMs),
    uid: runUid,
  }));
}

if (import.meta.main) {
  try {
    await verify();
  } finally {
    removeRunContainer();
    composeDown(true);
    command(["docker", "image", "rm", image], { allowFailure: true });
  }
}

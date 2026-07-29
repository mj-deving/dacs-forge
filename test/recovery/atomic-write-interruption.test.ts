import { afterEach, describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { copyFile, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { BASIC_FIXTURE } from "../../service/fixtures/basic.ts";
import { ATOMIC_WRITE_SITES } from "../../src/substrate/sqlite/atomic-write-registry.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { EXPECTED_ATOMIC_WRITE_SITES } from "../fixtures/atomic-write-expectations.ts";
import {
  killLinuxProcessTree,
  spawnInLinuxPidNamespace,
} from "../fixtures/linux-process-tree.ts";

const ROOT = join(import.meta.dir, "../..");
const PRELOAD = join(ROOT, "test/workers/atomic-write-preload.ts");
const API_WORKER = join(ROOT, "test/workers/atomic-write-api-worker.ts");
const RAW_SNAPSHOT = join(ROOT, "test/workers/atomic-write-raw-snapshot.ts");
const ROLLBACK_WORKER = join(ROOT, "test/workers/atomic-write-rollback-worker.ts");
const TRANSACTION_CONTROL_WORKER = join(ROOT, "test/workers/atomic-write-transaction-control-worker.ts");
const DESCENDANT_HOLDER = join(ROOT, "test/workers/atomic-write-descendant-holder.ts");
const FILESYSTEM_PROBE = join(ROOT, "test/workers/atomic-write-filesystem-probe.ts");
const VERIFIER = join(ROOT, "test/workers/atomic-write-verifier.ts");
const roots: string[] = [];

interface Driver {
  readonly file: string;
  readonly pattern: string;
}

const FULL_HANDSHAKE: Driver = Object.freeze({
  file: "test/e2e/full-handshake.test.ts",
  pattern: "delivers the handler output through terminal bundles",
});

const DRIVER_OVERRIDES: Readonly<Record<string, Driver>> = Object.freeze({
  "party-authority.cleanup-challenges": {
    file: "test/api/capability-proof-of-possession.test.ts",
    pattern: "bootstraps digest-only custody",
  },
  "party-authority.allocate-challenge": {
    file: "test/api/capability-proof-of-possession.test.ts",
    pattern: "bootstraps digest-only custody",
  },
  "party-authority.cleanup-preparations": {
    file: "test/api/capability-negative-matrix.test.ts",
    pattern: "bounds and expires unconsumed capability preparations",
  },
  "party-authority.prepare-capability": {
    file: "test/api/capability-negative-matrix.test.ts",
    pattern: "bounds and expires unconsumed capability preparations",
  },
  "party-authority.consume-preparation": {
    file: "test/api/capability-proof-of-possession.test.ts",
    pattern: "bootstraps digest-only custody",
  },
  "party-authority.consume-challenge": {
    file: "test/api/capability-proof-of-possession.test.ts",
    pattern: "bootstraps digest-only custody",
  },
  "party-authority.issue-capability": {
    file: "test/api/capability-proof-of-possession.test.ts",
    pattern: "bootstraps digest-only custody",
  },
  "party-authority.reclaim-party-capabilities": {
    file: "test/api/capability-proof-of-possession.test.ts",
    pattern: "bootstraps digest-only custody",
  },
  "party-authority.revoke-capability": {
    file: "test/api/capability-negative-matrix.test.ts",
    pattern: "rotates atomically",
  },
  "party-authority.apply-amendment": {
    file: "test/api/artifact-access.test.ts",
    pattern: "restores only an anchored two-party amendment",
  },
  "party-authority.invalidate-amended-capabilities": {
    file: "test/api/artifact-access.test.ts",
    pattern: "restores only an anchored two-party amendment",
  },
  "party-authority.invalidate-amended-challenges": {
    file: "test/api/artifact-access.test.ts",
    pattern: "restores only an anchored two-party amendment",
  },
  "party-authority.bootstrap-instance": {
    file: "test/cli/admin-bootstrap.test.ts",
    pattern: "keeps the durable output",
  },
  "party-authority.insert-offline-administrator": {
    file: "test/cli/admin-bootstrap.test.ts",
    pattern: "keeps the durable output",
  },
  "party-authority.recovery-delete-admins": {
    file: "test/cli/admin-recovery.test.ts",
    pattern: "requires stopped service",
  },
  "party-authority.recovery-generation": {
    file: "test/cli/admin-recovery.test.ts",
    pattern: "requires stopped service",
  },
  "party-authority.consume-recovery": {
    file: "test/cli/admin-recovery.test.ts",
    pattern: "requires stopped service",
  },
  "party-authority.clone-delete-amendments": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-delete-challenges": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-delete-admission-challenges": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-delete-preparations": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-vacate-source": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-create-instance": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-revoke-capabilities": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "party-authority.clone-delete-source": {
    file: "test/api/capability-restart-proxy.test.ts",
    pattern: "leaves exactly one clone administrator",
  },
  "http-rate.cleanup": {
    file: "test/api/session-admission.test.ts",
    pattern: "enforces global concurrency and durable route rate before the handler",
  },
  "http-rate.consume": {
    file: "test/api/session-admission.test.ts",
    pattern: "enforces global concurrency and durable route rate before the handler",
  },
  "production-key.activate": {
    file: "test/security/live-signer-provider.test.ts",
    pattern: "exposes only a non-exporting handle-backed signing capability",
  },
  "production-key.retain-listing": {
    file: "test/security/key-revocation-propagation.test.ts",
    pattern: "retains one signed revocation binding",
  },
  "production-key.revoke-current": {
    file: "test/security/key-revocation-propagation.test.ts",
    pattern: "retains one signed revocation binding",
  },
  "production-key.activate-replacement": {
    file: "test/security/key-revocation-propagation.test.ts",
    pattern: "retains one signed revocation binding",
  },
  "production-key.publish-revocation": {
    file: "test/security/key-revocation-propagation.test.ts",
    pattern: "retains one signed revocation binding",
  },
  "production-key.pin-committed-session": {
    file: "test/security/committed-session-key-pin.test.ts",
    pattern: "survives restart and preserves only exact pre-revocation evidence",
  },
  "listing.reserve-anchor": {
    file: "test/directory/publication-order.test.ts",
    pattern: "does not expose discovery until",
  },
  "listing.publish-version": {
    file: "test/directory/publication-order.test.ts",
    pattern: "does not expose discovery until",
  },
  "listing.advance-discovery": {
    file: "test/directory/publication-order.test.ts",
    pattern: "does not expose discovery until",
  },
  "listing.reserve-revocation-anchor": {
    file: "test/directory/listing-revocation.test.ts",
    pattern: "anchors a signed retained revocation",
  },
  "listing.publish-revocation": {
    file: "test/directory/listing-revocation.test.ts",
    pattern: "anchors a signed retained revocation",
  },
  "listing.withdraw-discovery": {
    file: "test/directory/listing-revocation.test.ts",
    pattern: "anchors a signed retained revocation",
  },
  "listing.pin-session": {
    file: "test/directory/session-listing-pin.test.ts",
    pattern: "keeps existing pins but atomically rejects",
  },
  "service-run.claim": {
    file: "test/runtime/service-runtime.test.ts",
    pattern: "passes only the frozen documented request",
  },
  "service-run.complete": {
    file: "test/runtime/service-runtime.test.ts",
    pattern: "passes only the frozen documented request",
  },
  "service-run.release": {
    file: "test/runtime/service-runtime.test.ts",
    pattern: "releases an ordinary failed handler claim",
  },
  "service-run.recover": {
    file: "test/runtime/service-runtime.test.ts",
    pattern: "recovers only an exact stale claim",
  },
  "failure-evidence.put": {
    file: "test/lifecycle/attestation-bundle-finalisation.test.ts",
    pattern: "persists x402 failure authority",
  },
  "settlement-evidence.put-anchor": {
    file: "test/lifecycle/attestation-bundle-finalisation.test.ts",
    pattern: "persists x402 failure authority",
  },
  "lifecycle.stop": {
    file: "test/lifecycle/attestation-bundle-finalisation.test.ts",
    pattern: "persists x402 failure authority",
  },
  "lifecycle.abort": {
    file: "test/lifecycle/attestation-bundle-finalisation.test.ts",
    pattern: "atomically seals an authenticated unilateral abort",
  },
  "lifecycle.recover-commit-pending": {
    file: "test/recovery/restart-matrix.test.ts",
    pattern: "adopts an actually persisted commitment",
  },
  "lifecycle.recover-settlement": {
    file: "test/lifecycle/settlement-delivery-order.test.ts",
    pattern: "recovers a clean settle-pending boundary",
  },
  "lifecycle.resume-paused": {
    file: "test/lifecycle/settlement-delivery-order.test.ts",
    pattern: "substrate pause resumes only",
  },
  "lifecycle.expire-pause": {
    file: "test/lifecycle/settlement-delivery-order.test.ts",
    pattern: "expired substrate pause becomes terminal",
  },
});

type Phase = "before-statement" | "after-statement" | "post-commit";

interface Verification {
  readonly exactSnapshotHash: string;
  readonly exactTableHashes: Readonly<Record<string, string>>;
  readonly kind: "atomic-write-verification";
  readonly ownerChecks: readonly string[];
  readonly preOpen: {
    readonly exactSnapshotHash: string;
    readonly exactTableHashes: Readonly<Record<string, string>>;
    readonly schemaContractHash: string;
    readonly schemaHash: string;
    readonly schemaVersion: number;
    readonly tableCount: number;
  };
  readonly schemaContractHash: string;
  readonly schemaHash: string;
  readonly snapshotHash: string;
  readonly tableHashes: Readonly<Record<string, string>>;
  readonly tableCount: number;
}

interface BoundaryEvent {
  readonly api: string;
  readonly callStack: readonly string[];
  readonly inTransaction: boolean;
  readonly kind: "atomic-write-boundary";
  readonly phase: Phase;
  readonly target: string;
  readonly transactionCallStack: readonly string[];
  readonly transactionId: number | null;
  readonly transactionMode: "autocommit" | "default" | "deferred" | "exclusive" | "immediate";
}

interface ObservationEvent extends Omit<BoundaryEvent, "kind" | "phase"> {
  readonly kind: "atomic-write-observation";
}

interface ControlEvent {
  readonly afterSchemaContractHash: string;
  readonly afterSchemaHash: string;
  readonly afterSnapshotHash: string;
  readonly beforeSchemaContractHash: string;
  readonly beforeSchemaHash: string;
  readonly beforeSnapshotHash: string;
  readonly beforeTableHashes: Readonly<Record<string, string>>;
  readonly kind: "atomic-write-control-pair";
  readonly oldSnapshotHash: string;
  readonly oldTableHashes: Readonly<Record<string, string>>;
  readonly target: string;
  readonly afterTableHashes: Readonly<Record<string, string>>;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("real-process atomic write interruption", () => {
  test("enforces one deadline and kills descendants retaining captured pipes", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-atomic-descendant-"));
    roots.push(root);
    const pidFile = join(root, "descendant.pid");
    const markerFile = join(root, "descendant.marker");
    const marker = `dacs-descendant-${randomUUID()}`;
    await writeFile(markerFile, `${marker}\n`, { mode: 0o600 });
    const child = spawnInLinuxPidNamespace([process.execPath, "run", DESCENDANT_HOLDER, pidFile, markerFile], {
      cwd: ROOT,
      detached: true,
      writableRoots: [root],
      stdout: "pipe",
      stderr: "pipe",
    });
    try {
      await waitForFile(pidFile, 2_000);
      const namespacePid = Number((await readFile(pidFile, "utf8")).trim());
      expect(Number.isSafeInteger(namespacePid)).toBe(true);
      const descendant = await waitForHostProcessArgument(marker, 2_000);
      expect(descendant.pid).not.toBe(namespacePid);
      const startedAt = performance.now();
      await expect(collectChild(child, "descendant pipe holder", 100))
        .rejects.toThrow("descendant pipe holder timed out after 100ms");
      expect(performance.now() - startedAt).toBeLessThan(500);
      await waitForProcessIdentityGone(descendant, 2_000);
    } finally {
      killLinuxProcessTree(child);
    }
  });

  test("mounts only explicit fixture roots writable in worker PID namespaces", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-atomic-mounts-"));
    roots.push(root);
    const child = spawnInLinuxPidNamespace(
      [process.execPath, "run", FILESYSTEM_PROBE, root, join(ROOT, "package.json")],
      {
        cwd: ROOT,
        detached: true,
        writableRoots: [root],
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const result = await collectChild(child, "PID namespace filesystem probe", 5_000);
    expect(result.exitCode, result.stderr).toBe(0);
    expect(await readFile(join(root, "namespace-write-probe"), "utf8")).toBe("bounded\n");
    expect(() => spawnInLinuxPidNamespace([process.execPath, "--version"], {
      cwd: ROOT,
      detached: true,
      writableRoots: [ROOT],
      stdout: "pipe",
      stderr: "pipe",
    })).toThrow("writable root must be a canonical /tmp child");
    const traversalAlias = `/tmp/../${ROOT.slice(1)}`;
    expect(() => spawnInLinuxPidNamespace([process.execPath, "--version"], {
      cwd: ROOT,
      detached: true,
      writableRoots: [traversalAlias],
      stdout: "pipe",
      stderr: "pipe",
    })).toThrow("writable root must be a canonical /tmp child");
    const symlinkAlias = join(root, "repository-alias");
    await symlink(ROOT, symlinkAlias, "dir");
    expect(() => spawnInLinuxPidNamespace([process.execPath, "--version"], {
      cwd: ROOT,
      detached: true,
      writableRoots: [symlinkAlias],
      stdout: "pipe",
      stderr: "pipe",
    })).toThrow("writable root must be a canonical /tmp child");
  });

  test("keeps an explicit repository cwd under private /tmp readable but not writable", async () => {
    const previousTmpdir = process.env["TMPDIR"];
    process.env["TMPDIR"] = "/var/tmp";
    try {
      const writableRoot = await mkdtemp(join(tmpdir(), "dacs-atomic-cwd-write-"));
      const repositoryRoot = await mkdtemp("/tmp/dacs-atomic-cwd-read-");
      roots.push(writableRoot, repositoryRoot);
      const readOnlyPath = join(repositoryRoot, "package.json");
      const probePath = join(repositoryRoot, "filesystem-probe.ts");
      await writeFile(readOnlyPath, "{}\n", { mode: 0o600 });
      await copyFile(FILESYSTEM_PROBE, probePath);
      expect(() => spawnInLinuxPidNamespace([process.execPath, "--version"], {
        cwd: repositoryRoot,
        detached: true,
        writableRoots: [repositoryRoot],
        stdout: "pipe",
        stderr: "pipe",
      })).toThrow("writable root must be a canonical /tmp child");
      const child = spawnInLinuxPidNamespace(
        [process.execPath, "run", probePath, writableRoot, readOnlyPath],
        {
          cwd: repositoryRoot,
          detached: true,
          writableRoots: [writableRoot],
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      const result = await collectChild(child, "private /tmp repository cwd probe", 5_000);
      expect(result.exitCode, result.stderr).toBe(0);
      expect(await readFile(join(writableRoot, "namespace-write-probe"), "utf8")).toBe("bounded\n");
      expect(await readFile(readOnlyPath, "utf8")).toBe("{}\n");
    } finally {
      if (previousTmpdir === undefined) delete process.env["TMPDIR"];
      else process.env["TMPDIR"] = previousTmpdir;
    }
  });

  test("copies rollback-journal and WAL sidecars into paused checkpoints", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-atomic-sidecars-"));
    roots.push(root);
    const path = join(root, "state.sqlite");
    await writeFile(path, "main");
    await writeFile(`${path}-journal`, "rollback");
    await writeFile(`${path}-wal`, "wal");
    const snapshotPath = await copyPausedDatabase(path, "sidecar-copy", "after-statement");
    expect(await readFile(snapshotPath, "utf8")).toBe("main");
    expect(await readFile(`${snapshotPath}-journal`, "utf8")).toBe("rollback");
    expect(await readFile(`${snapshotPath}-wal`, "utf8")).toBe("wal");
  });

  test("all registered Bun SQLite execution APIs expose before, after, and committed kill boundaries", async () => {
    const apis = [
      "run", "exec",
      "query.run", "query.get", "query.all", "query.values", "query.raw", "query.iterate", "query.iterator",
      "prepare.run", "prepare.get", "prepare.all", "prepare.values", "prepare.raw", "prepare.iterate",
      "prepare.iterator",
      "prepare.bindings",
      "query.iterate-finalize", "query.iterator-finalize",
      "prepare.iterate-finalize", "prepare.iterator-finalize",
    ];
    for (const api of apis) {
      for (const phase of ["before-statement", "after-statement", "post-commit"] as const) {
        const result = await interruptApiProbe(api, phase);
        expect(result.count, `${api}/${phase}`).toBe(phase === "post-commit" ? 1 : 0);
        if (api === "prepare.bindings") {
          expect(result.value, `${api}/${phase}`).toBe(phase === "post-commit" ? "prepare-bound-value" : null);
        }
      }
    }
  }, 60_000);

  test("rejects a mismatched API target or phase before SIGKILL", async () => {
    const event: BoundaryEvent = {
      kind: "atomic-write-boundary",
      api: "run",
      callStack: [],
      inTransaction: true,
      phase: "before-statement",
      target: "wrong-target",
      transactionCallStack: [],
      transactionId: 1,
      transactionMode: "immediate",
    };
    const stream = (value: BoundaryEvent) => new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`${JSON.stringify(value)}\n`));
        controller.close();
      },
    });
    const neverExits = new Promise<number>(() => {});
    await expect(waitForBoundary(
      stream(event),
      neverExits,
      "api-probe",
      "before-statement",
    )).rejects.toThrow("expected api-probe/before-statement, received wrong-target/before-statement");
    await expect(waitForBoundary(
      stream({ ...event, target: "api-probe" }),
      neverExits,
      "api-probe",
      "after-statement",
    )).rejects.toThrow("expected api-probe/after-statement, received api-probe/before-statement");
    const valid = { ...event, target: "api-probe" };
    const encoded = new TextEncoder().encode(`${JSON.stringify(valid)}\n`);
    const fragmented = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoded.slice(0, 23));
        controller.enqueue(encoded.slice(23));
        controller.close();
      },
    });
    expect((await waitForBoundary(fragmented, neverExits, "api-probe", "before-statement")).api).toBe("run");
  });

  test("every declared multi-site boundary shares one observed outer transaction", async () => {
    const expectedBoundaries = groupExpectedSites();
    const observations = await observeDriver(FULL_HANDSHAKE);
    const observedTargets = new Set(observations.map(({ target }) => target));
    const supplementalDrivers = new Map<string, Driver>();
    for (const sites of expectedBoundaries.values()) {
      if (sites.length < 2 || sites.every((site) => observedTargets.has(site))) continue;
      for (const site of sites) {
        const driver = DRIVER_OVERRIDES[site] ?? FULL_HANDSHAKE;
        supplementalDrivers.set(`${driver.file}\0${driver.pattern}`, driver);
      }
    }
    observations.push(...(await Promise.all(
      [...supplementalDrivers.values()].map(observeDriver),
    )).flat());
    const byBoundary = new Map<string, Map<string, Set<number>>>();
    for (const event of observations) {
      const expected = expectedSite(event.target);
      const stack = [...event.callStack, ...event.transactionCallStack];
      expect(event.transactionMode).toBe(expected.transactionMode);
      expectOwnerStack(stack, expected.owner, expected.runtimeFrame, expected.ownerFrames);
      if ((expectedBoundaries.get(expected.boundary)?.length ?? 0) > 1) {
        expect(event.transactionId, `${event.target} escaped ${expected.boundary}`).not.toBeNull();
      }
      if (event.transactionId === null) continue;
      const bySite = byBoundary.get(expected.boundary) ?? new Map<string, Set<number>>();
      byBoundary.set(expected.boundary, bySite);
      const transactions = bySite.get(event.target) ?? new Set<number>();
      bySite.set(event.target, transactions);
      transactions.add(event.transactionId);
    }
    for (const [boundary, sites] of expectedBoundaries) {
      if (sites.length < 2) continue;
      const observed = byBoundary.get(boundary);
      expect(observed, `No transaction evidence for ${boundary}`).toBeDefined();
      const transactionSets = sites.map((site) => observed?.get(site) ?? new Set<number>());
      expect(transactionSets.every((transactions) => transactions.size > 0), boundary).toBe(true);
      const expectedTransactions = [...transactionSets[0]!].sort((left, right) => left - right);
      for (const transactions of transactionSets.slice(1)) {
        expect([...transactions].sort((left, right) => left - right), `${boundary} split transaction set`)
          .toEqual(expectedTransactions);
      }
    }
  }, 60_000);

  test("rejects unexplained detached sessions and permits only the exact service-driver fixture", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-atomic-detached-session-"));
    roots.push(root);
    const path = join(root, "state.sqlite");
    const database = openDatabase(path);
    database.query<never, Record<string, string>>(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint, status, created_at
      ) VALUES (
        'reference-instance', 'https://service.example', $jobId, 'fixture', $fingerprint, 'admitted', $createdAt
      )
    `).run({ jobId: BASIC_FIXTURE.jobId, fingerprint: "0".repeat(64), createdAt: BASIC_FIXTURE.producedAt });
    database.close();

    const rejected = await runVerifier(path, "admission.create-session");
    expect(rejected.exitCode).not.toBe(0);
    expect(rejected.stderr).toContain(`Session owner cannot reopen ${BASIC_FIXTURE.jobId}`);
    const accepted = await runVerifier(path, "service-run.claim");
    expect(accepted.exitCode, accepted.stderr).toBe(0);
    expect(accepted.stdout).toContain('"detached-session-fixtures:1"');

    const dependent = openDatabase(path);
    dependent.query<never, Record<string, string | number>>(`
      INSERT INTO admission_challenges (
        nonce, job_id, instance_id, audience, principal_ref, principal_scheme,
        principal_identifier, evidence_mode, client_nonce, client_idempotency_key,
        allocation_fingerprint, requested_at_ms, issued_at_ms, expires_at_ms, retain_until_ms
      ) VALUES (
        $nonce, $jobId, 'reference-instance', 'https://service.example', $principal,
        'key', $identifier, 'fixture', $clientNonce, 'detached-regression',
        $fingerprint, 0, 0, 1, 1
      )
    `).run({
      nonce: "0".repeat(32),
      jobId: BASIC_FIXTURE.jobId,
      principal: `key:${"1".repeat(64)}`,
      identifier: "1".repeat(64),
      clientNonce: "2".repeat(32),
      fingerprint: "3".repeat(64),
    });
    dependent.close();
    const dependencyRejected = await runVerifier(path, "service-run.claim");
    expect(dependencyRejected.exitCode).not.toBe(0);
    expect(dependencyRejected.stderr).toContain(`Detached service test session ${BASIC_FIXTURE.jobId} owns dependent state`);
  });

  test("owner correlation requires the class-qualified owner and pinned runtime frame", () => {
    const wrongRecordOwner = ["at <anonymous> (/repo/fixture-settlement.ts:331:10)"];
    expect(() => expectOwnerStack(
      wrongRecordOwner,
      "FixtureFailureEvidenceStore.record",
      "fixture-settlement.ts:85",
      ["fixture-settlement.ts:85"],
    )).toThrow("Runtime frame fixture-settlement.ts:85 absent for FixtureFailureEvidenceStore.record");
    expect(() => expectOwnerStack(
      ["at <anonymous> (/repo/fixture-settlement.ts:86:10)"],
      "FixtureFailureEvidenceStore.record",
      "fixture-settlement.ts:85",
      ["fixture-settlement.ts:85"],
    )).toThrow("Runtime frame fixture-settlement.ts:85 absent for FixtureFailureEvidenceStore.record");
    expect(() => expectOwnerStack(
      ["at <anonymous> (/repo/fixture-settlement.ts:85:10)"],
      "FixtureFailureEvidenceStore.record",
      "fixture-settlement.ts:85",
      ["fixture-settlement.ts:85"],
    )).not.toThrow();
  });

  test("a rolled-back target cannot borrow an unrelated transaction commit", async () => {
    for (const mode of ["control", "interrupt"] as const) {
      const root = await mkdtemp(join(tmpdir(), `dacs-atomic-rollback-${mode}-`));
      roots.push(root);
      const child = spawnInLinuxPidNamespace([
        process.execPath,
        "--preload",
        PRELOAD,
        ROLLBACK_WORKER,
        join(root, "state.sqlite"),
      ], {
        cwd: ROOT,
        detached: true,
        writableRoots: [root],
        env: {
          ...process.env,
          DACS_ATOMIC_WRITE_MODE: mode,
          DACS_ATOMIC_WRITE_PHASE: "post-commit",
          DACS_ATOMIC_WRITE_TARGET: "rollback-probe",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      const result = await collectChild(child, `atomic rollback ${mode}`, 5_000);
      expect(result.exitCode, result.stderr).toBe(0);
      expect(result.stdout).toContain('"kind":"rollback-probe-complete"');
      expect(result.stdout).not.toContain('"kind":"atomic-write-boundary"');
      expect(result.stdout).not.toContain('"kind":"atomic-write-control"');
    }
  });

  test("a nested rollback cannot discard an outer pending write", async () => {
    for (const mode of ["control", "interrupt"] as const) {
      const root = await mkdtemp(join(tmpdir(), `dacs-atomic-nested-rollback-${mode}-`));
      roots.push(root);
      const child = spawnInLinuxPidNamespace([
        process.execPath,
        "--preload",
        PRELOAD,
        ROLLBACK_WORKER,
        join(root, "state.sqlite"),
        "outer-target-nested-rollback",
      ], {
        cwd: ROOT,
        detached: true,
        writableRoots: [root],
        env: {
          ...process.env,
          DACS_ATOMIC_WRITE_MODE: mode,
          DACS_ATOMIC_WRITE_PHASE: "post-commit",
          DACS_ATOMIC_WRITE_TARGET: "rollback-probe",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (mode === "control") {
        const result = await collectChild(child, "atomic nested rollback control", 5_000);
        expect(result.exitCode, result.stderr).toBe(0);
        expect(result.stdout).toContain('"kind":"atomic-write-control"');
        expect(result.stdout).toContain('"kind":"rollback-probe-complete"');
      } else {
        const stderrPromise = boundedStreamText(child.stderr);
        try {
          const boundary = await waitForBoundary(child.stdout, child.exited, "rollback-probe", "post-commit");
          expect(boundary.inTransaction).toBe(false);
          expect(boundary.transactionMode).toBe("immediate");
        } finally {
          killLinuxProcessTree(child);
          await waitForExit(child, "atomic nested rollback interrupt", 5_000);
        }
        expect(await stderrPromise).toBe("");
      }
      const database = new (await import("bun:sqlite")).Database(join(root, "state.sqlite"), {
        readonly: true,
        strict: true,
      });
      try {
        expect(database.query<{ id: number; value: string }, []>(
          "SELECT id, value FROM probe ORDER BY id",
        ).all()).toEqual([{ id: 1, value: "rolled-back" }]);
      } finally {
        database.close();
      }
    }
  });

  test("rejects raw SQL transaction control across every Database API", async () => {
    for (const [api, sql] of [
      ["exec", "BEGIN IMMEDIATE"],
      ["prepare", "SAVEPOINT nested"],
      ["query", "ROLLBACK TO nested"],
      ["run", "SELECT 1; RELEASE nested"],
      ["exec", "CREATE TRIGGER hidden_control AFTER UPDATE ON fixture BEGIN SELECT 'CASE'; END; SAVEPOINT hidden"],
      ["exec", "SELECT '('; SAVEPOINT hidden"],
      ["run", "SELECT '; SAVEPOINT quoted'; SAVEPOINT hidden"],
    ] as const) {
      const root = await mkdtemp(join(tmpdir(), `dacs-atomic-transaction-control-${api}-`));
      roots.push(root);
      const child = spawnInLinuxPidNamespace([
        process.execPath,
        "--preload",
        PRELOAD,
        TRANSACTION_CONTROL_WORKER,
        join(root, "state.sqlite"),
        api,
        sql,
      ], {
        cwd: ROOT,
        detached: true,
        writableRoots: [root],
        env: { ...process.env, DACS_ATOMIC_WRITE_MODE: "observe" },
        stdout: "pipe",
        stderr: "pipe",
      });
      const result = await collectChild(child, `atomic-write transaction control ${api}`, 5_000);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("SQL transaction control is forbidden");
    }
  });

  test.each([...ATOMIC_WRITE_SITES])(
    "$id is old-valid before/after its statement and new-valid after commit",
    async (site) => {
      const driver = DRIVER_OVERRIDES[site.id] ?? FULL_HANDSHAKE;
      const before = await killAndVerify(site.id, "before-statement", driver);
      const after = await killAndVerify(site.id, "after-statement", driver);
      const committed = await killAndVerify(site.id, "post-commit", driver);
      const control = await runControl(site.id, driver);

      if (site.transactionMode !== "autocommit") {
        expect(after.snapshotHash).toBe(before.snapshotHash);
        expect(before.snapshotHash).toBe(control.oldSnapshotHash);
        expect(after.snapshotHash).toBe(control.oldSnapshotHash);
        expect(before.tableHashes).toEqual(control.oldTableHashes);
        expect(after.tableHashes).toEqual(control.oldTableHashes);
        expect(committed.snapshotHash).not.toBe(before.snapshotHash);
      } else {
        expect(before.snapshotHash).toBe(control.oldSnapshotHash);
        expect(before.tableHashes).toEqual(control.oldTableHashes);
        expect(after.snapshotHash).not.toBe(before.snapshotHash);
        expect(committed.snapshotHash).toBe(after.snapshotHash);
      }
      expect(committed.snapshotHash).toBe(control.afterSnapshotHash);
      expect(committed.tableHashes).toEqual(control.afterTableHashes);
      expect(before.preOpen.schemaHash).toBe(before.preKillSchemaHash);
      expect(after.preOpen.schemaHash).toBe(after.preKillSchemaHash);
      expect(committed.preOpen.schemaHash).toBe(committed.preKillSchemaHash);
      expect(before.preOpen.schemaContractHash).toBe(before.preKillSchemaContractHash);
      expect(after.preOpen.schemaContractHash).toBe(after.preKillSchemaContractHash);
      expect(committed.preOpen.schemaContractHash).toBe(committed.preKillSchemaContractHash);
      expect(before.tableHashes).toEqual(before.preKillTableHashes);
      expect(after.tableHashes).toEqual(after.preKillTableHashes);
      expect(committed.tableHashes).toEqual(committed.preKillTableHashes);
      expect(before.snapshotHash).toBe(before.preKillSnapshotHash);
      expect(after.snapshotHash).toBe(after.preKillSnapshotHash);
      expect(committed.snapshotHash).toBe(committed.preKillSnapshotHash);
      expect(before.exactTableHashes).toEqual(before.preKillExactTableHashes);
      expect(after.exactTableHashes).toEqual(after.preKillExactTableHashes);
      expect(committed.exactTableHashes).toEqual(committed.preKillExactTableHashes);
      expect(before.exactSnapshotHash).toBe(before.preKillExactSnapshotHash);
      expect(after.exactSnapshotHash).toBe(after.preKillExactSnapshotHash);
      expect(committed.exactSnapshotHash).toBe(committed.preKillExactSnapshotHash);
      expect(before.preOpen.schemaContractHash).toBe(control.beforeSchemaContractHash);
      expect(after.preOpen.schemaContractHash).toBe(site.transactionMode !== "autocommit"
        ? control.beforeSchemaContractHash : control.afterSchemaContractHash);
      expect(committed.preOpen.schemaContractHash).toBe(control.afterSchemaContractHash);
      expect(before.schemaContractHash).toBe(before.preOpen.schemaContractHash);
      expect(after.schemaContractHash).toBe(after.preOpen.schemaContractHash);
      expect(committed.schemaContractHash).toBe(committed.preOpen.schemaContractHash);
      expect(before.tableCount).toBeGreaterThan(0);
      expect(before.ownerChecks.some((check) => check.startsWith("artifacts:"))).toBe(true);
      for (const authority of [
        "listing-authorities:",
        "listing-verification-authorities:",
        "identity-authorities:",
      ]) {
        expect(before.ownerChecks.some((check) => check.startsWith(authority))).toBe(true);
        expect(committed.ownerChecks.some((check) => check.startsWith(authority))).toBe(true);
      }
      expect(committed.ownerChecks.length).toBeGreaterThanOrEqual(before.ownerChecks.length);
    },
    60_000,
  );
});

async function interruptApiProbe(api: string, phase: Phase): Promise<{
  readonly count: number;
  readonly value: string | null;
}> {
  const root = await mkdtemp(join(tmpdir(), `dacs-atomic-api-${safeName(api)}-${phase}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  const child = spawnInLinuxPidNamespace([process.execPath, "run", "--preload", PRELOAD, API_WORKER, path, api], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      DACS_ATOMIC_WRITE_MODE: "interrupt",
      DACS_ATOMIC_WRITE_PHASE: phase,
      DACS_ATOMIC_WRITE_TARGET: "api-probe",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const stderrPromise = boundedStreamText(child.stderr);
  let boundaryError: unknown;
  try {
    const boundary = await waitForBoundary(child.stdout, child.exited, "api-probe", phase);
    expect(boundary.api).toBe(expectedBoundaryApi(api));
    expect(boundary.transactionMode).toBe("immediate");
    expect(boundary.inTransaction).toBe(phase !== "post-commit");
  } catch (error) {
    boundaryError = error;
  } finally {
    killLinuxProcessTree(child);
    await waitForExit(child, `atomic-write API child ${api}/${phase}`, 5_000);
  }
  const stderr = await stderrPromise;
  if (boundaryError !== undefined) {
    const reason = boundaryError instanceof Error ? boundaryError.message : String(boundaryError);
    throw new Error(`${reason}\nchild stderr:\n${stderr}`);
  }
  const database = new (await import("bun:sqlite")).Database(path, { readonly: true, strict: true });
  try {
    const row = database.query<{ count: number; value: string | null }, []>(
      "SELECT COUNT(*) AS count, MIN(api) AS value FROM api_probe",
    ).get()!;
    return { count: Number(row.count), value: row.value };
  } finally {
    database.close();
  }
}

async function killAndVerify(
  id: string,
  phase: Phase,
  driver: Driver,
): Promise<Verification & {
  readonly preKillExactSnapshotHash: string;
  readonly preKillExactTableHashes: Readonly<Record<string, string>>;
  readonly preKillSchemaContractHash: string;
  readonly preKillSchemaHash: string;
  readonly preKillSnapshotHash: string;
  readonly preKillTableHashes: Readonly<Record<string, string>>;
}> {
  const root = await mkdtemp(join(tmpdir(), `dacs-atomic-${safeName(id)}-${phase}-`));
  roots.push(root);
  const child = spawnInLinuxPidNamespace([
    process.execPath,
    "test",
    "--preload",
    PRELOAD,
    join(ROOT, driver.file),
    "-t",
    driver.pattern,
    "--timeout",
    "60000",
  ], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      TMPDIR: root,
      DACS_ATOMIC_WRITE_PHASE: phase,
      DACS_ATOMIC_WRITE_TARGET: id,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const stderrPromise = boundedStreamText(child.stderr);
  let boundary!: BoundaryEvent;
  let boundaryError: unknown;
  let databasePath = "";
  let preKill!: {
    readonly exactSnapshotHash: string;
    readonly exactTableHashes: Readonly<Record<string, string>>;
    readonly schemaContractHash: string;
    readonly schemaHash: string;
    readonly snapshotHash: string;
    readonly tableHashes: Readonly<Record<string, string>>;
  };
  let exitCode = 0;
  let stderr = "";
  try {
    boundary = await waitForBoundary(child.stdout, child.exited, id, phase);
    expect(boundary.api, `${id}/${phase}`).toBe(expectedSite(id).api);
    const databases = (await filesBelow(root)).filter((path) => path.endsWith(".sqlite"));
    if (databases.length !== 1) {
      throw new Error(`Expected one paused SQLite database for ${id}/${phase}, found ${databases.length}`);
    }
    databasePath = databases[0]!;
    preKill = await readRawSnapshot(await copyPausedDatabase(databasePath, id, phase), id, phase);
  } catch (error) {
    boundaryError = error;
  } finally {
    killLinuxProcessTree(child);
    [exitCode, stderr] = await Promise.all([
      waitForExit(child, `atomic-write child ${id}/${phase} after SIGKILL`, 5_000),
      stderrPromise,
    ]);
  }
  if (boundaryError !== undefined) {
    const reason = boundaryError instanceof Error ? boundaryError.message : String(boundaryError);
    throw new Error(`${reason}\nchild stderr:\n${stderr}`);
  }
  expect(boundary).toMatchObject({
    kind: "atomic-write-boundary",
    target: id,
    phase,
    inTransaction: sitePhaseIsTransactional(id, phase),
    transactionMode: expectedSite(id).transactionMode,
  });
  expect(boundary.callStack.some((line) => line.includes(`/${siteFor(id).source}:`))).toBe(true);
  expectOwnerStack(
    [...boundary.callStack, ...boundary.transactionCallStack],
    expectedSite(id).owner,
    expectedSite(id).runtimeFrame,
    expectedSite(id).ownerFrames,
  );
  if (exitCode === 0) throw new Error(`Atomic-write child exited successfully instead of being killed: ${stderr}`);

  return {
    ...await verifyInFreshProcess(databasePath, id),
    preKillExactSnapshotHash: preKill.exactSnapshotHash,
    preKillExactTableHashes: preKill.exactTableHashes,
    preKillSchemaContractHash: preKill.schemaContractHash,
    preKillSchemaHash: preKill.schemaHash,
    preKillSnapshotHash: preKill.snapshotHash,
    preKillTableHashes: preKill.tableHashes,
  };
}

async function copyPausedDatabase(path: string, id: string, phase: Phase): Promise<string> {
  const snapshotRoot = await mkdtemp(join(tmpdir(), `dacs-atomic-pre-kill-${safeName(id)}-${phase}-`));
  roots.push(snapshotRoot);
  const snapshotPath = join(snapshotRoot, basename(path));
  await copyFile(path, snapshotPath);
  for (const suffix of ["-journal", "-wal"] as const) {
    try {
      await copyFile(`${path}${suffix}`, `${snapshotPath}${suffix}`);
    } catch (error) {
      if (typeof error !== "object" || error === null || !("code" in error) || error.code !== "ENOENT") throw error;
    }
  }
  return snapshotPath;
}

async function readRawSnapshot(
  path: string,
  id: string,
  phase: Phase,
): Promise<{
  readonly exactSnapshotHash: string;
  readonly exactTableHashes: Readonly<Record<string, string>>;
  readonly schemaContractHash: string;
  readonly schemaHash: string;
  readonly snapshotHash: string;
  readonly tableHashes: Readonly<Record<string, string>>;
}> {
  const child = spawnInLinuxPidNamespace([process.execPath, "run", RAW_SNAPSHOT, path], {
    cwd: ROOT,
    detached: true,
    writableRoots: [dirname(path)],
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(
    child,
    `atomic-write raw snapshot for ${id}/${phase}`,
    20_000,
  );
  if (exitCode !== 0) throw new Error(`Atomic-write raw snapshot failed (${exitCode}): ${stderr}`);
  const line = stdout.split("\n").find((entry) => entry.startsWith('{"kind":"atomic-write-raw-snapshot"'));
  if (line === undefined) throw new Error(`Atomic-write raw snapshot emitted no result: ${stdout}`);
  return JSON.parse(line) as {
    readonly exactSnapshotHash: string;
    readonly exactTableHashes: Readonly<Record<string, string>>;
    readonly schemaContractHash: string;
    readonly schemaHash: string;
    readonly snapshotHash: string;
    readonly tableHashes: Readonly<Record<string, string>>;
  };
}

function sitePhaseIsTransactional(id: string, phase: Phase): boolean {
  if (phase === "post-commit") return false;
  return expectedSite(id).transactionMode !== "autocommit";
}

function siteFor(id: string) {
  const site = ATOMIC_WRITE_SITES.find((candidate) => candidate.id === id);
  if (site === undefined) throw new Error(`Atomic-write site ${id} is not registered`);
  return site;
}

async function waitForBoundary(
  stdout: ReadableStream<Uint8Array>,
  exited: Promise<number>,
  id: string,
  phase: Phase,
): Promise<BoundaryEvent> {
  const reader = stdout.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = setTimeout(() => reader.cancel(`Timeout waiting for ${id}/${phase}`), 20_000);
  try {
    while (true) {
      const next = await Promise.race([
        reader.read(),
        exited.then((code) => ({ done: true as const, value: new Uint8Array(), code })),
      ]);
      if ("code" in next) throw new Error(`Atomic-write child exited ${next.code} before ${id}/${phase}`);
      buffered += decoder.decode(next.value, { stream: !next.done });
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith('{"kind":"atomic-write-boundary"')) continue;
        const event = JSON.parse(line) as BoundaryEvent;
        if (event.target !== id || event.phase !== phase) {
          throw new Error(`Atomic-write boundary mismatch: expected ${id}/${phase}, received ${event.target}/${event.phase}`);
        }
        return event;
      }
      if (next.done) throw new Error(`Atomic-write child closed stdout before ${id}/${phase}: ${buffered}`);
    }
  } finally {
    clearTimeout(deadline);
    reader.releaseLock();
  }
}

function expectedBoundaryApi(api: string): string {
  if (api === "prepare.bindings") return "prepare.run";
  return api.endsWith("-finalize") ? api.slice(0, -"-finalize".length) : api;
}

async function verifyInFreshProcess(path: string, target: string): Promise<Verification> {
  const result = await runVerifier(path, target);
  const { exitCode, stdout, stderr } = result;
  if (exitCode !== 0) throw new Error(`Atomic-write verifier failed (${exitCode}): ${stderr}\n${stdout}`);
  const line = stdout.trim().split("\n").findLast((entry) => entry.startsWith('{"kind":"atomic-write-verification"'));
  if (line === undefined) throw new Error(`Atomic-write verifier emitted no result: ${stdout}`);
  return JSON.parse(line) as Verification;
}

async function runVerifier(path: string, target: string): Promise<{
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}> {
  const child = spawnInLinuxPidNamespace([process.execPath, "run", VERIFIER, path, target], {
    cwd: ROOT,
    detached: true,
    writableRoots: [dirname(path)],
    stdout: "pipe",
    stderr: "pipe",
  });
  return collectChild(child, `atomic-write verifier for ${target}`, 20_000);
}

async function observeDriver(driver: Driver): Promise<ObservationEvent[]> {
  const root = await mkdtemp(join(tmpdir(), "dacs-atomic-observe-"));
  roots.push(root);
  const child = spawnInLinuxPidNamespace([
    process.execPath,
    "test",
    "--preload",
    PRELOAD,
    join(ROOT, driver.file),
    "-t",
    driver.pattern,
    "--timeout",
    "60000",
  ], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: { ...process.env, TMPDIR: root, DACS_ATOMIC_WRITE_MODE: "observe" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(child, "atomic-write observer", 40_000);
  if (exitCode !== 0) throw new Error(`Atomic-write observer failed (${exitCode}): ${stderr}`);
  return stdout.split("\n")
    .filter((line) => line.startsWith('{"kind":"atomic-write-observation"'))
    .map((line) => JSON.parse(line) as ObservationEvent);
}

async function runControl(id: string, driver: Driver): Promise<ControlEvent> {
  const root = await mkdtemp(join(tmpdir(), `dacs-atomic-control-${safeName(id)}-`));
  roots.push(root);
  const child = spawnInLinuxPidNamespace([
    process.execPath,
    "test",
    "--preload",
    PRELOAD,
    join(ROOT, driver.file),
    "-t",
    driver.pattern,
    "--timeout",
    "60000",
  ], {
    cwd: ROOT,
    detached: true,
    writableRoots: [root],
    env: {
      ...process.env,
      TMPDIR: root,
      DACS_ATOMIC_WRITE_MODE: "control",
      DACS_ATOMIC_WRITE_TARGET: id,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const { exitCode, stdout, stderr } = await collectChild(child, `atomic-write control for ${id}`, 60_000);
  if (exitCode !== 0) throw new Error(`Atomic-write control failed (${exitCode}): ${stderr}`);
  const lines = stdout.split("\n");
  const beforeLine = lines.find((entry) => entry.startsWith('{"kind":"atomic-write-control-before"'));
  const afterLine = lines.find((entry) => entry.startsWith('{"kind":"atomic-write-control"'));
  if (beforeLine === undefined || afterLine === undefined) {
    throw new Error(`Atomic-write control omitted before/after checkpoints for ${id}: ${stdout}`);
  }
  const before = JSON.parse(beforeLine) as {
    readonly oldSnapshotHash: string;
    readonly oldTableHashes: Readonly<Record<string, string>>;
    readonly schemaContractHash: string;
    readonly schemaHash: string;
    readonly snapshotHash: string;
    readonly tableHashes: Readonly<Record<string, string>>;
    readonly target: string;
  };
  const after = JSON.parse(afterLine) as {
    readonly schemaContractHash: string;
    readonly schemaHash: string;
    readonly snapshotHash: string;
    readonly tableHashes: Readonly<Record<string, string>>;
    readonly target: string;
  };
  expect(before.target).toBe(id);
  expect(after.target).toBe(id);
  return {
    kind: "atomic-write-control-pair",
    oldSnapshotHash: before.oldSnapshotHash,
    oldTableHashes: before.oldTableHashes,
    target: id,
    beforeSchemaContractHash: before.schemaContractHash,
    beforeSchemaHash: before.schemaHash,
    beforeSnapshotHash: before.snapshotHash,
    beforeTableHashes: before.tableHashes,
    afterSchemaContractHash: after.schemaContractHash,
    afterSchemaHash: after.schemaHash,
    afterSnapshotHash: after.snapshotHash,
    afterTableHashes: after.tableHashes,
  };
}

function expectedSite(id: string) {
  const expected = EXPECTED_ATOMIC_WRITE_SITES[id];
  if (expected === undefined) throw new Error(`No independent atomic-write expectation for ${id}`);
  return expected;
}

function expectOwnerStack(
  callStack: readonly string[],
  owner: string,
  runtimeFrame: string | undefined,
  ownerFrames: readonly string[],
): void {
  if (runtimeFrame === undefined) throw new Error(`Owner ${owner} has no independently pinned runtime frame`);
  if (!hasRuntimeFrame(callStack, runtimeFrame)) {
    throw new Error(`Runtime frame ${runtimeFrame} absent for ${owner}:\n${callStack.join("\n")}`);
  }
  if (ownerFrames.length === 0 || !ownerFrames.some((frame) => hasRuntimeFrame(callStack, frame))) {
    throw new Error(`Class-qualified owner frame absent for ${owner}:\n${callStack.join("\n")}`);
  }
}

function hasRuntimeFrame(callStack: readonly string[], runtimeFrame: string): boolean {
  return callStack.some((line) => line.includes(`/${runtimeFrame}:`));
}

function groupExpectedSites(): Map<string, string[]> {
  const grouped = new Map<string, string[]>();
  for (const [id, { boundary }] of Object.entries(EXPECTED_ATOMIC_WRITE_SITES)) {
    grouped.set(boundary, [...(grouped.get(boundary) ?? []), id]);
  }
  return grouped;
}

interface CapturedChild {
  readonly exited: Promise<number>;
  readonly pid: number;
  readonly stderr: ReadableStream<Uint8Array>;
  readonly stdout: ReadableStream<Uint8Array>;
  kill(signal?: NodeJS.Signals | number): void;
}

async function collectChild(
  child: CapturedChild,
  label: string,
  timeoutMs: number,
): Promise<{ readonly exitCode: number; readonly stderr: string; readonly stdout: string }> {
  const stdoutReader = child.stdout.getReader();
  const stderrReader = child.stderr.getReader();
  const drain = async (reader: { read(): Promise<{ readonly done: boolean; readonly value?: Uint8Array }> }) => {
    const decoder = new TextDecoder();
    let output = "";
    while (true) {
      const next = await reader.read();
      if (next.done) return output + decoder.decode(new Uint8Array());
      output += decoder.decode(next.value!, { stream: true });
    }
  };
  const completion = Promise.all([
    child.exited,
    drain(stdoutReader as unknown as Parameters<typeof drain>[0]),
    drain(stderrReader as unknown as Parameters<typeof drain>[0]),
  ] as const);
  const absoluteDeadline = performance.now() + timeoutMs;
  const cleanupReserveMs = Math.min(250, Math.max(10, Math.floor(timeoutMs * 0.9)));
  const executionBudgetMs = Math.max(0, timeoutMs - cleanupReserveMs);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = Symbol("timed-out");
  const completed = await Promise.race([
    completion,
    new Promise<typeof timedOut>((resolve) => {
      timer = setTimeout(() => resolve(timedOut), executionBudgetMs);
    }),
  ]);
  if (timer !== undefined) clearTimeout(timer);
  if (completed === timedOut) {
    killLinuxProcessTree(child);
    await Promise.allSettled([stdoutReader.cancel(), stderrReader.cancel()]);
    void completion.catch(() => {});
    const remainingMs = Math.max(1, Math.floor(absoluteDeadline - performance.now()));
    await waitForExit(child, `${label} after SIGKILL`, remainingMs);
    throw new Error(`${label} timed out after ${timeoutMs}ms`);
  }
  const [exitCode, stdout, stderr] = completed;
  return { exitCode, stdout, stderr };
}

async function boundedStreamText(stream: ReadableStream<Uint8Array>, timeoutMs = 25_000): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let output = "";
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Child stream did not close within ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    while (true) {
      const next = await Promise.race([reader.read(), deadline]);
      if (next.done) return output + decoder.decode(new Uint8Array());
      output += decoder.decode(next.value, { stream: true });
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    reader.releaseLock();
  }
}

async function waitForFile(path: string, timeoutMs: number): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (true) {
    try {
      await readFile(path);
      return;
    } catch (error) {
      if (typeof error !== "object" || error === null || !("code" in error) || error.code !== "ENOENT") throw error;
      if (performance.now() >= deadline) throw new Error(`File did not appear within ${timeoutMs}ms: ${path}`);
      await Bun.sleep(10);
    }
  }
}

interface LinuxProcessIdentity {
  readonly pid: number;
  readonly startTime: string;
}

async function waitForHostProcessArgument(argument: string, timeoutMs: number): Promise<LinuxProcessIdentity> {
  const deadline = performance.now() + timeoutMs;
  while (true) {
    const matches: LinuxProcessIdentity[] = [];
    for (const entry of await readdir("/proc", { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) continue;
      const pid = Number(entry.name);
      try {
        const command = await readFile(`/proc/${pid}/cmdline`);
        if (!command.toString("utf8").split("\0").includes(argument)) continue;
        const startTime = await readLinuxProcessStartTime(pid);
        if (startTime !== undefined) matches.push({ pid, startTime });
      } catch (error) {
        if (!isTransientProcError(error)) throw error;
      }
    }
    if (matches.length === 1) return matches[0]!;
    if (matches.length > 1) throw new Error(`Descendant marker matched ${matches.length} host processes`);
    if (performance.now() >= deadline) throw new Error(`Descendant marker was not visible in host /proc: ${argument}`);
    await Bun.sleep(10);
  }
}

async function waitForProcessIdentityGone(identity: LinuxProcessIdentity, timeoutMs: number): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (true) {
    const startTime = await readLinuxProcessStartTime(identity.pid);
    if (startTime === undefined || startTime !== identity.startTime) return;
    if (performance.now() >= deadline) {
      throw new Error(`Descendant pid ${identity.pid} survived process-group SIGKILL`);
    }
    await Bun.sleep(10);
  }
}

async function readLinuxProcessStartTime(pid: number): Promise<string | undefined> {
  try {
    const stat = await readFile(`/proc/${pid}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    if (commandEnd < 0) throw new Error(`Malformed /proc/${pid}/stat`);
    const fieldsAfterCommand = stat.slice(commandEnd + 2).split(" ");
    const startTime = fieldsAfterCommand[19];
    if (startTime === undefined || !/^\d+$/.test(startTime)) {
      throw new Error(`Missing start time in /proc/${pid}/stat`);
    }
    return startTime;
  } catch (error) {
    if (isTransientProcError(error)) return undefined;
    throw error;
  }
}

function isTransientProcError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && (error.code === "ENOENT" || error.code === "ESRCH" || error.code === "EACCES" || error.code === "EPERM");
}

async function waitForExit(child: CapturedChild, label: string, timeoutMs: number): Promise<number> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      child.exited,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(
          new Error(`${label} did not terminate within ${timeoutMs}ms; leaked pid=${child.pid}`),
        ), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function filesBelow(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesBelow(path) : entry.isFile() ? [path] : [];
  }));
  return nested.flat();
}

function safeName(value: string): string {
  return value.replaceAll(/[^a-z0-9]+/g, "-");
}

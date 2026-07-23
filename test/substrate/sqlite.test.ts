import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";
import { chmod, mkdtemp, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { contentHash } from "../../src/protocol/hash.ts";
import { ArtifactIntegrityError, ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { FixtureSettlementLedger } from "../../src/substrate/sqlite/fixture-settlement.ts";
import {
  SessionStore,
  admissionSigningBytes,
  challengeAllocationSigningBytes,
  sessionBindingHash,
  type AdmissionInput,
  type ChallengeAllocationInput,
  type PrincipalProofAuthenticator,
  type SessionStoreOptions,
} from "../../src/substrate/sqlite/session-store.ts";
import { deliveryInput, openDeliveryFixture } from "../delivery/fixtures.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

const directories: string[] = [];
const START_MS = Date.parse("2026-07-16T18:00:00.000Z");
const AUTHENTICATION_KEY = "fixture-authentication-key";
const JOB_ID_1 = fixtureJobId(1);
let allocationSequence = 0;

const authenticator: PrincipalProofAuthenticator = {
  verify: ({ proof, signedBytes }) => proof === sign(signedBytes),
};

afterEach(async () => {
  allocationSequence = 0;
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

async function databasePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-template-"));
  directories.push(directory);
  return join(directory, "state.sqlite");
}

function sessionStore(
  database: ReturnType<typeof openDatabase>,
  overrides: Partial<SessionStoreOptions> = {},
): SessionStore {
  return new SessionStore(database, {
    audience: "https://service.example",
    authenticator,
    deploymentMode: "fixture",
    instanceId: "instance-1",
    jobAuthorizer: { authorize: () => true },
    now: () => START_MS,
    ...overrides,
  });
}

function challenge(
  overrides: Partial<ChallengeAllocationInput> = {},
): ChallengeAllocationInput {
  allocationSequence += 1;
  const unsigned: ChallengeAllocationInput = {
    instanceId: "instance-1",
    audience: "https://service.example",
    principal: "did:demos:buyer",
    jobId: JOB_ID_1,
    evidenceMode: "fixture",
    clientNonce: allocationSequence.toString(16).padStart(32, "0"),
    clientIdempotencyKey: `allocation-${allocationSequence}`,
    requestedAtMs: START_MS,
    proof: "pending",
    ...overrides,
  };
  return signChallenge(unsigned);
}

function admission(
  store: SessionStore,
  challengeOverrides: Partial<ChallengeAllocationInput> = {},
  admissionOverrides: Partial<AdmissionInput> = {},
): AdmissionInput {
  const allocated = store.allocateChallenge(challenge(challengeOverrides));
  if (allocated.disposition !== "created" && allocated.disposition !== "replayed") {
    throw new Error(`Challenge allocation failed: ${allocated.disposition}`);
  }
  const issued = allocated.challenge;
  const unsigned: AdmissionInput = {
    instanceId: issued.instanceId,
    audience: issued.audience,
    principal: issued.principal,
    jobId: issued.jobId,
    nonce: issued.nonce,
    idempotencyKey: "request-1",
    requestHash: contentHash({ input: "hello" }),
    evidenceMode: "fixture",
    proof: "pending",
    ...admissionOverrides,
  };
  return signAdmission(unsigned);
}

function sign(value: string): string {
  return createHmac("sha256", AUTHENTICATION_KEY).update(value).digest("hex");
}

function signChallenge(input: ChallengeAllocationInput): ChallengeAllocationInput {
  return { ...input, proof: sign(challengeAllocationSigningBytes(input)) };
}

function signAdmission(input: AdmissionInput): AdmissionInput {
  return { ...input, proof: sign(admissionSigningBytes(input)) };
}

function fixtureJobId(sequence: number): string {
  return `01J0000000${sequence.toString().padStart(16, "0")}`;
}

describe("SQLite substrate", () => {
  test("enables required durability pragmas and schema", async () => {
    const path = await databasePath();
    const database = openDatabase(path);
    expect(database.query<{ foreign_keys: bigint }, []>(
      "PRAGMA foreign_keys",
    ).get()?.foreign_keys).toBe(1n);
    expect(database.query<{ synchronous: bigint }, []>(
      "PRAGMA synchronous",
    ).get()?.synchronous).toBe(2n);
    expect(database.query<{ journal_mode: string }, []>(
      "PRAGMA journal_mode",
    ).get()?.journal_mode.toLowerCase()).toBe("wal");
    database.run("CREATE TABLE permission_probe (id INTEGER PRIMARY KEY) STRICT");
    for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
      expect((await stat(candidate)).mode & 0o777).toBe(0o600);
    }
    database.close();
  });

  test("migrates schema v1 state through the durable service and fixture-settlement ledgers", async () => {
    const path = await databasePath();
    const first = openDatabase(path);
    first.run("DROP TABLE fixture_lifecycle_runs");
    first.run("DROP TABLE fixture_commitments");
    first.run("DROP TABLE service_runs");
    first.run("DROP TABLE fixture_settlement_consumptions");
    first.run("DROP TABLE fixture_settlements");
    first.run("DROP TABLE fixture_anchors");
    first.run("PRAGMA user_version = 1");
    first.close();

    const migrated = openDatabase(path);
    expect(migrated.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version).toBe(19n);
    const tables = migrated.query<{ name: string }, []>(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name IN (
        'service_runs', 'fixture_settlements', 'fixture_anchors',
        'fixture_settlement_consumptions', 'fixture_commitments',
        'fixture_lifecycle_runs', 'fixture_deliveries', 'fixture_bundles',
        'fixture_listing_verification_authorities'
      )
      ORDER BY name
    `).all().map(({ name }) => name);
    expect(tables).toEqual([
      "fixture_anchors",
      "fixture_bundles",
      "fixture_commitments",
      "fixture_deliveries",
      "fixture_lifecycle_runs",
      "fixture_listing_verification_authorities",
      "fixture_settlement_consumptions",
      "fixture_settlements",
      "service_runs",
    ]);
    const anchorColumns = migrated.query<{ name: string }, []>(
      "PRAGMA table_info(fixture_anchors)",
    ).all().map(({ name }) => name);
    expect(anchorColumns).toContain("artifact_content_hash");
    migrated.close();
  });

  test("refuses populated v3 fixture state whose required bindings cannot be reconstructed", async () => {
    const settlementPath = await databasePath();
    createFixtureSchemaV3(settlementPath, "settlement");
    expect(() => openDatabase(settlementPath)).toThrow(/payee address is unavailable/);

    const anchorPath = await databasePath();
    createFixtureSchemaV3(anchorPath, "anchor");
    expect(() => openDatabase(anchorPath)).toThrow(/artifact binding is unavailable/);
  });

  test("refuses populated v6 fixture state without an authoritative orchestrator claim", async () => {
    const path = await databasePath();
    const legacy = openDatabase(path);
    legacy.run("ALTER TABLE fixture_settlements DROP COLUMN orchestrator_claim");
    legacy.run(`
      INSERT INTO fixture_settlements (
        tx_hash, job_id, phase_index, agreement_hash, payer_claim, payee_claim,
        payee_address, payment_amount_json, block_number, finality_observed_at, created_at
      ) VALUES (
        '${"a".repeat(64)}', '01J8ME0SXKQ4T9V2RC5HJ6WX7D', 2, '${"b".repeat(64)}',
        'key:${"1".repeat(64)}', 'key:${"2".repeat(64)}', '${"2".repeat(64)}',
        '{"amount":"5","currency":"DEM"}', 42, 1780014401000,
        '2026-07-17T17:40:01.000Z'
      )
    `);
    legacy.run("PRAGMA user_version = 6");
    legacy.close();

    expect(() => openDatabase(path)).toThrow(/orchestrator claim is unavailable/);
  });

  test("refuses an existing unversioned schema before applying migration DDL", async () => {
    const path = await databasePath();
    const existing = new Database(path, { create: true });
    existing.run("CREATE TABLE fixture_anchors (logical_address TEXT PRIMARY KEY) STRICT");
    existing.close();
    await chmod(path, 0o600);
    expect(() => openDatabase(path)).toThrow(/existing unversioned database safely/);
    const unchanged = new Database(path, { readonly: true });
    expect(unchanged.query<{ user_version: number }, []>("PRAGMA user_version").get()?.user_version).toBe(0);
    unchanged.close();
  });

  test("refuses populated schema v10 settlement state without a session binding", async () => {
    const path = await databasePath();
    const legacy = openDatabase(path);
    legacy.run("ALTER TABLE fixture_settlements DROP COLUMN session_binding_hash");
    legacy.run(`
      INSERT INTO fixture_settlements (
        tx_hash, job_id, phase_index, agreement_hash, orchestrator_claim,
        payer_claim, payee_claim, payee_address, payment_amount_json,
        block_number, finality_observed_at, created_at
      ) VALUES (
        '${"a".repeat(64)}', '01J8ME0SXKQ4T9V2RC5HJ6WX7D', 2, '${"b".repeat(64)}',
        'key:${"3".repeat(64)}', 'key:${"1".repeat(64)}', 'key:${"2".repeat(64)}',
        '0x${"2".repeat(64)}', '{"amount":"5","currency":"DEM"}',
        42, 1780014401000, '2026-07-17T17:40:01.000Z'
      );
      PRAGMA user_version = 10;
    `);
    legacy.close();
    expect(() => openDatabase(path)).toThrow(/session binding is unavailable/);
  });

  test("executes the empty v10 delivery migration before accepting new settlement and delivery state", async () => {
    const path = await databasePath();
    const legacy = openDatabase(path);
    legacy.run("DROP INDEX sessions_job_id_unique");
    legacy.run("DROP TABLE fixture_deliveries");
    legacy.run("ALTER TABLE fixture_settlements DROP COLUMN session_binding_hash");
    legacy.run("PRAGMA user_version = 10");
    legacy.close();

    const migrated = openDatabase(path);
    expect(migrated.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version).toBe(19n);
    expect(migrated.query<{ name: string }, []>(
      "PRAGMA table_info(fixture_settlements)",
    ).all().map(({ name }) => name)).toContain("session_binding_hash");
    expect(migrated.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM sqlite_master
      WHERE type = 'table' AND name = 'fixture_deliveries'
    `).get()?.count).toBe(1n);
    expect(migrated.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM sqlite_master
      WHERE type = 'index' AND name = 'sessions_job_id_unique'
    `).get()?.count).toBe(1n);

    migrated.close();
    const fixture = await openDeliveryFixture(path);
    const settlement = new FixtureSettlementLedger(fixture.database, "fixture").record({
      agreementHash: "a".repeat(64),
      blockNumber: 42,
      createdAt: "2026-07-19T08:00:00.000Z",
      finalityObservedAt: Date.parse("2026-07-19T08:00:00.000Z"),
      jobId: fixture.session.jobId,
      orchestrator: fixtureSigner().signer,
      payee: fixtureSigner().signer,
      payeeAddress: `0x${"2".repeat(64)}`,
      payer: `key:${"1".repeat(64)}`,
      paymentAmount: { amount: "1", currency: "DEM" },
      phaseIndex: 2,
      sessionBindingHash: sessionBindingHash(fixture.session),
    });
    expect(settlement.sessionBindingHash).toBe(sessionBindingHash(fixture.session));
    const delivered = fixture.store.deliver(deliveryInput(fixture.session));
    expect(delivered.sessionBindingHash).toBe(sessionBindingHash(fixture.session));
    fixture.database.close();
  });

  test("refuses v10 cross-namespace duplicate jobIds before applying delivery DDL", async () => {
    const path = await databasePath();
    const legacy = openDatabase(path);
    legacy.run("DROP INDEX sessions_job_id_unique");
    legacy.run("DROP TABLE fixture_deliveries");
    legacy.run("ALTER TABLE fixture_settlements DROP COLUMN session_binding_hash");
    legacy.query<never, {
      audience: string;
      fingerprint: string;
      instanceId: string;
      jobId: string;
    }>(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint,
        status, created_at
      ) VALUES (
        $instanceId, $audience, $jobId, 'fixture', $fingerprint,
        'admitted', '2026-07-19T08:00:00.000Z'
      )
    `).run({
      audience: "https://migration-a.example",
      fingerprint: "a".repeat(64),
      instanceId: "migration-a",
      jobId: JOB_ID_1,
    });
    legacy.query<never, {
      audience: string;
      fingerprint: string;
      instanceId: string;
      jobId: string;
    }>(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint,
        status, created_at
      ) VALUES (
        $instanceId, $audience, $jobId, 'fixture', $fingerprint,
        'admitted', '2026-07-19T08:00:00.000Z'
      )
    `).run({
      audience: "https://migration-b.example",
      fingerprint: "b".repeat(64),
      instanceId: "migration-b",
      jobId: JOB_ID_1,
    });
    legacy.run("PRAGMA user_version = 10");
    legacy.close();

    expect(() => openDatabase(path)).toThrow(/cross-namespace duplicate jobId/);
    const unchanged = new Database(path, { safeIntegers: true, strict: true });
    expect(unchanged.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version).toBe(10n);
    expect(unchanged.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM sqlite_master
      WHERE type = 'table' AND name = 'fixture_deliveries'
    `).get()?.count).toBe(0n);
    unchanged.close();
  });

  test("migrates empty schema v8 but refuses lifecycle rows missing pause-deadline semantics", async () => {
    const emptyPath = await databasePath();
    const empty = openDatabase(emptyPath);
    empty.run("PRAGMA user_version = 8");
    empty.close();
    const migrated = openDatabase(emptyPath);
    expect(migrated.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version).toBe(19n);
    migrated.close();

    const populatedPath = await databasePath();
    const populated = openDatabase(populatedPath);
    populated.run(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint,
        status, created_at
      ) VALUES (
        'migration-instance', 'https://migration.example',
        '01J8ME0SXKQ4T9V2RC5HJ6WX7D', 'fixture', '${"a".repeat(64)}',
        'admitted', '2026-07-18T00:00:00.000Z'
      );
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, created_at, updated_at
      ) VALUES (
        'migration-instance', 'https://migration.example',
        '01J8ME0SXKQ4T9V2RC5HJ6WX7D', '${"b".repeat(64)}', '${"c".repeat(64)}',
        '[{"phaseIndex":2,"phaseKind":"pay-x402"}]', 3,
        'deliver-attested-payload', 'commit-pending',
        '2026-07-18T00:00:00.000Z', '2026-07-18T00:00:00.000Z'
      );
      PRAGMA user_version = 8;
    `);
    populated.close();
    expect(() => openDatabase(populatedPath)).toThrow(/pause deadlines are unavailable/);
  });

  test("migrates the v9 expired substrate state to the normative terminal state", async () => {
    const path = await databasePath();
    const legacy = openDatabase(path);
    const currentSchema = legacy.query<{ sql: string }, []>(`
      SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'fixture_lifecycle_runs'
    `).get()?.sql;
    if (currentSchema === undefined) throw new Error("Lifecycle schema missing");
    legacy.run("DROP TABLE fixture_lifecycle_runs");
    legacy.run(currentSchema.replaceAll("failed-substrate", "substrate-failure-expired"));
    legacy.run(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint,
        status, created_at
      ) VALUES (
        'migration-instance', 'https://migration.example',
        '01J8ME0SXKQ4T9V2RC5HJ6WX7D', 'fixture', '${"a".repeat(64)}',
        'admitted', '2026-07-18T00:00:00.000Z'
      );
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, failure_stage, error_class, failure_reason, paused_at,
        pause_expires_at, created_at, updated_at, ended_at
      ) VALUES (
        'migration-instance', 'https://migration.example',
        '01J8ME0SXKQ4T9V2RC5HJ6WX7D', '${"b".repeat(64)}', '${"c".repeat(64)}',
        '[{"phaseIndex":2,"phaseKind":"pay-dem"}]', 3,
        'deliver-attested-payload', 'substrate-failure-expired', 'payment',
        'substrate', 'fixture substrate unavailable',
        '2026-07-18T00:00:00.000Z', '2026-07-18T01:00:00.000Z',
        '2026-07-18T00:00:00.000Z', '2026-07-18T01:00:00.000Z',
        '2026-07-18T01:00:00.000Z'
      );
      PRAGMA user_version = 9;
    `);
    legacy.close();

    const migrated = openDatabase(path);
    expect(migrated.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version).toBe(19n);
    expect(migrated.query<{ state: string }, []>(
      "SELECT state FROM fixture_lifecycle_runs",
    ).get()?.state).toBe("failed-substrate");
    expect(migrated.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM sqlite_master
      WHERE type = 'table' AND name = 'fixture_lifecycle_runs_v9'
    `).get()?.count).toBe(0n);
    migrated.close();
  });

  test("rejects non-persistent databases that cannot enable WAL", () => {
    expect(() => openDatabase(":memory:")).toThrow(/filesystem path/);
  });

  test("rejects a database directory accessible by another local user", async () => {
    const path = await databasePath();
    const directory = join(path, "..");
    await chmod(directory, 0o755);
    expect(() => openDatabase(path)).toThrow(/owner-only/);
  });

  test("rejects a symbolic-link component in the database directory chain", async () => {
    const targetPath = await databasePath();
    const linkParent = await mkdtemp(join(tmpdir(), "dacs-template-link-"));
    directories.push(linkParent);
    const linkedDirectory = join(linkParent, "state");
    await symlink(join(targetPath, ".."), linkedDirectory, "dir");

    expect(() => openDatabase(join(linkedDirectory, "state.sqlite"))).toThrow(/symbolic links/);
  });

  test("serializes concurrent first-start schema initialization", async () => {
    const path = await databasePath();
    const script = `
      import { openDatabase } from "./src/substrate/sqlite/database.ts";
      const database = openDatabase(process.argv[1]);
      database.close();
    `;
    const processes = Array.from({ length: 6 }, () => Bun.spawn({
      cmd: [process.execPath, "-e", script, path],
      cwd: import.meta.dir + "/../..",
      stderr: "pipe",
    }));
    const results = await Promise.all(processes.map(async (process) => ({
      exitCode: await process.exited,
      stderr: await new Response(process.stderr).text(),
    })));
    expect(results).toEqual(Array.from({ length: 6 }, () => ({ exitCode: 0, stderr: "" })));
  });

  test("creates a session only from a verifier-issued challenge", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const input = admission(store);
    expect(input.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(store.admit(input).disposition).toBe("created");
    expect(store.count()).toBe(1n);
    expect(store.get(JOB_ID_1)?.requestHash).toBe(input.requestHash);

    expect(store.admit({ ...input, nonce: "0".repeat(32), jobId: fixtureJobId(2) })).toEqual({
      disposition: "rejected",
      reason: "unknown-challenge",
    });
    database.close();
  });

  test("requires authenticated, fresh, fixture-bound challenge allocation", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    expect(store.allocateChallenge({ ...challenge(), proof: "invalid" }).disposition)
      .toBe("rejected");
    expect(store.allocateChallenge(signChallenge({
      ...challenge(),
      evidenceMode: "live",
      proof: "pending",
    })).disposition).toBe("rejected");
    expect(store.allocateChallenge(signChallenge({
      ...challenge(),
      requestedAtMs: START_MS - 60_001,
      proof: "pending",
    })).disposition).toBe("rejected");
    expect(store.allocateChallenge(signChallenge({
      ...challenge(),
      instanceId: "attacker-instance",
      proof: "pending",
    })).disposition).toBe("rejected");
    expect(store.allocateChallenge(signChallenge({
      ...challenge(),
      audience: "https://attacker.example",
      proof: "pending",
    })).disposition).toBe("rejected");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(0n);
    expect(() => new SessionStore(database, {
      audience: "https://service.example",
      authenticator,
      deploymentMode: "live",
      instanceId: "instance-1",
      jobAuthorizer: { authorize: () => true },
    })).toThrow(/fixture deployment only/);
    expect(() => sessionStore(database, { audience: "https://service.example/\ud800" }))
      .toThrow(/Configured audience/);
    database.close();
  });

  test("fails closed when an authenticator returns a Promise instead of boolean true", async () => {
    const database = openDatabase(await databasePath());
    const asynchronousAuthenticator = {
      verify: () => Promise.resolve(true),
    } as unknown as PrincipalProofAuthenticator;
    const asynchronousStore = sessionStore(database, {
      authenticator: asynchronousAuthenticator,
    });

    expect(asynchronousStore.allocateChallenge(challenge()).disposition).toBe("rejected");

    const validStore = sessionStore(database);
    const input = admission(validStore);
    expect(asynchronousStore.admit(input)).toEqual({
      disposition: "rejected",
      reason: "authentication-failed",
    });
    expect(asynchronousStore.count()).toBe(0n);
    database.close();
  });

  test("propagates challenge-allocation infrastructure failures", async () => {
    const database = openDatabase(await databasePath());
    const invalidClockStore = sessionStore(database, { now: () => -1 });
    expect(() => invalidClockStore.allocateChallenge(challenge())).toThrow(/Clock returned/);

    const authenticationFailureStore = sessionStore(database, {
      authenticator: {
        verify: () => {
          throw new Error("authentication backend unavailable");
        },
      },
    });
    expect(() => authenticationFailureStore.allocateChallenge(challenge()))
      .toThrow("authentication backend unavailable");

    const authorizationFailureStore = sessionStore(database, {
      jobAuthorizer: {
        authorize: () => {
          throw new Error("job registry unavailable");
        },
      },
    });
    expect(() => authorizationFailureStore.allocateChallenge(challenge()))
      .toThrow("job registry unavailable");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("requires synchronous principal-to-job authorization before challenge persistence", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, {
      jobAuthorizer: {
        authorize: ({ jobId, principalIdentity }) =>
          jobId === JOB_ID_1 && principalIdentity.canonicalReference === "did:demos:buyer",
      },
    });

    expect(store.allocateChallenge(challenge()).disposition).toBe("created");
    expect(store.allocateChallenge(challenge({
      principal: "did:demos:seller",
    })).disposition).toBe("rejected");
    expect(store.allocateChallenge(challenge({
      jobId: fixtureJobId(2),
    })).disposition).toBe("rejected");

    const asynchronous = sessionStore(database, {
      jobAuthorizer: {
        authorize: (() => Promise.resolve(true)) as unknown as () => boolean,
      },
    });
    expect(asynchronous.allocateChallenge(challenge({
      jobId: fixtureJobId(2),
    })).disposition).toBe("rejected");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("uses one immutable request snapshot across authentication and persistence", async () => {
    const database = openDatabase(await databasePath());
    const allocationInput = challenge({ jobId: fixtureJobId(10) });
    const allocationStore = sessionStore(database, {
      authenticator: {
        verify: (verification) => {
          const accepted = authenticator.verify(verification);
          (allocationInput as { jobId: string }).jobId = fixtureJobId(11);
          return accepted;
        },
      },
    });
    const allocated = allocationStore.allocateChallenge(allocationInput);
    expect(allocated.disposition).toBe("created");
    if (allocated.disposition !== "created") throw new Error("expected challenge creation");
    expect(allocated.challenge.jobId).toBe(fixtureJobId(10));

    const validStore = sessionStore(database);
    const admissionInput = admission(validStore, { jobId: fixtureJobId(12) });
    const admissionStore = sessionStore(database, {
      authenticator: {
        verify: (verification) => {
          const accepted = authenticator.verify(verification);
          (admissionInput as { jobId: string }).jobId = fixtureJobId(13);
          return accepted;
        },
      },
    });
    const admitted = admissionStore.admit(admissionInput);
    expect(admitted.disposition).toBe("created");
    if (admitted.disposition !== "created") throw new Error("expected session creation");
    expect(admitted.session.jobId).toBe(fixtureJobId(12));
    expect(admissionStore.get(fixtureJobId(13))).toBeNull();
    database.close();
  });

  test("prevents the admission authenticator from substituting the canonical principal", async () => {
    const database = openDatabase(await databasePath());
    const allocationStore = sessionStore(database);
    const input = admission(allocationStore, { jobId: fixtureJobId(15) });
    let mutationRejected = false;
    const admissionStore = sessionStore(database, {
      authenticator: {
        verify: (verification) => {
          try {
            (verification.principal as { identifier: string }).identifier = "seller";
          } catch {
            mutationRejected = true;
          }
          return authenticator.verify(verification);
        },
      },
    });

    expect(admissionStore.admit(input).disposition).toBe("created");
    expect(mutationRejected).toBe(true);
    expect(database.query<{ principalIdentifier: string }, []>(`
      SELECT principal_identifier AS principalIdentifier FROM admission_consumptions
    `).get()?.principalIdentifier).toBe("demos:buyer");
    database.close();
  });

  test("enforces the exact future-skew boundary for challenge allocation", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);

    expect(store.allocateChallenge(challenge({
      requestedAtMs: START_MS + 30_000,
    })).disposition).toBe("created");
    expect(store.allocateChallenge(challenge({
      requestedAtMs: START_MS + 30_001,
    })).disposition).toBe("rejected");

    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("rejects missing or unsigned extra runtime fields without persistence", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    expect(store.admit(null as unknown as AdmissionInput)).toEqual({
      disposition: "rejected",
      reason: "invalid-admission",
    });
    const { jobId: _jobId, ...missing } = challenge();
    expect(store.allocateChallenge(missing as ChallengeAllocationInput).disposition).toBe("rejected");
    expect(store.allocateChallenge({
      ...challenge(),
      unsignedExtra: "not-bound",
    } as ChallengeAllocationInput).disposition).toBe("rejected");

    const { requestHash: _requestHash, ...malformedAdmission } = admission(store);
    expect(store.admit(malformedAdmission as AdmissionInput)).toEqual({
      disposition: "rejected",
      reason: "invalid-admission",
    });
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM sessions",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("rejects ill-formed Unicode and consumes malformed admission attempts", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    expect(store.allocateChallenge({
      ...challenge(),
      clientIdempotencyKey: "\ud800",
      proof: "invalid",
    }).disposition).toBe("rejected");

    const input = admission(store, { jobId: fixtureJobId(19) });
    expect(store.admit({
      ...input,
      idempotencyKey: "\ud800",
      proof: "invalid",
    })).toEqual({ disposition: "rejected", reason: "invalid-admission" });
    expect(store.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("bases challenge expiry on the post-authentication transaction clock", async () => {
    let now = START_MS;
    let authenticationCalls = 0;
    const delayedAuthenticator: PrincipalProofAuthenticator = {
      verify: (input) => {
        authenticationCalls += 1;
        if (authenticationCalls === 1) now += 1_000;
        return authenticator.verify(input);
      },
    };
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, {
      authenticator: delayedAuthenticator,
      now: () => now,
      nonceLifetimeMs: 1_000,
    });
    const input = admission(store, { requestedAtMs: START_MS });
    expect(store.admit(input).disposition).toBe("created");
    database.close();
  });

  test("replays exact challenge allocation, rejects mutation, and bounds outstanding rows", async () => {
    let now = START_MS;
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, { now: () => now, nonceLifetimeMs: 1_000 });
    const request = challenge();
    const first = store.allocateChallenge(request);
    const replay = store.allocateChallenge(request);
    expect(first.disposition).toBe("created");
    expect(replay.disposition).toBe("replayed");
    expect(
      first.disposition === "created" && replay.disposition === "replayed"
        ? replay.challenge.nonce === first.challenge.nonce
        : false,
    ).toBe(true);
    expect(store.allocateChallenge(signChallenge({
      ...request,
      jobId: fixtureJobId(14),
      proof: "pending",
    })).disposition).toBe("conflict");

    for (let index = 0; index < 3; index += 1) {
      expect(store.allocateChallenge(challenge({ jobId: fixtureJobId(20 + index) })).disposition)
        .toBe("created");
    }
    expect(store.allocateChallenge(challenge({ jobId: fixtureJobId(30) })).disposition)
      .toBe("quota-exceeded");

    now += 1_001;
    expect(store.allocateChallenge(challenge({
      jobId: fixtureJobId(31),
      requestedAtMs: now,
    })).disposition).toBe("created");
    database.close();
  });

  test("retains an expired challenge through the allocation-proof replay window", async () => {
    let now = START_MS;
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, { now: () => now, nonceLifetimeMs: 1_000 });
    const request = challenge();
    const first = store.allocateChallenge(request);
    expect(first.disposition).toBe("created");
    now += 1_001;
    const replay = store.allocateChallenge(request);
    expect(replay.disposition).toBe("replayed");
    expect(
      first.disposition === "created" && replay.disposition === "replayed"
        ? replay.challenge.nonce === first.challenge.nonce
        : false,
    ).toBe(true);

    now += 90_000;
    expect(store.allocateChallenge(request).disposition).toBe("rejected");
    expect(store.allocateChallenge(challenge({ requestedAtMs: now })).disposition).toBe("created");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("consumes a challenge when admission authentication fails", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const input = admission(store);
    expect(store.admit({ ...input, proof: "invalid" })).toEqual({
      disposition: "rejected",
      reason: "authentication-failed",
    });
    expect(store.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("rolls back challenge consumption when admission authentication infrastructure fails", async () => {
    const database = openDatabase(await databasePath());
    const allocationStore = sessionStore(database);
    const input = admission(allocationStore, { jobId: fixtureJobId(18) });
    const failingStore = sessionStore(database, {
      authenticator: {
        verify: () => {
          throw new Error("authentication backend unavailable");
        },
      },
    });

    expect(() => failingStore.admit(input)).toThrow("authentication backend unavailable");
    expect(allocationStore.admit(input).disposition).toBe("created");
    database.close();
  });

  test("a differently configured store cannot consume another deployment's challenge", async () => {
    const database = openDatabase(await databasePath());
    const storeA = sessionStore(database);
    const input = admission(storeA);
    const storeB = new SessionStore(database, {
      audience: "https://other.example",
      authenticator,
      deploymentMode: "fixture",
      instanceId: "instance-2",
      jobAuthorizer: { authorize: () => true },
      now: () => START_MS,
    });
    expect(storeB.admit(input)).toEqual({
      disposition: "rejected",
      reason: "challenge-binding-mismatch",
    });
    expect(storeB.admit(signAdmission({
      ...input,
      audience: "https://other.example",
      instanceId: "instance-2",
    }))).toEqual({
      disposition: "rejected",
      reason: "unknown-challenge",
    });
    expect(storeA.admit(input).disposition).toBe("created");
    database.close();
  });

  test("refuses the same jobId across deployment namespaces", async () => {
    const database = openDatabase(await databasePath());
    const storeA = sessionStore(database);
    const storeB = sessionStore(database, {
      audience: "https://other.example",
      instanceId: "instance-2",
    });
    const inputA = admission(storeA, { jobId: fixtureJobId(19) });
    const inputB = admission(storeB, {
      audience: "https://other.example",
      instanceId: "instance-2",
      jobId: fixtureJobId(19),
    }, { idempotencyKey: "request-2" });
    expect(storeA.admit(inputA).disposition).toBe("created");
    expect(storeB.admit(inputB)).toEqual({
      disposition: "conflict",
      existingJobId: fixtureJobId(19),
    });
    expect(database.query<{ count: bigint }, { jobId: string }>(
      "SELECT count(*) AS count FROM sessions WHERE job_id = $jobId",
    ).get({ jobId: fixtureJobId(19) })?.count).toBe(1n);
    database.close();
  });

  test("does not clean another deployment's challenges with a different clock", async () => {
    const database = openDatabase(await databasePath());
    const storeA = sessionStore(database);
    const inputA = admission(storeA, { jobId: fixtureJobId(16) });
    const laterMs = START_MS + 10 * 60_000;
    const storeB = sessionStore(database, {
      audience: "https://other.example",
      instanceId: "instance-2",
      now: () => laterMs,
    });

    expect(storeB.allocateChallenge(challenge({
      audience: "https://other.example",
      instanceId: "instance-2",
      jobId: fixtureJobId(17),
      requestedAtMs: laterMs,
    })).disposition).toBe("created");
    expect(storeA.admit(inputA).disposition).toBe("created");
    database.close();
  });

  test("consumes and rejects principal substitution against an issued challenge", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const input = admission(store);
    const substituted = signAdmission({
      ...input,
      principal: "did:demos:seller",
    });

    expect(store.admit(substituted)).toEqual({
      disposition: "rejected",
      reason: "challenge-binding-mismatch",
    });
    expect(store.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("isolates globally distinct job sessions between deployments sharing a database", async () => {
    const database = openDatabase(await databasePath());
    const storeA = sessionStore(database);
    const storeB = sessionStore(database, {
      audience: "https://other.example",
      instanceId: "instance-2",
    });

    expect(storeA.admit(admission(storeA)).disposition).toBe("created");
    expect(storeB.admit(admission(storeB, {
      audience: "https://other.example",
      instanceId: "instance-2",
      jobId: fixtureJobId(20),
    })).disposition).toBe("created");

    expect(storeA.count()).toBe(1n);
    expect(storeB.count()).toBe(1n);
    expect(storeA.get(JOB_ID_1)?.admissionFingerprint)
      .not.toBe(storeB.get(fixtureJobId(20))?.admissionFingerprint);
    database.close();
  });

  test("cleans rejected consumed challenges after their replay window", async () => {
    let now = START_MS;
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, { now: () => now, nonceLifetimeMs: 1_000 });
    const input = admission(store);
    expect(store.admit({ ...input, proof: "invalid" }).disposition).toBe("rejected");
    now += 90_001;
    expect(store.allocateChallenge(challenge({ requestedAtMs: now })).disposition).toBe("created");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("consumes a challenge before rejecting invalid or mismatched presentations", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const invalid = admission(store, { jobId: fixtureJobId(40) }, { requestHash: "bad" });
    expect(store.admit(invalid)).toEqual({ disposition: "rejected", reason: "invalid-admission" });
    expect(store.admit({ ...invalid, requestHash: contentHash({ input: "hello" }) })).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });

    const invalidMode = admission(store, { jobId: fixtureJobId(41) }, {
      evidenceMode: "staging" as AdmissionInput["evidenceMode"],
    });
    expect(store.admit(invalidMode)).toEqual({
      disposition: "rejected",
      reason: "invalid-admission",
    });
    expect(store.admit({ ...invalidMode, evidenceMode: "fixture" })).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });

    const mismatched = admission(
      store,
      { jobId: fixtureJobId(42) },
      { jobId: fixtureJobId(43) },
    );
    expect(store.admit(mismatched)).toEqual({
      disposition: "rejected",
      reason: "challenge-binding-mismatch",
    });
    expect(store.admit({ ...mismatched, jobId: fixtureJobId(42) })).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    expect(store.count()).toBe(0n);
    database.close();
  });

  test("rejects expired challenges and keeps them consumed", async () => {
    let now = START_MS;
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, { now: () => now, nonceLifetimeMs: 1_000 });
    const input = admission(store);
    now += 1_000;
    expect(store.admit(input)).toEqual({ disposition: "rejected", reason: "expired-challenge" });
    now -= 1;
    expect(store.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("consumes and rejects a challenge if the wall clock moves backward", async () => {
    let now = START_MS;
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, { now: () => now });
    const input = admission(store);
    now -= 1;
    expect(store.admit(input)).toEqual({ disposition: "rejected", reason: "clock-regression" });
    now = START_MS;
    expect(store.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("consumed nonce cannot enter verification twice", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const input = admission(store);
    expect(store.admit(input).disposition).toBe("created");
    expect(store.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    expect(store.admit({ ...input, jobId: fixtureJobId(44) })).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("returns a structured conflict when another challenge already created the job", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const first = admission(store);
    const second = admission(store, {}, { idempotencyKey: "request-2" });
    expect(store.admit(first).disposition).toBe("created");
    expect(store.admit(second)).toEqual({ disposition: "conflict", existingJobId: JOB_ID_1 });
    expect(store.admit(second)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    database.close();
  });

  test("allows deployment-configured nonce lifetimes above the five-minute default", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database, {
      nonceLifetimeMs: 3 * 60 * 60 * 1_000,
    });
    const allocated = store.allocateChallenge(challenge());
    expect(allocated.disposition).toBe("created");
    expect(
      allocated.disposition === "created"
        ? allocated.challenge.expiresAtMs - allocated.challenge.issuedAtMs
        : 0,
    ).toBe(10_800_000);
    database.close();
  });

  test("same canonical principal and idempotency key cannot authorize a second request", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    expect(store.admit(admission(store)).disposition).toBe("created");

    const second = admission(
      store,
      { jobId: fixtureJobId(2), principal: "DID:demos:buyer?jurisdiction=DE" },
      { requestHash: contentHash({ input: "changed" }) },
    );
    expect(store.admit(second)).toEqual({ disposition: "conflict", existingJobId: JOB_ID_1 });
    expect(store.count()).toBe(1n);
    database.close();
  });

  test("normalizes principal ClaimReferences but rejects other non-canonical bindings", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const normalized = store.allocateChallenge(challenge({ principal: "cci-ethos:e\u0301" }));
    expect(normalized.disposition).toBe("created");
    if (normalized.disposition !== "created") throw new Error("expected challenge creation");
    expect(normalized.challenge.principal).toBe("cci-ethos:é");
    expect(store.allocateChallenge({ ...challenge(), jobId: "job-e\u0301" }).disposition)
      .toBe("rejected");
    expect(store.count()).toBe(0n);
    database.close();
  });

  test("propagates database failures instead of reporting invalid admission", async () => {
    const database = openDatabase(await databasePath());
    const store = sessionStore(database);
    const input = admission(store);
    database.close();

    expect(() => store.admit(input)).toThrow();
  });

  test("rejects short entropy and repeated nonce collisions", async () => {
    const database = openDatabase(await databasePath());
    const short = sessionStore(database, {
      randomBytes: () => new Uint8Array(15),
    });
    expect(() => short.allocateChallenge(challenge())).toThrow(/exactly 16 bytes/);

    const repeated = sessionStore(database, {
      randomBytes: () => new Uint8Array(16),
    });
    expect(repeated.allocateChallenge(challenge()).disposition).toBe("created");
    expect(() => repeated.allocateChallenge(challenge({ jobId: fixtureJobId(2) })))
      .toThrow(/collisions/);
    database.close();
  });

  test("issued and consumed challenge state survives restart", async () => {
    const path = await databasePath();
    const firstDatabase = openDatabase(path);
    const firstStore = sessionStore(firstDatabase);
    const input = admission(firstStore);
    firstDatabase.close();

    const secondDatabase = openDatabase(path);
    const secondStore = sessionStore(secondDatabase);
    expect(secondStore.admit(input).disposition).toBe("created");
    secondDatabase.close();

    const thirdDatabase = openDatabase(path);
    const thirdStore = sessionStore(thirdDatabase);
    expect(thirdStore.admit(input)).toEqual({
      disposition: "rejected",
      reason: "consumed-challenge",
    });
    expect(thirdStore.get(JOB_ID_1)?.version).toBe(0n);
    thirdDatabase.close();
  });

  test("stores immutable canonical artifacts and verifies them after restart", async () => {
    const path = await databasePath();
    const firstDatabase = openDatabase(path);
    const firstStore = new ArtifactStore(firstDatabase);
    const artifact = firstStore.put("work-product", { b: "e\u0301", a: 1 }, "2026-07-16T18:00:00.000Z");
    expect(firstStore.put("work-product", { a: 1, b: "é" }, "2026-07-16T18:01:00.000Z").contentHash)
      .toBe(artifact.contentHash);
    firstDatabase.close();

    const secondDatabase = openDatabase(path);
    expect(new ArtifactStore(secondDatabase).get(artifact.contentHash)?.canonicalJson)
      .toBe('{"a":1,"b":"é"}');
    secondDatabase.close();
  });

  test("associates identical content with multiple artifact kinds", async () => {
    const database = openDatabase(await databasePath());
    const store = new ArtifactStore(database);
    const first = store.put("request", { value: 1 }, "2026-07-16T18:00:00.000Z");
    const second = store.put("receipt", { value: 1 }, "2026-07-16T18:01:00.000Z");
    expect(second.contentHash).toBe(first.contentHash);
    expect(second.kinds).toEqual(["receipt", "request"]);
    database.close();
  });

  test("detects stored artifact corruption", async () => {
    const database = openDatabase(await databasePath());
    const store = new ArtifactStore(database);
    const artifact = store.put("work-product", { a: 1 }, "2026-07-16T18:00:00.000Z");
    database.query<never, { hash: string }>(
      "UPDATE artifacts SET canonical_json = '{\"a\":2}' WHERE content_hash = $hash",
    ).run({ hash: artifact.contentHash });
    expect(() => store.get(artifact.contentHash)).toThrow(ArtifactIntegrityError);
    database.close();
  });
});

function createFixtureSchemaV3(path: string, populated: "settlement" | "anchor"): void {
  const database = new Database(path, { create: true, strict: true });
  database.run(`
    CREATE TABLE fixture_settlements (
      tx_hash TEXT PRIMARY KEY NOT NULL,
      job_id TEXT NOT NULL,
      phase_index INTEGER NOT NULL,
      agreement_hash TEXT NOT NULL,
      payer_claim TEXT NOT NULL,
      payee_claim TEXT NOT NULL,
      payment_amount_json TEXT NOT NULL,
      block_number INTEGER NOT NULL,
      finality_observed_at INTEGER NOT NULL,
      created_at TEXT NOT NULL
    ) STRICT;
    CREATE TABLE fixture_anchors (
      logical_address TEXT PRIMARY KEY NOT NULL,
      artifact_kind TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    ) STRICT;
    PRAGMA user_version = 3;
  `);
  if (populated === "settlement") {
    database.run(`
      INSERT INTO fixture_settlements VALUES (
        '${"a".repeat(64)}', '01J8ME0SXKQ4T9V2RC5HJ6WX7D', 2, '${"b".repeat(64)}',
        'key:${"1".repeat(64)}', 'key:${"2".repeat(64)}', '{"amount":"5","currency":"DEM"}',
        42, 1780014401000, '2026-07-17T17:40:01.000Z'
      )
    `);
  } else {
    database.run(`
      INSERT INTO fixture_anchors VALUES (
        'dacs4:payment:fixture', 'dacs-4-evidence', '${"c".repeat(64)}',
        '2026-07-17T17:40:01.000Z'
      )
    `);
  }
  database.close();
}

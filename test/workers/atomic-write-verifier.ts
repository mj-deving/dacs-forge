import { Database } from "bun:sqlite";
import { FixtureLifecycleOrchestrator } from "../../src/lifecycle/fixture-orchestrator.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { FixtureBundleStore } from "../../src/substrate/sqlite/fixture-bundle.ts";
import { FixtureAuthorityStore } from "../../src/substrate/sqlite/fixture-authority-store.ts";
import { FixtureCommitmentStore } from "../../src/substrate/sqlite/fixture-commitment.ts";
import { FixtureDeliveryStore } from "../../src/substrate/sqlite/fixture-delivery.ts";
import {
  FixtureAnchorStore,
  FixtureFailureEvidenceStore,
  FixtureSettlementLedger,
} from "../../src/substrate/sqlite/fixture-settlement.ts";
import { FixtureVetStore } from "../../src/substrate/sqlite/fixture-vet.ts";
import { readPersistedSessionByJobId, type SessionRecord } from "../../src/substrate/sqlite/session-store.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import { BASIC_FIXTURE } from "../../service/fixtures/basic.ts";
import {
  atomicExactLogicalSnapshotHash,
  atomicExactLogicalTableHashes,
  atomicLogicalSnapshotHash,
  atomicLogicalTableHashes,
  atomicSchemaContractHash,
  atomicSchemaSnapshotHash,
} from "../fixtures/atomic-logical-snapshot.ts";

const path = process.argv[2];
if (path === undefined) throw new Error("Atomic-write verifier requires a database path");
const target = process.argv[3];
const DETACHED_JOB_DEPENDENCIES = Object.freeze([
  { column: "job_id", table: "admission_challenges" },
  { column: "session_id", table: "admission_consumptions" },
  { column: "job_id", table: "fixture_bundles" },
  { column: "job_id", table: "fixture_commitments" },
  { column: "job_id", table: "fixture_deliveries" },
  { column: "job_id", table: "fixture_failure_evidence" },
  { column: "job_id", table: "fixture_lifecycle_runs" },
  { column: "job_id", table: "fixture_listing_verification_authorities" },
  { column: "job_id", table: "fixture_settlement_consumptions" },
  { column: "job_id", table: "fixture_settlements" },
  { column: "job_id", table: "fixture_vet_records" },
]);

const raw = new Database(path, { safeIntegers: true });
const preOpen = {
  exactSnapshotHash: atomicExactLogicalSnapshotHash(raw),
  exactTableHashes: atomicExactLogicalTableHashes(raw),
  snapshotHash: atomicLogicalSnapshotHash(raw),
  tableHashes: atomicLogicalTableHashes(raw),
  schemaContractHash: atomicSchemaContractHash(raw),
  schemaHash: atomicSchemaSnapshotHash(raw),
  schemaVersion: Number(raw.query<{ user_version: bigint }, []>("PRAGMA user_version").get()?.user_version ?? 0n),
  tableCount: Number(raw.query<{ count: bigint }, []>(`
    SELECT count(*) AS count FROM sqlite_schema
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
  `).get()?.count ?? 0n),
};
raw.close();
const database = openDatabase(path);
try {
  const integrity = database.query<{ integrity_check: string }, []>("PRAGMA integrity_check").all();
  if (integrity.length !== 1 || integrity[0]?.integrity_check !== "ok") {
    throw new Error(`SQLite integrity check failed: ${JSON.stringify(integrity)}`);
  }
  const foreignKeyFailures = database.query<Record<string, unknown>, []>("PRAGMA foreign_key_check").all();
  if (foreignKeyFailures.length !== 0) {
    throw new Error(`SQLite foreign-key check failed: ${JSON.stringify(foreignKeyFailures)}`);
  }

  const ownerChecks: string[] = [];
  verifyArtifacts(ownerChecks);
  const sessions = verifySessions(ownerChecks);
  verifyServiceRuns(ownerChecks);
  const commitments = commitmentStore();
  verifyCommitments(commitments, ownerChecks);
  verifyAuthorities(ownerChecks);
  const vetAnchors = verifyVet(sessions, ownerChecks);
  verifyFailureEvidence(ownerChecks);
  verifySettlements(ownerChecks);
  const deliveryAnchors = verifyDeliveries(sessions, ownerChecks);
  const bundleAnchors = verifyBundles(commitments, ownerChecks);
  verifyAnchors(vetAnchors, deliveryAnchors, bundleAnchors, ownerChecks);
  verifyLifecycles(sessions, commitments, ownerChecks);

  process.stdout.write(`${JSON.stringify({
    kind: "atomic-write-verification",
    preOpen,
    exactSnapshotHash: atomicExactLogicalSnapshotHash(database),
    exactTableHashes: atomicExactLogicalTableHashes(database),
    schemaContractHash: atomicSchemaContractHash(database),
    schemaHash: atomicSchemaSnapshotHash(database),
    snapshotHash: atomicLogicalSnapshotHash(database),
    tableHashes: atomicLogicalTableHashes(database),
    tableCount: tableCount(database),
    ownerChecks: ownerChecks.sort(),
  })}\n`);
} finally {
  database.close();
}

function verifyArtifacts(checks: string[]): void {
  const store = new ArtifactStore(database);
  const rows = database.query<{ contentHash: string }, []>(
    "SELECT content_hash AS contentHash FROM artifacts ORDER BY content_hash",
  ).all();
  for (const { contentHash } of rows) {
    if (store.get(contentHash) === null) throw new Error(`Artifact owner lost ${contentHash}`);
  }
  checks.push(`artifacts:${rows.length}`);
}

function verifySessions(checks: string[]): ReadonlyMap<string, SessionRecord> {
  const sessionRows = database.query<{
    admissionFingerprint: string;
    audience: string;
    createdAt: string;
    evidenceMode: string;
    instanceId: string;
    jobId: string;
    status: string;
  }, []>(
    `SELECT instance_id AS instanceId, audience, job_id AS jobId, evidence_mode AS evidenceMode,
      admission_fingerprint AS admissionFingerprint, status, created_at AS createdAt
    FROM sessions ORDER BY job_id`,
  ).all();
  const sessions = new Map<string, SessionRecord>();
  let detached = 0;
  for (const row of sessionRows) {
    const { jobId } = row;
    const session = readPersistedSessionByJobId(database, jobId);
    if (session === null) {
      if (!isKnownDetachedServiceFixture(row)) {
        throw new Error(`Session owner cannot reopen ${jobId}`);
      }
      assertDetachedDependencyContract();
      const dependentRows = DETACHED_JOB_DEPENDENCIES.reduce((count, { column, table }) =>
        count + (database.query<{ count: bigint }, { jobId: string }>(
          `SELECT count(*) AS count FROM "${table}" WHERE "${column}" = $jobId`,
        ).get({ jobId })?.count ?? 0n), 0n);
      if (dependentRows !== 0n) {
        throw new Error(`Detached service test session ${jobId} owns dependent state`);
      }
      detached += 1;
    } else {
      sessions.set(jobId, session);
    }
  }
  checks.push(`sessions:${sessions.size}`);
  checks.push(`detached-session-fixtures:${detached}`);
  return sessions;
}

function assertDetachedDependencyContract(): void {
  const expected = DETACHED_JOB_DEPENDENCIES.map(({ column, table }) => `${table}.${column}`).sort();
  const tables = database.query<{ name: string }, []>(`
    SELECT name FROM sqlite_schema
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('sessions', 'service_runs')
    ORDER BY name
  `).all();
  const actual = tables.flatMap(({ name }) => database.query<{ name: string }, []>(
    `PRAGMA table_info("${name}")`,
  ).all().filter(({ name: column }) => column === "job_id" || column === "session_id")
    .map(({ name: column }) => `${name}.${column}`)).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Detached-session dependency contract drifted: ${JSON.stringify(actual)}`);
  }
}

function isKnownDetachedServiceFixture(row: {
  readonly admissionFingerprint: string;
  readonly audience: string;
  readonly createdAt: string;
  readonly evidenceMode: string;
  readonly instanceId: string;
  readonly jobId: string;
  readonly status: string;
}): boolean {
  return target?.startsWith("service-run.") === true
    && row.instanceId === "reference-instance"
    && row.audience === "https://service.example"
    && row.jobId === BASIC_FIXTURE.jobId
    && row.evidenceMode === "fixture"
    && row.admissionFingerprint === "0".repeat(64)
    && row.status === "admitted"
    && row.createdAt === BASIC_FIXTURE.producedAt;
}

function verifyServiceRuns(checks: string[]): void {
  const store = new ArtifactStore(database);
  const rows = database.query<{
    audience: string;
    contractHash: string;
    instanceId: string;
    jobId: string;
    outputContentHash: string | null;
    receiptContentHash: string | null;
    requestHash: string;
    status: "completed" | "running";
  }, []>(`
    SELECT instance_id AS instanceId, audience, job_id AS jobId,
      request_hash AS requestHash, contract_hash AS contractHash, status,
      output_content_hash AS outputContentHash, receipt_content_hash AS receiptContentHash
    FROM service_runs ORDER BY job_id
  `).all();
  for (const row of rows) {
    const observed = store.claimServiceRun({
      instanceId: row.instanceId,
      audience: row.audience,
      jobId: row.jobId,
      requestHash: row.requestHash,
      contractHash: row.contractHash,
    }, "verifier", () => { throw new Error("Verifier must not create a service-run claim"); });
    if (row.status === "running" && observed.disposition !== "in-progress") {
      throw new Error(`Service-run owner did not recover running ${row.jobId}`);
    }
    if (row.status === "completed") {
      if (observed.disposition !== "replayed" || row.outputContentHash === null || row.receiptContentHash === null
        || store.get(row.outputContentHash) === null || store.get(row.receiptContentHash) === null) {
        throw new Error(`Service-run owner did not recover completed ${row.jobId}`);
      }
    }
  }
  checks.push(`service-runs:${rows.length}`);
}

function commitmentStore(): FixtureCommitmentStore {
  return new FixtureCommitmentStore(database, {
    anchorTimeMs: () => 0,
    deploymentMode: "fixture",
    now: () => "1970-01-01T00:00:00.000Z",
    preAnchorTimeMs: () => 0,
    signer: fixtureSigner(),
  });
}

function verifyCommitments(store: FixtureCommitmentStore, checks: string[]): void {
  const rows = database.query<{ audience: string; instanceId: string; jobId: string }, []>(`
    SELECT audience, instance_id AS instanceId, job_id AS jobId
    FROM fixture_commitments ORDER BY job_id
  `).all();
  for (const row of rows) {
    if (store.get(row.instanceId, row.audience, row.jobId) === null) {
      throw new Error(`Commitment owner lost ${row.jobId}`);
    }
  }
  checks.push(`commitments:${rows.length}`);
}

function verifyAuthorities(checks: string[]): void {
  const store = new FixtureAuthorityStore(database);
  const listings = database.query<{
    contentHash: string; listingId: string; version: bigint;
  }, []>(`
    SELECT listing_id AS listingId, listing_version AS version,
      listing_content_hash AS contentHash
    FROM fixture_listing_authorities
    ORDER BY listing_id, listing_version
  `).all();
  const listingKeys = new Set(listings.map(({ listingId, version }) => `${listingId}:${version}`));
  const resolvedListingKeys = new Set<string>();
  const verifications = database.query<{
    contentHash: string; jobId: string; listingId: string; version: bigint;
  }, []>(`
    SELECT job_id AS jobId, listing_id AS listingId, listing_version AS version,
      listing_content_hash AS contentHash
    FROM fixture_listing_verification_authorities
    ORDER BY job_id
  `).all();
  for (const row of verifications) {
    const version = Number(row.version);
    const key = `${row.listingId}:${row.version}`;
    if (!Number.isSafeInteger(version) || !listingKeys.has(key)
      || store.resolveListing(row.jobId, {
        listingId: row.listingId,
        version,
        contentHash: row.contentHash,
      }).status !== "verified") {
      throw new Error(`Listing authority owner cannot reopen ${row.jobId}`);
    }
    resolvedListingKeys.add(key);
  }
  if (resolvedListingKeys.size !== listingKeys.size) {
    throw new Error("Listing authority owner found an authority without a verification binding");
  }

  const identities = database.query<{ bundleHash: string }, []>(`
    SELECT bundle_hash AS bundleHash FROM fixture_identity_authorities ORDER BY bundle_hash
  `).all();
  for (const { bundleHash } of identities) {
    if (store.resolveIdentity(bundleHash).status !== "verified") {
      throw new Error(`Identity authority owner cannot reopen ${bundleHash}`);
    }
  }
  checks.push(`listing-authorities:${listings.length}`);
  checks.push(`listing-verification-authorities:${verifications.length}`);
  checks.push(`identity-authorities:${identities.length}`);
}

function verifyVet(sessions: ReadonlyMap<string, SessionRecord>, checks: string[]): ReadonlySet<string> {
  const store = new FixtureVetStore(database, "fixture");
  const anchors = new Set<string>();
  const rows = database.query<{ evaluatedRole: "buyer" | "seller"; jobId: string }, []>(`
    SELECT evaluated_role AS evaluatedRole, job_id AS jobId
    FROM fixture_vet_records ORDER BY job_id, evaluated_role
  `).all();
  for (const row of rows) {
    const session = sessions.get(row.jobId);
    const record = session === undefined ? null : store.get(session, row.evaluatedRole);
    if (record === null) {
      throw new Error(`Vet owner lost ${row.jobId}/${row.evaluatedRole}`);
    }
    anchors.add(record.requirementSourceAddress);
    anchors.add(record.assertionAddress);
    anchors.add(record.verifyResultAddress);
    anchors.add(record.compositeAddress);
  }
  checks.push(`vet:${rows.length}`);
  return anchors;
}

function verifySettlements(checks: string[]): void {
  const store = new FixtureSettlementLedger(database, "fixture");
  const rows = database.query<{ txHash: string }, []>(
    "SELECT tx_hash AS txHash FROM fixture_settlements ORDER BY tx_hash",
  ).all();
  for (const { txHash } of rows) {
    if (store.get(txHash) === null) throw new Error(`Settlement owner lost ${txHash}`);
  }
  checks.push(`settlements:${rows.length}`);
}

function verifyFailureEvidence(checks: string[]): void {
  const store = new FixtureFailureEvidenceStore(database, "fixture");
  const rows = database.query<{ evidenceHash: string; expectationJson: string }, []>(`
    SELECT evidence_hash AS evidenceHash, expectation_json AS expectationJson
    FROM fixture_failure_evidence ORDER BY evidence_hash
  `).all();
  for (const { evidenceHash, expectationJson } of rows) {
    const expectation = JSON.parse(expectationJson) as Parameters<typeof store.verify>[0];
    const verified = store.verify(expectation);
    if (verified.status !== "verified" || verified.evidenceHash !== evidenceHash) {
      throw new Error(`Failure-evidence owner lost ${evidenceHash}`);
    }
  }
  checks.push(`failure-evidence:${rows.length}`);
}

function verifyAnchors(
  vetAnchors: ReadonlySet<string>,
  deliveryAnchors: ReadonlySet<string>,
  bundleAnchors: ReadonlySet<string>,
  checks: string[],
): void {
  const store = new FixtureAnchorStore(database, "fixture");
  const artifacts = new ArtifactStore(database);
  const rows = database.query<{
    artifactContentHash: string;
    artifactKind: string;
    logicalAddress: string;
  }, []>(
    "SELECT logical_address AS logicalAddress, artifact_kind AS artifactKind, artifact_content_hash AS artifactContentHash FROM fixture_anchors ORDER BY logical_address",
  ).all();
  for (const { artifactContentHash, artifactKind, logicalAddress } of rows) {
    const artifact = artifacts.get(artifactContentHash);
    if (artifact === null || !artifact.kinds.includes(artifactKind)) {
      throw new Error(`Anchor ${logicalAddress} lost its typed artifact`);
    }
    if (artifactKind === "dacs-4-evidence") {
      if (store.get(logicalAddress) === null) throw new Error(`Settlement anchor owner lost ${logicalAddress}`);
    } else if (!vetAnchors.has(logicalAddress)
      && !deliveryAnchors.has(logicalAddress)
      && !bundleAnchors.has(logicalAddress)) {
      throw new Error(`No product owner claimed ${artifactKind} anchor ${logicalAddress}`);
    }
  }
  checks.push(`anchors:${rows.length}`);
}

function verifyDeliveries(sessions: ReadonlyMap<string, SessionRecord>, checks: string[]): ReadonlySet<string> {
  const store = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
  const anchors = new Set<string>();
  const rows = database.query<{ jobId: string }, []>(
    "SELECT job_id AS jobId FROM fixture_deliveries ORDER BY job_id",
  ).all();
  for (const { jobId } of rows) {
    const session = sessions.get(jobId);
    const record = session === undefined ? null : store.get(session);
    if (record === null) throw new Error(`Delivery owner lost ${jobId}`);
    anchors.add(record.assertionAddress);
    anchors.add(record.verifyResultAddress);
    anchors.add(record.deliveryAddress);
    anchors.add(record.evidenceAddress);
  }
  checks.push(`deliveries:${rows.length}`);
  return anchors;
}

function verifyBundles(commitments: FixtureCommitmentStore, checks: string[]): ReadonlySet<string> {
  const store = new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" });
  const anchors = new Set<string>();
  const rows = database.query<{ anchoredByRole: "buyer" | "seller" | "orchestrator"; jobId: string }, []>(
    "SELECT job_id AS jobId, anchored_by_role AS anchoredByRole FROM fixture_bundles ORDER BY job_id, anchored_by_role",
  ).all();
  for (const { anchoredByRole, jobId } of rows) {
    const record = store.get(jobId, anchoredByRole);
    if (record === null) throw new Error(`Bundle owner lost ${jobId}/${anchoredByRole}`);
    anchors.add(record.logicalAddress);
  }
  for (const jobId of new Set(rows.map((row) => row.jobId))) {
    const result = store.verifySession(jobId);
    if (result.disposition === "rejected") throw new Error(`Bundle owner rejected ${jobId}: ${result.reason}`);
  }
  checks.push(`bundles:${rows.length}`);
  return anchors;
}

function verifyLifecycles(
  sessions: ReadonlyMap<string, SessionRecord>,
  commitments: FixtureCommitmentStore,
  checks: string[],
): void {
  const sessionStore = { get: (jobId: string) => sessions.get(jobId) ?? null };
  const store = new FixtureLifecycleOrchestrator(database, {
    commitmentStore: commitments,
    delivery: () => { throw new Error("Verifier must not invoke delivery"); },
    now: () => "1970-01-01T00:00:00.000Z",
    payment: () => { throw new Error("Verifier must not invoke payment"); },
    sessionStore,
    settlement: () => { throw new Error("Verifier must not invoke settlement"); },
  });
  const rows = database.query<{ jobId: string }, []>(
    "SELECT job_id AS jobId FROM fixture_lifecycle_runs ORDER BY job_id",
  ).all();
  for (const { jobId } of rows) {
    if (store.getRestartBoundary(jobId) === null) {
      throw new Error(`Lifecycle owner lost ${jobId}`);
    }
  }
  checks.push(`lifecycles:${rows.length}`);
}

function tableCount(value: Database): number {
  return Number(value.query<{ count: bigint }, []>(`
    SELECT count(*) AS count FROM sqlite_schema
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
  `).get()?.count ?? 0n);
}

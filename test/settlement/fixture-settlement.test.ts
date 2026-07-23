import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  signSettlementEvidence,
} from "../../src/producer/settlement-evidence.ts";
import { verifyCanonicalSettlementEvidenceJson } from "../../src/consumer/settlement-evidence-verifier.ts";
import {
  FixtureAnchorStore,
  FixtureSettlementConflictError,
  FixtureSettlementLedger,
} from "../../src/substrate/sqlite/fixture-settlement.ts";
import { openDatabase as openPersistentDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  readPersistedSessionByJobId,
  sessionBindingHash,
  type SessionRecord,
} from "../../src/substrate/sqlite/session-store.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

const JOB_ID = "01J8ME0SXKQ4T9V2RC5HJ6WX7D";
const RAIL_ID = "demos-native:DEM";
const PHASE_INDEX = 2;
const AGREEMENT_HASH = "a".repeat(64);
const CREATED_AT = "2026-07-17T17:40:01.000Z";
const SETTLEMENT_SESSION: SessionRecord = Object.freeze({
  instanceId: "fixture-settlement-instance",
  audience: "https://fixture-settlement.example",
  jobId: JOB_ID,
  evidenceMode: "fixture",
  requestHash: "c".repeat(64),
  admissionFingerprint: "d".repeat(64),
  status: "admitted",
  version: 0n,
  createdAt: CREATED_AT,
});
const SESSION_BINDING_HASH = sessionBindingHash(SETTLEMENT_SESSION);
const AMOUNT = Object.freeze({ amount: "5", currency: "DEM" });
const FINALITY_MS = 1_780_014_401_000;
const PAYEE_ADDRESS = `0x${"2".repeat(64)}`;
const ASSET_JSON = canonicalize({ kind: "native-dem", symbol: "DEM", decimals: 9 });
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("fixture no-spend SettlementEvidence lifecycle", () => {
  test("persists, anchors, independently verifies, and replays after restart", async () => {
    const path = await databasePath();
    let database = openDatabase(path);
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const settlementTxIds = [`demos:${transaction.txHash}`];
    const consumption = {
      canonicalSettlementTxIdsJson: canonicalize(settlementTxIds),
      evidenceHash: signed.evidenceHash,
      evidenceMode: "fixture" as const,
      jobId: JOB_ID,
      observedAt: FINALITY_MS,
      phaseIndex: PHASE_INDEX,
    };

    expect(Object.hasOwn(signed.evidence, "phaseIndex")).toBe(false);
    expect(signed.evidence.signature.value).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(signed.logicalAddress).toBe(
      "dacs4:payment:01J8ME0SXKQ4T9V2RC5HJ6WX7D:demos-native%3ADEM:2",
    );
    const anchors = new FixtureAnchorStore(database, "fixture");
    expect(ledger.verifyConsumption(settlementTxIds, consumption)).toMatchObject({
      status: "rejected",
      reason: expect.stringContaining("no authoritative consumption binding"),
    });
    anchors.put(
      signed.logicalAddress,
      "dacs-4-evidence",
      signed.evidenceHash,
      signed.canonicalJson,
      CREATED_AT,
    );
    expect(ledger.verifyConsumption(settlementTxIds, consumption).status).toBe("verified");
    expect(verifyPostAnchor(signed.canonicalJson, ledger, anchors)).toEqual({
      disposition: "verified",
      evidenceHash: signed.evidenceHash,
      logicalAddress: signed.logicalAddress,
      orchestrator: fixtureSigner().signer,
    });
    database.close();

    database = openDatabase(path);
    const restartedLedger = new FixtureSettlementLedger(database, "fixture");
    const restartedAnchors = new FixtureAnchorStore(database, "fixture");
    const replay = restartedLedger.record(settlementInput());
    const restartedEvidence = restartedAnchors.get(signed.logicalAddress);
    expect(replay.txHash).toBe(transaction.txHash);
    expect(restartedEvidence?.canonicalJson).toBe(signed.canonicalJson);
    expect(verifyPostAnchor(restartedEvidence!.canonicalJson, restartedLedger, restartedAnchors).disposition)
      .toBe("verified");
    database.close();
  });

  test("never signs a predicted transaction reference as successful evidence", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    let authoritativeChecks = 0;
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"0".repeat(64)}`, blockNumber: 42 }],
      paymentAmount: AMOUNT,
      settlementFinality: { model: "bft-final", finalityObservedAt: FINALITY_MS },
      observedAt: FINALITY_MS,
    }, fixtureSigner(), {
      agreementHash: AGREEMENT_HASH,
      deploymentMode: "fixture",
      evidenceMode: "fixture",
      expectedFinality: { model: "bft-final" },
      expectedJobId: JOB_ID,
      expectedPaymentAmount: AMOUNT,
      expectedPayee: fixtureSigner().signer,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: `key:${"1".repeat(64)}`,
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: PHASE_INDEX,
      railId: RAIL_ID,
      requestMode: "fixture",
      paymentTransactionCheck: (txRef, expected) => {
        authoritativeChecks += 1;
        return ledger.verifyTransaction(txRef, expected);
      },
      pinnedRail: {
        assetCanonicalJson: ASSET_JSON,
        assetCurrency: "DEM",
        networkKind: "demos",
        phaseHandler: "pay-dem",
        railId: RAIL_ID,
      },
    })).toThrow(/authoritatively absent/);
    expect(authoritativeChecks).toBe(1);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM artifacts").get()!.count)
      .toBe(0n);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_anchors").get()!.count)
      .toBe(0n);
    database.close();
  });

  test("rejects immutable settlement and anchor conflicts", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    expect(() => ledger.record({
      ...settlementInput(),
      orchestrator: "did:demos:fixture-orchestrator",
    })).toThrow(/resolvable Ed25519 key ClaimReference/);
    expect(() => ledger.record({
      ...settlementInput(),
      payeeAddress: "x",
    })).toThrow(/canonical Demos address/);
    expect(() => ledger.record({
      ...settlementInput(),
      paymentAmount: { amount: "5", currency: "USD" },
    })).toThrow(/must be canonical DEM/);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_settlements",
    ).get()!.count).toBe(0n);
    const transaction = ledger.record(settlementInput());
    expect(() => ledger.record({
      ...settlementInput(),
      paymentAmount: { amount: "6", currency: "DEM" },
    })).toThrow(FixtureSettlementConflictError);
    expect(() => ledger.record({
      ...settlementInput(),
      paymentAmount: { amount: "5", currency: "DEM", unit: "" },
    })).toThrow(/must be canonical DEM/);

    const anchors = new FixtureAnchorStore(database, "fixture");
    const firstEvidence = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const conflictingEvidence = signFixtureEvidence(
      ledger,
      transaction.txHash,
      transaction.blockNumber,
      { futureMinorField: "different signed scope" },
      `0x${transaction.txHash}`,
    );
    anchors.put(
      firstEvidence.logicalAddress,
      "dacs-4-evidence",
      firstEvidence.evidenceHash,
      firstEvidence.canonicalJson,
      CREATED_AT,
    );
    const artifactCountBeforeConflict = database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()!.count;
    expect(() => anchors.put(
      `${firstEvidence.logicalAddress}:wrong-hash`,
      "dacs-4-evidence",
      "b".repeat(64),
      firstEvidence.canonicalJson,
      CREATED_AT,
    )).toThrow(/hash does not match/);
    expect(() => anchors.put(
      firstEvidence.logicalAddress,
      "dacs-4-evidence",
      conflictingEvidence.evidenceHash,
      conflictingEvidence.canonicalJson,
      CREATED_AT,
    )).toThrow(FixtureSettlementConflictError);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()!.count).toBe(artifactCountBeforeConflict);
    database.close();
  });

  test("rejects an invalidly signed artifact before anchor or consumption persistence", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const poisoned = JSON.parse(signed.canonicalJson) as {
      signature: { value: string };
    };
    poisoned.signature.value = "A".repeat(86);
    const poisonedJson = canonicalize(poisoned);
    const anchors = new FixtureAnchorStore(database, "fixture");

    expect(() => anchors.put(
      signed.logicalAddress,
      "dacs-4-evidence",
      signed.evidenceHash,
      poisonedJson,
      CREATED_AT,
    )).toThrow(/rejected unverified SettlementEvidence: SettlementEvidence signature is invalid/);
    expect(anchors.get(signed.logicalAddress)).toBeNull();
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM artifacts").get()!.count)
      .toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_settlement_consumptions",
    ).get()!.count).toBe(0n);
    database.close();
  });

  test("rejects oversized evidence before JSON parsing or persistence", async () => {
    const database = openDatabase(await databasePath());
    const anchors = new FixtureAnchorStore(database, "fixture");
    const oversized = `"${"a".repeat(1_048_576)}"`;
    expect(() => anchors.put(
      `dacs4:payment:${JOB_ID}:demos-native%3ADEM:${PHASE_INDEX}`,
      "dacs-4-evidence",
      "a".repeat(64),
      oversized,
      CREATED_AT,
    )).toThrow(/exceeds 1048576 bytes/);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM artifacts").get()!.count)
      .toBe(0n);
    database.close();
  });

  test("anchors evidence when the phase orchestrator differs from the payee", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record({
      ...settlementInput(),
      payee: `key:${"3".repeat(64)}`,
    });
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const anchors = new FixtureAnchorStore(database, "fixture");

    anchors.put(
      signed.logicalAddress,
      "dacs-4-evidence",
      signed.evidenceHash,
      signed.canonicalJson,
      CREATED_AT,
    );
    expect(verifyPostAnchor(signed.canonicalJson, ledger, anchors, transaction.payee).disposition)
      .toBe("verified");
    database.close();
  });

  test("fails closed on amount, transaction, finality, and evidence-mode substitution", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const anchors = new FixtureAnchorStore(database, "fixture");
    anchors.put(
      signed.logicalAddress,
      "dacs-4-evidence",
      signed.evidenceHash,
      signed.canonicalJson,
      CREATED_AT,
    );
    const parsed = JSON.parse(signed.canonicalJson) as Record<string, unknown>;

    const wrongAmount = { ...verificationOptions(ledger), expectedPaymentAmount: { amount: "6", currency: "DEM" } };
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, wrongAmount))
      .toMatchObject({ disposition: "rejected", stage: "amount-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      expectedPayee: `key:${"2".repeat(64)}`,
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      expectedFinality: { model: "block-depth", finalityBlocks: 1 },
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      paymentTransactionCheck: () => {
        throw new Error("fixture RPC unavailable");
      },
    })).toMatchObject({
      disposition: "indeterminate",
      stage: "transaction-binding",
      reason: "Payment transaction verifier failed: fixture RPC unavailable",
    });

    const wrongTx = structuredClone(parsed) as { paymentTxRefs: { txHash: string }[] };
    wrongTx.paymentTxRefs[0]!.txHash = `0x${"b".repeat(64)}`;
    expect(verifyCanonicalSettlementEvidenceJson(canonicalize(wrongTx), verificationOptions(ledger)))
      .toMatchObject({ disposition: "rejected", stage: "signature" });

    const wrongFinality = structuredClone(parsed) as { settlementFinality: { model: string } };
    wrongFinality.settlementFinality.model = "block-depth";
    expect(verifyCanonicalSettlementEvidenceJson(canonicalize(wrongFinality), verificationOptions(ledger)))
      .toMatchObject({ disposition: "rejected", stage: "shape" });

    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      anchorContext: {
        mode: "post-anchor",
        read: () => ({
          status: "resolved",
          artifactContentHash: signed.artifactContentHash,
          artifactKind: "dacs-4-evidence",
          evidenceHash: signed.evidenceHash,
          evidenceMode: "live",
        }),
      },
    })).toMatchObject({ disposition: "rejected", stage: "evidence-mode" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      anchorContext: {
        mode: "post-anchor",
        read: () => ({
          status: "resolved",
          artifactContentHash: signed.artifactContentHash,
          artifactKind: "dacs-5-bundle",
          evidenceHash: signed.evidenceHash,
          evidenceMode: "fixture",
        }),
      },
    })).toMatchObject({ disposition: "rejected", stage: "anchor-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      anchorContext: {
        mode: "post-anchor",
        read: () => ({
          status: "resolved",
          artifactContentHash: "f".repeat(64),
          artifactKind: "dacs-4-evidence",
          evidenceHash: signed.evidenceHash,
          evidenceMode: "fixture",
        }),
      },
    })).toMatchObject({
      disposition: "rejected",
      stage: "anchor-binding",
      reason: expect.stringContaining("exact signed artifact"),
    });
    database.close();
  });

  test("keeps authoritative absence separate from unavailable anchor reads", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      anchorContext: { mode: "post-anchor", read: () => ({ status: "absent" }) },
    })).toMatchObject({ disposition: "rejected", stage: "anchor-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationOptions(ledger),
      anchorContext: {
        mode: "post-anchor",
        read: () => ({ status: "indeterminate", reason: "fixture anchor reader offline" }),
      },
    })).toEqual({
      disposition: "indeterminate",
      stage: "anchor-binding",
      reason: "fixture anchor reader offline",
      evidenceHash: signed.evidenceHash,
    });
    database.close();
  });

  test("keeps settlement-ledger unavailability indeterminate", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    database.close();

    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, verificationOptions(ledger)))
      .toMatchObject({
        disposition: "indeterminate",
        stage: "transaction-binding",
        evidenceHash: signed.evidenceHash,
      });
  });

  test("detects fixture settlement corruption before verification or replay", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    database.query<never, { txHash: string }>(`
      UPDATE fixture_settlements
      SET finality_observed_at = finality_observed_at + 1
      WHERE tx_hash = $txHash
    `).run({ txHash: transaction.txHash });

    expect(() => ledger.get(transaction.txHash)).toThrow(FixtureSettlementConflictError);
    expect(() => ledger.record(settlementInput())).toThrow(FixtureSettlementConflictError);
    expect(ledger.verifyTransaction(
      { kind: "demos", txHash: transaction.txHash, blockNumber: transaction.blockNumber },
      {} as Parameters<FixtureSettlementLedger["verifyTransaction"]>[1],
    )).toMatchObject({
      status: "indeterminate",
      reason: expect.stringContaining("integrity verification"),
    });
    database.close();
  });

  test("rejects transaction consumption replay across evidence, jobs, and phases", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const settlementTxIds = [`demos:${transaction.txHash}`];
    const expected = {
      canonicalSettlementTxIdsJson: canonicalize(settlementTxIds),
      evidenceHash: signed.evidenceHash,
      evidenceMode: "fixture" as const,
      jobId: JOB_ID,
      observedAt: FINALITY_MS,
      phaseIndex: PHASE_INDEX,
    };

    const malformedIds = ["demos:not-a-transaction-hash"];
    expect(ledger.verifyConsumption(malformedIds, {
      ...expected,
      canonicalSettlementTxIdsJson: canonicalize(malformedIds),
    })).toEqual({ status: "rejected", reason: "Fixture settlement consumption input is invalid" });
    expect(ledger.verifyConsumption(settlementTxIds, expected)).toMatchObject({ status: "rejected" });
    const anchors = new FixtureAnchorStore(database, "fixture");
    anchors.put(signed.logicalAddress, "dacs-4-evidence", signed.evidenceHash, signed.canonicalJson, CREATED_AT);
    expect(ledger.verifyConsumption(settlementTxIds, expected).status).toBe("verified");

    const conflicting = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber, {
      futureMinorField: "different evidence",
    });
    const artifactCount = database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()!.count;
    expect(() => anchors.put(
      conflicting.logicalAddress,
      "dacs-4-evidence",
      conflicting.evidenceHash,
      conflicting.canonicalJson,
      CREATED_AT,
    )).toThrow(/different evidence/);
    expect(anchors.get(signed.logicalAddress)?.canonicalJson).toBe(signed.canonicalJson);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()!.count).toBe(artifactCount);
    database.close();
  });

  test("rolls back artifact and consumption when anchor persistence fails", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber);
    const settlementTxIds = [`demos:${transaction.txHash}`];
    const expected = {
      canonicalSettlementTxIdsJson: canonicalize(settlementTxIds),
      evidenceHash: signed.evidenceHash,
      evidenceMode: "fixture" as const,
      jobId: JOB_ID,
      observedAt: FINALITY_MS,
      phaseIndex: PHASE_INDEX,
    };
    database.run(`
      CREATE TRIGGER fixture_anchor_failure
      BEFORE INSERT ON fixture_anchors
      BEGIN
        SELECT RAISE(ABORT, 'forced fixture anchor failure');
      END
    `);

    const anchors = new FixtureAnchorStore(database, "fixture");
    expect(() => anchors.put(
      signed.logicalAddress,
      "dacs-4-evidence",
      signed.evidenceHash,
      signed.canonicalJson,
      CREATED_AT,
    )).toThrow(/forced fixture anchor failure/);
    expect(anchors.get(signed.logicalAddress)).toBeNull();
    expect(ledger.verifyConsumption(settlementTxIds, expected)).toMatchObject({ status: "rejected" });
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM artifacts").get()!.count)
      .toBe(0n);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM artifact_kinds").get()!.count)
      .toBe(0n);
    database.close();
  });

  test("normalizes equivalent Demos transaction-hash spellings", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(
      ledger,
      transaction.txHash,
      transaction.blockNumber,
      {},
      transaction.txHash.toUpperCase(),
    );
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, verificationOptions(ledger)).disposition)
      .toBe("provisionally-verified");
    database.close();
  });

  test("retains unknown signed fields and rejects their mutation", async () => {
    const database = openDatabase(await databasePath());
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const transaction = ledger.record(settlementInput());
    const signed = signFixtureEvidence(ledger, transaction.txHash, transaction.blockNumber, {
      futureMinorField: { commitment: "retained" },
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, verificationOptions(ledger)).disposition)
      .toBe("provisionally-verified");
    const mutated = JSON.parse(signed.canonicalJson) as { futureMinorField: { commitment: string } };
    mutated.futureMinorField.commitment = "mutated";
    expect(verifyCanonicalSettlementEvidenceJson(canonicalize(mutated), verificationOptions(ledger)))
      .toMatchObject({ disposition: "rejected", stage: "signature" });
    database.close();
  });

  test("cannot initialize fixture ledgers in a live deployment", async () => {
    const database = openDatabase(await databasePath());
    expect(() => new FixtureSettlementLedger(database, "live")).toThrow(/fixture/);
    expect(() => new FixtureAnchorStore(database, "local-chain")).toThrow(/fixture/);
    database.close();
  });
});

function settlementInput() {
  return {
    agreementHash: AGREEMENT_HASH,
    blockNumber: 42,
    createdAt: CREATED_AT,
    finalityObservedAt: FINALITY_MS,
    jobId: JOB_ID,
    orchestrator: fixtureSigner().signer,
    payee: fixtureSigner().signer,
    payeeAddress: PAYEE_ADDRESS,
    payer: `key:${"1".repeat(64)}`,
    paymentAmount: AMOUNT,
    phaseIndex: PHASE_INDEX,
    sessionBindingHash: SESSION_BINDING_HASH,
  } as const;
}

function openDatabase(path: string) {
  const database = openPersistentDatabase(path);
  const exists = database.query<{ count: bigint }, { jobId: string }>(
    "SELECT count(*) AS count FROM sessions WHERE job_id = $jobId",
  ).get({ jobId: JOB_ID })?.count ?? 0n;
  if (exists === 0n) {
    const binding = {
      instanceId: SETTLEMENT_SESSION.instanceId,
      audience: SETTLEMENT_SESSION.audience,
      jobId: SETTLEMENT_SESSION.jobId,
      requestHash: SETTLEMENT_SESSION.requestHash,
      admissionFingerprint: SETTLEMENT_SESSION.admissionFingerprint,
      createdAt: SETTLEMENT_SESSION.createdAt,
    };
    database.query<never, Record<string, string | number>>(`
      INSERT INTO sessions (
        instance_id, audience, job_id, evidence_mode, admission_fingerprint,
        status, created_at
      ) VALUES (
        $instanceId, $audience, $jobId, 'fixture', $admissionFingerprint,
        'admitted', $createdAt
      )
    `).run(binding);
    database.query<never, Record<string, string | number>>(`
      INSERT INTO admission_challenges (
        nonce, job_id, instance_id, audience, principal_ref, principal_scheme,
        principal_identifier, evidence_mode, client_nonce, client_idempotency_key,
        allocation_fingerprint, requested_at_ms, issued_at_ms, expires_at_ms,
        retain_until_ms, consumed_at_ms
      ) VALUES (
        '${"1".repeat(32)}', $jobId, $instanceId, $audience,
        'did:demos:fixture-settlement-buyer', 'did',
        'demos:fixture-settlement-buyer', 'fixture', '${"2".repeat(32)}',
        'fixture-settlement', '${"e".repeat(64)}', 1, 1, 2, 3, 1
      )
    `).run(binding);
    database.query<never, Record<string, string | number>>(`
      INSERT INTO admission_consumptions (
        nonce, instance_id, audience, principal_ref, principal_scheme,
        principal_identifier, idempotency_key, request_hash,
        admission_fingerprint, session_id, consumed_at
      ) VALUES (
        '${"1".repeat(32)}', $instanceId, $audience,
        'did:demos:fixture-settlement-buyer', 'did',
        'demos:fixture-settlement-buyer', 'fixture-settlement', $requestHash,
        $admissionFingerprint, $jobId, $createdAt
      )
    `).run(binding);
  }
  const persisted = readPersistedSessionByJobId(database, JOB_ID);
  if (persisted === null || sessionBindingHash(persisted) !== SESSION_BINDING_HASH) {
    throw new Error(`Settlement test session fixture did not round-trip canonically: ${
      persisted === null ? "missing" : sessionBindingHash(persisted)
    } != ${SESSION_BINDING_HASH}`);
  }
  return database;
}

function signFixtureEvidence(
  ledger: FixtureSettlementLedger,
  txHash: string,
  blockNumber: number,
  extensions: Record<string, unknown> = {},
  txHashText = `0x${txHash}`,
) {
  const settlement = ledger.get(txHash);
  if (settlement === null) throw new Error("Fixture settlement must exist before signing evidence");
  return signSettlementEvidence({
    evidenceVersion: "1",
    jobId: settlement.jobId,
    phase: "pay-dem",
    outcome: "success",
    paymentTxRefs: [{ kind: "demos", txHash: txHashText, blockNumber }],
    paymentAmount: JSON.parse(settlement.paymentAmountCanonicalJson),
    settlementFinality: { model: "bft-final", finalityObservedAt: settlement.finalityObservedAt },
    observedAt: settlement.finalityObservedAt,
    ...extensions,
  }, fixtureSigner(), {
    agreementHash: settlement.agreementHash,
    deploymentMode: "fixture",
    evidenceMode: "fixture",
    expectedFinality: { model: "bft-final" },
    expectedJobId: settlement.jobId,
    expectedPaymentAmount: JSON.parse(settlement.paymentAmountCanonicalJson),
    expectedPayee: settlement.payee,
    expectedPayeeAddress: settlement.payeeAddress,
    expectedPayer: settlement.payer,
    expectedSessionBindingHash: settlement.sessionBindingHash,
    phaseIndex: settlement.phaseIndex,
    railId: RAIL_ID,
    requestMode: "fixture",
    paymentTransactionCheck: (txRef, expected) => ledger.verifyTransaction(txRef, expected),
    pinnedRail: {
      assetCanonicalJson: ASSET_JSON,
      assetCurrency: "DEM",
      networkKind: "demos",
      phaseHandler: "pay-dem",
      railId: RAIL_ID,
    },
  });
}

function verificationOptions(ledger: FixtureSettlementLedger) {
  return {
    agreementHash: AGREEMENT_HASH,
    anchorContext: { mode: "pre-anchor" as const },
    evidenceMode: "fixture" as const,
    expectedFinality: { model: "bft-final" },
    expectedJobId: JOB_ID,
    expectedOrchestrator: fixtureSigner().signer,
    expectedPayee: fixtureSigner().signer,
    expectedPayeeAddress: PAYEE_ADDRESS,
    expectedPayer: `key:${"1".repeat(64)}`,
    expectedPaymentAmount: AMOUNT,
    expectedPhase: "pay-dem",
    expectedSessionBindingHash: SESSION_BINDING_HASH,
    phaseIndex: PHASE_INDEX,
    railId: RAIL_ID,
    paymentTransactionCheck: (txRef: Readonly<Record<string, unknown>>, expected: Parameters<FixtureSettlementLedger["verifyTransaction"]>[1]) =>
      ledger.verifyTransaction(txRef, expected),
    settlementConsumptionCheck: (
      settlementTxIds: readonly string[],
      expected: Parameters<FixtureSettlementLedger["verifyConsumption"]>[1],
    ) => ledger.verifyConsumption(settlementTxIds, expected),
    pinnedRail: {
      assetCanonicalJson: ASSET_JSON,
      assetCurrency: "DEM",
      networkKind: "demos" as const,
      phaseHandler: "pay-dem",
      railId: RAIL_ID,
    },
  };
}

function verifyPostAnchor(
  evidenceJson: string,
  ledger: FixtureSettlementLedger,
  anchors: FixtureAnchorStore,
  expectedPayee = fixtureSigner().signer,
) {
  return verifyCanonicalSettlementEvidenceJson(evidenceJson, {
    ...verificationOptions(ledger),
    expectedPayee,
    anchorContext: {
      mode: "post-anchor",
      read: (logicalAddress) => {
        const anchor = anchors.get(logicalAddress);
        return anchor === null
          ? { status: "absent" as const }
          : {
            status: "resolved" as const,
            artifactContentHash: anchor.artifactContentHash,
            artifactKind: anchor.artifactKind,
            evidenceHash: anchor.contentHash,
            evidenceMode: anchor.evidenceMode,
          };
      },
    },
  });
}

async function databasePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-fixture-settlement-"));
  directories.push(directory);
  return join(directory, "state.sqlite");
}

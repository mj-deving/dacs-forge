import type { DacsDatabase } from "../../src/substrate/sqlite/database.ts";
import { FixtureDeliveryStore } from "../../src/substrate/sqlite/fixture-delivery.ts";
import type { SessionRecord } from "../../src/substrate/sqlite/session-store.ts";
import {
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "../lifecycle/fixtures.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import { fixtureUnsignedAgreementHash } from "../fixtures/reference-agreement.ts";

export const DELIVERY_AGREEMENT_HASH = fixtureUnsignedAgreementHash(agreementFixture().input);
export const DELIVERY_CREATED_AT = "2026-07-19T08:00:00.000Z";
export const DELIVERY_OBSERVED_AT = Date.parse(DELIVERY_CREATED_AT);
export const DELIVERY_PAYMENT_AMOUNT = Object.freeze({ amount: "1", currency: "USDC", unit: "job" });
export const DELIVERY_PHASE_INDEX = 3;
export const DELIVERY_PAYLOAD_FORMAT = "application/json";
export const DELIVERY_PAYLOAD_JSON = '{ "answer" : 42, "nested" : { "ok" : true } }';

export interface OpenDeliveryFixture {
  readonly database: DacsDatabase;
  readonly path: string;
  readonly session: SessionRecord;
  readonly store: FixtureDeliveryStore;
}

export async function openDeliveryFixture(path?: string): Promise<OpenDeliveryFixture> {
  const databasePath = path ?? await lifecycleDatabasePath();
  const database = openLifecycleDatabase(databasePath);
  const sessions = lifecycleSessionStore(database);
  const agreement = agreementFixture();
  if (sessions.get(agreement.input.jobId) === null) {
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
  }
  const session = sessions.get(agreement.input.jobId);
  if (session === null) throw new Error("Fixture session was not admitted");
  const commitments = lifecycleCommitmentStore(database);
  let commitment = commitments.get(session.instanceId, session.audience, session.jobId);
  if (commitment === null) {
    const result = commitments.commit({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      session,
      verification: agreement.verification,
    });
    if (result.disposition !== "committed") {
      throw new Error(`Fixture agreement was not committed: ${result.reason}`);
    }
    commitment = result.record;
  }
  const lifecycleCount = database.query<{ count: bigint }, {
    instanceId: string; audience: string; jobId: string;
  }>(`
    SELECT count(*) AS count FROM fixture_lifecycle_runs
    WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
  `).get({
    instanceId: session.instanceId,
    audience: session.audience,
    jobId: session.jobId,
  })?.count ?? 0n;
  if (lifecycleCount === 0n) {
    database.query<never, Record<string, string | number>>(`
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, version, commitment_artifact_hash, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        '[{"phaseIndex":2,"phaseKind":"pay-x402"}]', 3, 'deliver-attested-payload',
        'settle-pending', 2, $commitmentArtifactHash, $createdAt, $createdAt
      )
    `).run({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash: commitment.agreementArtifactHash,
      commitmentArtifactHash: commitment.commitmentArtifactHash,
      createdAt: DELIVERY_CREATED_AT,
    });
  }
  return Object.freeze({
    database,
    path: databasePath,
    session,
    store: new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() }),
  });
}

export function deliveryInput(session: SessionRecord, payloadJson = DELIVERY_PAYLOAD_JSON) {
  return {
    agreementHash: DELIVERY_AGREEMENT_HASH,
    createdAt: DELIVERY_CREATED_AT,
    observedAt: DELIVERY_OBSERVED_AT,
    payloadFormat: DELIVERY_PAYLOAD_FORMAT,
    payloadJson,
    paymentAmount: DELIVERY_PAYMENT_AMOUNT,
    phaseIndex: DELIVERY_PHASE_INDEX,
    session,
  } as const;
}

import { canonicalize, deepFreezeJson } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import { verifyCanonicalAgreementJson } from "../consumer/agreement-verifier.ts";
import type {
  FixtureCommitmentRecord,
  FixtureCommitmentResult,
} from "../substrate/sqlite/fixture-commitment.ts";
import {
  FixtureCommitmentStore,
  MAX_FIXTURE_AGREEMENT_BYTES,
  fixtureCommitmentRequestHash,
  fixtureCommitmentRequestMatches,
  type AgreementCommitVerification,
} from "../substrate/sqlite/fixture-commitment.ts";
import type { DacsDatabase } from "../substrate/sqlite/database.ts";
import type { SessionRecord } from "../substrate/sqlite/session-store.ts";
import { ArtifactStore } from "../substrate/sqlite/artifact-store.ts";
import { assertFixtureSigningAuthority, type ArtifactSigner } from "../producer/fixture-ed25519.ts";
import {
  fixtureLifecycleRestartBoundary,
  type FixtureLifecycleRestartBoundary,
} from "./restart-boundaries.ts";

const MAX_PHASE_RESULT_BYTES = 1_048_576;
const MAX_LISTING_BYTES = 16_384;
const MAX_FAILURE_REASON_CHARS = 4_096;
const DEFAULT_SUBSTRATE_PAUSE_MS = 3_600_000;
const NON_CROSS_CHAIN_PAYMENT_PHASES = new Set([
  "pay-evm-erc20", "pay-solana-spl", "pay-ap2", "pay-x402", "pay-dem",
]);

export type FixtureLifecycleState =
  | "commit-pending" | "commit-completed" | "commit-failed"
  | "settle-pending" | "settle-completed" | "settle-failed" | "settle-unsupported"
  | "substrate-failure-paused" | "failed-substrate" | "aborted" | "finalised";

export type FixtureLifecycleErrorClass =
  | "permanent" | "counterparty" | "transient"
  | "substrate" | "settlement-atomicity";
export type FixtureLifecycleFailureStage = "commit" | "payment" | "settlement" | "delivery";

export interface FixtureLifecyclePhaseBinding {
  readonly phaseIndex: number;
  readonly phaseKind: string;
}

export interface FixtureLifecyclePhaseEvidence extends FixtureLifecyclePhaseBinding {
  readonly authorityClaim?: string;
  readonly value: Readonly<Record<string, unknown>>;
}

export type FixturePhaseResult =
  | {
    readonly ok: true;
    readonly authorityClaim?: string;
    readonly value: Readonly<Record<string, unknown>>;
  }
  | {
    readonly ok: false;
    readonly authorityClaim?: string;
    readonly errorClass: FixtureLifecycleErrorClass;
    readonly reason: string;
    readonly value?: Readonly<Record<string, unknown>>;
  };

export interface FixtureLifecycleAbortInput {
  readonly actorRole: "buyer" | "seller";
  readonly actorSigner: ArtifactSigner;
  readonly jobId: string;
  readonly reason: string;
}

export interface FixtureLifecycleContext extends FixtureLifecyclePhaseBinding {
  readonly agreementHash: string;
  readonly commitment: FixtureCommitmentRecord;
  readonly evidenceMode: "fixture";
  readonly jobId: string;
  readonly payment?: Readonly<Record<string, unknown>>;
  readonly payments: readonly FixtureLifecyclePhaseEvidence[];
  readonly settlements: readonly FixtureLifecyclePhaseEvidence[];
}

export type FixturePhaseHandler = (
  context: FixtureLifecycleContext,
) => FixturePhaseResult | Promise<FixturePhaseResult>;

export interface FixtureLifecycleOrchestratorOptions {
  readonly commitmentStore: FixtureCommitmentStore;
  readonly delivery: FixturePhaseHandler;
  readonly now: () => string;
  readonly payment: FixturePhaseHandler;
  readonly sessionStore: { get(jobId: string): SessionRecord | null };
  readonly settlement: FixturePhaseHandler;
  readonly substratePauseMs?: number;
}

export interface FixtureLifecycleInput {
  readonly agreementCanonicalJson: string;
  readonly jobId: string;
  readonly serviceRequestHash?: string;
  readonly verification: AgreementCommitVerification;
}

export interface FixtureLifecycleInvocationCounts {
  readonly payment: number;
  readonly settlement: number;
  readonly delivery: number;
}

export interface FixtureLifecycleRecovery {
  readonly executorIsolationConfirmed: true;
  readonly expectedBoundaryId: string;
  readonly expectedUpdatedAt: string;
  readonly expectedVersion: number;
  readonly minimumAgeMs: number;
  readonly sideEffectReconciliationConfirmed: true;
}

export type FixtureLifecycleRecoverySnapshot =
  | {
    readonly boundaryId: string;
    readonly state: "commit-pending";
    readonly updatedAt: string;
    readonly version: number;
  }
  | {
    readonly boundaryId: string;
    readonly state: "settle-pending";
    readonly updatedAt: string;
    readonly version: number;
  }
  | {
    readonly boundaryId: string;
    readonly state: "substrate-failure-paused";
    readonly pauseExpiresAt: string;
    readonly updatedAt: string;
    readonly version: number;
  };

interface FixtureLifecycleBaseResult {
  readonly agreementArtifactHash: string;
  readonly commitment?: FixtureCommitmentRecord;
  readonly counts: FixtureLifecycleInvocationCounts;
  readonly jobId: string;
  readonly payments: readonly FixtureLifecyclePhaseEvidence[];
  readonly settlements: readonly FixtureLifecyclePhaseEvidence[];
  readonly terminalEvidence?: FixtureLifecyclePhaseEvidence;
}

export type FixtureLifecycleResult =
  | (FixtureLifecycleBaseResult & {
    readonly state: "commit-failed" | "settle-failed";
    readonly endedAt: string;
    readonly errorClass: Exclude<FixtureLifecycleErrorClass, "substrate" | "settlement-atomicity">;
    readonly failureStage: FixtureLifecycleFailureStage;
    readonly reason: string;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "aborted";
    readonly abortActorRole: "buyer" | "seller";
    readonly abortReason: string;
    readonly commitment: FixtureCommitmentRecord;
    readonly endedAt: string;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "settle-unsupported";
    readonly commitment: FixtureCommitmentRecord;
    readonly endedAt: string;
    readonly errorClass: "settlement-atomicity";
    readonly failureStage: Exclude<FixtureLifecycleFailureStage, "commit">;
    readonly reason: string;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "substrate-failure-paused";
    readonly commitment: FixtureCommitmentRecord;
    readonly errorClass: "substrate";
    readonly failureStage: Exclude<FixtureLifecycleFailureStage, "commit">;
    readonly pausedAt: string;
    readonly pauseExpiresAt: string;
    readonly reason: string;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "failed-substrate";
    readonly commitment: FixtureCommitmentRecord;
    readonly endedAt: string;
    readonly errorClass: "substrate";
    readonly failureStage: Exclude<FixtureLifecycleFailureStage, "commit">;
    readonly pausedAt: string;
    readonly pauseExpiresAt: string;
    readonly reason: string;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "settle-completed";
    readonly commitment: FixtureCommitmentRecord;
    readonly delivery: FixtureLifecyclePhaseEvidence;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "finalised";
    readonly commitment: FixtureCommitmentRecord;
    readonly delivery: FixtureLifecyclePhaseEvidence;
    readonly endedAt: string;
  })
  | (FixtureLifecycleBaseResult & {
    readonly state: "finalised";
    readonly commitment: FixtureCommitmentRecord;
    readonly endedAt: string;
    readonly terminalState: "settle-failed" | "settle-unsupported" | "failed-substrate" | "aborted";
    readonly abortActorRole?: "buyer" | "seller";
    readonly abortReason?: string;
    readonly errorClass?: FixtureLifecycleErrorClass;
    readonly failureStage?: Exclude<FixtureLifecycleFailureStage, "commit">;
    readonly reason?: string;
  });

export class FixtureLifecycleInProgressError extends Error {
  override readonly name = "FixtureLifecycleInProgressError";
}

export class FixtureLifecycleIntegrityError extends Error {
  override readonly name = "FixtureLifecycleIntegrityError";
}

interface LifecycleRow {
  readonly agreementArtifactHash: string;
  readonly audience: string;
  readonly commitmentArtifactHash: string | null;
  readonly createdAt: string;
  readonly deliveryInvocations: bigint;
  readonly deliveryPhaseIndex: bigint;
  readonly deliveryPhaseKind: string;
  readonly deliveryResultJson: string | null;
  readonly terminalResultJson: string | null;
  readonly terminalState: "settle-failed" | "settle-unsupported" | "failed-substrate" | "aborted" | null;
  readonly abortActorRole: "buyer" | "seller" | null;
  readonly abortReason: string | null;
  readonly endedAt: string | null;
  readonly errorClass: FixtureLifecycleErrorClass | null;
  readonly failureReason: string | null;
  readonly failureStage: FixtureLifecycleFailureStage | null;
  readonly instanceId: string;
  readonly jobId: string;
  readonly paymentInvocations: bigint;
  readonly paymentResultJson: string | null;
  readonly pausedAt: string | null;
  readonly pauseExpiresAt: string | null;
  readonly requestHash: string;
  readonly requiredPaymentPhasesJson: string;
  readonly settlementInvocations: bigint;
  readonly settlementResultJson: string | null;
  readonly state: FixtureLifecycleState;
  readonly updatedAt: string;
  readonly version: bigint;
}

interface LifecyclePlan {
  readonly delivery: FixtureLifecyclePhaseBinding;
  readonly payments: readonly FixtureLifecyclePhaseBinding[];
  readonly paymentsCanonicalJson: string;
}

interface FailureWindow {
  readonly pausedAt: string;
  readonly pauseExpiresAt: string;
}

interface LifecycleBinding {
  readonly agreementArtifactHash: string;
  readonly audience: string;
  readonly deliveryPhaseIndex: number;
  readonly deliveryPhaseKind: string;
  readonly instanceId: string;
  readonly jobId: string;
  readonly requestHash: string;
  readonly requiredPaymentPhasesJson: string;
}

interface PreparedLifecycle {
  readonly agreementCanonicalJson: string;
  readonly binding: LifecycleBinding;
  readonly plan: LifecyclePlan;
  readonly serviceRequestHash: string | undefined;
  readonly session: SessionRecord;
}

export class FixtureLifecycleOrchestrator {
  readonly #claim: (binding: LifecycleBinding) => { readonly created: boolean; readonly row: LifecycleRow };
  #clockFloorMs = 0;
  readonly #commitmentStore: FixtureCommitmentStore;
  readonly #database: DacsDatabase;
  readonly #delivery: FixturePhaseHandler;
  readonly #now: () => string;
  readonly #payment: FixturePhaseHandler;
  readonly #sessionStore: FixtureLifecycleOrchestratorOptions["sessionStore"];
  readonly #settlement: FixturePhaseHandler;
  readonly #substratePauseMs: number;

  constructor(database: DacsDatabase, options: FixtureLifecycleOrchestratorOptions) {
    if (typeof options.now !== "function" || typeof options.payment !== "function"
      || typeof options.settlement !== "function" || typeof options.delivery !== "function") {
      throw new TypeError("Fixture lifecycle orchestrator requires clocks and all phase handlers");
    }
    this.#database = database;
    this.#commitmentStore = options.commitmentStore;
    this.#sessionStore = options.sessionStore;
    this.#payment = options.payment;
    this.#settlement = options.settlement;
    this.#delivery = options.delivery;
    this.#now = options.now;
    this.#substratePauseMs = options.substratePauseMs ?? DEFAULT_SUBSTRATE_PAUSE_MS;
    if (!Number.isSafeInteger(this.#substratePauseMs) || this.#substratePauseMs <= 0
      || this.#substratePauseMs > DEFAULT_SUBSTRATE_PAUSE_MS) {
      throw new TypeError(
        `Fixture lifecycle substratePauseMs must be between 1 and ${DEFAULT_SUBSTRATE_PAUSE_MS}`,
      );
    }
    const claim = database.transaction((binding: LifecycleBinding) => this.#claimTransaction(binding));
    this.#claim = (binding) => claim.immediate(binding) as { readonly created: boolean; readonly row: LifecycleRow };
  }

  async run(input: FixtureLifecycleInput): Promise<FixtureLifecycleResult> {
    const { agreementCanonicalJson, binding, plan, session } = this.#prepare(input);
    const claimed = this.#claim(binding);
    if (!claimed.created) {
      const current = this.#expirePausedIfDue(claimed.row);
      if (isReturnableState(current.state)) return this.#result(current);
      throw new FixtureLifecycleInProgressError(
        `Lifecycle is already in progress at ${claimed.row.state}; automatic side-effect replay is forbidden`,
      );
    }

    const committed = this.#commitmentStore.commit({
      agreementCanonicalJson,
      ...(input.serviceRequestHash === undefined
        ? {} : { serviceRequestHash: input.serviceRequestHash }),
      session,
      verification: input.verification,
    });
    if (committed.disposition === "rejected") {
      return this.#result(this.#transitionStop(
        binding,
        "commit-failed",
        "commit",
        "permanent",
        `${committed.stage}: ${committed.reason}`,
        committed.record?.commitmentArtifactHash,
      ));
    }
    try {
      this.#commitmentStore.assertVetAuthority(committed.record);
    } catch (error) {
      return this.#result(this.#transitionStop(
        binding,
        "commit-failed",
        "commit",
        "permanent",
        `Vet authority recheck failed before lifecycle effects: ${message(error)}`,
        committed.record.commitmentArtifactHash,
      ));
    }
    this.#advanceCommitted(binding, committed.record.commitmentArtifactHash);
    return this.#runSettlement(binding, plan, committed.record);
  }

  abort(input: FixtureLifecycleAbortInput): FixtureLifecycleResult {
    assertFixtureSigningAuthority(input.actorSigner, {
      deploymentMode: "fixture",
      requestMode: "fixture",
    });
    const session = this.#sessionStore.get(input.jobId);
    if (session === null || session.status !== "admitted" || session.evidenceMode !== "fixture") {
      throw new FixtureLifecycleIntegrityError("Abort requires an admitted fixture session");
    }
    const row = this.#readBySession(session.instanceId, session.audience, session.jobId);
    if (row === null || row.state !== "settle-pending" || row.commitmentArtifactHash === null) {
      throw new FixtureLifecycleIntegrityError("Abort is permitted only from a committed settle-pending lifecycle");
    }
    const commitment = this.#commitmentStore.get(row.instanceId, row.audience, row.jobId);
    if (commitment === null || commitment.commitmentArtifactHash !== row.commitmentArtifactHash) {
      throw new FixtureLifecycleIntegrityError("Abort lacks the exact committed agreement authority");
    }
    const artifact = new ArtifactStore(this.#database).get(row.agreementArtifactHash);
    if (artifact === null) throw new FixtureLifecycleIntegrityError("Abort agreement artifact is unavailable");
    const agreement = JSON.parse(artifact.canonicalJson) as Record<string, unknown>;
    const parties = agreement["parties"];
    const actor = Array.isArray(parties) ? parties.find((party) => party !== null
      && typeof party === "object" && !Array.isArray(party)
      && (party as Record<string, unknown>)["role"] === input.actorRole) as Record<string, unknown> | undefined : undefined;
    if (actor?.["primaryClaim"] !== input.actorSigner.signer) {
      throw new FixtureLifecycleIntegrityError("Abort signer does not control the claimed agreement role");
    }
    const endedAt = this.#timestamp();
    const reason = normalizeFailureReason(input.reason);
    const updated = this.#database.query<never, Record<string, string | number>>( `
      /* atomic-write: lifecycle.abort */
      UPDATE fixture_lifecycle_runs
      SET state = 'aborted', abort_actor_role = $actorRole, abort_reason = $reason,
        version = version + 1, updated_at = $endedAt, ended_at = $endedAt
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'settle-pending' AND version = $version
    `).run({
      instanceId: row.instanceId,
      audience: row.audience,
      jobId: row.jobId,
      version: lifecycleVersion(row),
      actorRole: input.actorRole,
      reason,
      endedAt,
    });
    if (updated.changes !== 1) throw new FixtureLifecycleIntegrityError("Abort transition raced");
    const aborted = this.#readBySession(row.instanceId, row.audience, row.jobId);
    if (aborted === null) throw new FixtureLifecycleIntegrityError("Aborted lifecycle was not visible");
    return this.#result(aborted);
  }

  async recover(
    input: FixtureLifecycleInput,
    recovery: FixtureLifecycleRecovery,
  ): Promise<FixtureLifecycleResult> {
    validateRecovery(recovery);
    const { agreementCanonicalJson, binding, plan, serviceRequestHash, session } = this.#prepare(input);
    const persisted = this.#read(binding);
    if (persisted === null) throw new FixtureLifecycleIntegrityError("Lifecycle recovery target does not exist");
    const observedAt = this.#timestamp();
    if (persisted.state !== "commit-pending" && persisted.state !== "settle-pending"
      && persisted.state !== "substrate-failure-paused") {
      throw new FixtureLifecycleIntegrityError(`Lifecycle state ${persisted.state} is not recoverable`);
    }
    const persistedBoundary = this.#restartBoundary(persisted);
    assertRecoverableSnapshot(persisted, recovery, observedAt, persistedBoundary.id);
    const row = this.#expirePausedIfDue(persisted, observedAt);
    assertBinding(row, binding);
    if (row.state === "failed-substrate") return this.#result(row);
    let commitment = this.#commitmentStore.get(row.instanceId, row.audience, row.jobId);
    if (row.state === "commit-pending") {
      const committed = this.#claimCommitRecovery(
        binding,
        row,
        recovery,
        observedAt,
        agreementCanonicalJson,
        serviceRequestHash,
        session,
        input.verification,
      );
      if (committed.disposition === "rejected") {
        return this.#result(this.#transitionStop(
          binding,
          "commit-failed",
          "commit",
          "permanent",
          `${committed.stage} recovery: ${committed.reason}`,
          committed.record?.commitmentArtifactHash,
        ));
      }
      commitment = committed.record;
      if (commitment.agreementArtifactHash !== row.agreementArtifactHash) {
        throw new FixtureLifecycleIntegrityError("Recovered commitment does not bind the lifecycle agreement");
      }
      try {
        this.#commitmentStore.assertVetAuthority(commitment);
      } catch (error) {
        return this.#result(this.#transitionStop(
          binding,
          "commit-failed",
          "commit",
          "permanent",
          `Vet authority recovery recheck failed before lifecycle effects: ${message(error)}`,
          commitment.commitmentArtifactHash,
        ));
      }
      const postAnchor = verifyCanonicalAgreementJson(agreementCanonicalJson, {
        ...input.verification,
        expectedJobId: binding.jobId,
        temporalContext: {
          mode: "post-anchor",
          committedAt: commitment.committedAt,
          agreementHash: commitment.agreementHash,
        },
      });
      if (postAnchor.disposition !== "verified") {
        const reason = postAnchor.disposition === "provisionally-verified"
          ? "Agreement verifier returned an unexpected pre-anchor verdict during recovery"
          : `${postAnchor.stage}: ${postAnchor.reason}`;
        return this.#result(this.#transitionStop(
          binding,
          "commit-failed",
          "commit",
          "permanent",
          `post-anchor recovery: ${reason}`,
          commitment.commitmentArtifactHash,
        ));
      }
      this.#advanceCommitted(
        binding,
        commitment.commitmentArtifactHash,
        observedAt,
        recovery.expectedVersion + 1,
      );
    } else if (row.state === "substrate-failure-paused") {
      if (commitment === null || commitment.agreementArtifactHash !== row.agreementArtifactHash) {
        throw new FixtureLifecycleIntegrityError("Paused recovery lacks the exact verified commitment anchor");
      }
      this.#resumePaused(binding, row, recovery, observedAt);
    } else if (row.state === "settle-pending") {
      if (commitment === null || commitment.agreementArtifactHash !== row.agreementArtifactHash) {
        throw new FixtureLifecycleIntegrityError("Settlement recovery lacks the exact verified commitment anchor");
      }
      this.#claimSettlementRecovery(binding, row, recovery, observedAt);
    } else {
      throw new FixtureLifecycleIntegrityError(`Lifecycle state ${row.state} is not recoverable`);
    }
    if (commitment === null) throw new FixtureLifecycleIntegrityError("Recovery did not establish a commitment");
    return this.#runSettlement(binding, plan, commitment);
  }

  expirePaused(jobId: string): FixtureLifecycleResult {
    const session = this.#sessionStore.get(jobId);
    if (session === null) throw new FixtureLifecycleIntegrityError("Paused lifecycle session does not exist");
    const row = this.#readBySession(session.instanceId, session.audience, session.jobId);
    if (row === null || row.state !== "substrate-failure-paused" || row.pauseExpiresAt === null) {
      throw new FixtureLifecycleIntegrityError("Lifecycle is not paused for substrate recovery");
    }
    const endedAt = this.#timestamp();
    if (Date.parse(endedAt) < Date.parse(row.pauseExpiresAt)) {
      throw new FixtureLifecycleIntegrityError("Substrate recovery window has not expired");
    }
    return this.#result(this.#expirePaused(row, endedAt));
  }

  getRecoverySnapshot(jobId: string): FixtureLifecycleRecoverySnapshot | null {
    const session = this.#sessionStore.get(jobId);
    if (session === null) return null;
    const persisted = this.#readBySession(session.instanceId, session.audience, session.jobId);
    if (persisted === null) return null;
    const row = this.#expirePausedIfDue(persisted);
    if (row.state === "commit-pending") {
      const boundary = this.#restartBoundary(row);
      return Object.freeze({
        boundaryId: boundary.id,
        state: "commit-pending",
        updatedAt: row.updatedAt,
        version: lifecycleVersion(row),
      });
    }
    if (row.state === "settle-pending") {
      const boundary = this.#restartBoundary(row);
      return Object.freeze({
        boundaryId: boundary.id,
        state: "settle-pending",
        updatedAt: row.updatedAt,
        version: lifecycleVersion(row),
      });
    }
    if (row.state === "substrate-failure-paused" && row.pauseExpiresAt !== null) {
      const boundary = this.#restartBoundary(row);
      return Object.freeze({
        boundaryId: boundary.id,
        state: "substrate-failure-paused",
        pauseExpiresAt: row.pauseExpiresAt,
        updatedAt: row.updatedAt,
        version: lifecycleVersion(row),
      });
    }
    return null;
  }

  getRestartBoundary(jobId: string): FixtureLifecycleRestartBoundary | null {
    const session = this.#sessionStore.get(jobId);
    if (session === null) return null;
    const persisted = this.#readBySession(session.instanceId, session.audience, session.jobId);
    if (persisted === null) return null;
    return this.#restartBoundary(this.#expirePausedIfDue(persisted));
  }

  get(jobId: string): FixtureLifecycleResult | null {
    const session = this.#sessionStore.get(jobId);
    if (session === null) return null;
    const persisted = this.#readBySession(session.instanceId, session.audience, session.jobId);
    if (persisted === null) return null;
    const row = this.#expirePausedIfDue(persisted);
    if (!isReturnableState(row.state)) {
      throw new FixtureLifecycleInProgressError(`Lifecycle is in progress at ${row.state}`);
    }
    return this.#result(row);
  }

  #prepare(input: FixtureLifecycleInput): PreparedLifecycle {
    const agreementCanonicalJson = snapshotCanonicalJson(
      input.agreementCanonicalJson,
      fixtureAgreementByteLimit(input.verification.maxArtifactBytes),
      "Agreement",
    );
    const agreementArtifactHash = sha256Hex(agreementCanonicalJson);
    const plan = lifecyclePlan(input.verification.listingCanonicalJson);
    const session = this.#sessionStore.get(input.jobId);
    if (session === null || session.status !== "admitted" || session.evidenceMode !== "fixture") {
      throw new FixtureLifecycleIntegrityError("Fixture lifecycle requires an admitted fixture session");
    }
    if (!fixtureCommitmentRequestMatches(
      session.requestHash,
      agreementCanonicalJson,
      input.serviceRequestHash,
    )) {
      throw new FixtureLifecycleIntegrityError("Lifecycle agreement does not match the admitted request hash");
    }
    const binding = Object.freeze({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash,
      requiredPaymentPhasesJson: plan.paymentsCanonicalJson,
      deliveryPhaseIndex: plan.delivery.phaseIndex,
      deliveryPhaseKind: plan.delivery.phaseKind,
    });
    return Object.freeze({
      agreementCanonicalJson,
      binding,
      plan,
      serviceRequestHash: input.serviceRequestHash,
      session,
    });
  }

  #restartBoundary(row: LifecycleRow): FixtureLifecycleRestartBoundary {
    const plan = parseLifecyclePlan(row);
    const payments = parsePhaseEvidenceArray(row.paymentResultJson, "payment");
    const settlements = parsePhaseEvidenceArray(row.settlementResultJson, "settlement");
    const counts = invocationCounts(row);
    if (row.state === "commit-failed" || row.state === "settle-failed"
      || row.state === "settle-unsupported" || row.state === "failed-substrate"
      || row.state === "aborted" || row.state === "settle-completed" || row.state === "finalised") {
      this.#result(row);
    }
    return fixtureLifecycleRestartBoundary({
      commitmentPresent: this.#commitmentStore.get(row.instanceId, row.audience, row.jobId) !== null,
      deliveryInvocations: counts.delivery,
      deliveryResultPresent: row.deliveryResultJson !== null,
      failureStage: row.failureStage,
      paymentInvocations: counts.payment,
      paymentResults: payments.length,
      requiredPaymentCount: plan.payments.length,
      settlementInvocations: counts.settlement,
      settlementResults: settlements.length,
      state: row.state,
      terminalState: row.terminalState,
    });
  }

  async #runSettlement(
    binding: LifecycleBinding,
    plan: LifecyclePlan,
    commitment: FixtureCommitmentRecord,
  ): Promise<FixtureLifecycleResult> {
    const starting = this.#read(binding);
    if (starting === null || starting.state !== "settle-pending"
      || starting.commitmentArtifactHash !== commitment.commitmentArtifactHash) {
      throw new FixtureLifecycleIntegrityError("Settlement continuation lacks its exact pending commitment binding");
    }
    this.#commitmentStore.assertVetAuthority(commitment);
    const payments = [...parsePhaseEvidenceArray(starting.paymentResultJson, "payment")];
    const settlements = [...parsePhaseEvidenceArray(starting.settlementResultJson, "settlement")];
    assertEvidenceOrder(payments, plan.payments, "payment");
    assertEvidenceOrder(settlements, plan.payments, "settlement");
    if (settlements.length > payments.length) {
      throw new FixtureLifecycleIntegrityError("Settlement evidence exists without corresponding payment evidence");
    }
    const baseContext = {
      agreementHash: commitment.agreementHash,
      commitment,
      evidenceMode: "fixture" as const,
      jobId: binding.jobId,
    };

    for (let index = 0; index < plan.payments.length; index += 1) {
      const phase = plan.payments[index]!;
      if (payments.length === index) {
        const failureWindow = this.#markInvocation(binding, "payment", payments.length);
        const payment = await invokePhase(this.#payment, Object.freeze({
          ...baseContext,
          ...phase,
          payments: Object.freeze([...payments]),
          settlements: Object.freeze([...settlements]),
        }));
        if (!payment.ok) return this.#result(this.#stopSettle(binding, phase, "payment", payment, failureWindow));
        const prepared = preparePhaseEvidence(phase, payment.value, payment.authorityClaim, payments, "payment");
        if (prepared.disposition === "rejected") {
          return this.#result(this.#stopSettle(binding, phase, "payment", prepared.failure, failureWindow));
        }
        const evidence = prepared.evidence;
        this.#recordPhaseSuccess(binding, "payment", evidence, payments);
        payments.push(evidence);
      }
      if (payments.length <= index) {
        throw new FixtureLifecycleIntegrityError("Payment continuation did not produce required evidence");
      }
      if (settlements.length === index) {
        const failureWindow = this.#markInvocation(binding, "settlement", settlements.length);
        const settlement = await invokePhase(this.#settlement, Object.freeze({
          ...baseContext,
          ...phase,
          payment: payments[index]!.value,
          payments: Object.freeze([...payments]),
          settlements: Object.freeze([...settlements]),
        }));
        if (!settlement.ok) {
          return this.#result(this.#stopSettle(binding, phase, "settlement", settlement, failureWindow));
        }
        const prepared = preparePhaseEvidence(
          phase,
          settlement.value,
          settlement.authorityClaim,
          settlements,
          "settlement",
        );
        if (prepared.disposition === "rejected") {
          return this.#result(this.#stopSettle(binding, phase, "settlement", prepared.failure, failureWindow));
        }
        const evidence = prepared.evidence;
        this.#recordPhaseSuccess(binding, "settlement", evidence, settlements);
        settlements.push(evidence);
      }
    }

    const failureWindow = this.#markInvocation(binding, "delivery", 0);
    const delivery = await invokePhase(this.#delivery, Object.freeze({
      ...baseContext,
      ...plan.delivery,
      payments: Object.freeze([...payments]),
      settlements: Object.freeze([...settlements]),
    }));
    if (!delivery.ok) return this.#result(this.#stopSettle(binding, plan.delivery, "delivery", delivery, failureWindow));
    const preparedDelivery = preparePhaseEvidence(
      plan.delivery,
      delivery.value,
      delivery.authorityClaim,
      undefined,
      "delivery",
    );
    if (preparedDelivery.disposition === "rejected") {
      return this.#result(this.#stopSettle(binding, plan.delivery, "delivery", preparedDelivery.failure, failureWindow));
    }
    this.#recordDeliverySuccess(binding, preparedDelivery.evidence);
    const completed = this.#read(binding);
    if (completed === null || completed.state !== "settle-completed") {
      throw new FixtureLifecycleIntegrityError("Lifecycle completion was not visible after persistence");
    }
    return this.#result(completed);
  }

  #claimTransaction(binding: LifecycleBinding): { readonly created: boolean; readonly row: LifecycleRow } {
    const existing = this.#read(binding);
    if (existing !== null) {
      assertBinding(existing, binding);
      return Object.freeze({ created: false, row: existing });
    }
    const now = this.#timestamp();
    this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.claim */
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        $requiredPaymentPhasesJson, $deliveryPhaseIndex, $deliveryPhaseKind,
        'commit-pending', $now, $now
      )
    `).run({ ...binding, now });
    const row = this.#read(binding);
    if (row === null) throw new FixtureLifecycleIntegrityError("Lifecycle claim was not visible after persistence");
    return Object.freeze({ created: true, row });
  }

  #claimPendingRecovery(
    binding: LifecycleBinding,
    row: LifecycleRow,
    recovery: FixtureLifecycleRecovery,
    observedAt: string,
  ): void {
    if (row.commitmentArtifactHash !== null) {
      throw new FixtureLifecycleIntegrityError("Commit-pending row already contains a commitment binding");
    }
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.recover-commit-pending */
      UPDATE fixture_lifecycle_runs
      SET version = version + 1, updated_at = $observedAt
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'commit-pending' AND version = $expectedVersion
        AND updated_at = $expectedUpdatedAt
        AND (($expectedBoundaryId = 'commit.before-anchor' AND NOT EXISTS (
          SELECT 1 FROM fixture_commitments AS c
          WHERE c.instance_id = $instanceId AND c.audience = $audience AND c.job_id = $jobId
        )) OR ($expectedBoundaryId = 'commit.after-anchor' AND EXISTS (
          SELECT 1 FROM fixture_commitments AS c
          WHERE c.instance_id = $instanceId AND c.audience = $audience AND c.job_id = $jobId
        )))
    `).run({
      ...binding,
      observedAt,
      expectedBoundaryId: recovery.expectedBoundaryId,
      expectedVersion: recovery.expectedVersion,
      expectedUpdatedAt: recovery.expectedUpdatedAt,
    });
    if (updated.changes !== 1) throw new FixtureLifecycleIntegrityError("Commit recovery snapshot raced");
  }

  #claimCommitRecovery(
    binding: LifecycleBinding,
    row: LifecycleRow,
    recovery: FixtureLifecycleRecovery,
    observedAt: string,
    agreementCanonicalJson: string,
    serviceRequestHash: string | undefined,
    session: SessionRecord,
    verification: AgreementCommitVerification,
  ): FixtureCommitmentResult {
    const claim = this.#database.transaction(() => {
      this.#claimPendingRecovery(binding, row, recovery, observedAt);
      const existing = this.#commitmentStore.get(binding.instanceId, binding.audience, binding.jobId);
      if (existing !== null) return Object.freeze({ disposition: "committed" as const, record: existing });
      return this.#commitmentStore.commit({
        agreementCanonicalJson,
        ...(serviceRequestHash === undefined ? {} : { serviceRequestHash }),
        session,
        verification,
      });
    });
    return claim.immediate() as FixtureCommitmentResult;
  }

  #claimSettlementRecovery(
    binding: LifecycleBinding,
    row: LifecycleRow,
    recovery: FixtureLifecycleRecovery,
    observedAt: string,
  ): void {
    const plan = parseLifecyclePlan(row);
    const payments = parsePhaseEvidenceArray(row.paymentResultJson, "payment");
    const settlements = parsePhaseEvidenceArray(row.settlementResultJson, "settlement");
    const counts = invocationCounts(row);
    assertEvidenceOrder(payments, plan.payments, "payment");
    assertEvidenceOrder(settlements, plan.payments, "settlement");
    if (row.deliveryResultJson !== null || payments.length > plan.payments.length
      || settlements.length > payments.length) {
      throw new FixtureLifecycleIntegrityError("Pending settlement recovery evidence is inconsistent");
    }
    const outstanding: Array<{ readonly column: string; readonly completed: number }> = [];
    if (counts.payment === payments.length + 1) {
      if (payments.length !== settlements.length || payments.length >= plan.payments.length) {
        throw new FixtureLifecycleIntegrityError("Outstanding payment recovery order is invalid");
      }
      outstanding.push({ column: "payment_invocations", completed: payments.length });
    } else if (counts.payment !== payments.length) {
      throw new FixtureLifecycleIntegrityError("Payment recovery count is invalid");
    }
    if (counts.settlement === settlements.length + 1) {
      if (payments.length !== settlements.length + 1) {
        throw new FixtureLifecycleIntegrityError("Outstanding settlement recovery order is invalid");
      }
      outstanding.push({ column: "settlement_invocations", completed: settlements.length });
    } else if (counts.settlement !== settlements.length) {
      throw new FixtureLifecycleIntegrityError("Settlement recovery count is invalid");
    }
    if (counts.delivery === 1) {
      if (payments.length !== plan.payments.length || settlements.length !== plan.payments.length) {
        throw new FixtureLifecycleIntegrityError("Outstanding delivery recovery order is invalid");
      }
      outstanding.push({ column: "delivery_invocations", completed: 0 });
    }
    if (outstanding.length > 1
      || (outstanding.length === 0
        && payments.length !== settlements.length
        && payments.length !== settlements.length + 1)) {
      throw new FixtureLifecycleIntegrityError("Settlement recovery has ambiguous side-effect state");
    }
    const reset = outstanding[0];
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.recover-settlement */
      UPDATE fixture_lifecycle_runs
      SET version = version + 1, updated_at = $observedAt,
        payment_invocations = CASE WHEN $resetColumn = 'payment_invocations'
          THEN $completedCount ELSE payment_invocations END,
        settlement_invocations = CASE WHEN $resetColumn = 'settlement_invocations'
          THEN $completedCount ELSE settlement_invocations END,
        delivery_invocations = CASE WHEN $resetColumn = 'delivery_invocations'
          THEN $completedCount ELSE delivery_invocations END
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'settle-pending' AND version = $expectedVersion
        AND updated_at = $expectedUpdatedAt
    `).run({
      ...binding,
      observedAt,
      expectedVersion: recovery.expectedVersion,
      expectedUpdatedAt: recovery.expectedUpdatedAt,
      completedCount: reset?.completed ?? 0,
      resetColumn: reset?.column ?? "",
    });
    if (updated.changes !== 1) throw new FixtureLifecycleIntegrityError("Settlement recovery snapshot raced");
  }

  #advanceCommitted(
    binding: LifecycleBinding,
    commitmentArtifactHash: string,
    expectedUpdatedAt?: string,
    expectedVersion?: number,
  ): void {
    const now = this.#timestamp();
    const transition = this.#database.transaction(() => {
      const commitCompleted = this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: lifecycle.commit-completed */
        UPDATE fixture_lifecycle_runs
        SET state = 'commit-completed', commitment_artifact_hash = $commitmentArtifactHash,
          version = version + 1,
          updated_at = $now
        WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
          AND state = 'commit-pending' AND commitment_artifact_hash IS NULL
          AND ($checkUpdatedAt = 0 OR updated_at = $expectedUpdatedAt)
          AND ($checkVersion = 0 OR version = $expectedVersion)
      `).run({
        ...binding,
        commitmentArtifactHash,
        now,
        expectedUpdatedAt: expectedUpdatedAt ?? now,
        expectedVersion: expectedVersion ?? 0,
        checkUpdatedAt: expectedUpdatedAt === undefined ? 0 : 1,
        checkVersion: expectedVersion === undefined ? 0 : 1,
      });
      if (commitCompleted.changes !== 1) {
        throw new FixtureLifecycleIntegrityError("Illegal commit-pending to commit-completed transition");
      }
      const settlePending = this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: lifecycle.settle-pending */
        UPDATE fixture_lifecycle_runs
        SET state = 'settle-pending', version = version + 1, updated_at = $now
        WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
          AND state = 'commit-completed'
      `).run({ ...binding, now });
      if (settlePending.changes !== 1) {
        throw new FixtureLifecycleIntegrityError("Illegal commit-completed to settle-pending transition");
      }
    });
    transition.immediate();
  }

  #resumePaused(
    binding: LifecycleBinding,
    row: LifecycleRow,
    recovery: FixtureLifecycleRecovery,
    observedAt: string,
  ): void {
    if (row.failureStage === null || row.failureStage === "commit") {
      throw new FixtureLifecycleIntegrityError("Paused lifecycle lacks a recoverable stage");
    }
    const counts = invocationCounts(row);
    const payments = parsePhaseEvidenceArray(row.paymentResultJson, "payment");
    const settlements = parsePhaseEvidenceArray(row.settlementResultJson, "settlement");
    const completedCount = row.failureStage === "payment"
      ? payments.length
      : row.failureStage === "settlement"
        ? settlements.length
        : 0;
    if (counts[row.failureStage] !== completedCount + 1) {
      throw new FixtureLifecycleIntegrityError("Paused lifecycle invocation evidence is inconsistent");
    }
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.resume-paused */
      UPDATE fixture_lifecycle_runs SET state = 'settle-pending',
        payment_invocations = CASE WHEN $stage = 'payment' THEN $completedCount ELSE payment_invocations END,
        settlement_invocations = CASE WHEN $stage = 'settlement' THEN $completedCount ELSE settlement_invocations END,
        delivery_invocations = CASE WHEN $stage = 'delivery' THEN $completedCount ELSE delivery_invocations END,
        version = version + 1,
        failure_stage = NULL, error_class = NULL, failure_reason = NULL,
        terminal_result_json = NULL,
        paused_at = NULL, pause_expires_at = NULL, updated_at = $observedAt
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'substrate-failure-paused' AND updated_at = $expectedUpdatedAt
        AND version = $expectedVersion
    `).run({
      ...binding,
      completedCount,
      stage: row.failureStage,
      observedAt,
      expectedUpdatedAt: recovery.expectedUpdatedAt,
      expectedVersion: recovery.expectedVersion,
    });
    if (updated.changes !== 1) throw new FixtureLifecycleIntegrityError("Paused lifecycle recovery raced");
  }

  #markInvocation(
    binding: LifecycleBinding,
    stage: "payment" | "settlement" | "delivery",
    completedCount: number,
  ): FailureWindow {
    const row = this.#read(binding);
    if (row === null || row.state !== "settle-pending") {
      throw new FixtureLifecycleIntegrityError(`Cannot invoke ${stage} outside settle-pending`);
    }
    const counts = invocationCounts(row);
    const results = stage === "payment"
      ? parsePhaseEvidenceArray(row.paymentResultJson, "payment")
      : stage === "settlement"
        ? parsePhaseEvidenceArray(row.settlementResultJson, "settlement")
        : [];
    const currentCount = counts[stage];
    if (currentCount !== completedCount || results.length !== completedCount
      || (stage === "settlement"
        && parsePhaseEvidenceArray(row.paymentResultJson, "payment").length !== completedCount + 1)
      || (stage === "delivery" && (completedCount !== 0
        || parsePhaseEvidenceArray(row.paymentResultJson, "payment").length
          !== parseLifecyclePlan(row).payments.length
        || parsePhaseEvidenceArray(row.settlementResultJson, "settlement").length
          !== parseLifecyclePlan(row).payments.length))) {
      throw new FixtureLifecycleIntegrityError(`Illegal or duplicate ${stage} invocation`);
    }
    const failureWindow = this.#failureWindow();
    const now = failureWindow.pausedAt;
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.invoke-stage */
      UPDATE fixture_lifecycle_runs
      SET payment_invocations = payment_invocations + CASE WHEN $stage = 'payment' THEN 1 ELSE 0 END,
        settlement_invocations = settlement_invocations + CASE WHEN $stage = 'settlement' THEN 1 ELSE 0 END,
        delivery_invocations = delivery_invocations + CASE WHEN $stage = 'delivery' THEN 1 ELSE 0 END,
        version = version + 1, updated_at = $now
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'settle-pending'
        AND CASE $stage
          WHEN 'payment' THEN payment_invocations
          WHEN 'settlement' THEN settlement_invocations
          WHEN 'delivery' THEN delivery_invocations
        END = $completedCount
    `).run({ ...binding, stage, completedCount, now });
    if (updated.changes !== 1) throw new FixtureLifecycleIntegrityError(`Duplicate ${stage} invocation race`);
    return failureWindow;
  }

  #recordPhaseSuccess(
    binding: LifecycleBinding,
    stage: "payment" | "settlement",
    evidence: FixtureLifecyclePhaseEvidence,
    completed: readonly FixtureLifecyclePhaseEvidence[],
  ): void {
    const resultJson = canonicalPhaseEvidenceArray([...completed, evidence]);
    const now = this.#timestamp();
    const expectedCount = completed.length + 1;
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.record-stage */
      UPDATE fixture_lifecycle_runs
      SET payment_result_json = CASE WHEN $stage = 'payment' THEN $resultJson ELSE payment_result_json END,
        settlement_result_json = CASE WHEN $stage = 'settlement' THEN $resultJson ELSE settlement_result_json END,
        version = version + 1, updated_at = $now
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'settle-pending'
        AND CASE $stage WHEN 'payment' THEN payment_invocations
          WHEN 'settlement' THEN settlement_invocations END = $expectedCount
        AND (($completedCount = 0 AND CASE $stage WHEN 'payment' THEN payment_result_json
          WHEN 'settlement' THEN settlement_result_json END IS NULL)
          OR ($completedCount > 0 AND CASE $stage WHEN 'payment' THEN payment_result_json
            WHEN 'settlement' THEN settlement_result_json END = $previousJson))
    `).run({
      ...binding,
      resultJson,
      previousJson: canonicalPhaseEvidenceArray(completed),
      expectedCount,
      completedCount: completed.length,
      stage,
      now,
    });
    if (updated.changes !== 1) {
      throw new FixtureLifecycleIntegrityError(`Unable to persist successful ${stage} result`);
    }
  }

  #recordDeliverySuccess(binding: LifecycleBinding, evidence: FixtureLifecyclePhaseEvidence): void {
    const resultJson = canonicalPhaseValue(evidence as unknown as Readonly<Record<string, unknown>>);
    const now = this.#timestamp();
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.complete */
      UPDATE fixture_lifecycle_runs
      SET delivery_result_json = $resultJson, state = 'settle-completed',
        version = version + 1, updated_at = $now
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'settle-pending' AND delivery_invocations = 1
        AND delivery_result_json IS NULL
    `).run({ ...binding, resultJson, now });
    if (updated.changes !== 1) {
      throw new FixtureLifecycleIntegrityError("Unable to persist successful delivery result");
    }
  }

  #stopSettle(
    binding: LifecycleBinding,
    phase: FixtureLifecyclePhaseBinding,
    stage: "payment" | "settlement" | "delivery",
    failure: Extract<FixturePhaseResult, { readonly ok: false }>,
    failureWindow: FailureWindow,
  ): LifecycleRow {
    const terminalEvidence = failure.authorityClaim === undefined || failure.value === undefined
      ? undefined
      : preparePhaseEvidence(phase, failure.value, failure.authorityClaim, undefined, stage);
    const persistedEvidence = terminalEvidence?.disposition === "ready"
      ? terminalEvidence.evidence : undefined;
    const persistedFailure = terminalEvidence?.disposition === "rejected"
      ? terminalEvidence.failure : failure;
    if (persistedFailure.errorClass === "settlement-atomicity") {
      return this.#transitionStop(
        binding,
        "settle-unsupported",
        stage,
        persistedFailure.errorClass,
        `Unsupported on the non-cross-chain fixture rail: ${persistedFailure.reason}`,
        undefined,
        undefined,
        persistedEvidence,
      );
    }
    const state = persistedFailure.errorClass === "substrate" ? "substrate-failure-paused" : "settle-failed";
    return this.#transitionStop(
      binding, state, stage, persistedFailure.errorClass, persistedFailure.reason,
      undefined, failureWindow, persistedEvidence,
    );
  }

  #transitionStop(
    binding: LifecycleBinding,
    state: "commit-failed" | "settle-failed" | "settle-unsupported" | "substrate-failure-paused",
    stage: FixtureLifecycleFailureStage,
    errorClass: FixtureLifecycleErrorClass,
    reason: string,
    commitmentArtifactHash?: string,
    failureWindow?: FailureWindow,
    terminalEvidence?: FixtureLifecyclePhaseEvidence,
  ): LifecycleRow {
    const expectedState = state === "commit-failed" ? "commit-pending" : "settle-pending";
    const terminal = state !== "substrate-failure-paused";
    if (state === "substrate-failure-paused" && failureWindow === undefined) {
      throw new FixtureLifecycleIntegrityError("Substrate failure lacks its pre-invocation pause window");
    }
    const now = state === "substrate-failure-paused" ? failureWindow!.pausedAt : this.#timestamp();
    const pauseExpiresAt = state === "substrate-failure-paused" ? failureWindow!.pauseExpiresAt : null;
    const updated = this.#database.query<never, Record<string, string | number | null>>(`
      /* atomic-write: lifecycle.stop */
      UPDATE fixture_lifecycle_runs
      SET state = $state, commitment_artifact_hash = coalesce($commitmentArtifactHash, commitment_artifact_hash),
        terminal_result_json = $terminalResultJson,
        failure_stage = $stage, error_class = $errorClass, failure_reason = $reason,
        paused_at = $pausedAt, pause_expires_at = $pauseExpiresAt, version = version + 1,
        updated_at = $now, ended_at = $endedAt
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = $expectedState
    `).run({
      ...binding,
      state,
      commitmentArtifactHash: commitmentArtifactHash ?? null,
      terminalResultJson: terminalEvidence === undefined ? null
        : canonicalPhaseValue(terminalEvidence as unknown as Readonly<Record<string, unknown>>),
      stage,
      errorClass,
      reason: normalizeFailureReason(reason),
      pausedAt: state === "substrate-failure-paused" ? now : null,
      pauseExpiresAt,
      now,
      endedAt: terminal ? now : null,
      expectedState,
    });
    if (updated.changes !== 1) {
      throw new FixtureLifecycleIntegrityError(`Illegal ${expectedState} to ${state} transition`);
    }
    const row = this.#read(binding);
    if (row === null) throw new FixtureLifecycleIntegrityError("Stopped lifecycle was not visible after persistence");
    return row;
  }

  #read(binding: Pick<LifecycleBinding, "instanceId" | "audience" | "jobId">): LifecycleRow | null {
    return this.#readBySession(binding.instanceId, binding.audience, binding.jobId);
  }

  #timestamp(): string {
    const now = canonicalTimestamp(this.#now());
    const nowMs = Date.parse(now);
    if (nowMs < this.#clockFloorMs) {
      throw new FixtureLifecycleIntegrityError("Fixture lifecycle trusted clock moved backward");
    }
    this.#clockFloorMs = nowMs;
    return now;
  }

  #failureWindow(): FailureWindow {
    const pausedAt = this.#timestamp();
    const deadlineMs = Date.parse(pausedAt) + this.#substratePauseMs;
    if (!Number.isSafeInteger(deadlineMs)) {
      throw new FixtureLifecycleIntegrityError("Fixture lifecycle substrate pause deadline is not representable");
    }
    let pauseExpiresAt: string;
    try {
      pauseExpiresAt = new Date(deadlineMs).toISOString();
    } catch {
      throw new FixtureLifecycleIntegrityError("Fixture lifecycle substrate pause deadline is not representable");
    }
    return Object.freeze({ pausedAt, pauseExpiresAt });
  }

  #expirePausedIfDue(row: LifecycleRow, observedAt = this.#timestamp()): LifecycleRow {
    if (row.state !== "substrate-failure-paused") return row;
    if (row.pauseExpiresAt === null) {
      throw new FixtureLifecycleIntegrityError("Paused lifecycle lacks an expiry deadline");
    }
    return Date.parse(observedAt) >= Date.parse(row.pauseExpiresAt)
      ? this.#expirePaused(row, observedAt)
      : row;
  }

  #expirePaused(row: LifecycleRow, endedAt: string): LifecycleRow {
    if (row.state !== "substrate-failure-paused" || row.pauseExpiresAt === null) {
      throw new FixtureLifecycleIntegrityError("Lifecycle is not paused for substrate recovery");
    }
    const updated = this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: lifecycle.expire-pause */
      UPDATE fixture_lifecycle_runs
      SET state = 'failed-substrate', version = version + 1,
        updated_at = $endedAt, ended_at = $endedAt
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
        AND state = 'substrate-failure-paused' AND updated_at = $expectedUpdatedAt
        AND version = $expectedVersion
        AND pause_expires_at = $pauseExpiresAt
    `).run({
      instanceId: row.instanceId,
      audience: row.audience,
      jobId: row.jobId,
      expectedUpdatedAt: row.updatedAt,
      expectedVersion: lifecycleVersion(row),
      pauseExpiresAt: row.pauseExpiresAt,
      endedAt,
    });
    if (updated.changes !== 1) {
      const raced = this.#readBySession(row.instanceId, row.audience, row.jobId);
      if (raced?.state === "failed-substrate" && raced.pauseExpiresAt === row.pauseExpiresAt) {
        return raced;
      }
      throw new FixtureLifecycleIntegrityError("Paused lifecycle expiry raced");
    }
    const expired = this.#readBySession(row.instanceId, row.audience, row.jobId);
    if (expired === null) throw new FixtureLifecycleIntegrityError("Expired lifecycle was not visible");
    return expired;
  }

  #readBySession(instanceId: string, audience: string, jobId: string): LifecycleRow | null {
    return this.#database.query<LifecycleRow, { instanceId: string; audience: string; jobId: string }>(`
      SELECT instance_id AS instanceId, audience, job_id AS jobId,
        request_hash AS requestHash, agreement_artifact_hash AS agreementArtifactHash,
        required_payment_phases_json AS requiredPaymentPhasesJson,
        delivery_phase_index AS deliveryPhaseIndex, delivery_phase_kind AS deliveryPhaseKind,
        state, version, commitment_artifact_hash AS commitmentArtifactHash,
        payment_invocations AS paymentInvocations,
        settlement_invocations AS settlementInvocations,
        delivery_invocations AS deliveryInvocations,
        payment_result_json AS paymentResultJson,
        settlement_result_json AS settlementResultJson,
        delivery_result_json AS deliveryResultJson,
        terminal_result_json AS terminalResultJson,
        terminal_state AS terminalState,
        abort_actor_role AS abortActorRole,
        abort_reason AS abortReason,
        failure_stage AS failureStage, error_class AS errorClass,
        failure_reason AS failureReason, paused_at AS pausedAt,
        pause_expires_at AS pauseExpiresAt, created_at AS createdAt,
        updated_at AS updatedAt, ended_at AS endedAt
      FROM fixture_lifecycle_runs
      WHERE instance_id = $instanceId AND audience = $audience AND job_id = $jobId
    `).get({ instanceId, audience, jobId });
  }

  #result(row: LifecycleRow): FixtureLifecycleResult {
    const counts = invocationCounts(row);
    const plan = parseLifecyclePlan(row);
    const payments = parsePhaseEvidenceArray(row.paymentResultJson, "payment");
    const settlements = parsePhaseEvidenceArray(row.settlementResultJson, "settlement");
    assertEvidenceOrder(payments, plan.payments, "payment");
    assertEvidenceOrder(settlements, plan.payments, "settlement");
    const commitment = row.commitmentArtifactHash === null
      ? undefined
      : this.#commitmentStore.get(row.instanceId, row.audience, row.jobId) ?? undefined;
    if (row.commitmentArtifactHash !== null
      && (commitment === undefined || commitment.commitmentArtifactHash !== row.commitmentArtifactHash)) {
      throw new FixtureLifecycleIntegrityError("Lifecycle commitment binding is missing or inconsistent");
    }
    const base = {
      agreementArtifactHash: row.agreementArtifactHash,
      ...(commitment === undefined ? {} : { commitment }),
      counts,
      jobId: row.jobId,
      payments,
      settlements,
      ...(row.terminalResultJson === null
        ? {} : { terminalEvidence: parsePhaseEvidence(row.terminalResultJson, "terminal") }),
    };
    if (row.state === "commit-failed" || row.state === "settle-failed") {
      if (row.failureStage === null || !isTerminalErrorClass(row.errorClass)
        || row.failureReason === null || row.endedAt === null
        || row.pausedAt !== null || row.pauseExpiresAt !== null
        || row.terminalState !== null || row.abortActorRole !== null || row.abortReason !== null) {
        throw new FixtureLifecycleIntegrityError("Failed lifecycle row lacks terminal failure evidence");
      }
      assertStoppedCounts(row, counts, payments, settlements, plan);
      return Object.freeze({
        ...base,
        state: row.state,
        endedAt: row.endedAt,
        errorClass: row.errorClass,
        failureStage: row.failureStage,
        reason: row.failureReason,
      });
    }
    if (row.state === "settle-unsupported") {
      if (commitment === undefined || row.errorClass !== "settlement-atomicity"
        || row.failureStage === null || row.failureStage === "commit"
        || row.failureReason === null || row.endedAt === null
        || row.pausedAt !== null || row.pauseExpiresAt !== null
        || row.terminalState !== null || row.abortActorRole !== null || row.abortReason !== null) {
        throw new FixtureLifecycleIntegrityError("Unsupported lifecycle row lacks exact terminal evidence");
      }
      assertStoppedCounts(row, counts, payments, settlements, plan);
      return Object.freeze({
        ...base,
        commitment,
        state: "settle-unsupported",
        endedAt: row.endedAt,
        errorClass: "settlement-atomicity",
        failureStage: row.failureStage,
        reason: row.failureReason,
      });
    }
    if (row.state === "substrate-failure-paused" || row.state === "failed-substrate") {
      if (commitment === undefined || row.errorClass !== "substrate" || row.failureStage === null
        || row.failureStage === "commit" || row.failureReason === null
        || row.pausedAt === null || row.pauseExpiresAt === null
        || (row.state === "substrate-failure-paused" ? row.endedAt !== null : row.endedAt === null)
        || row.terminalState !== null || row.abortActorRole !== null || row.abortReason !== null) {
        throw new FixtureLifecycleIntegrityError("Substrate-stop lifecycle row lacks exact evidence");
      }
      assertStoppedCounts(row, counts, payments, settlements, plan);
      const stopped = {
        ...base,
        commitment,
        errorClass: "substrate" as const,
        failureStage: row.failureStage,
        pausedAt: row.pausedAt,
        pauseExpiresAt: row.pauseExpiresAt,
        reason: row.failureReason,
      };
      if (row.state === "substrate-failure-paused") {
        return Object.freeze({ ...stopped, state: "substrate-failure-paused" as const });
      }
      return Object.freeze({
        ...stopped,
        state: "failed-substrate" as const,
        endedAt: row.endedAt!,
      });
    }
    if (row.state === "aborted") {
      if (commitment === undefined || row.abortActorRole === null || row.abortReason === null
        || row.endedAt === null || row.terminalState !== null || row.terminalResultJson !== null
        || row.failureStage !== null || row.errorClass !== null || row.failureReason !== null
        || row.pausedAt !== null || row.pauseExpiresAt !== null) {
        throw new FixtureLifecycleIntegrityError("Aborted lifecycle lacks exact actor authority");
      }
      assertAbortedCounts(row, counts, payments, settlements, plan);
      return Object.freeze({
        ...base,
        state: "aborted",
        commitment,
        abortActorRole: row.abortActorRole,
        abortReason: row.abortReason,
        endedAt: row.endedAt,
      });
    }
    if (row.state === "finalised" && row.terminalState !== null) {
      if (commitment === undefined || row.endedAt === null) {
        throw new FixtureLifecycleIntegrityError("Finalised terminal lifecycle lacks commitment or terminal time");
      }
      if (row.terminalState === "aborted") {
        if (row.abortActorRole === null || row.abortReason === null
          || row.terminalResultJson !== null || row.failureStage !== null || row.errorClass !== null
          || row.failureReason !== null || row.pausedAt !== null || row.pauseExpiresAt !== null) {
          throw new FixtureLifecycleIntegrityError("Finalised abort lacks exact actor authority");
        }
        assertAbortedCounts(row, counts, payments, settlements, plan);
        return Object.freeze({
          ...base,
          state: "finalised",
          commitment,
          endedAt: row.endedAt,
          terminalState: "aborted",
          abortActorRole: row.abortActorRole,
          abortReason: row.abortReason,
        });
      }
      if (row.failureStage === null || row.failureStage === "commit" || row.errorClass === null
        || row.failureReason === null || row.terminalResultJson === null
        || row.abortActorRole !== null || row.abortReason !== null) {
        throw new FixtureLifecycleIntegrityError("Finalised failure lacks exact terminal authority");
      }
      const exactTerminal = (row.terminalState === "settle-failed"
          && isTerminalErrorClass(row.errorClass) && row.pausedAt === null && row.pauseExpiresAt === null)
        || (row.terminalState === "settle-unsupported" && row.errorClass === "settlement-atomicity"
          && row.pausedAt === null && row.pauseExpiresAt === null)
        || (row.terminalState === "failed-substrate" && row.errorClass === "substrate"
          && row.pausedAt !== null && row.pauseExpiresAt !== null);
      if (!exactTerminal) {
        throw new FixtureLifecycleIntegrityError("Finalised failure terminal mapping is inconsistent");
      }
      assertStoppedCounts(row, counts, payments, settlements, plan);
      return Object.freeze({
        ...base,
        state: "finalised",
        commitment,
        endedAt: row.endedAt,
        terminalState: row.terminalState,
        errorClass: row.errorClass,
        failureStage: row.failureStage,
        reason: row.failureReason,
      });
    }
    if ((row.state !== "settle-completed" && row.state !== "finalised") || commitment === undefined
      || payments.length !== plan.payments.length || settlements.length !== plan.payments.length
      || counts.payment !== plan.payments.length || counts.settlement !== plan.payments.length
      || counts.delivery !== 1) {
      throw new FixtureLifecycleIntegrityError(`Lifecycle state ${row.state} is not terminal for this slice`);
    }
    const delivery = parsePhaseEvidence(row.deliveryResultJson, "delivery");
    if (delivery.phaseIndex !== plan.delivery.phaseIndex || delivery.phaseKind !== plan.delivery.phaseKind) {
      throw new FixtureLifecycleIntegrityError("Delivery result does not match the pinned pipeline phase");
    }
    if (row.state === "finalised") {
      if (row.endedAt === null || row.failureStage !== null || row.errorClass !== null
        || row.failureReason !== null || row.pausedAt !== null || row.pauseExpiresAt !== null
        || row.terminalState !== null || row.terminalResultJson !== null
        || row.abortActorRole !== null || row.abortReason !== null) {
        throw new FixtureLifecycleIntegrityError("Finalised lifecycle lacks exact terminal evidence");
      }
      return Object.freeze({ ...base, state: "finalised", commitment, delivery, endedAt: row.endedAt });
    }
    if (row.endedAt !== null) throw new FixtureLifecycleIntegrityError("Settled lifecycle ended before bundle finalisation");
    return Object.freeze({ ...base, state: "settle-completed", commitment, delivery });
  }
}

export function fixtureLifecycleRequestHash(agreementCanonicalJson: string): string {
  return fixtureCommitmentRequestHash(agreementCanonicalJson);
}

async function invokePhase(
  handler: FixturePhaseHandler,
  context: FixtureLifecycleContext,
): Promise<FixturePhaseResult> {
  let result: unknown;
  try {
    result = await handler(context);
  } catch (error) {
    return Object.freeze({
      ok: false,
      errorClass: "transient",
      reason: normalizeFailureReason(`Handler threw: ${safeErrorDescription(error)}`),
    });
  }
  if (result === null || typeof result !== "object") {
    return Object.freeze({ ok: false, errorClass: "permanent", reason: "Handler returned an invalid result" });
  }
  try {
    const candidate = result as {
      readonly authorityClaim?: unknown;
      readonly errorClass?: unknown;
      readonly ok?: unknown;
      readonly reason?: unknown;
      readonly value?: unknown;
    };
    const ok = candidate.ok;
    if (ok === true) {
      try {
        const authorityClaim = candidate.authorityClaim;
        if (authorityClaim !== undefined && (typeof authorityClaim !== "string"
          || canonicalizeClaimReference(authorityClaim).canonicalReference !== authorityClaim)) {
          throw new TypeError("Handler authorityClaim is not a canonical ClaimReference");
        }
        return Object.freeze({
          ok: true,
          ...(typeof authorityClaim === "string" ? { authorityClaim } : {}),
          value: deepFreezeJson(JSON.parse(canonicalPhaseValue(candidate.value))),
        });
      } catch (error) {
        return Object.freeze({
          ok: false,
          errorClass: "permanent",
          reason: normalizeFailureReason(`Handler success value is invalid: ${safeErrorDescription(error)}`),
        });
      }
    }
    if (ok === false) {
      const errorClass = candidate.errorClass;
      const reason = candidate.reason;
      if (isErrorClass(errorClass) && typeof reason === "string") {
        if (reason.trim().length === 0) {
          return Object.freeze({
            ok: false,
            errorClass: "permanent",
            reason: "Handler returned an empty failure reason",
          });
        }
        const hasAuthority = candidate.authorityClaim !== undefined;
        const hasValue = candidate.value !== undefined;
        if (hasAuthority !== hasValue) {
          return Object.freeze({
            ok: false,
            errorClass: "permanent",
            reason: "Handler failure evidence requires both authorityClaim and value",
          });
        }
        if (hasAuthority) {
          const authorityClaim = candidate.authorityClaim;
          if (typeof authorityClaim !== "string"
            || canonicalizeClaimReference(authorityClaim).canonicalReference !== authorityClaim) {
            return Object.freeze({
              ok: false,
              errorClass: "permanent",
              reason: "Handler failure authorityClaim is invalid",
            });
          }
          try {
            return Object.freeze({
              ok: false,
              authorityClaim,
              errorClass,
              reason: normalizeFailureReason(reason),
              value: deepFreezeJson(JSON.parse(canonicalPhaseValue(candidate.value))),
            });
          } catch (error) {
            return Object.freeze({
              ok: false,
              errorClass: "permanent",
              reason: normalizeFailureReason(`Handler failure evidence is invalid: ${safeErrorDescription(error)}`),
            });
          }
        }
        return Object.freeze({ ok: false, errorClass, reason: normalizeFailureReason(reason) });
      }
    }
    return Object.freeze({ ok: false, errorClass: "permanent", reason: "Handler returned an invalid result" });
  } catch (error) {
    return Object.freeze({
      ok: false,
      errorClass: "permanent",
      reason: normalizeFailureReason(`Handler result inspection threw: ${safeErrorDescription(error)}`),
    });
  }
}

function lifecyclePlan(listingCanonicalJson: string): LifecyclePlan {
  const canonical = snapshotCanonicalJson(listingCanonicalJson, MAX_LISTING_BYTES, "Listing");
  const listing = JSON.parse(canonical) as Record<string, unknown>;
  const pipeline = listing["pipeline"];
  if (!Array.isArray(pipeline)) throw new FixtureLifecycleIntegrityError("Pinned Listing pipeline is unavailable");
  const phases = pipeline.map((entry, phaseIndex) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
      || typeof (entry as Record<string, unknown>)["kind"] !== "string") {
      throw new FixtureLifecycleIntegrityError("Pinned Listing pipeline phase is malformed");
    }
    return Object.freeze({
      phaseIndex,
      phaseKind: (entry as Record<string, unknown>)["kind"] as string,
    });
  });
  const deliveries = phases.filter(({ phaseKind }) => phaseKind.startsWith("deliver-"));
  if (deliveries.length !== 1) {
    throw new FixtureLifecycleIntegrityError("This vertical requires exactly one delivery phase");
  }
  const delivery = deliveries[0]!;
  const laterSettlementPhases = phases.filter(({ phaseIndex, phaseKind }) =>
    phaseIndex > delivery.phaseIndex
    && (phaseKind.startsWith("pay-") || phaseKind.startsWith("deliver-")));
  if (laterSettlementPhases.length > 0) {
    throw new FixtureLifecycleIntegrityError("This payment-to-delivery vertical forbids later settlement phases");
  }
  const payments = Object.freeze(phases.filter(({ phaseIndex, phaseKind }) =>
    phaseIndex < delivery.phaseIndex && phaseKind.startsWith("pay-")));
  if (payments.length === 0) {
    throw new FixtureLifecycleIntegrityError("This payment-to-delivery vertical requires a preceding payment phase");
  }
  const unsupportedPayment = payments.find(({ phaseKind }) => !NON_CROSS_CHAIN_PAYMENT_PHASES.has(phaseKind));
  if (unsupportedPayment !== undefined) {
    throw new FixtureLifecycleIntegrityError(
      `This non-cross-chain fixture vertical does not support ${unsupportedPayment.phaseKind}`,
    );
  }
  return Object.freeze({ delivery, payments, paymentsCanonicalJson: canonicalize(payments) });
}

function parseLifecyclePlan(row: LifecycleRow): LifecyclePlan {
  let payments: readonly FixtureLifecyclePhaseBinding[];
  try {
    const parsed = JSON.parse(row.requiredPaymentPhasesJson) as unknown;
    if (!Array.isArray(parsed) || canonicalize(parsed) !== row.requiredPaymentPhasesJson) {
      throw new Error("not a canonical array");
    }
    payments = Object.freeze(parsed.map((entry) => phaseBinding(entry)));
  } catch (error) {
    throw new FixtureLifecycleIntegrityError(`Persisted payment phase plan is invalid: ${message(error)}`);
  }
  const deliveryPhaseIndex = Number(row.deliveryPhaseIndex);
  const delivery = phaseBinding({ phaseIndex: deliveryPhaseIndex, phaseKind: row.deliveryPhaseKind });
  if (payments.length === 0 || payments.some((phase) => phase.phaseIndex >= delivery.phaseIndex)) {
    throw new FixtureLifecycleIntegrityError("Persisted payment-to-delivery phase order is invalid");
  }
  return Object.freeze({ delivery, payments, paymentsCanonicalJson: row.requiredPaymentPhasesJson });
}

function phaseBinding(value: unknown): FixtureLifecyclePhaseBinding {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Phase binding must be an object");
  }
  const record = value as Record<string, unknown>;
  if (!Number.isSafeInteger(record["phaseIndex"]) || (record["phaseIndex"] as number) < 0
    || typeof record["phaseKind"] !== "string" || record["phaseKind"].length === 0) {
    throw new TypeError("Phase binding is invalid");
  }
  return Object.freeze({
    phaseIndex: record["phaseIndex"] as number,
    phaseKind: record["phaseKind"],
  });
}

function phaseEvidence(
  binding: FixtureLifecyclePhaseBinding,
  value: Readonly<Record<string, unknown>>,
  authorityClaim?: string,
): FixtureLifecyclePhaseEvidence {
  return deepFreezeJson(JSON.parse(canonicalPhaseValue({
    ...binding,
    ...(authorityClaim === undefined ? {} : { authorityClaim }),
    value,
  }))) as FixtureLifecyclePhaseEvidence;
}

function preparePhaseEvidence(
  binding: FixtureLifecyclePhaseBinding,
  value: Readonly<Record<string, unknown>>,
  authorityClaim: string | undefined,
  completed: readonly FixtureLifecyclePhaseEvidence[] | undefined,
  stage: "payment" | "settlement" | "delivery",
):
  | { readonly disposition: "ready"; readonly evidence: FixtureLifecyclePhaseEvidence }
  | {
    readonly disposition: "rejected";
    readonly failure: Extract<FixturePhaseResult, { readonly ok: false }>;
  } {
  try {
    const hasAttestationRef = Object.hasOwn(value, "attestationRef");
    if (hasAttestationRef && authorityClaim === undefined) {
      throw new TypeError("Phase evidence with an AttestationRef requires authenticated authority");
    }
    if (authorityClaim !== undefined
      && canonicalizeClaimReference(authorityClaim).canonicalReference !== authorityClaim) {
      throw new TypeError("Phase evidence authority must be a canonical ClaimReference");
    }
    const evidence = phaseEvidence(binding, value, authorityClaim);
    if (completed === undefined) {
      canonicalPhaseValue(evidence as unknown as Readonly<Record<string, unknown>>);
    } else {
      canonicalPhaseEvidenceArray([...completed, evidence]);
    }
    return Object.freeze({ disposition: "ready", evidence });
  } catch (error) {
    return Object.freeze({
      disposition: "rejected",
      failure: Object.freeze({
        ok: false as const,
        errorClass: "permanent" as const,
        reason: normalizeFailureReason(
          `${stage} evidence cannot be persisted: ${error instanceof Error ? error.message : String(error)}`,
        ),
      }),
    });
  }
}

function canonicalPhaseValue(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Phase value must be a JSON object");
  }
  const canonical = canonicalize(value);
  if (Buffer.byteLength(canonical, "utf8") > MAX_PHASE_RESULT_BYTES) {
    throw new TypeError(`Phase value exceeds ${MAX_PHASE_RESULT_BYTES} bytes`);
  }
  return canonical;
}

function canonicalPhaseEvidenceArray(value: readonly FixtureLifecyclePhaseEvidence[]): string {
  const canonical = canonicalize(value);
  if (Buffer.byteLength(canonical, "utf8") > MAX_PHASE_RESULT_BYTES) {
    throw new TypeError(`Accumulated phase evidence exceeds ${MAX_PHASE_RESULT_BYTES} bytes`);
  }
  return canonical;
}

function parsePhaseEvidenceArray(value: string | null, stage: string): readonly FixtureLifecyclePhaseEvidence[] {
  if (value === null) return Object.freeze([]);
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed) || canonicalPhaseEvidenceArray(parsed as FixtureLifecyclePhaseEvidence[]) !== value) {
      throw new Error("not a canonical phase-evidence array");
    }
    return Object.freeze(parsed.map((entry) => parsePhaseEvidenceValue(entry)));
  } catch (error) {
    throw new FixtureLifecycleIntegrityError(`Persisted ${stage} results are invalid: ${message(error)}`);
  }
}

function parsePhaseEvidence(value: string | null, stage: string): FixtureLifecyclePhaseEvidence {
  if (value === null) throw new FixtureLifecycleIntegrityError(`Lifecycle lacks ${stage} result`);
  try {
    const parsed = JSON.parse(value) as unknown;
    if (canonicalPhaseValue(parsed as Record<string, unknown>) !== value) throw new Error("not canonical");
    return parsePhaseEvidenceValue(parsed);
  } catch (error) {
    throw new FixtureLifecycleIntegrityError(`Persisted ${stage} result is invalid: ${message(error)}`);
  }
}

function parsePhaseEvidenceValue(value: unknown): FixtureLifecyclePhaseEvidence {
  const binding = phaseBinding(value);
  const record = value as Record<string, unknown>;
  if (record["value"] === null || typeof record["value"] !== "object" || Array.isArray(record["value"])) {
    throw new TypeError("Phase evidence value must be an object");
  }
  const authorityClaim = record["authorityClaim"];
  const phaseValue = record["value"] as Record<string, unknown>;
  if ((authorityClaim !== undefined && typeof authorityClaim !== "string")
    || (Object.hasOwn(phaseValue, "attestationRef") && typeof authorityClaim !== "string")) {
    throw new TypeError("Persisted phase evidence authority is invalid");
  }
  if (typeof authorityClaim === "string"
    && canonicalizeClaimReference(authorityClaim).canonicalReference !== authorityClaim) {
    throw new TypeError("Persisted phase evidence authority is non-canonical");
  }
  return deepFreezeJson({
    ...binding,
    ...(typeof authorityClaim === "string" ? { authorityClaim } : {}),
    value: phaseValue,
  });
}

function invocationCounts(row: LifecycleRow): FixtureLifecycleInvocationCounts {
  const payment = Number(row.paymentInvocations);
  const settlement = Number(row.settlementInvocations);
  const delivery = Number(row.deliveryInvocations);
  if (!Number.isSafeInteger(payment) || payment < 0
    || !Number.isSafeInteger(settlement) || settlement < 0
    || (delivery !== 0 && delivery !== 1)) {
    throw new FixtureLifecycleIntegrityError("Lifecycle invocation counts are invalid");
  }
  return Object.freeze({ payment, settlement, delivery });
}

function lifecycleVersion(row: LifecycleRow): number {
  const version = Number(row.version);
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new FixtureLifecycleIntegrityError("Lifecycle version is invalid");
  }
  return version;
}

function assertStoppedCounts(
  row: LifecycleRow,
  counts: FixtureLifecycleInvocationCounts,
  payments: readonly FixtureLifecyclePhaseEvidence[],
  settlements: readonly FixtureLifecyclePhaseEvidence[],
  plan: LifecyclePlan,
): void {
  if (row.failureStage === "commit") {
    if (counts.payment !== 0 || counts.settlement !== 0 || counts.delivery !== 0
      || payments.length !== 0 || settlements.length !== 0) {
      throw new FixtureLifecycleIntegrityError("Commit failure contains downstream activity");
    }
    return;
  }
  if (row.failureStage === "payment") {
    if (counts.payment !== payments.length + 1 || counts.settlement !== settlements.length
      || settlements.length !== payments.length || counts.delivery !== 0) {
      throw new FixtureLifecycleIntegrityError("Payment stop invocation order is invalid");
    }
    return;
  }
  if (row.failureStage === "settlement") {
    if (counts.payment !== payments.length || counts.settlement !== settlements.length + 1
      || payments.length !== settlements.length + 1 || counts.delivery !== 0) {
      throw new FixtureLifecycleIntegrityError("Settlement stop invocation order is invalid");
    }
    return;
  }
  if (row.failureStage === "delivery") {
    if (payments.length !== plan.payments.length || settlements.length !== plan.payments.length
      || counts.payment !== payments.length || counts.settlement !== settlements.length
      || counts.delivery !== 1 || row.deliveryResultJson !== null) {
      throw new FixtureLifecycleIntegrityError("Delivery stop invocation order is invalid");
    }
    return;
  }
  throw new FixtureLifecycleIntegrityError("Stopped lifecycle lacks a recognized failure stage");
}

function assertAbortedCounts(
  row: LifecycleRow,
  counts: FixtureLifecycleInvocationCounts,
  payments: readonly FixtureLifecyclePhaseEvidence[],
  settlements: readonly FixtureLifecyclePhaseEvidence[],
  plan: LifecyclePlan,
): void {
  if (row.deliveryResultJson !== null || payments.length > plan.payments.length
    || settlements.length > payments.length) {
    throw new FixtureLifecycleIntegrityError("Aborted lifecycle contains impossible phase results");
  }
  const cleanBoundary = counts.payment === payments.length
    && counts.settlement === settlements.length && counts.delivery === 0
    && payments.length === settlements.length;
  const paymentPending = counts.payment === payments.length + 1
    && counts.settlement === settlements.length && counts.delivery === 0
    && payments.length === settlements.length && payments.length < plan.payments.length;
  const settlementPending = counts.payment === payments.length
    && counts.settlement === settlements.length + 1 && counts.delivery === 0
    && payments.length === settlements.length + 1;
  const deliveryPending = payments.length === plan.payments.length
    && settlements.length === plan.payments.length
    && counts.payment === payments.length && counts.settlement === settlements.length
    && counts.delivery === 1;
  if (!cleanBoundary && !paymentPending && !settlementPending && !deliveryPending) {
    throw new FixtureLifecycleIntegrityError("Aborted lifecycle invocation boundary is inconsistent");
  }
}

function assertEvidenceOrder(
  evidence: readonly FixtureLifecyclePhaseEvidence[],
  expected: readonly FixtureLifecyclePhaseBinding[],
  stage: string,
): void {
  if (evidence.length > expected.length || evidence.some((entry, index) =>
    entry.phaseIndex !== expected[index]?.phaseIndex || entry.phaseKind !== expected[index]?.phaseKind)) {
    throw new FixtureLifecycleIntegrityError(`Persisted ${stage} results do not follow the pinned pipeline`);
  }
}

function assertBinding(row: LifecycleRow, binding: LifecycleBinding): void {
  if (row.requestHash !== binding.requestHash || row.agreementArtifactHash !== binding.agreementArtifactHash
    || row.requiredPaymentPhasesJson !== binding.requiredPaymentPhasesJson
    || Number(row.deliveryPhaseIndex) !== binding.deliveryPhaseIndex
    || row.deliveryPhaseKind !== binding.deliveryPhaseKind) {
    throw new FixtureLifecycleIntegrityError("Lifecycle replay conflicts with the admitted agreement or pipeline binding");
  }
}

function isReturnableState(state: FixtureLifecycleState): boolean {
  return state === "commit-failed" || state === "settle-failed" || state === "settle-unsupported"
    || state === "settle-completed"
    || state === "finalised"
    || state === "substrate-failure-paused" || state === "failed-substrate" || state === "aborted";
}

function isErrorClass(value: unknown): value is FixtureLifecycleErrorClass {
  return new Set(["permanent", "counterparty", "transient", "substrate", "settlement-atomicity"])
    .has(value as string);
}

function isTerminalErrorClass(
  value: FixtureLifecycleErrorClass | null,
): value is "permanent" | "counterparty" | "transient" {
  return value === "permanent" || value === "counterparty" || value === "transient";
}

function snapshotCanonicalJson(value: string, maxBytes: number, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError("Canonical JSON is required");
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new TypeError(`${label} byte limit must be a positive safe integer`);
  }
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new TypeError(`${label} exceeds implementation input limit of ${maxBytes} bytes`);
  }
  const parsed = JSON.parse(value) as unknown;
  if (canonicalize(parsed) !== value) throw new TypeError("Input is not canonical JSON");
  return value;
}

function fixtureAgreementByteLimit(configured?: number): number {
  const maxBytes = configured ?? MAX_FIXTURE_AGREEMENT_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_FIXTURE_AGREEMENT_BYTES) {
    throw new TypeError(
      `Fixture lifecycle agreement byte limit must be between 1 and ${MAX_FIXTURE_AGREEMENT_BYTES} bytes`,
    );
  }
  return maxBytes;
}

function normalizeFailureReason(value: string): string {
  const reason = value.trim();
  if (reason.length === 0) throw new TypeError("Failure reason must not be empty");
  return reason.slice(0, MAX_FAILURE_REASON_CHARS);
}

function safeErrorDescription(value: unknown): string {
  try {
    if (value instanceof Error && typeof value.message === "string") return value.message;
  } catch {
    // Continue to guarded string coercion.
  }
  try {
    return String(value);
  } catch {
    return "unprintable thrown value";
  }
}

function canonicalTimestamp(value: string): string {
  if (typeof value !== "string" || value.length === 0 || new Date(value).toISOString() !== value) {
    throw new TypeError("Lifecycle clock must return a canonical ISO timestamp");
  }
  return value;
}

function validateRecovery(recovery: FixtureLifecycleRecovery): void {
  if (recovery === null || typeof recovery !== "object" || Array.isArray(recovery)) {
    throw new TypeError("Fixture lifecycle recovery must be an object");
  }
  if (recovery.executorIsolationConfirmed !== true
    || recovery.sideEffectReconciliationConfirmed !== true) {
    throw new TypeError(
      "Fixture lifecycle recovery requires executor isolation and side-effect reconciliation",
    );
  }
  if (typeof recovery.expectedBoundaryId !== "string" || recovery.expectedBoundaryId.length === 0) {
    throw new TypeError("Fixture lifecycle recovery requires an expected restart boundary id");
  }
  canonicalTimestamp(recovery.expectedUpdatedAt);
  if (!Number.isSafeInteger(recovery.minimumAgeMs) || recovery.minimumAgeMs <= 0) {
    throw new TypeError("Fixture lifecycle recovery minimumAgeMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(recovery.expectedVersion) || recovery.expectedVersion < 0) {
    throw new TypeError("Fixture lifecycle recovery expectedVersion must be a non-negative safe integer");
  }
}

function assertRecoverableSnapshot(
  row: LifecycleRow,
  recovery: FixtureLifecycleRecovery,
  observedAt: string,
  boundaryId: string,
): void {
  if (boundaryId !== recovery.expectedBoundaryId) {
    throw new FixtureLifecycleIntegrityError("Lifecycle recovery boundary no longer matches persisted state");
  }
  if (row.updatedAt !== recovery.expectedUpdatedAt || lifecycleVersion(row) !== recovery.expectedVersion) {
    throw new FixtureLifecycleIntegrityError("Lifecycle recovery snapshot no longer matches persisted state");
  }
  const ageMs = Date.parse(observedAt) - Date.parse(row.updatedAt);
  if (ageMs < recovery.minimumAgeMs) {
    throw new FixtureLifecycleIntegrityError("Lifecycle recovery target is not old enough");
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

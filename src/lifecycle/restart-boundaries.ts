export type FixtureLifecycleRestartStage = "commit" | "payment" | "settlement" | "delivery";

export type FixtureLifecycleRestartStrategy =
  | "resume"
  | "reconcile-then-resume"
  | "replay-terminal"
  | "reject-impossible";

export interface FixtureLifecycleRestartBoundary {
  readonly id: string;
  readonly persistedState: string;
  readonly stage: FixtureLifecycleRestartStage | "terminal";
  readonly strategy: FixtureLifecycleRestartStrategy;
}

export interface FixtureLifecycleRestartObservation {
  readonly commitmentPresent: boolean;
  readonly deliveryInvocations: number;
  readonly deliveryResultPresent: boolean;
  readonly failureStage: FixtureLifecycleRestartStage | null;
  readonly paymentInvocations: number;
  readonly paymentResults: number;
  readonly requiredPaymentCount: number;
  readonly settlementInvocations: number;
  readonly settlementResults: number;
  readonly state: string;
  readonly terminalState: string | null;
}

const BOUNDARIES = [
  ["commit.before-anchor", "commit-pending", "commit", "resume"],
  ["commit.after-anchor", "commit-pending", "commit", "resume"],
  ["commit.atomic-transition", "commit-completed", "commit", "reject-impossible"],
  ["payment.ready", "settle-pending", "payment", "resume"],
  ["payment.in-flight", "settle-pending", "payment", "reconcile-then-resume"],
  ["settlement.ready", "settle-pending", "settlement", "resume"],
  ["settlement.in-flight", "settle-pending", "settlement", "reconcile-then-resume"],
  ["delivery.ready", "settle-pending", "delivery", "resume"],
  ["delivery.in-flight", "settle-pending", "delivery", "reconcile-then-resume"],
  ["payment.substrate-paused", "substrate-failure-paused", "payment", "reconcile-then-resume"],
  ["settlement.substrate-paused", "substrate-failure-paused", "settlement", "reconcile-then-resume"],
  ["delivery.substrate-paused", "substrate-failure-paused", "delivery", "reconcile-then-resume"],
  ["commit.failed", "commit-failed", "terminal", "replay-terminal"],
  ["payment.failed", "settle-failed", "terminal", "replay-terminal"],
  ["settlement.failed", "settle-failed", "terminal", "replay-terminal"],
  ["delivery.failed", "settle-failed", "terminal", "replay-terminal"],
  ["payment.unsupported", "settle-unsupported", "terminal", "replay-terminal"],
  ["settlement.unsupported", "settle-unsupported", "terminal", "replay-terminal"],
  ["delivery.unsupported", "settle-unsupported", "terminal", "replay-terminal"],
  ["payment.failed-substrate", "failed-substrate", "terminal", "replay-terminal"],
  ["settlement.failed-substrate", "failed-substrate", "terminal", "replay-terminal"],
  ["delivery.failed-substrate", "failed-substrate", "terminal", "replay-terminal"],
  ["session.aborted", "aborted", "terminal", "replay-terminal"],
  ["settlement.completed", "settle-completed", "terminal", "replay-terminal"],
  ["bundle.finalised-completed", "finalised", "terminal", "replay-terminal"],
  ["bundle.finalised-settle-failed", "finalised", "terminal", "replay-terminal"],
  ["bundle.finalised-settle-unsupported", "finalised", "terminal", "replay-terminal"],
  ["bundle.finalised-failed-substrate", "finalised", "terminal", "replay-terminal"],
  ["bundle.finalised-aborted", "finalised", "terminal", "replay-terminal"],
] as const satisfies readonly (readonly [
  string,
  string,
  FixtureLifecycleRestartBoundary["stage"],
  FixtureLifecycleRestartStrategy,
])[];

export const FIXTURE_LIFECYCLE_RESTART_BOUNDARIES = Object.freeze(BOUNDARIES.map(
  ([id, persistedState, stage, strategy]) => Object.freeze({ id, persistedState, stage, strategy }),
));

const BOUNDARY_BY_ID: ReadonlyMap<string, FixtureLifecycleRestartBoundary> = new Map(
  FIXTURE_LIFECYCLE_RESTART_BOUNDARIES.map((entry) => [entry.id, entry]),
);

export function fixtureLifecycleRestartBoundary(
  observation: FixtureLifecycleRestartObservation,
): FixtureLifecycleRestartBoundary {
  assertCounts(observation);
  const id = boundaryId(observation);
  const boundary = BOUNDARY_BY_ID.get(id);
  if (boundary === undefined) throw new TypeError(`Unregistered fixture lifecycle restart boundary: ${id}`);
  return boundary;
}

function boundaryId(observation: FixtureLifecycleRestartObservation): string {
  const { state } = observation;
  if (state !== "finalised" && observation.terminalState !== null) {
    throw new TypeError("Non-finalised lifecycle contains a terminal-state marker");
  }
  const carriesFailureStage = state === "commit-failed" || state === "settle-failed"
    || state === "settle-unsupported" || state === "substrate-failure-paused"
    || state === "failed-substrate"
    || (state === "finalised" && observation.terminalState !== null
      && observation.terminalState !== "aborted");
  if (!carriesFailureStage && observation.failureStage !== null) {
    throw new TypeError("Non-failure lifecycle contains a failure-stage marker");
  }
  if (state === "commit-pending") {
    assertEmptySettlementProgress(observation);
    return observation.commitmentPresent ? "commit.after-anchor" : "commit.before-anchor";
  }
  if (state === "commit-completed") {
    throw new TypeError("Transaction-internal commit-completed state is not restart-visible");
  }
  if (state === "settle-pending") return pendingBoundaryId(observation);
  if (state === "substrate-failure-paused") {
    if (observation.failureStage === null || observation.failureStage === "commit") {
      throw new TypeError("Paused lifecycle has no recoverable phase stage");
    }
    assertPausedProgress(observation, observation.failureStage);
    return `${observation.failureStage}.substrate-paused`;
  }
  if (state === "commit-failed") {
    assertStoppedProgress(observation, "commit");
    return terminalStageId(observation, "commit", "failed");
  }
  if (state === "settle-failed") return terminalFailureId(observation, "failed");
  if (state === "settle-unsupported") return terminalFailureId(observation, "unsupported");
  if (state === "failed-substrate") return terminalFailureId(observation, "failed-substrate");
  if (state === "aborted") {
    assertAbortedProgress(observation);
    return "session.aborted";
  }
  if (state === "settle-completed") {
    assertCompletedProgress(observation);
    return "settlement.completed";
  }
  if (state === "finalised") {
    if (observation.terminalState === null) {
      assertCompletedProgress(observation);
    } else if (observation.terminalState === "aborted") {
      assertAbortedProgress(observation);
    } else {
      if (observation.terminalState !== "settle-failed"
        && observation.terminalState !== "settle-unsupported"
        && observation.terminalState !== "failed-substrate") {
        throw new TypeError("Finalised lifecycle has an unknown terminal state");
      }
      assertTerminalFailureProgress(observation);
    }
    return observation.terminalState === null
      ? "bundle.finalised-completed"
      : `bundle.finalised-${observation.terminalState}`;
  }
  throw new TypeError(`Unknown fixture lifecycle persisted state: ${state}`);
}

function pendingBoundaryId(observation: FixtureLifecycleRestartObservation): string {
  const {
    deliveryInvocations,
    deliveryResultPresent,
    paymentInvocations,
    paymentResults,
    requiredPaymentCount,
    settlementInvocations,
    settlementResults,
  } = observation;
  if (!observation.commitmentPresent || deliveryResultPresent) {
    throw new TypeError("Pending settlement lacks exact commitment or already contains delivery output");
  }
  if (paymentResults > requiredPaymentCount || settlementResults > paymentResults
    || paymentInvocations < paymentResults || settlementInvocations < settlementResults
    || paymentInvocations > paymentResults + 1 || settlementInvocations > settlementResults + 1) {
    throw new TypeError("Pending settlement progress is inconsistent");
  }
  const inFlight = [
    paymentInvocations === paymentResults + 1,
    settlementInvocations === settlementResults + 1,
    deliveryInvocations === 1,
  ].filter(Boolean).length;
  if (inFlight > 1) throw new TypeError("Pending settlement has multiple in-flight effects");
  if (deliveryInvocations === 1) {
    if (paymentResults !== requiredPaymentCount || settlementResults !== requiredPaymentCount) {
      throw new TypeError("Delivery started before every settlement completed");
    }
    return "delivery.in-flight";
  }
  if (settlementInvocations === settlementResults + 1) {
    if (paymentResults !== settlementResults + 1 || paymentInvocations !== paymentResults
      || paymentResults > requiredPaymentCount) {
      throw new TypeError("Settlement started without exactly one unmatched payment");
    }
    return "settlement.in-flight";
  }
  if (paymentInvocations === paymentResults + 1) {
    if (paymentResults !== settlementResults || settlementInvocations !== settlementResults
      || paymentResults >= requiredPaymentCount) {
      throw new TypeError("Payment started before prior settlement completion");
    }
    return "payment.in-flight";
  }
  if (paymentInvocations !== paymentResults || settlementInvocations !== settlementResults) {
    throw new TypeError("Pending settlement invocation counts are inconsistent");
  }
  if (paymentResults === requiredPaymentCount && settlementResults === requiredPaymentCount) {
    return "delivery.ready";
  }
  if (paymentResults === settlementResults) return "payment.ready";
  if (paymentResults === settlementResults + 1) return "settlement.ready";
  throw new TypeError("Pending settlement has no deterministic next phase");
}

function terminalFailureId(
  observation: FixtureLifecycleRestartObservation,
  suffix: "failed" | "unsupported" | "failed-substrate",
): string {
  if (observation.failureStage === null || observation.failureStage === "commit") {
    throw new TypeError("Terminal settlement has no valid phase stage");
  }
  assertTerminalFailureProgress(observation);
  return `${observation.failureStage}.${suffix}`;
}

function assertPausedProgress(
  observation: FixtureLifecycleRestartObservation,
  stage: Exclude<FixtureLifecycleRestartStage, "commit">,
): void {
  if (!observation.commitmentPresent || observation.deliveryResultPresent) {
    throw new TypeError("Paused lifecycle lacks exact commitment or already contains delivery output");
  }
  const {
    deliveryInvocations,
    paymentInvocations,
    paymentResults,
    requiredPaymentCount,
    settlementInvocations,
    settlementResults,
  } = observation;
  const valid = stage === "payment"
    ? paymentInvocations === paymentResults + 1
      && paymentResults === settlementResults
      && settlementInvocations === settlementResults
      && paymentResults < requiredPaymentCount
      && deliveryInvocations === 0
    : stage === "settlement"
      ? settlementInvocations === settlementResults + 1
        && paymentInvocations === paymentResults
        && paymentResults === settlementResults + 1
        && paymentResults <= requiredPaymentCount
        && deliveryInvocations === 0
      : paymentInvocations === requiredPaymentCount
        && paymentResults === requiredPaymentCount
        && settlementInvocations === requiredPaymentCount
        && settlementResults === requiredPaymentCount
        && deliveryInvocations === 1;
  if (!valid) throw new TypeError(`Paused ${stage} progress is inconsistent`);
}

function assertTerminalFailureProgress(observation: FixtureLifecycleRestartObservation): void {
  if (observation.failureStage === null || observation.failureStage === "commit") {
    throw new TypeError("Terminal settlement has no valid phase stage");
  }
  assertStoppedProgress(observation, observation.failureStage);
}

function assertStoppedProgress(
  observation: FixtureLifecycleRestartObservation,
  stage: FixtureLifecycleRestartStage,
): void {
  const {
    deliveryInvocations,
    paymentInvocations,
    paymentResults,
    requiredPaymentCount,
    settlementInvocations,
    settlementResults,
  } = observation;
  if (observation.deliveryResultPresent || (stage !== "commit" && !observation.commitmentPresent)) {
    throw new TypeError(`Terminal ${stage} progress lacks its exact commitment or contains delivery output`);
  }
  const valid = stage === "commit"
    ? paymentInvocations === 0 && paymentResults === 0
      && settlementInvocations === 0 && settlementResults === 0 && deliveryInvocations === 0
    : stage === "payment"
      ? paymentInvocations === paymentResults + 1
        && paymentResults === settlementResults
        && settlementInvocations === settlementResults
        && paymentResults < requiredPaymentCount
        && deliveryInvocations === 0
      : stage === "settlement"
        ? settlementInvocations === settlementResults + 1
          && paymentInvocations === paymentResults
          && paymentResults === settlementResults + 1
          && paymentResults <= requiredPaymentCount
          && deliveryInvocations === 0
        : paymentInvocations === requiredPaymentCount
          && paymentResults === requiredPaymentCount
          && settlementInvocations === requiredPaymentCount
          && settlementResults === requiredPaymentCount
          && deliveryInvocations === 1;
  if (!valid) throw new TypeError(`Terminal ${stage} progress is inconsistent`);
}

function assertAbortedProgress(observation: FixtureLifecycleRestartObservation): void {
  if (!observation.commitmentPresent || observation.deliveryResultPresent
    || observation.paymentResults > observation.requiredPaymentCount
    || observation.settlementResults > observation.paymentResults) {
    throw new TypeError("Aborted lifecycle progress is inconsistent");
  }
  const {
    deliveryInvocations,
    paymentInvocations,
    paymentResults,
    requiredPaymentCount,
    settlementInvocations,
    settlementResults,
  } = observation;
  const clean = paymentInvocations === paymentResults
    && settlementInvocations === settlementResults && deliveryInvocations === 0
    && paymentResults === settlementResults;
  const paymentPending = paymentInvocations === paymentResults + 1
    && settlementInvocations === settlementResults && deliveryInvocations === 0
    && paymentResults === settlementResults && paymentResults < requiredPaymentCount;
  const settlementPending = paymentInvocations === paymentResults
    && settlementInvocations === settlementResults + 1 && deliveryInvocations === 0
    && paymentResults === settlementResults + 1 && paymentResults <= requiredPaymentCount;
  const deliveryPending = paymentInvocations === requiredPaymentCount
    && paymentResults === requiredPaymentCount && settlementInvocations === requiredPaymentCount
    && settlementResults === requiredPaymentCount && deliveryInvocations === 1;
  if (!clean && !paymentPending && !settlementPending && !deliveryPending) {
    throw new TypeError("Aborted lifecycle progress is inconsistent");
  }
}

function assertCompletedProgress(observation: FixtureLifecycleRestartObservation): void {
  if (!observation.commitmentPresent || !observation.deliveryResultPresent
    || observation.paymentInvocations !== observation.requiredPaymentCount
    || observation.paymentResults !== observation.requiredPaymentCount
    || observation.settlementInvocations !== observation.requiredPaymentCount
    || observation.settlementResults !== observation.requiredPaymentCount
    || observation.deliveryInvocations !== 1) {
    throw new TypeError("Completed lifecycle progress is inconsistent");
  }
}

function terminalStageId(
  observation: FixtureLifecycleRestartObservation,
  stage: FixtureLifecycleRestartStage,
  suffix: string,
): string {
  if (observation.failureStage !== stage) throw new TypeError(`Terminal lifecycle does not bind ${stage}`);
  return `${stage}.${suffix}`;
}

function assertCounts(observation: FixtureLifecycleRestartObservation): void {
  for (const value of [
    observation.deliveryInvocations,
    observation.paymentInvocations,
    observation.paymentResults,
    observation.requiredPaymentCount,
    observation.settlementInvocations,
    observation.settlementResults,
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Restart observation count is invalid");
  }
  if (observation.deliveryInvocations > 1) throw new TypeError("Delivery invocation count exceeds one");
}

function assertEmptySettlementProgress(observation: FixtureLifecycleRestartObservation): void {
  if (observation.paymentInvocations !== 0 || observation.paymentResults !== 0
    || observation.settlementInvocations !== 0 || observation.settlementResults !== 0
    || observation.deliveryInvocations !== 0 || observation.deliveryResultPresent) {
    throw new TypeError("Commit boundary contains settlement progress");
  }
}

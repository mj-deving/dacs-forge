import type { AgreementCommitVerification } from "../substrate/sqlite/fixture-commitment.ts";
import type { DacsDatabase } from "../substrate/sqlite/database.ts";
import type { FixtureCommitmentStore } from "../substrate/sqlite/fixture-commitment.ts";
import type { FixtureDeliveryStore } from "../substrate/sqlite/fixture-delivery.ts";
import type { SessionRecord } from "../substrate/sqlite/session-store.ts";
import {
  ServiceRuntime,
  serviceRequestHash,
  type ServiceRunResult,
} from "../service/runtime.ts";
import type { ServiceContract } from "../service/contract.ts";
import { fixtureCommitmentRequestHash } from "../substrate/sqlite/fixture-commitment.ts";
import { integratedServiceLifecycleRequestHash } from "../protocol/integrated-service-request.ts";
import {
  FixtureLifecycleOrchestrator,
  type FixtureLifecycleOrchestratorOptions,
  type FixtureLifecycleResult,
} from "./fixture-orchestrator.ts";
import {
  createFixtureAttestedDeliveryHandler,
  type FixtureAttestedDeliveryHandlerOptions,
} from "./fixture-attested-delivery-handler.ts";

export interface IntegratedServiceLifecycleOptions<TInput, TOutput> {
  readonly agreementCanonicalJson: string;
  readonly commitmentStore: FixtureCommitmentStore;
  readonly contract: ServiceContract<TInput, TOutput>;
  readonly database: DacsDatabase;
  readonly delivery: Omit<FixtureAttestedDeliveryHandlerOptions, "payloadJson" | "sessionStore">;
  readonly deliveryStore: FixtureDeliveryStore;
  readonly input: TInput;
  readonly jobId: string;
  readonly lifecycle: Pick<FixtureLifecycleOrchestratorOptions, "now" | "payment" | "settlement">
    & Partial<Pick<FixtureLifecycleOrchestratorOptions, "substratePauseMs">>;
  readonly runtime: ServiceRuntime<TInput, TOutput>;
  readonly seed: string;
  readonly sessionStore: { get(jobId: string): SessionRecord | null };
  readonly verification: AgreementCommitVerification;
}

export interface IntegratedServiceLifecycleResult<TInput, TOutput> {
  readonly lifecycle: FixtureLifecycleResult;
  readonly requestHash: string;
  readonly service: ServiceRunResult<TInput, TOutput>;
}

export async function runIntegratedServiceLifecycle<TInput, TOutput>(
  options: IntegratedServiceLifecycleOptions<TInput, TOutput>,
): Promise<IntegratedServiceLifecycleResult<TInput, TOutput>> {
  const agreementRequestHash = fixtureCommitmentRequestHash(options.agreementCanonicalJson);
  const serviceHash = serviceRequestHash(options.contract, options.input, options.seed);
  const requestHash = integratedServiceLifecycleRequestHash(agreementRequestHash, serviceHash);
  const service = await options.runtime.run({
    agreementRequestHash,
    input: options.input,
    jobId: options.jobId,
    seed: options.seed,
  });
  if (service.receipt.jobId !== options.jobId || service.receipt.requestHash !== requestHash) {
    throw new Error("Service receipt does not match the integrated lifecycle authority");
  }
  if (service.receipt.output.contentHash !== service.outputArtifact.contentHash) {
    throw new Error("Service receipt does not bind the canonical output artifact");
  }
  const delivery = createFixtureAttestedDeliveryHandler(options.deliveryStore, {
    ...options.delivery,
    payloadJson: service.outputArtifact.canonicalJson,
    sessionStore: options.sessionStore,
  });
  const lifecycle = await new FixtureLifecycleOrchestrator(options.database, {
    ...options.lifecycle,
    commitmentStore: options.commitmentStore,
    delivery,
    sessionStore: options.sessionStore,
  }).run({
    agreementCanonicalJson: options.agreementCanonicalJson,
    jobId: options.jobId,
    serviceRequestHash: serviceHash,
    verification: options.verification,
  });
  if (lifecycle.jobId !== options.jobId) {
    throw new Error("DACS lifecycle does not match the service job authority");
  }
  if ((lifecycle.state === "settle-completed" || lifecycle.state === "finalised")
    && "delivery" in lifecycle) {
    const deliveredHash = lifecycle.delivery.value["deliverableContentHash"];
    if (deliveredHash !== service.outputArtifact.contentHash) {
      throw new Error("DACS Delivery substituted the canonical service output");
    }
  }
  return Object.freeze({ lifecycle, requestHash, service });
}

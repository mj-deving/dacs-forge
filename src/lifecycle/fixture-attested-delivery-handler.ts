import type { SettlementPriceTerm } from "../producer/settlement-evidence.ts";
import {
  FixtureDeliverySubstrateError,
  FixtureDeliveryStore,
  type FixtureAttestedDeliveryRecord,
} from "../substrate/sqlite/fixture-delivery.ts";
import type { SessionRecord } from "../substrate/sqlite/session-store.ts";
import type { FixtureLifecycleContext, FixturePhaseHandler } from "./fixture-orchestrator.ts";

export interface FixtureAttestedDeliveryHandlerOptions {
  readonly now: () => string;
  readonly observedAt: () => number;
  readonly payloadFormat: string;
  readonly payloadJson: string | ((context: FixtureLifecycleContext) => string);
  readonly paymentAmount: SettlementPriceTerm;
  readonly sessionStore: { get(jobId: string): SessionRecord | null };
}

export function createFixtureAttestedDeliveryHandler(
  store: FixtureDeliveryStore,
  options: FixtureAttestedDeliveryHandlerOptions,
): FixturePhaseHandler {
  if (typeof options.now !== "function" || typeof options.observedAt !== "function"
    || (typeof options.payloadJson !== "string" && typeof options.payloadJson !== "function")) {
    throw new TypeError("Fixture attested delivery handler configuration is invalid");
  }
  return async (context) => {
    if (context.phaseKind !== "deliver-attested-payload") {
      return Object.freeze({
        ok: false,
        errorClass: "permanent",
        reason: "Fixture attested delivery handler received an unsupported delivery phase",
      });
    }
    let session: SessionRecord | null;
    try {
      session = options.sessionStore.get(context.jobId);
    } catch {
      return Object.freeze({
        ok: false,
        errorClass: "substrate",
        reason: "Fixture attested delivery session read failed",
      });
    }
    if (session === null) {
      return Object.freeze({
        ok: false,
        errorClass: "permanent",
        reason: "Fixture attested delivery session is unavailable",
      });
    }
    try {
      const payloadJson = typeof options.payloadJson === "function"
        ? await Promise.resolve(options.payloadJson(context)) : options.payloadJson;
      const record = store.deliver({
        agreementHash: context.agreementHash,
        createdAt: options.now(),
        observedAt: options.observedAt(),
        payloadFormat: options.payloadFormat,
        payloadJson,
        paymentAmount: options.paymentAmount,
        phaseIndex: context.phaseIndex,
        session,
      });
      return Object.freeze({
        ok: true,
        authorityClaim: record.orchestrator,
        value: deliveryPhaseValue(record),
      });
    } catch (error) {
      return Object.freeze({
        ok: false,
        errorClass: error instanceof FixtureDeliverySubstrateError ? "substrate" : "permanent",
        reason: error instanceof Error && error.message.length > 0
          ? error.message : "Fixture attested delivery failed",
      });
    }
  };
}

function deliveryPhaseValue(record: FixtureAttestedDeliveryRecord): Readonly<Record<string, unknown>> {
  return Object.freeze({
    attestationRef: record.attestationRef,
    deliverableContentHash: record.deliverableContentHash,
    deliveryAddress: record.deliveryAddress,
    deliveryArtifactHash: record.deliveryArtifactHash,
    evidenceAddress: record.evidenceAddress,
    evidenceArtifactHash: record.evidenceArtifactHash,
    evidenceHash: record.evidenceHash,
    sessionBindingHash: record.sessionBindingHash,
  });
}

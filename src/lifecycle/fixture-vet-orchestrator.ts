import type { VetDecision } from "../protocol/vet.ts";
import {
  FixtureVetPresentationError,
  FixtureVetStore,
  type FixtureVetInput,
  type FixtureVetRecord,
} from "../substrate/sqlite/fixture-vet.ts";

export type FixtureVetPhaseErrorClass = "counterparty" | "permanent";

export type FixtureBilateralVetResult =
  | {
      readonly state: "passed";
      readonly buyer: FixtureVetRecord;
      readonly seller: FixtureVetRecord;
      readonly vetRecordRefs: readonly [
        Readonly<Record<string, unknown>>,
        Readonly<Record<string, unknown>>,
      ];
    }
  | {
      readonly state: "failed";
      readonly evaluatedRole: "buyer" | "seller";
      readonly decision: Exclude<VetDecision, "pass">;
      readonly errorClass: FixtureVetPhaseErrorClass;
      readonly reason: string;
      readonly record?: FixtureVetRecord;
    };

export interface FixtureBilateralVetInput {
  readonly buyer: FixtureVetInput;
  readonly seller: FixtureVetInput;
}

export class FixtureBilateralVetOrchestrator {
  readonly #store: Pick<FixtureVetStore, "run">;

  constructor(store: Pick<FixtureVetStore, "run">) {
    this.#store = store;
  }

  run(input: FixtureBilateralVetInput): FixtureBilateralVetResult {
    assertBilateralBindings(input);
    let buyer: FixtureVetRecord;
    try {
      buyer = this.#store.run(input.buyer);
    } catch (error) {
      if (error instanceof FixtureVetPresentationError) return presentationFailed("buyer", error);
      throw error;
    }
    if (buyer.overallDecision !== "pass") return failed(buyer);

    let seller: FixtureVetRecord;
    try {
      seller = this.#store.run(input.seller);
    } catch (error) {
      if (error instanceof FixtureVetPresentationError) return presentationFailed("seller", error);
      throw error;
    }
    if (seller.overallDecision !== "pass") return failed(seller);

    const vetRecordRefs = Object.freeze([
      buyer.compositeReference,
      seller.compositeReference,
    ]) as readonly [Readonly<Record<string, unknown>>, Readonly<Record<string, unknown>>];
    return Object.freeze({
      state: "passed",
      buyer,
      seller,
      vetRecordRefs,
    });
  }
}

export function classifyFixtureVetPhaseFailure(
  decision: Exclude<VetDecision, "pass">,
  counterpartyPresentationUnparseable = false,
): FixtureVetPhaseErrorClass {
  if (decision === "fail" || counterpartyPresentationUnparseable) return "counterparty";
  return "permanent";
}

function failed(record: FixtureVetRecord): FixtureBilateralVetResult {
  const decision = record.overallDecision;
  if (decision === "pass") throw new TypeError("Passing Vet record cannot fail the bilateral phase");
  return Object.freeze({
    state: "failed",
    evaluatedRole: record.evaluatedRole,
    decision,
    errorClass: classifyFixtureVetPhaseFailure(decision),
    reason: `Fixture Vet completed with ${decision}`,
    record,
  });
}

function presentationFailed(
  evaluatedRole: "buyer" | "seller",
  error: FixtureVetPresentationError,
): FixtureBilateralVetResult {
  return Object.freeze({
    state: "failed",
    evaluatedRole,
    decision: "error",
    errorClass: classifyFixtureVetPhaseFailure("error", true),
    reason: error.message,
  });
}

function assertBilateralBindings(input: FixtureBilateralVetInput): void {
  const buyer = input.buyer;
  const seller = input.seller;
  if (buyer.evaluatedRole !== "buyer" || seller.evaluatedRole !== "seller"
    || buyer.session.instanceId !== seller.session.instanceId
    || buyer.session.audience !== seller.session.audience
    || buyer.session.jobId !== seller.session.jobId
    || buyer.evaluatedSigner.signer !== seller.verifierSigner.signer
    || buyer.verifierSigner.signer !== seller.evaluatedSigner.signer) {
    throw new TypeError("Bilateral Vet inputs do not bind one reciprocal session and recipe registry");
  }
}

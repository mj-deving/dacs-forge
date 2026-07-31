import type { LiveEffectStore } from "./effect-store.ts";
import type { AdmittedExecutionProfile, LiveEffectKind } from "./profile.ts";

export type EffectReconciliation<TResult extends Readonly<Record<string, unknown>>> =
  | TResult
  | Readonly<{ readonly disposition: "absent" }>
  | Readonly<{ readonly disposition: "indeterminate"; readonly reason: string }>;

export interface EffectAdapter<
  TPayload extends Readonly<Record<string, unknown>>,
  TResult extends Readonly<Record<string, unknown>> = Readonly<Record<string, unknown>>,
> {
  readonly reconcile: (input: Readonly<{
    readonly effectKey: string;
    readonly payload: TPayload;
  }>) => Promise<EffectReconciliation<TResult>>;
  readonly submit: (input: Readonly<{
    readonly effectKey: string;
    readonly payload: TPayload;
  }>) => Promise<TResult>;
}

export type EffectCrashBoundary = "before-submit" | "after-submit" | "after-observation" | "before-commit";

export async function runRecoverableEffect<
  TPayload extends Readonly<Record<string, unknown>>,
  TResult extends Readonly<Record<string, unknown>>,
>(input: {
  readonly store: LiveEffectStore;
  readonly profile: AdmittedExecutionProfile;
  readonly effectKey: string;
  readonly kind: LiveEffectKind;
  readonly payload: TPayload;
  readonly adapter: EffectAdapter<TPayload, TResult>;
  readonly crash?: (boundary: EffectCrashBoundary) => void;
}): Promise<TResult> {
  if (input.profile.mode !== "live-testnet" || !input.profile.networkEffects
    || !input.profile.allowedEffects.includes(input.kind)) {
    throw new Error(`Execution profile does not admit ${input.kind}`);
  }
  let intent = input.store.prepare(input.effectKey, input.kind, input.payload);
  if (intent.state === "committed") return parseResult<TResult>(intent.resultJson);
  if (intent.state === "observed") {
    intent = input.store.commit(input.effectKey);
    return parseResult<TResult>(intent.resultJson);
  }

  let observation = await input.adapter.reconcile(Object.freeze({
    effectKey: input.effectKey,
    payload: input.payload,
  }));
  if (isIndeterminate(observation)) {
    throw new Error(`Effect reconciliation is indeterminate: ${observation.reason}`);
  }
  if (isAbsent(observation)) {
    if (intent.state === "submitting") {
      throw new Error("Effect submission was already attempted and remains unobservable; refusing to resubmit");
    }
    input.crash?.("before-submit");
    intent = input.store.markSubmitting(input.effectKey);
    await input.adapter.submit(Object.freeze({ effectKey: input.effectKey, payload: input.payload }));
    input.crash?.("after-submit");
    observation = await input.adapter.reconcile(Object.freeze({
      effectKey: input.effectKey,
      payload: input.payload,
    }));
    if (isIndeterminate(observation)) {
      throw new Error(`Post-submission reconciliation is indeterminate: ${observation.reason}`);
    }
    if (isAbsent(observation)) throw new Error("Submitted effect is not yet observable; refusing to resubmit");
  }
  input.crash?.("after-observation");
  intent = input.store.observe(input.effectKey, observation);
  input.crash?.("before-commit");
  intent = input.store.commit(input.effectKey);
  return parseResult<TResult>(intent.resultJson);
}

function parseResult<TResult>(value: string | undefined): TResult {
  if (value === undefined) throw new Error("Committed effect result is missing");
  const parsed = JSON.parse(value) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Committed effect result is invalid");
  }
  return Object.freeze(parsed) as TResult;
}

function isAbsent(value: Readonly<Record<string, unknown>>): value is Readonly<{ disposition: "absent" }> {
  return value["disposition"] === "absent";
}

function isIndeterminate(value: Readonly<Record<string, unknown>>): value is Readonly<{
  disposition: "indeterminate"; reason: string;
}> {
  return value["disposition"] === "indeterminate";
}

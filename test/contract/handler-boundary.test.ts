import { describe, expect, test } from "bun:test";
import type {
  ServiceExecutionContext,
  ServiceHandler,
} from "../../src/service/contract.ts";

interface Input { readonly value: string }
interface Output { readonly value: string }

const compileTimeBoundary: ServiceHandler<Input, Output> = (input, context) => {
  // @ts-expect-error Core signer capabilities are intentionally absent.
  void context.signer;
  // @ts-expect-error Substrate stores are intentionally absent.
  void context.artifactStore;
  // @ts-expect-error Network clients are intentionally absent.
  void context.fetch;
  return { value: `${input.value}:${context.seed}` };
};

describe("service handler compile-time boundary", () => {
  test("exposes only inert execution metadata", () => {
    const context: ServiceExecutionContext = Object.freeze({
      evidenceMode: "fixture",
      jobId: "01J00000000000000000000001",
      seed: "seed",
    });
    expect(compileTimeBoundary({ value: "value" }, context)).toEqual({ value: "value:seed" });
    expect(Object.keys(context).sort()).toEqual(["evidenceMode", "jobId", "seed"]);
  });
});

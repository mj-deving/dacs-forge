import type { ReferenceTransformInput, ReferenceTransformOutput } from "../handler.ts";

export const BASIC_FIXTURE = Object.freeze({
  jobId: "01J00000000000000000000001",
  seed: "reference-json-transform-v1",
  producedAt: "2026-07-17T08:00:00.000Z",
  input: Object.freeze({
    document: Object.freeze({ alpha: "one", beta: "two" }),
    select: Object.freeze(["beta", "missing", "alpha"]),
  }) satisfies ReferenceTransformInput,
  alternateInput: Object.freeze({
    document: Object.freeze({ alpha: "changed", beta: "two" }),
    select: Object.freeze(["beta", "missing", "alpha"]),
  }) satisfies ReferenceTransformInput,
  invalidInputs: Object.freeze([
    Object.freeze({ document: Object.freeze({ alpha: "one" }) }),
    Object.freeze({ document: Object.freeze({ alpha: "one" }), select: Object.freeze([]), extra: true }),
    Object.freeze({ document: Object.freeze({ alpha: 1 }), select: Object.freeze(["alpha"]) }),
    Object.freeze({ document: Object.freeze({ alpha: Number.NaN }), select: Object.freeze(["alpha"]) }),
  ]),
  invalidOutput: null,
  behaviorVectors: Object.freeze([
    Object.freeze({
      input: Object.freeze({
        document: Object.freeze({}),
        select: Object.freeze(["toString", "__proto__"]),
      }) satisfies ReferenceTransformInput,
      output: Object.freeze({
        evidenceMode: "fixture" as const,
        missing: Object.freeze(["__proto__", "toString"]),
        selected: Object.freeze({}),
        seed: "reference-json-transform-v1",
      }) satisfies ReferenceTransformOutput,
    }),
  ]),
  output: Object.freeze({
    evidenceMode: "fixture",
    missing: Object.freeze(["missing"]),
    selected: Object.freeze({ alpha: "one", beta: "two" }),
    seed: "reference-json-transform-v1",
  }) satisfies ReferenceTransformOutput,
});

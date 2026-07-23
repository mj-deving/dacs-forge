import type { ReferenceTransformInput, ReferenceTransformOutput } from "../handler.ts";

export const BASIC_FIXTURE = Object.freeze({
  jobId: "01J00000000000000000000001",
  seed: "reference-json-transform-v1",
  producedAt: "2026-07-17T08:00:00.000Z",
  input: Object.freeze({
    document: Object.freeze({ alpha: "one", beta: "two" }),
    select: Object.freeze(["beta", "missing", "alpha"]),
  }) satisfies ReferenceTransformInput,
  output: Object.freeze({
    evidenceMode: "fixture",
    missing: Object.freeze(["missing"]),
    selected: Object.freeze({ alpha: "one", beta: "two" }),
    seed: "reference-json-transform-v1",
  }) satisfies ReferenceTransformOutput,
});

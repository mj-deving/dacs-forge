import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  classifyBundleAddressRead,
  resolveBundleBindingCandidates,
} from "../../src/consumer/bundle-binding-resolver.ts";

const corpus = JSON.parse(readFileSync(
  join(import.meta.dir, "../../vectors/dacs-standard-pr248/bundle-binding-v0.1.json"),
  "utf8",
));
const valid = corpus.vectors.find((vector: any) => vector.name === "bb-valid-resolution");
const publicKeys = new Map<string, Uint8Array>(
  Object.entries(corpus.publicKeys).map(([claim, value]) => [
    claim,
    new Uint8Array(Buffer.from(value as string, "base64url")),
  ]),
);

describe("ISC-40 unavailable or unverifiable BundleBinding authority", () => {
  test("never resolves when signature authority is unavailable", () => {
    const result = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: valid.bindings,
      anchored: new Map(Object.entries(valid.anchored)),
      publicKeys: new Map(),
      partyMap: valid.partyMap,
    });
    expect(result).toMatchObject({ disposition: "indeterminate", resolvedNativeAddress: null });
  });

  test("never resolves a binding whose authenticated signature is corrupt", () => {
    const binding = structuredClone(valid.bindings[0]);
    binding.signature.value = `${binding.signature.value.slice(0, -1)}A`;
    const result = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: [binding],
      anchored: new Map(Object.entries(valid.anchored)),
      publicKeys,
      partyMap: valid.partyMap,
    });
    expect(result).toMatchObject({ disposition: "indeterminate", resolvedNativeAddress: null });
  });

  test("non-discovery and an unqualified not-found never become absence", () => {
    const unresolved = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: [],
      publicKeys,
    });
    const resolved = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: valid.bindings,
      anchored: new Map(Object.entries(valid.anchored)),
      publicKeys,
      partyMap: valid.partyMap,
    });
    expect(classifyBundleAddressRead({
      resolution: unresolved,
      read: { nativeAddress: null, response: "not-found" },
    })).toMatchObject({ disposition: "indeterminate", oneSidedReachable: false });
    expect(classifyBundleAddressRead({
      resolution: resolved,
      read: { nativeAddress: resolved.resolvedNativeAddress, response: "not-found" },
      absenceEvidencePolicy: null,
    })).toMatchObject({ disposition: "indeterminate", oneSidedReachable: false });
  });
});

import { describe, expect, test } from "bun:test";
import {
  gateBundleReputationOutput,
  type BundleConsistencyResult,
} from "../../src/consumer/bundle-consistency.ts";
import { gateReputationOutputCandidate } from "../../src/consumer/reputation-eligibility.ts";

const fixtureProvenance = Object.freeze({
  authority: "fixture-signer",
  economicMode: "no-spend",
  evidenceMode: "fixture",
});
const liveProvenance = Object.freeze({
  authority: "independently-verified",
  economicMode: "live-value",
  evidenceMode: "live",
});

describe("fixture reputation exclusion", () => {
  test("rejects every fixture artifact class before type-specific parsing or output", () => {
    const fixtureArtifacts = [
      { kind: "SettlementEvidence", settlement: { txId: "fixture:payment" } },
      { bundleVersion: "1", kind: "AttestationBundle", outcome: "completed" },
      { bundleVersion: "0", kind: "legacy-bundle", ratings: [] },
      { bundleVersion: "0.3", fault: { role: "seller" }, kind: "FaultAttestationBundle" },
      { kind: "Rating", score: 5 },
      { derivedFrom: "legacy-bundle", kind: "legacy-derived-reputation" },
      { kind: "ReplayableReputationDerivation", receipts: [{ hash: "fixture" }] },
    ] as const;
    for (const artifact of fixtureArtifacts) {
      const result = gateReputationOutputCandidate({
        artifact,
        protocolEligibility: "eligible",
        provenance: fixtureProvenance,
      });
      expect(result).toEqual({
        disposition: "excluded",
        reason: "Reputation output requires independently verified live-value provenance",
        stage: "provenance",
      });
      expect(Object.hasOwn(result, "output")).toBeFalse();
    }
  });

  test("does not inspect opaque future fixture artifacts", () => {
    let artifactReads = 0;
    const opaqueArtifact = new Proxy({}, {
      get() {
        artifactReads += 1;
        throw new Error("artifact parser became reachable");
      },
      ownKeys() {
        artifactReads += 1;
        throw new Error("artifact parser became reachable");
      },
    });
    const result = gateReputationOutputCandidate({
      artifact: opaqueArtifact,
      protocolEligibility: "eligible",
      provenance: fixtureProvenance,
    });

    expect(result).toMatchObject({ disposition: "excluded", stage: "provenance" });
    expect(artifactReads).toBe(0);
  });

  test("keeps fixture and no-spend provenance distinct from a live-shaped positive control", () => {
    const rejectedProvenance = [
      fixtureProvenance,
      { ...liveProvenance, economicMode: "no-spend" },
      { ...liveProvenance, evidenceMode: "local-chain" },
      { ...liveProvenance, authority: "directory-proxy" },
      { evidenceMode: "live" },
    ];
    for (const provenance of rejectedProvenance) {
      expect(gateReputationOutputCandidate({
        artifact: { kind: "opaque" },
        protocolEligibility: "eligible",
        provenance,
      })).toMatchObject({ disposition: "excluded", stage: "provenance" });
    }
    expect(gateReputationOutputCandidate({
      artifact: { kind: "live-control", value: 7 },
      protocolEligibility: "eligible",
      provenance: liveProvenance,
    })).toEqual({
      disposition: "blocked",
      reason: "No trusted artifact-bound live reputation authority is implemented",
      stage: "live-authority",
    });
  });

  test("gates the current bundle eligibility classifier before output projection", () => {
    const eligible: BundleConsistencyResult = {
      disposition: "unified",
      reason: "Protocol reconciliation passed",
      reputationEligibility: "eligible",
    };
    const fixture = gateBundleReputationOutput(eligible, {
      artifact: { bundleVersion: "1" },
      provenance: fixtureProvenance,
    });
    expect(fixture).toMatchObject({ disposition: "excluded", stage: "provenance" });
    expect(Object.hasOwn(fixture, "output")).toBeFalse();

    const ineligible: BundleConsistencyResult = {
      disposition: "rejected",
      reason: "Protocol reconciliation failed",
      reputationEligibility: "excluded",
    };
    const liveButIneligible = gateBundleReputationOutput(ineligible, {
      artifact: { bundleVersion: "1" },
      provenance: liveProvenance,
    });
    expect(liveButIneligible).toMatchObject({ disposition: "excluded", stage: "protocol-eligibility" });
    expect(Object.hasOwn(liveButIneligible, "output")).toBeFalse();
  });
});

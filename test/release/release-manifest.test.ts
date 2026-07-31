import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import manifest from "../../release/release-manifest.json";
import profile from "../../release/capability-profile.json";
import compatibility from "../../release/compatibility.json";
import { rigInventory, verifyReleaseManifest } from "../../scripts/verify-release-manifest.ts";

const ROOT = resolve(import.meta.dir, "../..");

describe("Product Seal release manifest", () => {
  test("binds the source-only patch, v0.1.0 predecessor, pins, contracts, and complete rig", () => {
    expect(verifyReleaseManifest(ROOT, manifest, profile, compatibility)).toMatchObject({
      schema: "dacs-forge-release-manifest-verification/v1",
      version: "0.1.1",
      tag: "v0.1.1",
      predecessor: "81507c792c158a5782ea67e6c43c873d49356903",
      dacsCommit: "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
      communityCommit: "634caef4b952838281c8c602402e657d41074703",
    });
    expect(rigInventory(ROOT, "v0.1.1")).toBe(
      (manifest.rig.definition as { inventorySha256: string }).inventorySha256,
    );
    expect(rigInventory(ROOT)).not.toBe(rigInventory(ROOT, "v0.1.1"));
  });

  test("rejects support, source, predecessor, pin, digest, rig, and distribution substitution", () => {
    const mutations: Array<(value: Record<string, any>) => void> = [
      (value) => { value["support"].status = "supported"; },
      (value) => { value["sourceBinding"].commit = "0".repeat(40); },
      (value) => { value["mandatoryPredecessor"].commit = "0".repeat(40); },
      (value) => { value["pins"].dacsStandard.commit = "0".repeat(40); },
      (value) => { value["contracts"].capabilityProfile.sha256 = "0".repeat(64); },
      (value) => { value["contracts"].capabilityProfile.path = "release/../release/capability-profile.json"; },
      (value) => { value["contracts"].security = "missing.md"; },
      (value) => { value["pins"].dacsStandard.vectorSources[0] = "0".repeat(40); },
      (value) => { value["pins"].community.main = "0".repeat(40); },
      (value) => { value["rig"].commands[0] = "true"; },
      (value) => { value["rig"].commands = []; },
      (value) => { value["rig"].definition.inventorySha256 = "0".repeat(64); },
      (value) => { value["rig"].qualificationEvidence.embedded = false; },
      (value) => { value["distributedArtifacts"].push({ kind: "container-image" }); },
      (value) => { value["notDistributed"].package = false; },
      (value) => { value["claims"].certification = true; },
    ];
    for (const mutate of mutations) {
      const changed = structuredClone(manifest) as unknown as Record<string, any>;
      mutate(changed);
      expect(() => verifyReleaseManifest(ROOT, changed, profile, compatibility)).toThrow();
    }
    const changedProfile = structuredClone(profile) as unknown as Record<string, any>;
    changedProfile["capabilities"].livePayment = "implemented";
    expect(() => verifyReleaseManifest(ROOT, manifest, changedProfile, compatibility)).toThrow("capability profile");
  });
});

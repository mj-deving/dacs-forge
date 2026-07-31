import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import manifest from "../../release/release-manifest.json";
import profile from "../../release/capability-profile.json";
import compatibility from "../../release/compatibility.json";
import index from "../../release/qualification/index.json";
import { verifyPublicQualification } from "../../scripts/verify-public-qualification.ts";

const ROOT = resolve(import.meta.dir, "../..");

describe("public qualification coherence", () => {
  test("binds public consumer and reference-fork evidence across every release record", () => {
    expect(verifyPublicQualification(ROOT, manifest, profile, compatibility, index)).toEqual({
      schema: "dacs-forge-public-qualification-verification/v1",
      version: "0.1.1",
      tag: "v0.1.1",
      reports: 2,
      releaseAssets: 5,
      status: "qualified-public-evidence",
    });
  });

  test("rejects status, report digest, asset locator, and attestation drift", () => {
    const cases: Array<[unknown, unknown, unknown, unknown]> = [];
    const changedProfile = structuredClone(profile) as Record<string, any>;
    changedProfile["qualification"].status = "pending";
    cases.push([manifest, changedProfile, compatibility, index]);
    const changedCompatibility = structuredClone(compatibility) as Record<string, any>;
    changedCompatibility["qualificationEvidence"].embedded = false;
    cases.push([manifest, profile, changedCompatibility, index]);
    const changedReport = structuredClone(index) as Record<string, any>;
    changedReport["reports"].independentConsumer.sha256 = "0".repeat(64);
    cases.push([manifest, profile, compatibility, changedReport]);
    const changedAsset = structuredClone(index) as Record<string, any>;
    changedAsset["releaseAssets"][1].url = "https://example.invalid/consumer.bundle";
    cases.push([manifest, profile, compatibility, changedAsset]);
    const renamedAsset = structuredClone(index) as Record<string, any>;
    renamedAsset["releaseAssets"][1].name = "renamed-consumer.bundle";
    renamedAsset["releaseAssets"][1].url = "https://github.com/mj-deving/dacs-forge/releases/download/v0.1.1/renamed-consumer.bundle";
    cases.push([manifest, profile, compatibility, renamedAsset]);
    const changedAttestation = structuredClone(index) as Record<string, any>;
    changedAttestation["attestation"].cryptographicGitTagSignature = "signed";
    cases.push([manifest, profile, compatibility, changedAttestation]);
    const changedConsumerLocator = structuredClone(compatibility) as Record<string, any>;
    changedConsumerLocator["qualificationEvidence"].consumerReport = "release/qualification/missing.json";
    cases.push([manifest, profile, changedConsumerLocator, index]);
    const changedAssetDigest = structuredClone(index) as Record<string, any>;
    changedAssetDigest["releaseAssets"][1].sha256 = "1".repeat(64);
    cases.push([manifest, profile, compatibility, changedAssetDigest]);
    const changedClaim = structuredClone(index) as Record<string, any>;
    changedClaim["claims"].certification = true;
    cases.push([manifest, profile, compatibility, changedClaim]);
    for (const values of cases) expect(() => verifyPublicQualification(ROOT, ...values)).toThrow();
  });
});

#!/usr/bin/env bun

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

type JsonObject = Record<string, unknown>;

const PREVIEW_COMMIT = "0c6e92cc707c62db0ca3c9627d59bb95ba9970e9";
const DACS_COMMIT = "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091";
const PRODUCT_SEAL_COMMIT = "81507c792c158a5782ea67e6c43c873d49356903";
const PRODUCT_SEAL_TAG_OBJECT = "7fe4d4e26191725cf3b98f2b28f2729cc4226ec5";
const PRODUCT_SEAL_RELEASE_ID = 362626525;
const EXACT_PATHS = ["service/handler.ts", "service/input.schema.json", "service/output.schema.json", "service/service.config.ts"];
const PREFIX = "service/fixtures/";
const SHA256 = /^[0-9a-f]{64}$/;

function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} is invalid`);
  return value as JsonObject;
}

export function gitChangedPaths(repository: string, range: string): readonly string[] {
  const result = spawnSync("git", ["diff", "--no-renames", "--name-only", "-z", range], {
    cwd: repository,
    encoding: "buffer",
    env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (result.status !== 0) throw new Error("migration path derivation failed");
  return new TextDecoder().decode(result.stdout).split("\0").filter(Boolean).sort();
}

export function gitMergeTreeClean(repository: string, left: string, right: string): boolean {
  const result = spawnSync("git", ["merge-tree", "--write-tree", left, right], {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (result.status === 0) return true;
  if (result.status === 1) return false;
  throw new Error("migration merge-tree conflict probe failed");
}

export function verifyMigrationDisposition(value: unknown): Readonly<JsonObject> {
  const disposition = object(value, "compatibility disposition");
  if (disposition["schema"] !== "dacs-forge-compatibility-disposition/v1" || disposition["version"] !== "0.1.1"
    || disposition["status"] !== "qualified-public-evidence") throw new Error("compatibility identity is invalid");
  const predecessors = disposition["directPredecessors"];
  if (!Array.isArray(predecessors) || predecessors.length !== 1) throw new Error("exactly one direct predecessor is required");
  const predecessor = object(predecessors[0], "direct predecessor");
  if (predecessor["version"] !== "0.1.0" || predecessor["commit"] !== PRODUCT_SEAL_COMMIT
    || predecessor["tag"] !== "v0.1.0" || predecessor["tagObject"] !== PRODUCT_SEAL_TAG_OBJECT
    || predecessor["releaseId"] !== PRODUCT_SEAL_RELEASE_ID
    || predecessor["supported"] !== true || predecessor["immutable"] !== true
    || predecessor["path"] !== "metadata-only-patch-no-runtime-or-persisted-artifact-change") {
    throw new Error("direct predecessor is invalid");
  }
  const preview = object(disposition["originatingFinalPreview"], "originating final Preview");
  if (preview["version"] !== "0.1.0-preview.2" || preview["commit"] !== PREVIEW_COMMIT
    || preview["tag"] !== "v0.1.0-preview.2" || preview["supported"] !== false
    || preview["immutable"] !== true) throw new Error("originating final Preview is invalid");
  const boundary = object(disposition["extensionBoundary"], "extension boundary");
  if (JSON.stringify(boundary["exactPaths"]) !== JSON.stringify(EXACT_PATHS)
    || JSON.stringify(boundary["prefixes"]) !== JSON.stringify([PREFIX])) throw new Error("extension boundary is invalid");
  const requirements = object(disposition["requirements"], "requirements");
  for (const key of ["preserveSignedArtifacts", "preserveEvidence", "unchangedCompleteRig", "detectExtensionConflicts"]) {
    if (requirements[key] !== true) throw new Error(`migration requirement ${key} is missing`);
  }
  if (requirements["dacsPinDisposition"] !== "unchanged-v0.4") throw new Error("DACS pin disposition is invalid");
  const others = object(disposition["otherPredecessors"], "other predecessors");
  if (others["disposition"] !== "unsupported" || !Array.isArray(others["multiHopPaths"]) || others["multiHopPaths"].length !== 0) {
    throw new Error("untested predecessor disposition is invalid");
  }
  const evidence = object(disposition["qualificationEvidence"], "qualification evidence");
  if (evidence["authority"] !== "external-product-seal-qualification-record" || evidence["required"] !== true
    || evidence["embedded"] !== true || evidence["status"] !== "qualified-public-evidence"
    || evidence["index"] !== "release/qualification/index.json") throw new Error("qualification authority is invalid");
  return Object.freeze({ schema: "dacs-forge-migration-disposition-verification/v1", predecessor: PRODUCT_SEAL_COMMIT,
    originatingFinalPreview: PREVIEW_COMMIT, status: "qualified-public-evidence" });
}

export function verifyMigrationEvidence(
  disposition: unknown,
  evidenceValue: unknown,
  expected: Readonly<{ candidateCommit: string; rigDefinitionSha256: string }>,
  observed: Readonly<{
    previewAncestorOfCandidate: boolean;
    previewAncestorOfFork: boolean;
    candidateAncestorOfTip: boolean;
    previewForkAncestorOfTip: boolean;
    migrationHeadMatches: boolean;
    previewForkPathsWithinBoundary: boolean;
    mergeTreeClean: boolean;
    migrationTree: string;
    changedPaths: readonly string[];
    conflictingExtensionPaths: readonly string[];
    artifactGraphSha256: string;
    priorEvidenceSha256: string;
    rigEvidenceSha256: string;
    consumerReportSha256: string;
  }>,
): Readonly<JsonObject> {
  verifyMigrationDisposition(disposition);
  const evidence = object(evidenceValue, "migration qualification evidence");
  if (evidence["schema"] !== "dacs-forge-migration-qualification/v1" || evidence["predecessorCommit"] !== PREVIEW_COMMIT
    || evidence["candidateVersion"] !== "0.1.0" || evidence["dacsCommit"] !== DACS_COMMIT) {
    throw new Error("migration qualification identity is invalid");
  }
  if (typeof evidence["candidateCommit"] !== "string" || !/^[0-9a-f]{40}$/.test(evidence["candidateCommit"])
    || evidence["candidateCommit"] !== expected.candidateCommit) {
    throw new Error("candidate commit is invalid");
  }
  if (typeof evidence["previewForkCommit"] !== "string" || !/^[0-9a-f]{40}$/.test(evidence["previewForkCommit"])
    || typeof evidence["migrationTipCommit"] !== "string" || !/^[0-9a-f]{40}$/.test(evidence["migrationTipCommit"])
    || evidence["migrationTree"] !== observed.migrationTree) throw new Error("migration Git identity is invalid");
  const changed = evidence["changedPaths"];
  if (!Array.isArray(changed) || changed.length === 0 || changed.some((path) => typeof path !== "string"
    || (!EXACT_PATHS.includes(path) && !path.startsWith(PREFIX)))) throw new Error("migration changes leave the extension boundary");
  if (JSON.stringify(changed) !== JSON.stringify(observed.changedPaths)) throw new Error("migration changed paths do not match Git");
  if (!observed.previewAncestorOfCandidate || !observed.previewAncestorOfFork || !observed.candidateAncestorOfTip
    || !observed.previewForkAncestorOfTip || !observed.migrationHeadMatches
    || !observed.previewForkPathsWithinBoundary || evidence["sharedHistory"] !== true) {
    throw new Error("migration shared history is invalid");
  }
  if (!observed.mergeTreeClean || observed.conflictingExtensionPaths.length !== 0 || evidence["conflictsChecked"] !== true) {
    throw new Error("migration extension conflict detected");
  }
  for (const key of ["signedArtifactsPreserved", "evidencePreserved", "completeRigPassed"]) {
    if (evidence[key] !== true) throw new Error(`migration evidence ${key} is not green`);
  }
  for (const key of ["artifactGraphSha256", "priorEvidenceSha256", "rigEvidenceSha256", "consumerReportSha256", "rigDefinitionSha256"]) {
    if (typeof evidence[key] !== "string" || !SHA256.test(String(evidence[key]))) throw new Error(`${key} is invalid`);
  }
  if (evidence["rigDefinitionSha256"] !== expected.rigDefinitionSha256) throw new Error("rig definition digest mismatch");
  for (const [key, digest] of [
    ["artifactGraphSha256", observed.artifactGraphSha256],
    ["priorEvidenceSha256", observed.priorEvidenceSha256],
    ["rigEvidenceSha256", observed.rigEvidenceSha256],
    ["consumerReportSha256", observed.consumerReportSha256],
  ] as const) if (evidence[key] !== digest) throw new Error(`${key} does not match referenced bytes`);
  return Object.freeze({ schema: "dacs-forge-migration-qualification-verification/v1",
    candidateCommit: evidence["candidateCommit"], predecessorCommit: PREVIEW_COMMIT });
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, "..");
  const disposition = JSON.parse(readFileSync(resolve(root, "release/compatibility.json"), "utf8"));
  if (process.argv.includes("--contract-only")) console.log(JSON.stringify(verifyMigrationDisposition(disposition)));
  else {
    const option = (name: string): string => {
      const index = process.argv.indexOf(name);
      const value = index >= 0 ? process.argv[index + 1] : undefined;
      if (value === undefined) throw new Error(`${name} is required`);
      return resolve(value);
    };
    const path = option("--evidence");
    const repository = option("--repository");
    const artifactGraph = option("--artifact-graph");
    const priorEvidence = option("--prior-evidence");
    const rigEvidence = option("--rig-evidence");
    const consumerReport = option("--consumer-report");
    const status = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
      cwd: root,
      encoding: "utf8",
    });
    if (status.status !== 0 || status.stdout !== "") throw new Error("candidate worktree is not clean");
    const git = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" });
    if (git.status !== 0) throw new Error("cannot resolve candidate commit");
    const manifest = JSON.parse(readFileSync(resolve(root, "release/release-manifest.json"), "utf8")) as JsonObject;
    const rig = object(manifest["rig"], "release rig");
    const definition = object(rig["definition"], "rig definition");
    const evidenceValue = JSON.parse(readFileSync(path, "utf8")) as JsonObject;
    const runGit = (args: string[]): string => {
      const result = spawnSync("git", args, { cwd: repository, encoding: "utf8", env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" } });
      if (result.status !== 0) throw new Error(`migration repository check failed: git ${args[0] ?? "command"}`);
      return result.stdout.trim();
    };
    if (runGit(["status", "--porcelain=v1", "--untracked-files=all"]) !== "") throw new Error("migration repository is not clean");
    const candidateCommit = git.stdout.trim();
    const previewForkCommit = String(evidenceValue["previewForkCommit"]);
    const migrationTipCommit = String(evidenceValue["migrationTipCommit"]);
    const ancestor = (older: string, newer: string): boolean => {
      const result = spawnSync("git", ["merge-base", "--is-ancestor", older, newer], {
        cwd: repository,
        env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
      });
      if (result.status === 0) return true;
      if (result.status === 1) return false;
      throw new Error("migration ancestry check failed");
    };
    const candidatePaths = gitChangedPaths(repository, `${PREVIEW_COMMIT}..${candidateCommit}`);
    const forkPaths = gitChangedPaths(repository, `${PREVIEW_COMMIT}..${previewForkCommit}`);
    const conflictingExtensionPaths = candidatePaths.filter((candidatePath) =>
      (EXACT_PATHS.includes(candidatePath) || candidatePath.startsWith(PREFIX)) && forkPaths.includes(candidatePath));
    const digest = (file: string): string => new Bun.CryptoHasher("sha256").update(readFileSync(file)).digest("hex");
    console.log(JSON.stringify(verifyMigrationEvidence(disposition, evidenceValue,
      { candidateCommit, rigDefinitionSha256: String(definition["inventorySha256"]) },
      {
        previewAncestorOfCandidate: ancestor(PREVIEW_COMMIT, candidateCommit),
        previewAncestorOfFork: ancestor(PREVIEW_COMMIT, previewForkCommit),
        candidateAncestorOfTip: ancestor(candidateCommit, migrationTipCommit),
        previewForkAncestorOfTip: ancestor(previewForkCommit, migrationTipCommit),
        migrationHeadMatches: runGit(["rev-parse", "HEAD"]) === migrationTipCommit,
        previewForkPathsWithinBoundary: forkPaths.every((forkPath) =>
          EXACT_PATHS.includes(forkPath) || forkPath.startsWith(PREFIX)),
        mergeTreeClean: gitMergeTreeClean(repository, candidateCommit, previewForkCommit),
        migrationTree: runGit(["rev-parse", `${migrationTipCommit}^{tree}`]),
        changedPaths: gitChangedPaths(repository, `${candidateCommit}..${migrationTipCommit}`),
        conflictingExtensionPaths,
        artifactGraphSha256: digest(artifactGraph),
        priorEvidenceSha256: digest(priorEvidence),
        rigEvidenceSha256: digest(rigEvidence),
        consumerReportSha256: digest(consumerReport),
      })));
  }
}

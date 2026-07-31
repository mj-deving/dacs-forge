import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import disposition from "../../release/compatibility.json";
import {
  gitChangedPaths,
  gitMergeTreeClean,
  verifyMigrationDisposition,
  verifyMigrationEvidence,
} from "../../scripts/verify-migrations.ts";

const repositories: string[] = [];

afterEach(() => {
  for (const repository of repositories.splice(0)) rmSync(repository, { recursive: true, force: true });
});

function git(repository: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd: repository, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed`);
  return result.stdout.trim();
}

function evidence(): Record<string, unknown> {
  return {
    schema: "dacs-forge-migration-qualification/v1",
    predecessorCommit: "0c6e92cc707c62db0ca3c9627d59bb95ba9970e9",
    candidateCommit: "1".repeat(40),
    candidateVersion: "0.1.0",
    dacsCommit: "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
    changedPaths: ["service/handler.ts", "service/fixtures/counterparty.ts"],
    sharedHistory: true,
    signedArtifactsPreserved: true,
    evidencePreserved: true,
    conflictsChecked: true,
    completeRigPassed: true,
    artifactGraphSha256: "2".repeat(64),
    priorEvidenceSha256: "3".repeat(64),
    rigEvidenceSha256: "5".repeat(64),
    consumerReportSha256: "6".repeat(64),
    rigDefinitionSha256: "4".repeat(64),
    previewForkCommit: "7".repeat(40),
    migrationTipCommit: "8".repeat(40),
    migrationTree: "9".repeat(40),
  };
}

const EXPECTED = {
  candidateCommit: "1".repeat(40),
  rigDefinitionSha256: "4".repeat(64),
};

const OBSERVED = {
  previewAncestorOfCandidate: true,
  previewAncestorOfFork: true,
  candidateAncestorOfTip: true,
  previewForkAncestorOfTip: true,
  migrationHeadMatches: true,
  previewForkPathsWithinBoundary: true,
  mergeTreeClean: true,
  migrationTree: "9".repeat(40),
  changedPaths: ["service/handler.ts", "service/fixtures/counterparty.ts"],
  conflictingExtensionPaths: [],
  artifactGraphSha256: "2".repeat(64),
  priorEvidenceSha256: "3".repeat(64),
  rigEvidenceSha256: "5".repeat(64),
  consumerReportSha256: "6".repeat(64),
};

describe("Product Seal migration disposition", () => {
  test("declares one v0.1.0 patch predecessor and public qualification edge", () => {
    expect(verifyMigrationDisposition(disposition)).toEqual({
      schema: "dacs-forge-migration-disposition-verification/v1",
      predecessor: "81507c792c158a5782ea67e6c43c873d49356903",
      originatingFinalPreview: "0c6e92cc707c62db0ca3c9627d59bb95ba9970e9",
      status: "qualified-public-evidence",
    });
  });

  test("accepts a separately supplied exact qualification record", () => {
    expect(verifyMigrationEvidence(disposition, evidence(), EXPECTED, OBSERVED)).toMatchObject({
      schema: "dacs-forge-migration-qualification-verification/v1",
      candidateCommit: "1".repeat(40),
    });
  });

  test("rejects core drift, out-of-bound changes, and failed preservation", () => {
    const badPath = evidence();
    badPath["changedPaths"] = ["src/index.ts"];
    expect(() => verifyMigrationEvidence(disposition, badPath, EXPECTED, OBSERVED)).toThrow("extension boundary");
    const lost = evidence();
    lost["signedArtifactsPreserved"] = false;
    expect(() => verifyMigrationEvidence(disposition, lost, EXPECTED, OBSERVED)).toThrow("not green");
    const wrongCandidate = evidence();
    wrongCandidate["candidateCommit"] = "2".repeat(40);
    expect(() => verifyMigrationEvidence(disposition, wrongCandidate, EXPECTED, OBSERVED)).toThrow("candidate commit");
    const wrongRig = evidence();
    wrongRig["rigDefinitionSha256"] = "5".repeat(64);
    expect(() => verifyMigrationEvidence(disposition, wrongRig, EXPECTED, OBSERVED)).toThrow("rig definition");
    expect(() => verifyMigrationEvidence(disposition, evidence(), EXPECTED, {
      ...OBSERVED,
      candidateAncestorOfTip: false,
    })).toThrow("shared history");
    expect(() => verifyMigrationEvidence(disposition, evidence(), EXPECTED, {
      ...OBSERVED,
      conflictingExtensionPaths: ["service/handler.ts"],
    })).toThrow("extension conflict");
    expect(() => verifyMigrationEvidence(disposition, evidence(), EXPECTED, {
      ...OBSERVED,
      migrationHeadMatches: false,
    })).toThrow("shared history");
    expect(() => verifyMigrationEvidence(disposition, evidence(), EXPECTED, {
      ...OBSERVED,
      previewForkPathsWithinBoundary: false,
    })).toThrow("shared history");
    expect(() => verifyMigrationEvidence(disposition, evidence(), EXPECTED, {
      ...OBSERVED,
      mergeTreeClean: false,
    })).toThrow("extension conflict");
    const changed = structuredClone(disposition) as unknown as Record<string, any>;
    (changed["directPredecessors"] as unknown[]).push(
      structuredClone((changed["directPredecessors"] as unknown[])[0]),
    );
    expect(() => verifyMigrationDisposition(changed)).toThrow("exactly one");
  });

  test("reports both sides of a core-to-extension rename", () => {
    const repository = mkdtempSync(join(tmpdir(), "dacs-forge-migration-paths-"));
    repositories.push(repository);
    git(repository, "init", "--quiet");
    git(repository, "config", "user.name", "Fixture");
    git(repository, "config", "user.email", "fixture@example.invalid");
    mkdirSync(join(repository, "src"), { recursive: true });
    writeFileSync(join(repository, "src/core.ts"), "export const core = true;\n");
    git(repository, "add", ".");
    git(repository, "commit", "--quiet", "-m", "base");
    const base = git(repository, "rev-parse", "HEAD");
    mkdirSync(join(repository, "service/fixtures"), { recursive: true });
    git(repository, "mv", "src/core.ts", "service/fixtures/core.ts");
    git(repository, "commit", "--quiet", "-m", "rename");
    expect(gitChangedPaths(repository, `${base}..HEAD`)).toEqual([
      "service/fixtures/core.ts",
      "src/core.ts",
    ]);
  });

  test("detects an extension directory/file merge conflict", () => {
    const repository = mkdtempSync(join(tmpdir(), "dacs-forge-migration-conflict-"));
    repositories.push(repository);
    git(repository, "init", "--quiet");
    git(repository, "config", "user.name", "Fixture");
    git(repository, "config", "user.email", "fixture@example.invalid");
    writeFileSync(join(repository, "README.md"), "base\n");
    git(repository, "add", ".");
    git(repository, "commit", "--quiet", "-m", "base");
    const base = git(repository, "rev-parse", "HEAD");
    git(repository, "switch", "--quiet", "-c", "candidate");
    mkdirSync(join(repository, "service/fixtures"), { recursive: true });
    writeFileSync(join(repository, "service/fixtures/slot"), "candidate\n");
    git(repository, "add", ".");
    git(repository, "commit", "--quiet", "-m", "candidate");
    const candidate = git(repository, "rev-parse", "HEAD");
    git(repository, "switch", "--quiet", "-c", "fork", base);
    mkdirSync(join(repository, "service/fixtures/slot"), { recursive: true });
    writeFileSync(join(repository, "service/fixtures/slot/item"), "fork\n");
    git(repository, "add", ".");
    git(repository, "commit", "--quiet", "-m", "fork");
    expect(gitMergeTreeClean(repository, candidate, "HEAD")).toBe(false);
  });
});

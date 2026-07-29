#!/usr/bin/env bun

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import packageMetadata from "../package.json";

const DACS_RELEASE_COMMIT = "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091";
const COMMUNITY_DIRECTORY_COMMIT = "634caef4b952838281c8c602402e657d41074703";
const PRIOR_PUBLIC_PREVIEW_COMMIT = "7b964e79d48e6863892140780cea2b26db764439";
const PRIOR_PUBLIC_PREVIEW_TAG = "v0.1.0-preview.1";

type JsonObject = Readonly<Record<string, unknown>>;

function expectedProfile(version: string): JsonObject {
  const tag = `v${version}`;
  return {
    schema: "dacs-forge-preview-profile/v2",
    version,
    tag,
    maturity: "unsupported-final-preview",
    supported: false,
    repository: "https://github.com/mj-deving/dacs-forge",
    priorPublicAuthority: PRIOR_PUBLIC_PREVIEW_COMMIT,
    sourceBinding: {
      kind: "git-tag-and-live-readback",
      requiredRef: `refs/tags/${tag}`,
      candidateCommitAuthority: "approval-envelope",
    },
    releaseImmutability: {
      required: true,
      activationScope: "future-releases-only",
      activationRequest: {
        method: "PUT",
        endpoint: "/repos/mj-deving/dacs-forge/immutable-releases",
        apiVersion: "2026-03-10",
        authentication: "repository-administration-write",
        expectedStatus: 204,
      },
      readbackRequest: {
        method: "GET",
        endpoint: "/repos/mj-deving/dacs-forge/immutable-releases",
        apiVersion: "2026-03-10",
        authentication: "repository-administration-read",
        expectedStatus: 200,
        expectedBody: { enabled: true, enforced_by_owner: false },
      },
      publicationMode: "draft-then-publish",
      verificationCommand: `gh release verify ${tag} --repo mj-deving/dacs-forge`,
      predecessor: {
        tag: PRIOR_PUBLIC_PREVIEW_TAG,
        commit: PRIOR_PUBLIC_PREVIEW_COMMIT,
        releaseImmutable: false,
      },
    },
    pins: {
      dacsStandard: { tag: "v0.4", commit: DACS_RELEASE_COMMIT },
      community: { listingFixtureCommit: COMMUNITY_DIRECTORY_COMMIT },
    },
    capabilities: {
      fixtureNoSpendLifecycle: "implemented",
      handlerToTerminalArtifactGraph: "implemented",
      extensionOnlyServiceFork: "qualified",
      independentArtifactConsumer: "qualified",
      liveRegistration: "unsupported",
      livePayment: "unsupported",
      productionDeployment: "unsupported",
      normativeConformanceAuthority: "not-claimed",
    },
    rig: {
      commands: [
        "bun install --frozen-lockfile",
        "bun run verify:public-export",
        "bun run verify:preview-profile",
        "bun run verify:provenance",
        "bun run typecheck",
        "bun test --timeout 10000",
        "bun run build",
        "bun run mutation:calibrate",
        "bun run verify:container",
      ],
      externalEvidenceBinding: "private-qualification-authority",
    },
    distributedArtifacts: ["git-source-tag", "github-generated-source-archive"],
    claims: {
      productSeal: false,
      certification: false,
      stewardEndorsement: false,
      communityListing: false,
      adoption: false,
    },
  };
}

export function verifyPreviewProfile(
  profile: unknown,
  metadata: JsonObject,
  provenance: JsonObject,
): Readonly<{ schema: string; version: string; tag: string; dacsCommit: string; communityCommit: string }> {
  const version = metadata["version"];
  if (typeof version !== "string" || !/^0\.[0-9]+\.[0-9]+-preview\.[1-9][0-9]*$/.test(version)) {
    throw new Error("package version is not a final Preview SemVer");
  }
  if (metadata["private"] !== true) throw new Error("Preview source candidate must remain non-publishable");
  if (JSON.stringify(profile) !== JSON.stringify(expectedProfile(version))) {
    throw new Error("Preview profile differs from the closed candidate contract");
  }
  const upstream = provenance["upstreamPins"] as JsonObject | undefined;
  const dacs = upstream?.["dacsStandard"] as JsonObject | undefined;
  const community = upstream?.["community"] as JsonObject | undefined;
  if (dacs?.["main"] !== DACS_RELEASE_COMMIT || dacs?.["next"] !== DACS_RELEASE_COMMIT) {
    throw new Error("source provenance does not bind the released DACS v0.4 commit");
  }
  if (community?.["listingFixtureSource"] !== COMMUNITY_DIRECTORY_COMMIT) {
    throw new Error("source provenance does not bind the Community fixture commit");
  }
  return Object.freeze({
    schema: "dacs-forge-preview-profile-verification/v1",
    version,
    tag: `v${version}`,
    dacsCommit: DACS_RELEASE_COMMIT,
    communityCommit: COMMUNITY_DIRECTORY_COMMIT,
  });
}

function git(root: string, args: readonly string[]): string {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`Preview repository check failed: git ${args[0] ?? "command"}`);
  return result.stdout.trim();
}

export function verifyPreviewRepository(root: string): Readonly<{
  schema: string;
  candidateCommit: string;
  priorPublicAuthority: string;
}> {
  const candidateCommit = git(root, ["rev-parse", "--verify", "HEAD"]);
  if (!/^[0-9a-f]{40}$/.test(candidateCommit)) throw new Error("Preview candidate commit is invalid");
  git(root, ["merge-base", "--is-ancestor", PRIOR_PUBLIC_PREVIEW_COMMIT, candidateCommit]);
  if (git(root, ["status", "--porcelain=v1", "--untracked-files=all"]) !== "") {
    throw new Error("Preview candidate worktree is not clean");
  }
  return Object.freeze({
    schema: "dacs-forge-preview-repository-verification/v1",
    candidateCommit,
    priorPublicAuthority: PRIOR_PUBLIC_PREVIEW_COMMIT,
  });
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, "..");
  const profile = JSON.parse(readFileSync(resolve(root, "release/preview-profile.json"), "utf8"));
  const provenance = JSON.parse(readFileSync(resolve(root, "docs/SOURCE-PROVENANCE.json"), "utf8"));
  console.log(JSON.stringify({
    profile: verifyPreviewProfile(profile, packageMetadata, provenance),
    repository: verifyPreviewRepository(root),
  }));
}

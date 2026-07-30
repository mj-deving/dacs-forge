#!/usr/bin/env bun

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import packageMetadata from "../package.json";

type JsonObject = Record<string, unknown>;

const VERSION = "0.1.0";
const TAG = "v0.1.0";
const PREVIEW_COMMIT = "0c6e92cc707c62db0ca3c9627d59bb95ba9970e9";
const DACS_COMMIT = "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091";
const COMMUNITY_COMMIT = "634caef4b952838281c8c602402e657d41074703";
const COMMUNITY_MAIN = "f2fd2145cddfd12ecaa32da2b953e859ec3fd8c3";
const SHA256 = /^[0-9a-f]{64}$/;
const DACS_VECTOR_SOURCES = [
  "db9f9c0075a63d69d4464bac62cbfb2362a3f223",
  "c4ace086a6f7117784d65f527b93e632039db6de",
  "ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4",
  "fcbf804dcc53184726eed4385d794a0fdbbe00cc",
  "9a1ca624e8cc68361cff35c85a919cd72ba25199",
  "2567c6c357d3fd28f75034b920258f2fd7da20d7",
  DACS_COMMIT,
] as const;
const RIG_COMMANDS = [
  "bun install --frozen-lockfile --ignore-scripts",
  "bun run verify:public-export",
  "bun run verify:release-manifest",
  "bun run verify:migrations -- --evidence <qualification-record.json> --repository <migrated-fork> --artifact-graph <artifact-graph.json> --prior-evidence <prior-evidence.json> --rig-evidence <rig-evidence.json> --consumer-report <consumer-report.json>",
  "bun run verify:directory-supply -- --repository <migrated-fork> --base <candidate-commit> --tip <migration-tip>",
  "bun run verify:fork -- --repository <migrated-fork> --base <candidate-commit> --tip <migration-tip>",
  "bun run verify:product-seal-fork",
  "bun run verify:governance",
  "bun run verify:provenance",
  "bun run typecheck",
  "bun test --timeout 10000",
  "bun run build",
  "bun run mutation:calibrate",
  "bun run verify:container",
] as const;

function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} is invalid`);
  return value as JsonObject;
}

function sha256(bytes: Uint8Array | string): string {
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

function git(root: string, args: readonly string[]): string {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`release manifest check failed: git ${args[0] ?? "command"}`);
  return result.stdout.trim();
}

export function rigInventory(root: string): string {
  const tracked = git(root, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    .split("\0").filter((path) => path.length > 0 && existsSync(resolve(root, path))).filter((path) =>
    path === ".tool-versions" || path === "package.json" || path === "bun.lock" || path === "tsconfig.json"
    || path === "Dockerfile" || path === "compose.yaml" || path.startsWith(".github/workflows/")
    || path.startsWith("scripts/") || path.startsWith("test/") || path.startsWith("tools/"));
  tracked.sort();
  return sha256(tracked.map((path) => `${path}\0${sha256(readFileSync(resolve(root, path)))}`).join("\n"));
}

export function verifyReleaseManifest(root: string, manifest: unknown, profile: unknown, compatibility: unknown): Readonly<JsonObject> {
  const value = object(manifest, "release manifest");
  if (value["schema"] !== "dacs-forge-release-manifest/v1") throw new Error("unknown release manifest schema");
  if (value["version"] !== VERSION || value["tag"] !== TAG || value["releaseKind"] !== "product-seal") {
    throw new Error("release identity is invalid");
  }
  if (packageMetadata.version !== VERSION || packageMetadata.private !== true) {
    throw new Error("package and source-only release identity disagree");
  }
  const support = object(value["support"], "support");
  if (support["status"] !== "activates-on-immutable-release-readback"
    || support["prepublicationStatus"] !== "candidate-not-supported") throw new Error("support activation is invalid");
  const source = object(value["sourceBinding"], "source binding");
  if (source["kind"] !== "containing-commit-via-annotated-tag" || source["requiredRef"] !== `refs/tags/${TAG}`
    || source["candidateCommitAuthority"] !== "annotated-tag-target-and-live-readback"
    || source["historyBase"] !== PREVIEW_COMMIT || source["liveReadbackRequired"] !== true) {
    throw new Error("source binding is invalid");
  }
  if (Object.hasOwn(source, "commit") || Object.hasOwn(value, "sourceCommit")) {
    throw new Error("manifest must not embed its containing commit");
  }
  const predecessor = object(value["mandatoryPredecessor"], "mandatory predecessor");
  if (predecessor["version"] !== "0.1.0-preview.2" || predecessor["tag"] !== "v0.1.0-preview.2"
    || predecessor["commit"] !== PREVIEW_COMMIT || predecessor["supported"] !== false || predecessor["immutable"] !== true) {
    throw new Error("mandatory predecessor is invalid");
  }
  const pins = object(value["pins"], "pins");
  const dacs = object(pins["dacsStandard"], "DACS pin");
  const community = object(pins["community"], "Community pin");
  if (dacs["profile"] !== "v0.4" || dacs["tag"] !== "v0.4" || dacs["commit"] !== DACS_COMMIT
    || JSON.stringify(dacs["vectorSources"]) !== JSON.stringify(DACS_VECTOR_SOURCES)
    || community["main"] !== COMMUNITY_MAIN || community["listingFixtureCommit"] !== COMMUNITY_COMMIT) {
    throw new Error("upstream pins are invalid");
  }
  const expectedProfile = {
    schema: "dacs-forge-capability-profile/v1",
    version: VERSION,
    releaseKind: "product-seal",
    support: { status: "activates-on-immutable-release-readback", prepublicationStatus: "candidate-not-supported" },
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
    claims: {
      productSeal: "activates-on-immutable-release-readback",
      certification: false,
      stewardEndorsement: false,
      communityListing: false,
      adoption: false,
    },
  };
  if (JSON.stringify(profile) !== JSON.stringify(expectedProfile)) throw new Error("capability profile is invalid");
  const contracts = object(value["contracts"], "contracts");
  for (const [key, path, candidate] of [
    ["capabilityProfile", "release/capability-profile.json", profile],
    ["compatibilityDisposition", "release/compatibility.json", compatibility],
  ] as const) {
    const reference = object(contracts[key], `${key} reference`);
    if (reference["path"] !== path || !SHA256.test(String(reference["sha256"]))) throw new Error(`${key} reference is invalid`);
    if (sha256(readFileSync(resolve(root, path))) !== reference["sha256"]
      || sha256(`${JSON.stringify(candidate, null, 2)}\n`) !== reference["sha256"]) throw new Error(`${key} digest mismatch`);
  }
  for (const [key, path] of Object.entries({
    upgrading: "UPGRADING.md",
    governance: "GOVERNANCE.md",
    security: "SECURITY.md",
    contributing: "CONTRIBUTING.md",
    provenance: "docs/SOURCE-PROVENANCE.json",
  })) {
    if (contracts[key] !== path || !existsSync(resolve(root, path))) throw new Error(`${key} contract reference is invalid`);
  }
  const rig = object(value["rig"], "rig");
  if (JSON.stringify(rig["commands"]) !== JSON.stringify(RIG_COMMANDS)) throw new Error("release rig is incomplete");
  const definition = object(rig["definition"], "rig definition");
  if (definition["inventorySha256"] !== rigInventory(root)) throw new Error("release rig inventory digest mismatch");
  const evidence = object(rig["qualificationEvidence"], "qualification evidence");
  if (evidence["authority"] !== "external-product-seal-qualification-record" || evidence["required"] !== true
    || evidence["embedded"] !== false || evidence["prepublicationStatus"] !== "pending") {
    throw new Error("qualification evidence boundary is invalid");
  }
  const expectedDistributed = [
    { kind: "git-source-tag", ref: `refs/tags/${TAG}` },
    { kind: "github-generated-source-archive", formats: ["tar.gz", "zip"] },
  ];
  if (JSON.stringify(value["distributedArtifacts"]) !== JSON.stringify(expectedDistributed)
    || JSON.stringify(value["notDistributed"]) !== JSON.stringify({ package: true, containerImage: true, binary: true })) {
    throw new Error("distributed artifact inventory is invalid");
  }
  if (JSON.stringify(value["claims"]) !== JSON.stringify({
    certification: false,
    stewardEndorsement: false,
    communityListing: false,
    adoption: false,
  })) throw new Error("release claims are invalid");
  return Object.freeze({ schema: "dacs-forge-release-manifest-verification/v1", version: VERSION, tag: TAG,
    predecessor: PREVIEW_COMMIT, dacsCommit: DACS_COMMIT, communityCommit: COMMUNITY_COMMIT,
    rigInventorySha256: definition["inventorySha256"] });
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, "..");
  const read = (path: string): unknown => JSON.parse(readFileSync(resolve(root, path), "utf8"));
  console.log(JSON.stringify(verifyReleaseManifest(root, read("release/release-manifest.json"),
    read("release/capability-profile.json"), read("release/compatibility.json"))));
}

#!/usr/bin/env bun

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

type JsonObject = Record<string, unknown>;

const VERSION = "0.1.1";
const TAG = "v0.1.1";
const SHA256 = /^[0-9a-f]{64}$/;
const ASSET_PREFIX = `https://github.com/mj-deving/dacs-forge/releases/download/${TAG}/`;
const CONSUMER_REPORT_PATH = "release/qualification/independent-consumer.json";
const FORK_REPORT_PATH = "release/qualification/reference-fork.json";
const CONSUMER_REPORT_SHA256 = "a8cb7fa690be5aafdd4d6bc0da0fc4f76a5cbf1cb731f27382f3f4cbe8cacfc5";
const FORK_REPORT_SHA256 = "a896fb32b2ac73bb59721ca31f6291ef13d1125f934978924e1e2abd15490cab";
const CONSUMER_COMMIT = "a8e307a34a143357dc3e74203854ad1fa9918027";
const CONSUMER_TREE = "bc565bd13012674fb20bcaf0d7932bcc52b319bc";
const PRODUCER_COMMIT = "ab24b97652d8bcafed5be14793637665300afb87";
const PRODUCER_TREE = "b862866558b0f72ea9f3227d1c80e1af07292ad3";
const RELEASE_COMMIT = "81507c792c158a5782ea67e6c43c873d49356903";
const FORK_COMMIT = "e8b2f2cc2fd7e18dc222488866218d5d9b5e7212";
const FORK_TREE = "954cf9a3efd1eb795e2fa1b47bbd1767ce1ac458";
const AUTHORITY_COMMIT = "863ff5b0bfecf1e40a7a84d02cf1021ffa2f5866";
const AUTHORITY_TREE = "23d7424b14554db87d51daf76e593209d058a604";
const DACS_COMMIT = "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091";
const EXTENSION_PATHS = [
  "service/fixtures/basic.ts",
  "service/fixtures/corpus.ts",
  "service/fixtures/directory-supply.json",
  "service/fixtures/product-origin.json",
  "service/fixtures/service-descriptor.json",
  "service/handler.ts",
  "service/input.schema.json",
  "service/output.schema.json",
  "service/service.config.ts",
] as const;
const CONSUMER_CLAIM_BOUNDARY = "Producer-independent Forge product verification only; no normative DACS conformance, certification, external authority, registration, deployment, or live-payment claim.";
const FORK_PRODUCT_CLAIMS = ["fixture observations and source descriptors",
  "observation timestamps and content hashes", "source availability and ambiguity",
  "explicit fixture-only, no-source-truth, no-KYB-or-compliance, and time-bounded limitations"] as const;
const FORK_CLAIM_BOUNDARY = "Bounded fixture-first reference fork only; no KYB certificate, source-truth, compliance, sanctions-clearance, registration, deployment, payment, certification, or endorsement claim.";
const ASSET_NAMES = [
  "dacs-forge-v0.1.1-qualification-index.json",
  "dacs-forge-v0.1.1-independent-consumer.bundle",
  "dacs-forge-v0.1.1-independent-artifact-graph.json",
  "dacs-forge-v0.1.1-counterparty-reference.bundle",
  "dacs-forge-v0.1.1-counterparty-authority.bundle",
] as const;

function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} is invalid`);
  return value as JsonObject;
}

function digest(root: string, path: string): string {
  return new Bun.CryptoHasher("sha256").update(readFileSync(resolve(root, path))).digest("hex");
}

export function verifyPublicQualification(
  root: string,
  manifestValue: unknown,
  profileValue: unknown,
  compatibilityValue: unknown,
  indexValue: unknown,
): Readonly<JsonObject> {
  const manifest = object(manifestValue, "release manifest");
  const profile = object(profileValue, "capability profile");
  const compatibility = object(compatibilityValue, "compatibility disposition");
  const index = object(indexValue, "qualification index");
  if (manifest["version"] !== VERSION || manifest["tag"] !== TAG
    || profile["version"] !== VERSION || compatibility["version"] !== VERSION
    || index["version"] !== VERSION || index["tag"] !== TAG) {
    throw new Error("qualification release identity disagrees");
  }
  if (index["schema"] !== "dacs-forge-public-qualification-index/v1"
    || index["status"] !== "qualified-public-evidence"
    || compatibility["status"] !== index["status"]) {
    throw new Error("qualification status disagrees");
  }
  const manifestEvidence = object(object(manifest["rig"], "release rig")["qualificationEvidence"], "manifest evidence");
  const compatibilityEvidence = object(compatibility["qualificationEvidence"], "compatibility evidence");
  const profileEvidence = object(profile["qualification"], "profile evidence");
  for (const evidence of [manifestEvidence, compatibilityEvidence]) {
    if (evidence["required"] !== true || evidence["embedded"] !== true
      || evidence["status"] !== "qualified-public-evidence"
      || evidence["index"] !== "release/qualification/index.json") {
      throw new Error("machine-readable qualification boundary disagrees");
    }
  }
  if (compatibilityEvidence["consumerReport"] !== CONSUMER_REPORT_PATH
    || compatibilityEvidence["referenceForkReport"] !== FORK_REPORT_PATH) {
    throw new Error("compatibility report locators disagree");
  }
  if (profileEvidence["status"] !== "qualified-public-evidence"
    || profileEvidence["index"] !== "release/qualification/index.json"
    || profileEvidence["independentConsumer"] !== "qualified"
    || profileEvidence["extensionOnlyServiceFork"] !== "qualified") {
    throw new Error("capability qualification disagrees");
  }
  const reports = object(index["reports"], "qualification reports");
  for (const [name, schema] of [
    ["independentConsumer", "dacs-forge-independent-consumer-qualification/v1"],
    ["referenceFork", "dacs-forge-reference-fork-qualification/v1"],
  ] as const) {
    const reference = object(reports[name], `${name} report reference`);
    const path = String(reference["path"]);
    if (!path.startsWith("release/qualification/") || !SHA256.test(String(reference["sha256"]))
      || digest(root, path) !== reference["sha256"]) throw new Error(`${name} report digest mismatch`);
    const report = object(JSON.parse(readFileSync(resolve(root, path), "utf8")), `${name} report`);
    if (report["schema"] !== schema || report["version"] !== VERSION || report["status"] !== "qualified") {
      throw new Error(`${name} report identity disagrees`);
    }
  }
  if (object(reports["independentConsumer"], "consumer report reference")["sha256"] !== CONSUMER_REPORT_SHA256
    || object(reports["referenceFork"], "fork report reference")["sha256"] !== FORK_REPORT_SHA256) {
    throw new Error("qualification report authority digest disagrees");
  }
  if (object(reports["independentConsumer"], "consumer report reference")["path"] !== CONSUMER_REPORT_PATH
    || object(reports["referenceFork"], "fork report reference")["path"] !== FORK_REPORT_PATH) {
    throw new Error("qualification report locators disagree");
  }
  const consumer = object(JSON.parse(readFileSync(resolve(root, String(object(reports["independentConsumer"], "consumer report")["path"])), "utf8")), "consumer report");
  const consumerSource = object(consumer["consumer"], "consumer source");
  const inputGraph = object(consumer["inputGraph"], "input graph");
  const run = object(consumer["releaseCompatibilityRun"], "consumer run");
  const dependency = object(consumer["dependencyBoundary"], "consumer dependency boundary");
  const expectedForbidden = ["Forge source modules", "producer modules", "lifecycle modules", "fixtures",
    "database", "handler", "service implementation"];
  if (consumerSource["commit"] !== CONSUMER_COMMIT || consumerSource["tree"] !== CONSUMER_TREE
    || !SHA256.test(String(consumerSource["sha256"])) || consumerSource["completeHistory"] !== true
    || inputGraph["producerCommit"] !== PRODUCER_COMMIT || inputGraph["producerTree"] !== PRODUCER_TREE
    || !SHA256.test(String(inputGraph["sha256"]))
    || dependency["allowed"] !== "the built public Forge entrypoint"
    || JSON.stringify(dependency["forbidden"]) !== JSON.stringify(expectedForbidden)
    || consumer["claimBoundary"] !== CONSUMER_CLAIM_BOUNDARY
    || run["forgeSourceCommit"] !== RELEASE_COMMIT
    || run["tests"] !== 32 || run["failures"] !== 0 || run["result"] !== "pass") {
    throw new Error("independent consumer qualification is incomplete");
  }
  const fork = object(JSON.parse(readFileSync(resolve(root, String(object(reports["referenceFork"], "fork report")["path"])), "utf8")), "fork report");
  const migration = object(fork["migration"], "fork migration");
  const authority = object(fork["productAuthority"], "fork authority");
  const extension = object(fork["extensionBoundary"], "fork extension boundary");
  const negatives = object(fork["negativeTests"], "fork negative tests");
  const rig = object(fork["rig"], "fork rig");
  const effects = object(fork["effects"], "fork effects");
  if (migration["baseCommit"] !== RELEASE_COMMIT || migration["tipCommit"] !== FORK_COMMIT
    || migration["tipTree"] !== FORK_TREE
    || migration["completeHistory"] !== true || migration["sharedForgeHistory"] !== true
    || !SHA256.test(String(migration["sourceSha256"]))
    || authority["commit"] !== AUTHORITY_COMMIT || authority["tree"] !== AUTHORITY_TREE
    || authority["progress"] !== "29/29" || !SHA256.test(String(authority["sourceSha256"]))
    || authority["completeHistory"] !== true
    || JSON.stringify(extension["changedPaths"]) !== JSON.stringify(EXTENSION_PATHS)
    || extension["trustedRigModified"] !== false || negatives["invalidInputs"] !== 6
    || JSON.stringify(negatives["covers"]) !== JSON.stringify(["missing subject",
      "simultaneous entity name and identifier", "empty source selection", "duplicate source selection",
      "unknown source", "unsupported jurisdiction"])
    || negatives["outputBoundary"] !== "output schema requires bounded observations, descriptors, availability, ambiguity, and explicit limitations"
    || JSON.stringify(fork["boundedProductClaims"]) !== JSON.stringify(FORK_PRODUCT_CLAIMS)
    || fork["claimBoundary"] !== FORK_CLAIM_BOUNDARY
    || rig["dacsProfile"] !== "v0.4" || rig["dacsCommit"] !== DACS_COMMIT
    || ["baseInstall", "forkInstall", "baseDoctor", "forkDoctor", "baseRig", "forkRig", "qualification"]
      .some((key) => rig[key] !== "pass")
    || JSON.stringify(effects) !== JSON.stringify({ registration: false, deployment: false, payment: false,
      transfer: false, spend: false, liveValue: false })) {
    throw new Error("reference-fork qualification is incomplete");
  }
  const assets = index["releaseAssets"];
  if (!Array.isArray(assets) || assets.length !== 5) throw new Error("qualification asset inventory is incomplete");
  if (JSON.stringify(assets.map((candidate) => object(candidate, "qualification asset")["name"]))
    !== JSON.stringify(ASSET_NAMES)) throw new Error("qualification asset inventory names disagree");
  const names = new Set<string>();
  const assetDigests = new Map<string, string>();
  for (const candidate of assets) {
    const asset = object(candidate, "qualification asset");
    const name = String(asset["name"]);
    if (names.has(name) || asset["url"] !== `${ASSET_PREFIX}${name}`) throw new Error("qualification asset locator is invalid");
    names.add(name);
    if (name.endsWith("qualification-index.json")) {
      if (asset["sourcePath"] !== "release/qualification/index.json"
        || asset["digestAuthority"] !== "release-manifest-contract") throw new Error("qualification index asset is unbound");
    } else if (!SHA256.test(String(asset["sha256"]))) throw new Error("qualification asset digest is invalid");
    else assetDigests.set(name, String(asset["sha256"]));
  }
  for (const [name, expectedDigest] of [[consumerSource["asset"], consumerSource["sha256"]],
    [inputGraph["asset"], inputGraph["sha256"]], [migration["sourceAsset"], migration["sourceSha256"]],
    [authority["sourceAsset"], authority["sourceSha256"]]] as const) {
    if (!names.has(String(name))) throw new Error("qualified source lacks a release asset locator");
    if (assetDigests.get(String(name)) !== expectedDigest) throw new Error("qualification asset digest disagrees with report");
  }
  const attestation = object(index["attestation"], "attestation disposition");
  if (attestation["githubImmutableRelease"] !== "required"
    || attestation["githubArtifactAttestation"] !== "required-live-readback"
    || attestation["cryptographicGitTagSignature"] !== "deferred-no-maintainer-signing-identity-configured"
    || attestation["tagType"] !== "annotated") throw new Error("attestation disposition is incomplete");
  if (JSON.stringify(index["claims"]) !== JSON.stringify({ independentConsumerQualified: true,
    extensionOnlyReferenceForkQualified: true, normativeDacsConformance: false, certification: false,
    stewardEndorsement: false })) throw new Error("qualification claims are invalid");
  return Object.freeze({
    schema: "dacs-forge-public-qualification-verification/v1",
    version: VERSION,
    tag: TAG,
    reports: 2,
    releaseAssets: assets.length,
    status: "qualified-public-evidence",
  });
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, "..");
  const read = (path: string): unknown => JSON.parse(readFileSync(resolve(root, path), "utf8"));
  console.log(JSON.stringify(verifyPublicQualification(root, read("release/release-manifest.json"),
    read("release/capability-profile.json"), read("release/compatibility.json"),
    read("release/qualification/index.json"))));
}

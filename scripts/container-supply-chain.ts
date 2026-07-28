#!/usr/bin/env bun

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, normalize, relative, resolve } from "node:path";
import { verifyDockerfileBases } from "./lint-dockerfile-bases.ts";

type JsonObject = Record<string, unknown>;
type DockerAnchors = Readonly<{
  finalDigest: string; baseDigest: string;
  immutableReference: string;
}>;
type Verification = Readonly<{
  critical: number; high: number; packages: number;
  finalDigest: string; baseDigest: string;
  manifestSha256: string;
  databaseAgeMs: number;
}>;

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MAX_DB_AGE_MS = 24 * 60 * 60 * 1_000;
const MAX_DISPOSITION_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_QUALIFICATION_AGE_MS = 10 * 60 * 1_000;
const TRUSTED_TOOLS = { syft: "1.49.0", trivy: "0.69.3" } as const;

function fail(message: string): never {
  throw new Error(`container supply-chain verification failed: ${message}`);
}

function object(value: unknown, name: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${name} must be an object`);
  return value as JsonObject;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) fail(`${name} must be a non-empty string`);
  return value;
}

function instant(value: unknown, name: string): number {
  const parsed = Date.parse(string(value, name));
  if (!Number.isFinite(parsed)) fail(`${name} must be an ISO timestamp`);
  return parsed;
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`cannot read JSON ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function sha256(path: string): string {
  return new Bun.CryptoHasher("sha256").update(readFileSync(path)).digest("hex");
}

function safeArtifact(root: string, path: unknown, name: string): string {
  const candidate = string(path, name);
  if (isAbsolute(candidate) || normalize(candidate) !== candidate || candidate.startsWith("../")) {
    fail(`${name} is unsafe`);
  }
  const resolved = resolve(root, candidate);
  if (relative(root, resolved).startsWith("..")) fail(`${name} escapes the bundle`);
  return resolved;
}

function assertHash(path: string, expected: unknown, name: string): void {
  const digest = string(expected, `${name}.sha256`);
  if (!/^[0-9a-f]{64}$/.test(digest) || sha256(path) !== digest) fail(`${name} digest mismatch`);
}

function buildProvenance(path: string, baseDigest: string): string {
  const metadata = object(readJson(path), "BuildKit metadata");
  const finalDigest = string(metadata["containerimage.digest"], "BuildKit final image digest");
  const provenance = object(metadata["buildx.build.provenance"], "BuildKit provenance");
  const materials = provenance["materials"];
  const entryPoint = object(object(provenance["invocation"], "BuildKit invocation")["configSource"], "BuildKit config source")["entryPoint"];
  if (!SHA256.test(finalDigest) || provenance["buildType"] !== "https://mobyproject.org/buildkit@v1"
    || !Array.isArray(materials) || entryPoint !== "Dockerfile" || !materials.some((entry) => {
      const material = object(entry, "BuildKit material");
      const uri = string(material["uri"], "BuildKit material URI");
      return uri.startsWith("pkg:docker/") && uri.includes(`digest=${baseDigest}`)
        && object(material["digest"], "BuildKit material digest")["sha256"] === baseDigest.slice(7);
    })) {
    fail("BuildKit provenance does not bind the final image and pinned Dockerfile base");
  }
  return finalDigest;
}

function vulnerabilities(scan: JsonObject): readonly JsonObject[] {
  if (scan["SchemaVersion"] !== 2 || scan["ArtifactType"] !== "container_image") {
    fail("Trivy report has an unsupported shape");
  }
  if (!Array.isArray(scan["Results"])) fail("Trivy report Results must be an array");
  return scan["Results"].flatMap((result) => {
    const entry = object(result, "Trivy result");
    const found = entry["Vulnerabilities"];
    if (found === null || found === undefined) return [];
    if (!Array.isArray(found)) fail("Trivy vulnerabilities must be an array");
    return found.map((finding) => object(finding, "Trivy vulnerability"));
  });
}

export function verifyContainerSupplyChain(
  repositoryRoot: string,
  manifestPath: string,
  anchors: DockerAnchors,
  expectedManifestSha256: string,
  at = new Date(),
): Verification {
  const atMs = at.getTime();
  if (!Number.isFinite(atMs)) fail("verification time must be valid");
  if (!/^[0-9a-f]{64}$/.test(expectedManifestSha256) || sha256(manifestPath) !== expectedManifestSha256) {
    fail("manifest digest does not match the trusted qualification anchor");
  }
  const manifest = object(readJson(manifestPath), "manifest");
  if (manifest["schema"] !== "dacs-forge-container-supply-chain/v1") fail("unknown manifest schema");
  const releaseTime = instant(manifest["releaseTime"], "releaseTime");
  if (atMs < releaseTime || atMs - releaseTime > MAX_QUALIFICATION_AGE_MS) {
    fail("qualification evidence is not current within 10 minutes");
  }
  const bundleRoot = resolve(manifestPath, "..");
  const build = object(manifest["build"], "build");
  const buildMetadataPath = safeArtifact(bundleRoot, build["path"], "build.path");
  assertHash(buildMetadataPath, build["sha256"], "build metadata");

  const distribution = object(manifest["distribution"], "distribution");
  const signature = object(manifest["signatureProvenance"], "signatureProvenance");
  const image = object(manifest["image"], "image");
  const finalDigest = string(image["finalDigest"], "image.finalDigest");
  const baseDigest = string(image["baseDigest"], "image.baseDigest");
  if (!SHA256.test(finalDigest) || !SHA256.test(baseDigest)) fail("image digests must be sha256 values");
  if (finalDigest === baseDigest) fail("final and base image digests must be distinct");
  if (finalDigest !== anchors.finalDigest || baseDigest !== anchors.baseDigest
    || image["immutableReference"] !== anchors.immutableReference) {
    fail("manifest image identity does not match the inspected Docker images");
  }
  if (buildProvenance(buildMetadataPath, baseDigest) !== finalDigest) {
    fail("BuildKit provenance does not bind the final image digest");
  }

  const status = distribution["status"];
  if (status === "not-applicable") {
    if (distribution["imageReference"] !== null || string(distribution["reason"], "distribution.reason").length < 12) {
      fail("not-applicable distribution requires null reference and reason");
    }
    if (signature["status"] !== "not-applicable" || string(signature["reason"], "signatureProvenance.reason").length < 12) {
      fail("not-applicable signature provenance requires a reason");
    }
  } else if (status === "distributed") {
    if (string(distribution["imageReference"], "distribution.imageReference").split("@")[1] !== finalDigest) {
      fail("distributed image reference does not bind the final digest");
    }
    if (signature["status"] !== "verified") fail("distributed image signature/provenance is not verified");
    string(signature["expectedRepository"], "signatureProvenance.expectedRepository");
    string(signature["expectedWorkflowIdentity"], "signatureProvenance.expectedWorkflowIdentity");
  } else {
    fail("unknown distribution status");
  }

  const dockerfile = safeArtifact(repositoryRoot, manifest["dockerfile"], "dockerfile");
  const bases = verifyDockerfileBases(dockerfile);
  const baseReference = string(image["baseReference"], "image.baseReference");
  if (!baseReference.endsWith(`@${baseDigest}`) || !bases.some(({ reference }) => reference === baseReference)) {
    fail("recorded base image is not the pinned Dockerfile base");
  }

  const sbom = object(manifest["sbom"], "sbom");
  const sbomTool = object(sbom["tool"], "sbom.tool");
  if (sbom["format"] !== "spdx-json" || sbomTool["name"] !== "syft"
    || sbomTool["version"] !== TRUSTED_TOOLS.syft) {
    fail("SBOM must be trusted Syft SPDX JSON");
  }
  const sbomPath = safeArtifact(bundleRoot, sbom["path"], "sbom.path");
  assertHash(sbomPath, sbom["sha256"], "sbom");
  const sbomSource = object(sbom["source"], "sbom.source");
  const sbomSourcePath = safeArtifact(bundleRoot, sbomSource["path"], "sbom.source.path");
  assertHash(sbomSourcePath, sbomSource["sha256"], "sbom source");
  const sourceDocument = object(readJson(sbomSourcePath), "Syft source document");
  const source = object(sourceDocument["source"], "Syft source");
  const sourceMetadata = object(source["metadata"], "Syft source metadata");
  const sourceId = string(source["id"], "Syft source id");
  const platformDigest = string(sourceMetadata["manifestDigest"], "Syft platform manifest digest");
  if (source["type"] !== "image" || source["version"] !== finalDigest
    || !SHA256.test(platformDigest) || platformDigest !== `sha256:${sourceId}`
    || !Array.isArray(sourceMetadata["repoDigests"])
    || !sourceMetadata["repoDigests"].some((entry) => entry === anchors.immutableReference)) {
    fail("Syft source does not bind the final image digest");
  }
  const sbomDocument = object(readJson(sbomPath), "SBOM");
  const creationInfo = object(sbomDocument["creationInfo"], "SBOM creationInfo");
  if (sbomDocument["spdxVersion"] !== "SPDX-2.3" || sbomDocument["dataLicense"] !== "CC0-1.0"
    || sbomDocument["SPDXID"] !== "SPDXRef-DOCUMENT"
    || string(sbomDocument["name"], "SBOM name").length === 0
    || !string(sbomDocument["documentNamespace"], "SBOM documentNamespace").startsWith("https://")
    || !Array.isArray(creationInfo["creators"]) || creationInfo["creators"].length === 0
    || !creationInfo["creators"].every((creator) => typeof creator === "string" && creator.length > 0)
    || !Number.isFinite(Date.parse(string(creationInfo["created"], "SBOM creationInfo.created")))
    || !Array.isArray(sbomDocument["packages"]) || sbomDocument["packages"].length === 0) {
    fail("SBOM is not a valid SPDX 2.3 document");
  }
  const packages = sbomDocument["packages"].map((entry) => object(entry, "SBOM package"));
  for (const entry of packages) {
    for (const field of ["name", "SPDXID", "downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText"]) {
      string(entry[field], `SBOM package ${field}`);
    }
    if (typeof entry["filesAnalyzed"] !== "boolean") fail("SBOM package filesAnalyzed must be boolean");
  }
  const sbomRoots = packages
    .filter((entry) => string(entry["SPDXID"], "SBOM package SPDXID").startsWith("SPDXRef-DocumentRoot-Image-"));
  if (sbomRoots.length !== 1 || !Array.isArray(sbomRoots[0]!["checksums"])
    || !sbomRoots[0]!["checksums"].some((entry) => {
      const checksum = object(entry, "SBOM root checksum");
      return checksum["algorithm"] === "SHA256" && checksum["checksumValue"] === sourceId;
    })) {
    fail("SBOM does not bind its Syft image source");
  }

  const scan = object(manifest["scan"], "scan");
  const scanTool = object(scan["tool"], "scan.tool");
  if (scanTool["name"] !== "trivy" || scanTool["version"] !== TRUSTED_TOOLS.trivy) {
    fail("scan tool must be trusted Trivy");
  }
  const scanPath = safeArtifact(bundleRoot, scan["path"], "scan.path");
  assertHash(scanPath, scan["sha256"], "scan");
  const scanDocument = object(readJson(scanPath), "scan report");
  const metadata = object(scanDocument["Metadata"], "scan Metadata");
  if (metadata["ImageID"] !== finalDigest || !Array.isArray(metadata["RepoDigests"])
    || !metadata["RepoDigests"].includes(anchors.immutableReference)) {
    fail("Trivy report does not bind the final image digest");
  }

  const database = object(scan["database"], "scan.database");
  const metadataPath = safeArtifact(bundleRoot, database["metadataPath"], "scan.database.metadataPath");
  const databasePath = safeArtifact(bundleRoot, database["path"], "scan.database.path");
  assertHash(metadataPath, database["metadataSha256"], "scan database metadata");
  assertHash(databasePath, database["sha256"], "scan database");
  const databaseMetadata = object(readJson(metadataPath), "Trivy database metadata");
  const updatedAt = instant(databaseMetadata["UpdatedAt"], "Trivy database UpdatedAt");
  if (updatedAt !== instant(database["updatedAt"], "scan.database.updatedAt")) fail("database time is not metadata-bound");
  const databaseAgeMs = atMs - updatedAt;
  if (databaseAgeMs < 0 || databaseAgeMs > MAX_DB_AGE_MS) fail("vulnerability database is not fresh within 24 hours");

  const findings = vulnerabilities(scanDocument);
  const critical = findings.filter((finding) => finding["Severity"] === "CRITICAL");
  const high = findings.filter((finding) => finding["Severity"] === "HIGH");
  if (critical.length > 0) fail(`critical vulnerabilities remain: ${critical.length}`);

  const dispositions = object(manifest["dispositions"], "dispositions");
  const dispositionsPath = safeArtifact(bundleRoot, dispositions["path"], "dispositions.path");
  assertHash(dispositionsPath, dispositions["sha256"], "dispositions");
  if (sha256(dispositionsPath) !== sha256(resolve(repositoryRoot, "release/vulnerability-dispositions.json"))) {
    fail("dispositions do not match the reviewed repository policy");
  }
  const dispositionDocument = readJson(dispositionsPath);
  const schemaPath = resolve(repositoryRoot, "schemas/vulnerability-dispositions.schema.json");
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(object(readJson(schemaPath), "disposition schema"));
  if (!validate(dispositionDocument)) fail(`invalid dispositions: ${ajv.errorsText(validate.errors)}`);
  const dispositionEntries = object(dispositionDocument, "dispositions document")["dispositions"] as JsonObject[];
  const byCve = new Map<string, JsonObject>();
  for (const entry of dispositionEntries) {
    const vulnerabilityId = string(entry["vulnerabilityId"], "disposition.vulnerabilityId");
    if (vulnerabilityId.startsWith("CVE-") && entry["cve"] !== vulnerabilityId) {
      fail(`${vulnerabilityId} disposition must name its CVE`);
    }
    if (byCve.has(vulnerabilityId)) fail(`duplicate disposition ${vulnerabilityId}`);
    const createdAt = instant(entry["createdAt"], `${vulnerabilityId}.createdAt`);
    const expiresAt = instant(entry["expiresAt"], `${vulnerabilityId}.expiresAt`);
    if (expiresAt <= createdAt || expiresAt - createdAt > MAX_DISPOSITION_MS) fail(`${vulnerabilityId} expiry exceeds 30 days`);
    if (releaseTime < createdAt || releaseTime >= expiresAt || atMs >= expiresAt) {
      fail(`${vulnerabilityId} disposition is not active at verification time`);
    }
    byCve.set(vulnerabilityId, entry);
  }
  const highCves = new Set(high.map((finding) => string(finding["VulnerabilityID"], "high VulnerabilityID")));
  for (const cve of highCves) if (!byCve.has(cve)) fail(`missing high-vulnerability disposition ${cve}`);
  for (const cve of byCve.keys()) if (!highCves.has(cve)) fail(`stale disposition without high finding ${cve}`);

  return {
    critical: critical.length,
    high: highCves.size,
    packages: sbomDocument["packages"].length,
    finalDigest,
    baseDigest,
    manifestSha256: expectedManifestSha256,
    databaseAgeMs,
  };
}

function command(args: readonly string[], cwd: string): string {
  const result = Bun.spawnSync([...args], {
    cwd,
    env: {
      HOME: Bun.env["HOME"] ?? "/tmp",
      PATH: Bun.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(`${args.join(" ")} failed (${result.exitCode})\n${result.stdout.toString()}${result.stderr.toString()}`);
  }
  return result.stdout.toString("utf8").trim();
}

function option(args: readonly string[], name: string, fallback?: string): string {
  const index = args.indexOf(name);
  if (index < 0) {
    if (fallback !== undefined) return fallback;
    throw new Error(`missing ${name}`);
  }
  const value = args[index + 1];
  if (!value) throw new Error(`missing value for ${name}`);
  return value;
}

function dockerAnchors(root: string, finalReference: string, baseReference: string, buildMetadataPath: string): DockerAnchors {
  const driverStatus = JSON.parse(command(["docker", "info", "--format", "{{json .DriverStatus}}"], root)) as unknown;
  if (!Array.isArray(driverStatus) || !driverStatus.some((entry) =>
    Array.isArray(entry) && entry[0] === "driver-type" && entry[1] === "io.containerd.snapshotter.v1")) {
    fail("Docker containerd image store is required for immutable local descriptors");
  }
  const inspect = (reference: string, name: string): JsonObject => {
    const documents = JSON.parse(command(["docker", "image", "inspect", reference], root)) as unknown;
    if (!Array.isArray(documents) || documents.length !== 1) fail(`${name} Docker inspect result is not singular`);
    return object(documents[0], `${name} Docker image`);
  };
  const finalImage = inspect(finalReference, "final");
  const baseImage = inspect(baseReference, "base");
  const baseDigest = string(object(baseImage["Descriptor"], "base Docker descriptor")["digest"], "base Docker descriptor digest");
  const finalDigest = buildProvenance(buildMetadataPath, baseDigest);
  if (object(finalImage["Descriptor"], "final Docker descriptor")["digest"] !== finalDigest) {
    fail("BuildKit final digest does not match the inspected Docker image");
  }
  const repoDigests = finalImage["RepoDigests"];
  if (!Array.isArray(repoDigests)) fail("final Docker image has no immutable repository digest");
  const immutableReference = repoDigests.find((entry) => typeof entry === "string" && entry.endsWith(`@${finalDigest}`));
  if (typeof immutableReference !== "string") fail("final Docker image digest has no immutable local reference");
  return {
    finalDigest,
    baseDigest,
    immutableReference,
  };
}

function qualify(root: string, args: readonly string[]): Verification {
  const imageReference = option(args, "--image");
  const outputRoot = resolve(root, option(args, "--output", "dist/container-supply-chain"));
  const dispositionsSource = resolve(root, "release/vulnerability-dispositions.json");
  const buildMetadataPath = resolve(outputRoot, "build-metadata.json");
  const bases = verifyDockerfileBases(resolve(root, "Dockerfile"));
  if (bases.length !== 1) throw new Error("the prototype qualifier supports exactly one external Dockerfile base");
  const baseReference = bases[0]!.reference;
  mkdirSync(outputRoot, { recursive: true });

  const anchors = dockerAnchors(root, imageReference, baseReference, buildMetadataPath);
  const sbomPath = resolve(outputRoot, "sbom.spdx.json");
  const sbomSourcePath = resolve(outputRoot, "sbom.syft.json");
  const scanPath = resolve(outputRoot, "trivy.json");
  const cacheRoot = resolve(outputRoot, ".trivy-cache");
  const dispositionsPath = resolve(outputRoot, "vulnerability-dispositions.json");
  command([
    "syft", "scan", `docker:${anchors.immutableReference}`, "--quiet",
    "--output", `spdx-json=${sbomPath}`,
    "--output", `syft-json=${sbomSourcePath}`,
  ], root);
  command(["trivy", "image", "--cache-dir", cacheRoot, "--download-db-only", "--no-progress"], root);
  command([
    "trivy", "image", "--cache-dir", cacheRoot, "--skip-db-update", "--skip-java-db-update",
    "--scanners", "vuln", "--image-src", "docker", "--format", "json", "--output", scanPath,
    anchors.immutableReference,
  ], root);
  const stableAnchors = dockerAnchors(root, anchors.immutableReference, baseReference, buildMetadataPath);
  if (JSON.stringify(stableAnchors) !== JSON.stringify(anchors)) {
    fail("Docker image identity changed during qualification");
  }
  copyFileSync(dispositionsSource, dispositionsPath);

  const databaseMetadataPath = resolve(cacheRoot, "db/metadata.json");
  const databasePath = resolve(cacheRoot, "db/trivy.db");
  const databaseMetadata = object(readJson(databaseMetadataPath), "Trivy database metadata");
  const syftVersion = command(["syft", "version"], root).match(/Version:\s*([^\s]+)/)?.[1] ?? "unknown";
  const trivyVersion = command(["trivy", "version"], root).match(/Version:\s*([^\s]+)/)?.[1] ?? "unknown";
  const artifactPath = (path: string): string => relative(outputRoot, path);
  const releaseTime = new Date().toISOString();
  const manifest = {
    schema: "dacs-forge-container-supply-chain/v1",
    releaseTime,
    dockerfile: "Dockerfile",
    distribution: {
      status: "not-applicable",
      imageReference: null,
      reason: "This local Product Seal candidate does not distribute a container image.",
    },
    signatureProvenance: {
      status: "not-applicable",
      reason: "No container image is distributed, so remote signature and SLSA verification do not apply.",
    },
    image: {
      localReference: imageReference,
      immutableReference: anchors.immutableReference,
      finalDigest: anchors.finalDigest,
      baseReference,
      baseDigest: anchors.baseDigest,
    },
    build: { path: artifactPath(buildMetadataPath), sha256: sha256(buildMetadataPath) },
    sbom: {
      format: "spdx-json",
      path: artifactPath(sbomPath),
      sha256: sha256(sbomPath),
      tool: { name: "syft", version: syftVersion },
      source: { path: artifactPath(sbomSourcePath), sha256: sha256(sbomSourcePath) },
    },
    scan: {
      path: artifactPath(scanPath),
      sha256: sha256(scanPath),
      tool: { name: "trivy", version: trivyVersion },
      database: {
        path: artifactPath(databasePath),
        sha256: sha256(databasePath),
        metadataPath: artifactPath(databaseMetadataPath),
        metadataSha256: sha256(databaseMetadataPath),
        updatedAt: databaseMetadata["UpdatedAt"],
      },
    },
    dispositions: { path: artifactPath(dispositionsPath), sha256: sha256(dispositionsPath) },
  };
  const manifestPath = resolve(outputRoot, "manifest.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return verifyContainerSupplyChain(root, manifestPath, anchors, sha256(manifestPath));
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, "..");
  const [mode, ...args] = process.argv.slice(2);
  if (mode !== "qualify") fail("usage: container-supply-chain.ts qualify");
  const result = qualify(root, args);
  console.log(JSON.stringify(result));
}

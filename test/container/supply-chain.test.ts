import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { verifyContainerSupplyChain } from "../../scripts/container-supply-chain.ts";
import { verifyDockerfileBases } from "../../scripts/lint-dockerfile-bases.ts";

const FINAL = `sha256:${"1".repeat(64)}`;
const BASE = `sha256:${"2".repeat(64)}`;
const CONFIG = `sha256:${"4".repeat(64)}`;
const RELEASE_TIME = "2026-07-28T08:00:00.000Z";
const ANCHORS = {
  finalDigest: FINAL,
  baseDigest: BASE,
  immutableReference: `example@${FINAL}`,
};

function digest(path: string): string {
  return new Bun.CryptoHasher("sha256").update(readFileSync(path)).digest("hex");
}

function fixture(): { root: string; manifestPath: string; manifest: Record<string, any>; expectedManifestSha256: string } {
  const root = mkdtempSync(resolve(tmpdir(), "dacs-forge-supply-chain-"));
  const output = resolve(root, "dist/container-supply-chain");
  mkdirSync(resolve(output, ".trivy-cache/db"), { recursive: true });
  mkdirSync(resolve(root, "schemas"), { recursive: true });
  mkdirSync(resolve(root, "release"), { recursive: true });
  writeFileSync(resolve(root, "Dockerfile"), `FROM example/base:1@${BASE}\n`);
  writeFileSync(resolve(root, "schemas/vulnerability-dispositions.schema.json"), readFileSync(resolve(import.meta.dir, "../../schemas/vulnerability-dispositions.schema.json")));
  writeFileSync(resolve(output, "sbom.spdx.json"), JSON.stringify({
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "fixture",
    documentNamespace: "https://example.test/spdx/fixture",
    creationInfo: { creators: ["Tool: syft-fixture"], created: RELEASE_TIME },
    packages: [{
      name: "fixture",
      SPDXID: "SPDXRef-DocumentRoot-Image-fixture",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      checksums: [{ algorithm: "SHA256", checksumValue: FINAL.slice("sha256:".length) }],
    }],
  }));
  writeFileSync(resolve(output, "sbom.syft.json"), JSON.stringify({
    source: {
      id: FINAL.slice("sha256:".length),
      version: FINAL,
      type: "image",
      metadata: { imageID: CONFIG, manifestDigest: FINAL, repoDigests: [`example@${FINAL}`] },
    },
  }));
  writeFileSync(resolve(output, "trivy.json"), JSON.stringify({ SchemaVersion: 2, ArtifactType: "container_image", Metadata: { ImageID: FINAL, RepoDigests: [`example@${FINAL}`] }, Results: [] }));
  writeFileSync(resolve(output, "build-metadata.json"), JSON.stringify({
    "containerimage.digest": FINAL,
    "buildx.build.provenance": {
      buildType: "https://mobyproject.org/buildkit@v1",
      materials: [{ uri: `pkg:docker/example/base@1?digest=${BASE}`, digest: { sha256: BASE.slice("sha256:".length) } }],
      invocation: { configSource: { entryPoint: "Dockerfile" } },
    },
  }));
  writeFileSync(resolve(output, ".trivy-cache/db/metadata.json"), JSON.stringify({ UpdatedAt: "2026-07-28T07:00:00.000Z" }));
  writeFileSync(resolve(output, ".trivy-cache/db/trivy.db"), "fixture-db");
  const emptyDispositions = JSON.stringify({ schema: "dacs-forge-vulnerability-dispositions/v1", dispositions: [] });
  writeFileSync(resolve(output, "vulnerability-dispositions.json"), emptyDispositions);
  writeFileSync(resolve(root, "release/vulnerability-dispositions.json"), emptyDispositions);
  const manifest: Record<string, any> = {
    schema: "dacs-forge-container-supply-chain/v1",
    releaseTime: RELEASE_TIME,
    dockerfile: "Dockerfile",
    distribution: { status: "not-applicable", imageReference: null, reason: "No public container distribution in this candidate." },
    signatureProvenance: { status: "not-applicable", reason: "No distributed image needs remote signature verification." },
    image: {
      localReference: "example:local",
      immutableReference: `example@${FINAL}`,
      finalDigest: FINAL,
      baseReference: `example/base:1@${BASE}`,
      baseDigest: BASE,
    },
    build: { path: "build-metadata.json", sha256: digest(resolve(output, "build-metadata.json")) },
    sbom: {
      format: "spdx-json",
      path: "sbom.spdx.json",
      sha256: digest(resolve(output, "sbom.spdx.json")),
      tool: { name: "syft", version: "1.49.0" },
      source: { path: "sbom.syft.json", sha256: digest(resolve(output, "sbom.syft.json")) },
    },
    scan: {
      path: "trivy.json", sha256: digest(resolve(output, "trivy.json")), tool: { name: "trivy", version: "0.69.3" },
      database: {
        path: ".trivy-cache/db/trivy.db", sha256: digest(resolve(output, ".trivy-cache/db/trivy.db")),
        metadataPath: ".trivy-cache/db/metadata.json", metadataSha256: digest(resolve(output, ".trivy-cache/db/metadata.json")),
        updatedAt: "2026-07-28T07:00:00.000Z",
      },
    },
    dispositions: { path: "vulnerability-dispositions.json", sha256: digest(resolve(output, "vulnerability-dispositions.json")) },
  };
  const manifestPath = resolve(output, "manifest.json");
  writeFileSync(manifestPath, JSON.stringify(manifest));
  return { root, manifestPath, manifest, expectedManifestSha256: digest(manifestPath) };
}

function rewrite(subject: ReturnType<typeof fixture>, trusted = true): void {
  writeFileSync(subject.manifestPath, JSON.stringify(subject.manifest));
  if (trusted) subject.expectedManifestSha256 = digest(subject.manifestPath);
}

function verify(subject: ReturnType<typeof fixture>, at = new Date(RELEASE_TIME)) {
  return verifyContainerSupplyChain(subject.root, subject.manifestPath, ANCHORS, subject.expectedManifestSha256, at);
}

describe("container supply-chain policy", () => {
  test("accepts the bounded no-distribution release evidence", () => {
    const subject = fixture();
    expect(verify(subject)).toMatchObject({ critical: 0, high: 0, packages: 1, finalDigest: FINAL, baseDigest: BASE });
  });

  test("rejects every tag-only external Dockerfile base", () => {
    const subject = fixture();
    writeFileSync(resolve(subject.root, "Dockerfile"), "FROM example/base:latest\n");
    expect(() => verifyDockerfileBases(resolve(subject.root, "Dockerfile"))).toThrow("tag-only Dockerfile base");
    writeFileSync(resolve(subject.root, "Dockerfile"), `FROM alpine AS alpine\nFROM example/base:1@${BASE}\n`);
    expect(() => verifyDockerfileBases(resolve(subject.root, "Dockerfile"))).toThrow("1:alpine");
  });

  test("rejects final-image, base-image, and distribution digest drift", () => {
    for (const mutate of [
      (subject: ReturnType<typeof fixture>) => { subject.manifest["image"].finalDigest = `sha256:${"3".repeat(64)}`; },
      (subject: ReturnType<typeof fixture>) => { subject.manifest["image"].baseDigest = `sha256:${"3".repeat(64)}`; },
      (subject: ReturnType<typeof fixture>) => { subject.manifest["distribution"] = { status: "distributed", imageReference: `registry.example/forge@${BASE}` }; },
    ]) {
      const subject = fixture(); mutate(subject); rewrite(subject);
      expect(() => verify(subject)).toThrow();
    }
  });

  test("rejects invalid or substituted SBOM bytes", () => {
    const untrusted = fixture();
    untrusted.manifest["sbom"].sha256 = "3".repeat(64);
    rewrite(untrusted, false);
    expect(() => verify(untrusted)).toThrow("trusted qualification anchor");

    const subject = fixture();
    writeFileSync(resolve(subject.manifestPath, "../sbom.spdx.json"), JSON.stringify({ packages: [] }));
    subject.manifest["sbom"].sha256 = digest(resolve(subject.manifestPath, "../sbom.spdx.json"));
    rewrite(subject);
    expect(() => verify(subject)).toThrow("SBOM");

    const substituted = fixture();
    const sbomPath = resolve(substituted.manifestPath, "../sbom.spdx.json");
    const document = JSON.parse(readFileSync(sbomPath, "utf8"));
    document.packages[0].checksums[0].checksumValue = "3".repeat(64);
    writeFileSync(sbomPath, JSON.stringify(document));
    substituted.manifest["sbom"].sha256 = digest(sbomPath);
    rewrite(substituted);
    expect(() => verify(substituted)).toThrow("bind its Syft image source");

    const incomplete = fixture();
    const incompletePath = resolve(incomplete.manifestPath, "../sbom.spdx.json");
    const incompleteDocument = JSON.parse(readFileSync(incompletePath, "utf8"));
    delete incompleteDocument.creationInfo;
    writeFileSync(incompletePath, JSON.stringify(incompleteDocument));
    incomplete.manifest["sbom"].sha256 = digest(incompletePath); rewrite(incomplete);
    expect(() => verify(incomplete)).toThrow("creationInfo");

    const malformedCreator = fixture();
    const malformedCreatorPath = resolve(malformedCreator.manifestPath, "../sbom.spdx.json");
    const malformedCreatorDocument = JSON.parse(readFileSync(malformedCreatorPath, "utf8"));
    malformedCreatorDocument.creationInfo.creators = [42];
    writeFileSync(malformedCreatorPath, JSON.stringify(malformedCreatorDocument));
    malformedCreator.manifest["sbom"].sha256 = digest(malformedCreatorPath); rewrite(malformedCreator);
    expect(() => verify(malformedCreator)).toThrow("valid SPDX");
  });

  test("rejects missing provenance and substituted scanner identities", () => {
    const missingProvenance = fixture();
    const metadataPath = resolve(missingProvenance.manifestPath, "../build-metadata.json");
    writeFileSync(metadataPath, JSON.stringify({ "containerimage.digest": FINAL }));
    missingProvenance.manifest["build"].sha256 = digest(metadataPath); rewrite(missingProvenance);
    expect(() => verify(missingProvenance)).toThrow("BuildKit provenance");

    for (const artifact of ["sbom.syft.json", "trivy.json"]) {
      const subject = fixture();
      const path = resolve(subject.manifestPath, `../${artifact}`);
      const document = JSON.parse(readFileSync(path, "utf8"));
      if (artifact.startsWith("sbom")) document.source.metadata.manifestDigest = BASE;
      else document.Metadata.ImageID = BASE;
      writeFileSync(path, JSON.stringify(document));
      const record = artifact.startsWith("sbom") ? subject.manifest["sbom"].source : subject.manifest["scan"];
      record.sha256 = digest(path); rewrite(subject);
      expect(() => verify(subject)).toThrow("does not bind the final image digest");
    }
  });

  test("rejects untrusted scanner versions", () => {
    for (const path of [["sbom", "1.48.9"], ["scan", "0.69.2"]] as const) {
      const subject = fixture();
      subject.manifest[path[0]].tool.version = path[1]; rewrite(subject);
      expect(() => verify(subject)).toThrow("trusted");
    }
  });

  test("rejects stale or unbound vulnerability databases", () => {
    const subject = fixture();
    const metadataPath = resolve(subject.manifestPath, "../.trivy-cache/db/metadata.json");
    writeFileSync(metadataPath, JSON.stringify({ UpdatedAt: "2026-07-27T07:59:00.000Z" }));
    subject.manifest["scan"].database.updatedAt = "2026-07-27T07:59:00.000Z";
    subject.manifest["scan"].database.metadataSha256 = digest(metadataPath);
    rewrite(subject);
    expect(() => verify(subject)).toThrow("fresh within 24 hours");

    const unbound = fixture();
    unbound.manifest["scan"].database.updatedAt = "2026-07-28T07:30:00.000Z";
    rewrite(unbound);
    expect(() => verify(unbound)).toThrow("metadata-bound");
    expect(() => verify(unbound, new Date("invalid"))).toThrow("verification time must be valid");
  });

  test("rejects every critical and undispositioned high finding", () => {
    for (const severity of ["CRITICAL", "HIGH"]) {
      const subject = fixture();
      const scanPath = resolve(subject.manifestPath, "../trivy.json");
      writeFileSync(scanPath, JSON.stringify({ SchemaVersion: 2, ArtifactType: "container_image", Metadata: { ImageID: FINAL, RepoDigests: [`example@${FINAL}`] }, Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-2026-12345", Severity: severity }] }] }));
      subject.manifest["scan"].sha256 = digest(scanPath); rewrite(subject);
      expect(() => verify(subject)).toThrow(severity === "CRITICAL" ? "critical" : "missing high");
    }
  });

  test("accepts only active high dispositions lasting at most 30 days", () => {
    const subject = fixture();
    const scanPath = resolve(subject.manifestPath, "../trivy.json");
    const dispositionsPath = resolve(subject.manifestPath, "../vulnerability-dispositions.json");
    const reviewedDispositionsPath = resolve(subject.root, "release/vulnerability-dispositions.json");
    writeFileSync(scanPath, JSON.stringify({ SchemaVersion: 2, ArtifactType: "container_image", Metadata: { ImageID: FINAL, RepoDigests: [`example@${FINAL}`] }, Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-2026-12345", Severity: "HIGH" }] }] }));
    writeFileSync(dispositionsPath, JSON.stringify({ schema: "dacs-forge-vulnerability-dispositions/v1", dispositions: [{ vulnerabilityId: "CVE-2026-12345", cve: "CVE-2026-12345", justification: "No reachable affected code path in the fixture runtime.", owner: "mj-deving", createdAt: "2026-07-28T07:00:00.000Z", expiresAt: "2026-08-27T07:00:00.000Z" }] }));
    subject.manifest["scan"].sha256 = digest(scanPath);
    subject.manifest["dispositions"].sha256 = digest(dispositionsPath); rewrite(subject);
    expect(() => verify(subject)).toThrow("reviewed repository policy");
    writeFileSync(reviewedDispositionsPath, readFileSync(dispositionsPath));
    expect(verify(subject).high).toBe(1);
    const document = JSON.parse(readFileSync(dispositionsPath, "utf8"));
    document.dispositions[0].expiresAt = RELEASE_TIME;
    writeFileSync(dispositionsPath, JSON.stringify(document));
    writeFileSync(reviewedDispositionsPath, readFileSync(dispositionsPath));
    subject.manifest["dispositions"].sha256 = digest(dispositionsPath); rewrite(subject);
    expect(() => verify(subject)).toThrow("not active at verification time");
    document.dispositions[0].expiresAt = "2026-08-28T07:00:00.000Z";
    writeFileSync(dispositionsPath, JSON.stringify(document));
    writeFileSync(reviewedDispositionsPath, readFileSync(dispositionsPath));
    subject.manifest["dispositions"].sha256 = digest(dispositionsPath); rewrite(subject);
    expect(() => verify(subject)).toThrow("exceeds 30 days");
  });

  test("accepts a bounded non-CVE advisory disposition", () => {
    const subject = fixture();
    const scanPath = resolve(subject.manifestPath, "../trivy.json");
    const dispositionsPath = resolve(subject.manifestPath, "../vulnerability-dispositions.json");
    const reviewedDispositionsPath = resolve(subject.root, "release/vulnerability-dispositions.json");
    writeFileSync(scanPath, JSON.stringify({ SchemaVersion: 2, ArtifactType: "container_image", Metadata: { ImageID: FINAL, RepoDigests: [`example@${FINAL}`] }, Results: [{ Vulnerabilities: [{ VulnerabilityID: "GHSA-abcd-1234-5678", Severity: "HIGH" }] }] }));
    writeFileSync(dispositionsPath, JSON.stringify({ schema: "dacs-forge-vulnerability-dispositions/v1", dispositions: [{ vulnerabilityId: "GHSA-abcd-1234-5678", justification: "No reachable affected code path in the fixture runtime.", owner: "mj-deving", createdAt: "2026-07-28T07:00:00.000Z", expiresAt: "2026-08-27T07:00:00.000Z" }] }));
    writeFileSync(reviewedDispositionsPath, readFileSync(dispositionsPath));
    subject.manifest["scan"].sha256 = digest(scanPath);
    subject.manifest["dispositions"].sha256 = digest(dispositionsPath); rewrite(subject);
    expect(verify(subject).high).toBe(1);
  });
});

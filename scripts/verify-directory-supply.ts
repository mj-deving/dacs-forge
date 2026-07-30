#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { verifyCanonicalListingJson } from "../src/consumer/listing-verifier.ts";
import { signPerClaimIdentityBundle } from "../src/producer/identity-bundle.ts";
import { createFixtureEd25519Signer } from "../src/producer/fixture-ed25519.ts";
import { signListing } from "../src/producer/listing.ts";
import { canonicalize } from "../src/protocol/canonical-json.ts";
import {
  COMMUNITY_DIRECTORY_COMMIT,
  LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
  validateDirectoryListingSummary,
} from "../src/protocol/directory-summary-schema.ts";
import type { ServiceContract } from "../src/service/contract.ts";
import {
  assertTrustedVerifierCheckout,
  formatFindings,
  verifyExtensionDelta,
} from "../tools/exemplar-policy.ts";

const FIXTURE_NOW_MS = 1_784_073_600_000;
const FIXTURE_PATH = "service/fixtures/directory-supply.json";
const DESCRIPTOR_PATH = "service/fixtures/service-descriptor.json";
const SIGNING_CONTEXT = Object.freeze({
  deploymentMode: "fixture" as const,
  requestMode: "fixture" as const,
});

type JsonObject = Record<string, unknown>;

export interface ServiceDirectorySupply {
  readonly service: Readonly<{
    id: string;
    version: string;
    title: string;
    deliverableKind: string;
  }>;
  readonly serviceImplementationSha256: string;
  readonly listing: Readonly<{
    canonicalJson: string;
    artifactSha256: string;
    contentHash: string;
    signer: string;
  }>;
  readonly discovery: Readonly<{
    canonicalJson: string;
    artifactSha256: string;
    communityCommit: string;
    schemaSha256: string;
  }>;
  readonly source: Readonly<{
    path: typeof FIXTURE_PATH;
    blob: string;
  }>;
  readonly effects: Readonly<{
    codeExecuted: false;
    liveRegistrationCalls: 0;
    networkCalls: 0;
  }>;
}

interface DirectorySupplyFixture {
  readonly schema: "dacs-forge-service-directory-supply/v1";
  readonly service: ServiceDirectorySupply["service"];
  readonly serviceImplementationSha256: string;
  readonly listingCanonicalJson: string;
  readonly discoveryCanonicalJson: string;
}

export function assertDistinctServiceSupply(
  base: ServiceDirectorySupply,
  fork: ServiceDirectorySupply,
): void {
  if (base.service.id === fork.service.id
    || base.serviceImplementationSha256 === fork.serviceImplementationSha256
    || base.listing.artifactSha256 === fork.listing.artifactSha256
    || base.discovery.artifactSha256 === fork.discovery.artifactSha256) {
    throw new Error("Directory supply rejected generic or substituted fork artifacts");
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function implementationTags(digest: string): readonly string[] {
  return [0, 1, 2, 3].map((index) => `impl-sha256-${index}-${digest.slice(index * 16, (index + 1) * 16)}`);
}

function git(repository: string, args: readonly string[]): string {
  const result = spawnSync("git", args, {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, GIT_NO_LAZY_FETCH: "1", GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} exited ${result.status}: ${result.stderr.trim()}`);
  }
  return result.stdout;
}

function exactCheckout(repository: string, revision: string): void {
  if (!existsSync(resolve(repository, ".git")) || !/^[0-9a-f]{40}$/.test(revision)) {
    throw new Error("Directory supply requires an exact Git checkout and commit");
  }
  if (git(repository, ["rev-parse", "--verify", `${revision}^{commit}`]).trim() !== revision
    || git(repository, ["rev-parse", "HEAD"]).trim() !== revision) {
    throw new Error(`Directory supply checkout is not at exact commit ${revision}`);
  }
  if (git(repository, ["status", "--porcelain=v1"]).trim() !== "") {
    throw new Error("Directory supply checkout must be clean");
  }
}

function exactRevision(repository: string, revision: string): void {
  if (!existsSync(resolve(repository, ".git")) || !/^[0-9a-f]{40}$/.test(revision)
    || git(repository, ["rev-parse", "--verify", `${revision}^{commit}`]).trim() !== revision) {
    throw new Error("Directory supply source does not contain the exact requested commit");
  }
}

function serviceDescriptor(contract: ServiceContract<unknown, unknown>): ServiceDirectorySupply["service"] {
  const service = contract?.service;
  if (service === null || typeof service !== "object"
    || typeof service.id !== "string" || typeof service.version !== "string"
    || typeof service.title !== "string" || typeof service.deliverableKind !== "string"
    || typeof contract.handler !== "function") {
    throw new TypeError("Target service contract is invalid");
  }
  return Object.freeze({
    id: service.id,
    version: service.version,
    title: service.title,
    deliverableKind: service.deliverableKind,
  });
}

export function serviceImplementationSha256(repository: string, revision: string): string {
  if (!/^[0-9a-f]{40}$/.test(revision)) throw new Error("service implementation requires an exact commit");
  const records = git(repository, ["ls-tree", "-r", "-z", "--full-tree", revision, "--", "service/"])
    .split("\0")
    .filter(Boolean)
    .filter((record) => !record.endsWith(`\t${FIXTURE_PATH}`));
  if (records.length < 4) throw new Error("service implementation tree is incomplete");
  for (const required of [
    "service/handler.ts",
    "service/input.schema.json",
    "service/output.schema.json",
    "service/service.config.ts",
  ]) {
    if (!records.some((record) => record.endsWith(`\t${required}`))) {
      throw new Error(`service implementation is missing ${required}`);
    }
  }
  return sha256(records.sort().join("\n"));
}

export function createServiceDirectoryFixture(
  contract: ServiceContract<unknown, unknown>,
  implementationSha256: string,
): DirectorySupplyFixture {
  if (!/^[0-9a-f]{64}$/.test(implementationSha256)) {
    throw new TypeError("Service implementation digest is invalid");
  }
  const service = serviceDescriptor(contract);
  const seed = createHash("sha256")
    .update(`dacs-forge-directory-supply:${service.id}:${implementationSha256}`)
    .digest();
  const signer = createFixtureEd25519Signer(seed, {
    deploymentMode: "fixture",
    authorityMode: "fixture",
  });
  const identity = signPerClaimIdentityBundle({
    bundleVersion: "1",
    presentedBy: signer.signer,
    presentedAt: FIXTURE_NOW_MS,
    claims: [{ ref: signer.signer }],
  }, signer, SIGNING_CONTEXT).bundle;
  const publicEndpoint = `https://service.example/${encodeURIComponent(service.id)}/v1`;
  const produced = signListing({
    dacsVersion: "1",
    listingVersion: 1,
    listingId: service.id,
    requiredCapabilities: ["SR-2"],
    seller: { identity, displayName: service.title, publicEndpoint },
    offering: {
      title: service.title,
      description: `Fixture-qualified ${service.title} service; deliverable ${service.deliverableKind}.`,
      category: "services.other",
      tags: ["fixture", "dacs-forge", ...implementationTags(implementationSha256)],
      deliverable: {
        kind: "attested-payload",
        payloadFormat: "application/json",
        verificationMethod: { kind: "self-signed" },
      },
    },
    buyerRequirement: {
      requirementVersion: "1",
      required: [{ scheme: "key", verificationRequired: false }],
    },
    pipeline: [
      { kind: "negotiate-fixed-price" },
      { kind: "commit-agreement" },
      { kind: "deliver-attested-payload" },
    ],
    pricing: { kind: "fixed", price: { amount: "1", currency: "USDC", unit: "job" } },
    terms: { cancellationPolicy: "pre-commit" },
    validity: { notBefore: FIXTURE_NOW_MS, notAfter: FIXTURE_NOW_MS + 86_400_000 },
  }, signer, { ...SIGNING_CONTEXT, nowMs: FIXTURE_NOW_MS });
  const summary = directorySummary(produced.listing, produced.contentHash, service.id, produced.canonicalJson);
  if (!validateDirectoryListingSummary(summary).valid) {
    throw new Error("Generated Directory summary is invalid");
  }
  return Object.freeze({
    schema: "dacs-forge-service-directory-supply/v1" as const,
    service,
    serviceImplementationSha256: implementationSha256,
    listingCanonicalJson: produced.canonicalJson,
    discoveryCanonicalJson: canonicalize(summary),
  });
}

function directorySummary(
  listing: JsonObject,
  contentHash: string,
  serviceId: string,
  listingCanonicalJson: string,
): JsonObject {
  const seller = listing["seller"] as JsonObject;
  const sellerIdentity = seller["identity"] as JsonObject;
  const offering = listing["offering"] as JsonObject;
  const pipeline = listing["pipeline"] as JsonObject[];
  return {
    listingId: serviceId,
    version: 1,
    contentHash,
    anchor: { kind: "fixture", locator: `fixture://${serviceId}/v1/${sha256(listingCanonicalJson)}` },
    seller: { primaryClaim: sellerIdentity["presentedBy"], displayName: seller["displayName"] },
    artifactProfile: "fixture-listing",
    publicEndpoint: seller["publicEndpoint"],
    offering: {
      title: offering["title"],
      description: offering["description"],
      category: offering["category"],
      tags: offering["tags"],
      rails: [],
      delivery: pipeline.map((phase) => phase["kind"]).filter((kind) =>
        typeof kind === "string" && kind.startsWith("deliver-")),
      negotiation: pipeline.map((phase) => phase["kind"]).filter((kind) =>
        typeof kind === "string" && kind.startsWith("negotiate-")),
      deliverable: offering["deliverable"],
    },
    pricing: listing["pricing"],
    status: "active",
    catalogObservedAt: FIXTURE_NOW_MS,
  };
}

function exactFixture(repository: string, revision: string): { readonly fixture: DirectorySupplyFixture; readonly blob: string } {
  const entry = git(repository, ["ls-tree", revision, "--", FIXTURE_PATH]).trim();
  const match = /^100644 blob ([0-9a-f]{40})\tservice\/fixtures\/directory-supply\.json$/.exec(entry);
  if (!match) throw new Error("Directory supply fixture must be a regular committed Git blob");
  const bytes = git(repository, ["show", `${revision}:${FIXTURE_PATH}`]);
  const parsed = JSON.parse(bytes) as JsonObject;
  const fixture = parsed as unknown as DirectorySupplyFixture;
  const exactKeys = (value: JsonObject, expected: readonly string[]): boolean =>
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
  if (fixture.schema !== "dacs-forge-service-directory-supply/v1"
    || !exactKeys(parsed, ["schema", "service", "serviceImplementationSha256", "listingCanonicalJson", "discoveryCanonicalJson"])
    || fixture.service === null || typeof fixture.service !== "object"
    || !exactKeys(fixture.service as unknown as JsonObject, ["id", "version", "title", "deliverableKind"])
    || typeof fixture.service.id !== "string" || typeof fixture.service.version !== "string"
    || typeof fixture.service.title !== "string" || typeof fixture.service.deliverableKind !== "string"
    || !/^[0-9a-f]{64}$/.test(fixture.serviceImplementationSha256)
    || typeof fixture.listingCanonicalJson !== "string"
    || typeof fixture.discoveryCanonicalJson !== "string") {
    throw new Error("Directory supply fixture shape is invalid");
  }
  if (bytes !== `${canonicalize(parsed)}\n`) {
    throw new Error("Directory supply fixture bytes are not canonical JSON");
  }
  return Object.freeze({ fixture, blob: match[1]! });
}

function exactServiceDescriptor(repository: string, revision: string): ServiceDirectorySupply["service"] {
  const entry = git(repository, ["ls-tree", revision, "--", DESCRIPTOR_PATH]).trim();
  if (!/^100644 blob [0-9a-f]{40}\tservice\/fixtures\/service-descriptor\.json$/.test(entry)) {
    throw new Error("Service descriptor must be a regular committed Git blob");
  }
  const bytes = git(repository, ["show", `${revision}:${DESCRIPTOR_PATH}`]);
  const parsed = JSON.parse(bytes) as JsonObject;
  if (JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify(["id", "version", "title", "deliverableKind"].sort())
    || typeof parsed["id"] !== "string" || typeof parsed["version"] !== "string"
    || typeof parsed["title"] !== "string" || typeof parsed["deliverableKind"] !== "string"
    || bytes !== `${canonicalize(parsed)}\n`) {
    throw new Error("Committed service descriptor is invalid or noncanonical");
  }
  return Object.freeze({
    id: parsed["id"],
    version: parsed["version"],
    title: parsed["title"],
    deliverableKind: parsed["deliverableKind"],
  });
}

export function verifyCommittedSupply(repository: string, revision: string): ServiceDirectorySupply {
  const { fixture, blob } = exactFixture(repository, revision);
  const descriptor = exactServiceDescriptor(repository, revision);
  const implementationSha256 = serviceImplementationSha256(repository, revision);
  if (fixture.serviceImplementationSha256 !== implementationSha256
    || canonicalize(fixture.service) !== canonicalize(descriptor)) {
    throw new Error("Directory supply fixture is not bound to the exact service implementation tree");
  }
  const verified = verifyCanonicalListingJson(fixture.listingCanonicalJson, {
    nowMs: FIXTURE_NOW_MS,
    revocationCheck: () => "absent",
  });
  const listing = JSON.parse(fixture.listingCanonicalJson) as JsonObject;
  const seller = listing["seller"] as JsonObject;
  const offering = listing["offering"] as JsonObject;
  const signature = listing["signature"] as JsonObject;
  const tags = offering?.["tags"];
  if (verified.disposition !== "accepted" || verified.listingId !== fixture.service.id
    || listing["listingId"] !== fixture.service.id
    || seller?.["displayName"] !== fixture.service.title
    || offering?.["title"] !== fixture.service.title
    || listing["listingVersion"] !== 1
    || !String(offering?.["description"]).includes(`deliverable ${fixture.service.deliverableKind}`)
    || !Array.isArray(tags)
    || !implementationTags(implementationSha256).every((tag) => tags.includes(tag))
    || typeof signature?.["signer"] !== "string") {
    throw new Error("Committed Listing is not bound to the service identity and implementation");
  }
  const discovery = JSON.parse(fixture.discoveryCanonicalJson) as JsonObject;
  const validation = validateDirectoryListingSummary(discovery);
  const expectedDiscovery = directorySummary(listing, verified.contentHash, fixture.service.id, fixture.listingCanonicalJson);
  if (!validation.valid || discovery["listingId"] !== fixture.service.id
    || discovery["contentHash"] !== verified.contentHash
    || canonicalize(discovery) !== fixture.discoveryCanonicalJson
    || fixture.discoveryCanonicalJson !== canonicalize(expectedDiscovery)) {
    throw new Error("Committed Directory discovery artifact is invalid or unbound");
  }
  return Object.freeze({
    service: Object.freeze({ ...fixture.service }),
    serviceImplementationSha256: implementationSha256,
    listing: Object.freeze({
      canonicalJson: fixture.listingCanonicalJson,
      artifactSha256: sha256(fixture.listingCanonicalJson),
      contentHash: verified.contentHash,
      signer: signature["signer"] as string,
    }),
    discovery: Object.freeze({
      canonicalJson: fixture.discoveryCanonicalJson,
      artifactSha256: sha256(fixture.discoveryCanonicalJson),
      communityCommit: COMMUNITY_DIRECTORY_COMMIT,
      schemaSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
    }),
    source: Object.freeze({ path: FIXTURE_PATH, blob }),
    effects: Object.freeze({ codeExecuted: false as const, liveRegistrationCalls: 0 as const, networkCalls: 0 as const }),
  });
}

export async function verifyDirectorySupply(input: {
  readonly trustedRoot: string;
  readonly baseCommit: string;
  readonly forkRepository: string;
  readonly forkTip: string;
}): Promise<Readonly<JsonObject>> {
  assertTrustedVerifierCheckout(input.trustedRoot, input.baseCommit);
  exactCheckout(input.trustedRoot, input.baseCommit);
  exactRevision(input.forkRepository, input.forkTip);
  const findings = verifyExtensionDelta(input.forkRepository, input.baseCommit, input.forkTip);
  if (findings.length > 0) {
    throw new Error(`Directory supply fork boundary rejected:\n${formatFindings(findings)}`);
  }
  const base = verifyCommittedSupply(input.trustedRoot, input.baseCommit);
  const fork = verifyCommittedSupply(input.forkRepository, input.forkTip);
  assertDistinctServiceSupply(base, fork);
  return Object.freeze({
    schema: "dacs-forge-directory-supply-qualification/v1",
    baseCommit: input.baseCommit,
    forkTip: input.forkTip,
    communityCommit: COMMUNITY_DIRECTORY_COMMIT,
    listingSummarySchemaSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
    base,
    fork,
    distinctServiceListings: true,
    distinctDiscoveryArtifacts: true,
    applicableRigPassed: false,
    effects: Object.freeze({ codeExecuted: false, liveRegistrationCalls: 0, networkCalls: 0 }),
  });
}

function option(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? undefined : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

if (import.meta.main) {
  const trustedRoot = resolve(import.meta.dir, "..");
  const result = await verifyDirectorySupply({
    trustedRoot,
    baseCommit: option("--base"),
    forkRepository: resolve(option("--repository")),
    forkTip: option("--tip"),
  });
  console.log(JSON.stringify(result));
}

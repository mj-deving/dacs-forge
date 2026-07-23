import {
  verifyCanonicalListingJson,
  type ListingVerificationOptions,
  type PaymentRailCheck,
  type RevocationCheck,
} from "../../consumer/listing-verifier.ts";
import { canonicalize, withoutFields } from "../../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../../protocol/claim-reference.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import { assertPerClaimIdentityBundleForPublication } from "../../producer/identity-bundle.ts";
import { ArtifactIntegrityError, ArtifactStore } from "./artifact-store.ts";
import type { DacsDatabase } from "./database.ts";

export class FixtureAuthorityIntegrityError extends Error {
  override readonly name = "FixtureAuthorityIntegrityError";
}

export interface FixtureIdentityAuthority {
  readonly bundleHash: string;
  readonly primaryClaim: string;
  readonly publicKey: Uint8Array;
}

export interface FixtureListingVerificationAuthority extends Pick<
  ListingVerificationOptions,
  "revocationCheck" | "paymentRailCheck"
> {
  readonly railRegistryVersion: number;
  readonly recipeRegistryVersion: number;
}

interface PersistedRailResolution {
  readonly request: {
    readonly canonicalJson: string;
    readonly railId: string;
    readonly railVersion?: number;
    readonly referencedByPhaseKinds: readonly string[];
  };
  readonly result: PaymentRailCheck;
}

export class FixtureAuthorityStore {
  readonly #artifacts: ArtifactStore;
  readonly #database: DacsDatabase;

  constructor(database: DacsDatabase) {
    this.#database = database;
    this.#artifacts = new ArtifactStore(database);
  }

  putListingWithinTransaction(
    jobId: string,
    canonicalJson: string,
    createdAt: string,
    authority: FixtureListingVerificationAuthority,
  ): void {
    const listing = parseCanonicalObject(canonicalJson, "Listing");
    const verifiedAt = parseTimestamp(createdAt, "Listing authority createdAt");
    if (!Number.isSafeInteger(authority.recipeRegistryVersion) || authority.recipeRegistryVersion < 1
      || !Number.isSafeInteger(authority.railRegistryVersion) || authority.railRegistryVersion < 1) {
      throw new FixtureAuthorityIntegrityError("Fixture registry authority versions are invalid");
    }
    const observed: {
      revocation?: { readonly request: Readonly<Record<string, unknown>>; readonly result: RevocationCheck };
    } = {};
    const railResolutions: PersistedRailResolution[] = [];
    const verification = verifyFixtureListing(canonicalJson, verifiedAt, {
      revocationCheck: (request) => {
        const result = authority.revocationCheck(request);
        observed.revocation = Object.freeze({ request, result });
        return result;
      },
      ...(authority.paymentRailCheck === undefined ? {} : { paymentRailCheck: (request) => {
        const result = authority.paymentRailCheck!(request);
        railResolutions.push(Object.freeze({ request, result }));
        return result;
      } }),
    });
    if (verification.disposition !== "accepted") {
      throw new FixtureAuthorityIntegrityError(`Listing authority is invalid: ${verification.stage}: ${verification.reason}`);
    }
    if (observed.revocation === undefined || observed.revocation.result !== "absent") {
      throw new FixtureAuthorityIntegrityError("Accepted Listing lacks an authoritative absent revocation result");
    }
    const artifact = this.#artifacts.putWithinTransaction("dacs-1-listing", listing, createdAt);
    const existing = this.#database.query<{
      artifactContentHash: string; contentHash: string;
    }, { listingId: string; version: number }>(`
      SELECT artifact_content_hash AS artifactContentHash,
        listing_content_hash AS contentHash
      FROM fixture_listing_authorities
      WHERE listing_id = $listingId AND listing_version = $version
    `).get({ listingId: verification.listingId, version: verification.listingVersion });
    if (existing !== null) {
      if (existing.contentHash !== verification.contentHash
        || existing.artifactContentHash !== artifact.contentHash) {
        throw new FixtureAuthorityIntegrityError("Listing authority version is already bound to different content");
      }
    } else {
      this.#database.query<never, Record<string, string | number>>(`
        /* atomic-write: authority.put-listing */
        INSERT INTO fixture_listing_authorities (
          listing_id, listing_version, listing_content_hash, artifact_content_hash, created_at
        ) VALUES ($listingId, $version, $contentHash, $artifactContentHash, $createdAt)
      `).run({
        listingId: verification.listingId,
        version: verification.listingVersion,
        contentHash: verification.contentHash,
        artifactContentHash: artifact.contentHash,
        createdAt,
      });
    }
    this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: authority.put-listing-verification */
      INSERT INTO fixture_listing_verification_authorities (
        job_id, listing_id, listing_version, listing_content_hash, verified_at,
        revocation_status, revocation_check_json, rail_resolutions_json,
        created_at, recipe_registry_version, rail_registry_version
      ) VALUES (
        $jobId, $listingId, $version, $contentHash, $verifiedAt,
        $revocationStatus, $revocationCheckJson, $railResolutionsJson, $createdAt,
        $recipeRegistryVersion, $railRegistryVersion
      )
    `).run({
      jobId,
      listingId: verification.listingId,
      version: verification.listingVersion,
      contentHash: verification.contentHash,
      verifiedAt,
      revocationStatus: observed.revocation.result,
      revocationCheckJson: canonicalize(observed.revocation.request),
      railResolutionsJson: canonicalize(railResolutions),
      recipeRegistryVersion: authority.recipeRegistryVersion,
      railRegistryVersion: authority.railRegistryVersion,
      createdAt,
    });
  }

  putCommitmentIdentityWithinTransaction(
    canonicalJson: string,
    createdAt: string,
  ): FixtureIdentityAuthority {
    return this.#putIdentityWithinTransaction(canonicalJson, createdAt, "agreement-commitment");
  }

  putBundleIdentityWithinTransaction(
    canonicalJson: string,
    createdAt: string,
  ): FixtureIdentityAuthority {
    return this.#putIdentityWithinTransaction(canonicalJson, createdAt, "bundle-finalisation");
  }

  #putIdentityWithinTransaction(
    canonicalJson: string,
    createdAt: string,
    boundary: "agreement-commitment" | "bundle-finalisation",
  ): FixtureIdentityAuthority {
    const identity = parseCanonicalObject(canonicalJson, "IdentityBundle");
    assertPerClaimIdentityBundleForPublication(identity);
    const primaryClaim = identity["presentedBy"] as string;
    const publicKey = directPublicKey(primaryClaim);
    if (publicKey === null) {
      throw new FixtureAuthorityIntegrityError("Fixture IdentityBundle requires a direct Ed25519 key claim");
    }
    const bundleHash = sha256Hex(canonicalize(withoutFields(identity, "presentation")));
    const artifact = this.#artifacts.putWithinTransaction("dacs-identity-bundle", identity, createdAt);
    const existing = this.#database.query<{
      artifactContentHash: string; primaryClaim: string;
    }, { bundleHash: string }>(`
      SELECT artifact_content_hash AS artifactContentHash, primary_claim AS primaryClaim
      FROM fixture_identity_authorities WHERE bundle_hash = $bundleHash
    `).get({ bundleHash });
    if (existing !== null) {
      if (existing.primaryClaim !== primaryClaim || existing.artifactContentHash !== artifact.contentHash) {
        throw new FixtureAuthorityIntegrityError("IdentityBundle hash is already bound to different authority");
      }
      return Object.freeze({ bundleHash, primaryClaim, publicKey });
    }
    const bindings = { bundleHash, primaryClaim, artifactContentHash: artifact.contentHash, createdAt };
    if (boundary === "agreement-commitment") {
      this.#database.query<never, Record<string, string>>(`
        /* atomic-write: authority.put-commitment-identity */
        INSERT INTO fixture_identity_authorities (
          bundle_hash, primary_claim, artifact_content_hash, created_at
        ) VALUES ($bundleHash, $primaryClaim, $artifactContentHash, $createdAt)
      `).run(bindings);
    } else {
      this.#database.query<never, Record<string, string>>(`
        /* atomic-write: authority.put-identity */
        INSERT INTO fixture_identity_authorities (
          bundle_hash, primary_claim, artifact_content_hash, created_at
        ) VALUES ($bundleHash, $primaryClaim, $artifactContentHash, $createdAt)
      `).run(bindings);
    }
    return Object.freeze({ bundleHash, primaryClaim, publicKey });
  }

  resolveListing(jobId: string, ref: Readonly<Record<string, unknown>>) {
    try {
      return this.#resolveListing(jobId, ref);
    } catch (error) {
      if (!(error instanceof FixtureAuthorityIntegrityError) && !(error instanceof ArtifactIntegrityError)) {
        throw error;
      }
      return Object.freeze({
        status: "rejected" as const,
        reason: error.message,
      });
    }
  }

  #resolveListing(jobId: string, ref: Readonly<Record<string, unknown>>) {
    const row = this.#database.query<{
      artifactContentHash: string; contentHash: string; createdAt: string; listingId: string;
      railResolutionsJson: string; revocationCheckJson: string; revocationStatus: RevocationCheck;
      verificationContentHash: string; verifiedAt: bigint; version: bigint;
    }, { jobId: string }>(`
      SELECT l.listing_id AS listingId, l.listing_version AS version,
        l.listing_content_hash AS contentHash, l.artifact_content_hash AS artifactContentHash,
        v.verified_at AS verifiedAt, v.revocation_status AS revocationStatus,
        v.listing_content_hash AS verificationContentHash,
        v.revocation_check_json AS revocationCheckJson,
        v.rail_resolutions_json AS railResolutionsJson, v.created_at AS createdAt
      FROM fixture_listing_verification_authorities AS v
      JOIN fixture_listing_authorities AS l
        ON l.listing_id = v.listing_id AND l.listing_version = v.listing_version
      WHERE v.job_id = $jobId
    `).get({ jobId });
    if (row === null) return Object.freeze({ status: "absent" as const });
    const version = Number(row.version);
    const verifiedAt = Number(row.verifiedAt);
    if (!Number.isSafeInteger(verifiedAt) || verifiedAt < 0 || parseTimestamp(row.createdAt, "Listing verification createdAt") !== verifiedAt
      || row.verificationContentHash !== row.contentHash
      || row.contentHash !== ref["contentHash"] || row.listingId !== ref["listingId"] || version !== ref["version"]) {
      throw new FixtureAuthorityIntegrityError("Per-commitment Listing authority binding is inconsistent");
    }
    const artifact = this.#artifacts.get(row.artifactContentHash);
    if (artifact === null || !artifact.kinds.includes("dacs-1-listing")) {
      return Object.freeze({ status: "rejected" as const, reason: "Listing authority artifact is missing or mistyped" });
    }
    const revocationRequest = parseCanonicalObject(row.revocationCheckJson, "Listing revocation check");
    const railResolutions = parseRailResolutions(row.railResolutionsJson);
    const verification = verifyFixtureListing(artifact.canonicalJson, verifiedAt, {
      revocationCheck: (request) => canonicalize(request) === canonicalize(revocationRequest)
        ? row.revocationStatus : "indeterminate",
      paymentRailCheck: (request) => railResolutions.find((entry) =>
        canonicalize(entry.request) === canonicalize(request))?.result ?? { status: "indeterminate" },
    });
    if (verification.disposition !== "accepted" || verification.contentHash !== row.contentHash
      || verification.listingId !== row.listingId || verification.listingVersion !== version
      || row.revocationStatus !== "absent") {
      return Object.freeze({ status: "rejected" as const, reason: "Listing authority failed content, signature, or reference verification" });
    }
    return Object.freeze({ status: "verified" as const, contentHash: row.contentHash, listingId: row.listingId, version });
  }

  resolveIdentity(bundleHash: string) {
    const row = this.#database.query<{
      artifactContentHash: string; primaryClaim: string;
    }, { bundleHash: string }>(`
      SELECT artifact_content_hash AS artifactContentHash, primary_claim AS primaryClaim
      FROM fixture_identity_authorities WHERE bundle_hash = $bundleHash
    `).get({ bundleHash });
    if (row === null) return Object.freeze({ status: "absent" as const });
    try {
      const artifact = this.#artifacts.get(row.artifactContentHash);
      if (artifact === null || !artifact.kinds.includes("dacs-identity-bundle")) {
        return Object.freeze({ status: "rejected" as const, reason: "IdentityBundle authority artifact is missing or mistyped" });
      }
      const identity = parseCanonicalObject(artifact.canonicalJson, "IdentityBundle");
      assertPerClaimIdentityBundleForPublication(identity);
      const actualHash = sha256Hex(canonicalize(withoutFields(identity, "presentation")));
      const primaryClaim = identity["presentedBy"] as string;
      const publicKey = directPublicKey(primaryClaim);
      if (actualHash !== bundleHash || primaryClaim !== row.primaryClaim || publicKey === null) {
        throw new FixtureAuthorityIntegrityError("IdentityBundle authority binding is inconsistent");
      }
      return Object.freeze({ status: "verified" as const, bundleHash, primaryClaim, publicKey });
    } catch (error) {
      if (!(error instanceof FixtureAuthorityIntegrityError) && !(error instanceof ArtifactIntegrityError)) {
        throw error;
      }
      return Object.freeze({
        status: "rejected" as const,
        reason: error.message,
      });
    }
  }
}

function verifyFixtureListing(
  canonicalJson: string,
  nowMs: number,
  authority: Pick<ListingVerificationOptions, "revocationCheck" | "paymentRailCheck">,
) {
  return verifyCanonicalListingJson(canonicalJson, {
    nowMs,
    ...authority,
  });
}

function parseRailResolutions(canonicalJson: string): readonly PersistedRailResolution[] {
  let value: unknown;
  try { value = JSON.parse(canonicalJson) as unknown; }
  catch { throw new FixtureAuthorityIntegrityError("Listing rail authority is not valid JSON"); }
  if (!Array.isArray(value) || canonicalize(value) !== canonicalJson) {
    throw new FixtureAuthorityIntegrityError("Listing rail authority is not canonical JSON");
  }
  for (const entry of value) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
      || !("request" in entry) || !("result" in entry)) {
      throw new FixtureAuthorityIntegrityError("Listing rail authority entry is invalid");
    }
    const record = entry as Record<string, unknown>;
    if (!exactKeys(record, ["request", "result"])
      || !validPersistedRailRequest(record["request"])
      || !validPersistedRailResult(record["result"])) {
      throw new FixtureAuthorityIntegrityError("Listing rail authority entry has an invalid request or result");
    }
  }
  return value as PersistedRailResolution[];
}

function validPersistedRailRequest(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const request = value as Record<string, unknown>;
  const expectedKeys = request["railVersion"] === undefined
    ? ["canonicalJson", "railId", "referencedByPhaseKinds"]
    : ["canonicalJson", "railId", "railVersion", "referencedByPhaseKinds"];
  if (!exactKeys(request, expectedKeys) || typeof request["canonicalJson"] !== "string"
    || typeof request["railId"] !== "string" || request["railId"].length === 0
    || (request["railVersion"] !== undefined
      && (!Number.isSafeInteger(request["railVersion"]) || (request["railVersion"] as number) < 1))
    || !Array.isArray(request["referencedByPhaseKinds"])
    || !request["referencedByPhaseKinds"].every((kind) => typeof kind === "string" && kind.startsWith("pay-"))) {
    return false;
  }
  let rail: unknown;
  try { rail = JSON.parse(request["canonicalJson"] as string) as unknown; }
  catch { return false; }
  if (rail === null || typeof rail !== "object" || Array.isArray(rail)
    || canonicalize(rail) !== request["canonicalJson"]) return false;
  const railRef = rail as Record<string, unknown>;
  return railRef["railId"] === request["railId"]
    && railRef["railVersion"] === request["railVersion"];
}

function validPersistedRailResult(value: unknown): value is PaymentRailCheck {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const result = value as Record<string, unknown>;
  if (result["status"] === "resolved") {
    return exactKeys(result, ["phaseHandler", "status"])
      && typeof result["phaseHandler"] === "string" && result["phaseHandler"].length > 0;
  }
  return (result["status"] === "unresolved" || result["status"] === "indeterminate")
    && exactKeys(result, ["status"]);
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === [...expected].sort()[index]);
}

function parseTimestamp(value: string, label: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isSafeInteger(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new FixtureAuthorityIntegrityError(`${label} is invalid`);
  }
  return timestamp;
}

function parseCanonicalObject(canonicalJson: string, label: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(canonicalJson) as unknown; }
  catch { throw new FixtureAuthorityIntegrityError(`${label} authority is not valid JSON`); }
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || canonicalize(value) !== canonicalJson) {
    throw new FixtureAuthorityIntegrityError(`${label} authority is not canonical JSON`);
  }
  return value as Record<string, unknown>;
}

function directPublicKey(claim: string): Uint8Array | null {
  try {
    const parsed = canonicalizeClaimReference(claim);
    return parsed.scheme === "key" && /^[0-9a-f]{64}$/.test(parsed.identifier)
      ? Uint8Array.from(Buffer.from(parsed.identifier, "hex")) : null;
  } catch {
    return null;
  }
}

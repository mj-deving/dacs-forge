import { canonicalize } from "../../protocol/canonical-json.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import {
  createLifecycleBoundEd25519Signer,
  resolveProviderBackedEd25519Claim,
  type ArtifactSigner,
  type NonExportingEd25519Provider,
} from "../../producer/fixture-ed25519.ts";
import type { EvidenceMode } from "../../core/evidence-mode.ts";
import type { DacsDatabase } from "../sqlite/database.ts";

const REVOCATION_DOMAIN = "dacs-production-key-revocation:v1:";
const KEY_CLAIM = /^key:[0-9a-f]{64}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

type ProductionMode = Exclude<EvidenceMode, "fixture">;

export type KeyCurrentnessResolution =
  | Readonly<{
    readonly disposition: "current";
    readonly currentClaim: string;
    readonly recipeVersion: number;
    readonly checkedAt: number;
  }>
  | Readonly<{
    readonly disposition: "superseded" | "revoked";
    readonly currentClaim: string;
    readonly recipeVersion: number;
    readonly checkedAt: number;
  }>
  | Readonly<{
    readonly disposition: "indeterminate";
    readonly recipeVersion: number;
    readonly checkedAt: number;
  }>;

export interface Dacs2KeyCurrentnessResolver {
  resolve(input: Readonly<{ readonly keyClaim: string; readonly checkedAt: number }>):
    KeyCurrentnessResolution;
}

export interface ProductionSigningStartupOptions<TActionProvider> {
  readonly deploymentMode: ProductionMode;
  readonly initializeActionProvider: () => TActionProvider;
  readonly keyHandle: string;
  readonly provider: NonExportingEd25519Provider;
}

export interface RetainedListingKeyBinding {
  readonly contentHash: string;
  readonly listingId: string;
  readonly listingVersion: number;
}

export interface ProductionKeyRevocation {
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly keyClaim: string;
  readonly listingId: string;
  readonly listingVersion: number;
  readonly replacementKeyClaim: string;
  readonly revokedAt: number;
}

interface KeyRow {
  readonly activatedAt: bigint;
  readonly keyClaim: string;
  readonly keyHandle: string;
  readonly providerId: string;
  readonly revokedAt: bigint | null;
  readonly state: "current" | "revoked";
}

interface ListingRow {
  readonly contentHash: string;
  readonly listingId: string;
  readonly listingVersion: bigint;
}

interface PinRow {
  readonly agreementHash: string;
  readonly committedAt: bigint;
  readonly keyClaim: string;
}

interface LatestPinRow {
  readonly latestCommittedAt: bigint | null;
}

interface RevocationRow {
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly keyClaim: string;
  readonly listingId: string;
  readonly listingVersion: bigint;
  readonly replacementKeyClaim: string;
  readonly revokedAt: bigint;
}

export function initializeProductionSigning<TActionProvider>(
  options: ProductionSigningStartupOptions<TActionProvider>,
): Readonly<{ readonly keyClaim: string; readonly actionProvider: TActionProvider }> {
  assertExactKeys(options, [
    "deploymentMode", "initializeActionProvider", "keyHandle", "provider",
  ]);
  if (typeof options.initializeActionProvider !== "function") {
    throw new TypeError("Production signing startup requires an action-provider initializer");
  }
  const keyClaim = resolveProviderBackedEd25519Claim({
    deploymentMode: options.deploymentMode,
    keyHandle: options.keyHandle,
    provider: options.provider,
  });
  return Object.freeze({ keyClaim, actionProvider: options.initializeActionProvider() });
}

export class ProductionKeyLifecycle {
  readonly #deploymentMode: ProductionMode;
  readonly #provider: NonExportingEd25519Provider;
  readonly #resolver: Dacs2KeyCurrentnessResolver;
  #rotationSigning = false;

  constructor(
    private readonly database: DacsDatabase,
    options: Readonly<{
      readonly deploymentMode: ProductionMode;
      readonly provider: NonExportingEd25519Provider;
      readonly resolver: Dacs2KeyCurrentnessResolver;
    }>,
  ) {
    if (options.deploymentMode !== "local-chain" && options.deploymentMode !== "live") {
      throw new TypeError("Production key lifecycle requires local-chain or live deployment");
    }
    if (options.provider === null || typeof options.provider !== "object"
      || typeof options.provider.providerId !== "string"
      || typeof options.provider.publicKey !== "function"
      || typeof options.provider.sign !== "function") {
      throw new TypeError("Production key lifecycle requires a non-exporting signer provider");
    }
    if (options.resolver === null || typeof options.resolver !== "object"
      || typeof options.resolver.resolve !== "function") {
      throw new TypeError("Production key lifecycle requires DACS-2 currentness authority");
    }
    this.#deploymentMode = options.deploymentMode;
    this.#provider = options.provider;
    this.#resolver = options.resolver;
  }

  activateInitialKey(keyHandle: string, activatedAt: number): ArtifactSigner {
    this.#assertNoCallerTransaction("Initial production-key activation");
    validateTime(activatedAt, "activatedAt");
    return this.database.transaction((snapshot: Readonly<{
      readonly activatedAt: number;
      readonly keyHandle: string;
    }>) => {
      if (this.#currentRow() !== null) throw new Error("Production signing key is already active");
      const signer = this.#signer(snapshot.keyHandle);
      this.#assertResolvedCurrent(signer.signer, snapshot.activatedAt);
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: production-key.activate */
        INSERT INTO production_signing_keys (
          key_claim, provider_id, key_handle, state, activated_at, revoked_at
        ) VALUES ($keyClaim, $providerId, $keyHandle, 'current', $activatedAt, NULL)
      `).run({
        keyClaim: signer.signer,
        providerId: this.#provider.providerId,
        keyHandle: snapshot.keyHandle,
        activatedAt: snapshot.activatedAt,
      });
      return signer;
    }).immediate(Object.freeze({ keyHandle, activatedAt }));
  }

  currentSigner(): ArtifactSigner {
    const current = this.#currentRow();
    if (current === null) throw new Error("Production signing key is not initialized");
    this.#assertProviderBinding(current);
    const signer = this.#signer(current.keyHandle);
    if (signer.signer !== current.keyClaim) {
      throw new Error("Provider public key no longer matches persisted current authority");
    }
    return signer;
  }

  #registerRetainedListing(keyClaim: string, binding: RetainedListingKeyBinding): void {
    validateKeyClaim(keyClaim);
    validateListing(binding);
    this.database.transaction((snapshot: RetainedListingKeyBinding) => {
      const current = this.#currentRow();
      if (current === null || current.keyClaim !== keyClaim) {
        throw new Error("Retained Listing signer is not the current production key");
      }
      const existing = this.database.query<{ contentHash: string }, Record<string, string | number>>(`
        SELECT listing_content_hash AS contentHash
        FROM production_key_listing_versions
        WHERE key_claim = $keyClaim AND listing_id = $listingId
          AND listing_version = $listingVersion
      `).get({ keyClaim, ...snapshot });
      if (existing !== null) {
        if (existing.contentHash !== snapshot.contentHash) {
          throw new Error("Retained Listing version cannot change content hash");
        }
        return;
      }
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: production-key.retain-listing */
        INSERT INTO production_key_listing_versions (
          key_claim, listing_id, listing_version, listing_content_hash
        ) VALUES ($keyClaim, $listingId, $listingVersion, $contentHash)
      `).run({ keyClaim, ...snapshot });
    }).immediate(binding);
  }

  rotate(replacementKeyHandle: string, revokedAt: number): readonly ProductionKeyRevocation[] {
    this.#assertNoCallerTransaction("Production-key rotation");
    validateTime(revokedAt, "revokedAt");
    const replacementSigner = this.#signer(replacementKeyHandle);
    return this.database.transaction(() => {
      this.#assertResolvedCurrent(replacementSigner.signer, revokedAt);
      const current = this.#currentRow();
      if (current === null) throw new Error("Production signing key is not initialized");
      if (revokedAt < Number(current.activatedAt)) {
        throw new TypeError("Key revocation cannot precede activation");
      }
      if (replacementSigner.signer === current.keyClaim) {
        throw new TypeError("Replacement key must differ from the current key");
      }
      const latestPin = this.database.query<LatestPinRow, { keyClaim: string }>(`
        SELECT MAX(committed_at) AS latestCommittedAt
        FROM production_session_key_pins WHERE key_claim = $keyClaim
      `).get({ keyClaim: current.keyClaim });
      const latestCommittedAt = latestPin?.latestCommittedAt ?? null;
      if (latestCommittedAt !== null && revokedAt <= Number(latestCommittedAt)) {
        throw new Error("Key revocation must follow every committed session pin");
      }
      this.#assertProviderBinding(current);
      const oldSigner = this.#signer(current.keyHandle);
      if (oldSigner.signer !== current.keyClaim) {
        throw new Error("Provider public key no longer matches persisted current authority");
      }
      const retained = this.database.query<ListingRow, { keyClaim: string }>(`
        SELECT listing_id AS listingId, listing_version AS listingVersion,
          listing_content_hash AS contentHash
        FROM production_key_listing_versions
        WHERE key_claim = $keyClaim
        ORDER BY listing_id, listing_version
      `).all({ keyClaim: current.keyClaim });
      let revocations: readonly ProductionKeyRevocation[];
      this.#rotationSigning = true;
      try {
        revocations = retained.map((listing) => this.#signedRevocation(
          oldSigner,
          {
            listingId: listing.listingId,
            listingVersion: Number(listing.listingVersion),
            contentHash: listing.contentHash,
          },
          replacementSigner.signer,
          revokedAt,
        ));
      } finally {
        this.#rotationSigning = false;
      }
      const changed = this.database.query<never, { keyClaim: string; revokedAt: number }>(`
        /* atomic-write: production-key.revoke-current */
        UPDATE production_signing_keys
        SET state = 'revoked', revoked_at = $revokedAt
        WHERE key_claim = $keyClaim AND state = 'current' AND revoked_at IS NULL
      `).run({ keyClaim: current.keyClaim, revokedAt });
      if (changed.changes !== 1) throw new Error("Current production key changed during rotation");
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: production-key.activate-replacement */
        INSERT INTO production_signing_keys (
          key_claim, provider_id, key_handle, state, activated_at, revoked_at
        ) VALUES ($keyClaim, $providerId, $keyHandle, 'current', $activatedAt, NULL)
      `).run({
        keyClaim: replacementSigner.signer,
        providerId: this.#provider.providerId,
        keyHandle: replacementKeyHandle,
        activatedAt: revokedAt,
      });
      for (const revocation of revocations) {
        this.database.query<never, Record<string, string | number>>(`
          /* atomic-write: production-key.publish-revocation */
          INSERT INTO production_key_revocations (
            key_claim, listing_id, listing_version, listing_content_hash,
            replacement_key_claim, revoked_at, revocation_content_hash, canonical_json
          ) VALUES (
            $keyClaim, $listingId, $listingVersion, $listingContentHash,
            $replacementKeyClaim, $revokedAt, $contentHash, $canonicalJson
          )
        `).run({
          ...revocation,
          listingContentHash: JSON.parse(revocation.canonicalJson)["listingContentHash"] as string,
        });
      }
      return Object.freeze(revocations);
    }).immediate();
  }

  assertCurrentForNewSession(input: Readonly<{
    readonly checkedAt: number;
    readonly keyClaim: string;
  }>): void {
    validateKeyClaim(input.keyClaim);
    validateTime(input.checkedAt, "checkedAt");
    this.#assertNoCallerTransaction("New-session currentness admission");
    this.database.transaction(() => this.#assertCurrentForNewSession(input)).immediate();
  }

  #assertCurrentForNewSession(input: Readonly<{
    readonly checkedAt: number;
    readonly keyClaim: string;
  }>): void {
    const current = this.#currentRow();
    if (current === null || current.keyClaim !== input.keyClaim) {
      throw new Error("New session key is not the persisted current production key");
    }
    if (input.checkedAt < Number(current.activatedAt)) {
      throw new Error("New session currentness check precedes key activation");
    }
    this.#assertResolvedCurrent(input.keyClaim, input.checkedAt);
  }

  assertSignatureForNewSession(input: Readonly<{
    readonly checkedAt: number;
    readonly keyClaim: string;
    readonly signedAt: number;
  }>): void {
    validateKeyClaim(input.keyClaim);
    validateTime(input.checkedAt, "checkedAt");
    validateTime(input.signedAt, "signedAt");
    this.#assertNoCallerTransaction("New-session signature admission");
    this.database.transaction(() => {
      this.#assertCurrentForNewSession(input);
      const row = this.#keyRow(input.keyClaim);
      if (row === null || row.state !== "current"
        || input.signedAt < Number(row.activatedAt)
        || input.signedAt > input.checkedAt
        || (row.revokedAt !== null && input.signedAt >= Number(row.revokedAt))) {
        throw new Error("New session signature falls outside the current key validity interval");
      }
    }).immediate();
  }

  pinCommittedSession(input: Readonly<{
    readonly agreementHash: string;
    readonly committedAt: number;
    readonly jobId: string;
    readonly keyClaim: string;
  }>): void {
    validateHash(input.agreementHash, "agreementHash");
    validateText(input.jobId, "jobId");
    validateKeyClaim(input.keyClaim);
    validateTime(input.committedAt, "committedAt");
    this.#assertNoCallerTransaction("Committed-session key pin");
    this.database.transaction((snapshot: typeof input) => {
      this.#assertCurrentForNewSession({
        keyClaim: snapshot.keyClaim,
        checkedAt: snapshot.committedAt,
      });
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: production-key.pin-committed-session */
        INSERT INTO production_session_key_pins (
          job_id, agreement_hash, key_claim, committed_at
        ) VALUES ($jobId, $agreementHash, $keyClaim, $committedAt)
      `).run(snapshot);
    }).immediate(input);
  }

  assertCommittedSessionKey(input: Readonly<{
    readonly agreementHash: string;
    readonly checkedAt: number;
    readonly evidenceSignedAt: number;
    readonly jobId: string;
    readonly keyClaim: string;
  }>): void {
    validateHash(input.agreementHash, "agreementHash");
    validateText(input.jobId, "jobId");
    validateKeyClaim(input.keyClaim);
    validateTime(input.checkedAt, "checkedAt");
    validateTime(input.evidenceSignedAt, "evidenceSignedAt");
    this.#assertNoCallerTransaction("Committed-session evidence admission");
    this.database.transaction(() => {
      const pin = this.database.query<PinRow, { jobId: string }>(`
        SELECT agreement_hash AS agreementHash, committed_at AS committedAt, key_claim AS keyClaim
        FROM production_session_key_pins WHERE job_id = $jobId
      `).get({ jobId: input.jobId });
      if (pin === null || pin.agreementHash !== input.agreementHash
        || pin.keyClaim !== input.keyClaim) {
        throw new Error("Session evidence does not match its committed pre-revocation key pin");
      }
      const key = this.#keyRow(input.keyClaim);
      if (key === null || input.checkedAt < Number(pin.committedAt)
        || input.evidenceSignedAt < Number(pin.committedAt)
        || input.evidenceSignedAt > input.checkedAt
        || input.evidenceSignedAt < Number(key.activatedAt)
        || (key.revokedAt !== null && input.evidenceSignedAt >= Number(key.revokedAt))) {
        throw new Error("Session evidence falls outside its pinned key validity interval");
      }
    }).immediate();
  }

  revocationsForKey(keyClaim: string): readonly ProductionKeyRevocation[] {
    validateKeyClaim(keyClaim);
    return Object.freeze(this.database.query<RevocationRow, { keyClaim: string }>(`
      SELECT key_claim AS keyClaim, listing_id AS listingId,
        listing_version AS listingVersion, replacement_key_claim AS replacementKeyClaim,
        revoked_at AS revokedAt, revocation_content_hash AS contentHash,
        canonical_json AS canonicalJson
      FROM production_key_revocations
      WHERE key_claim = $keyClaim ORDER BY listing_id, listing_version
    `).all({ keyClaim }).map((row) => Object.freeze({
      keyClaim: row.keyClaim,
      listingId: row.listingId,
      listingVersion: Number(row.listingVersion),
      replacementKeyClaim: row.replacementKeyClaim,
      revokedAt: Number(row.revokedAt),
      contentHash: row.contentHash,
      canonicalJson: row.canonicalJson,
    })));
  }

  #assertProviderBinding(row: KeyRow): void {
    if (row.providerId !== this.#provider.providerId) {
      throw new Error("Persisted production key belongs to a different signer provider");
    }
  }

  #assertResolvedCurrent(keyClaim: string, checkedAt: number): void {
    const resolution = this.#resolver.resolve(Object.freeze({ keyClaim, checkedAt }));
    validateResolution(resolution, checkedAt);
    if (resolution.disposition !== "current" || resolution.currentClaim !== keyClaim) {
      throw new Error("DACS-2 currentness authority does not resolve the requested key as current");
    }
  }

  #currentRow(): KeyRow | null {
    const rows = this.database.query<KeyRow, []>(`
      SELECT key_claim AS keyClaim, provider_id AS providerId, key_handle AS keyHandle,
        state, activated_at AS activatedAt, revoked_at AS revokedAt
      FROM production_signing_keys WHERE state = 'current'
    `).all();
    if (rows.length > 1) throw new Error("Production signing authority has multiple current keys");
    return rows[0] ?? null;
  }

  #keyRow(keyClaim: string): KeyRow | null {
    return this.database.query<KeyRow, { keyClaim: string }>(`
      SELECT key_claim AS keyClaim, provider_id AS providerId, key_handle AS keyHandle,
        state, activated_at AS activatedAt, revoked_at AS revokedAt
      FROM production_signing_keys WHERE key_claim = $keyClaim
    `).get({ keyClaim });
  }

  #signedRevocation(
    signer: ArtifactSigner,
    listing: RetainedListingKeyBinding,
    replacementKeyClaim: string,
    revokedAt: number,
  ): ProductionKeyRevocation {
    const unsigned = {
      revocationVersion: "1",
      keyClaim: signer.signer,
      replacementKeyClaim,
      listingId: listing.listingId,
      listingVersion: listing.listingVersion,
      listingContentHash: listing.contentHash,
      revokedAt,
    };
    const scopeHash = sha256Hex(canonicalize(unsigned));
    const signature = signer.sign(
      new TextEncoder().encode(`${REVOCATION_DOMAIN}${scopeHash}`),
      { deploymentMode: this.#deploymentMode, requestMode: this.#deploymentMode },
    );
    const canonicalJson = canonicalize({
      ...unsigned,
      signature: { algorithm: signer.algorithm, signer: signer.signer, value: signature },
    });
    return Object.freeze({
      keyClaim: signer.signer,
      listingId: listing.listingId,
      listingVersion: listing.listingVersion,
      replacementKeyClaim,
      revokedAt,
      contentHash: sha256Hex(canonicalJson),
      canonicalJson,
    });
  }

  #signer(keyHandle: string): ArtifactSigner {
    return createLifecycleBoundEd25519Signer({
      deploymentMode: this.#deploymentMode,
      keyHandle,
      provider: this.#provider,
      retainListing: (keyClaim, binding) => this.#registerRetainedListing(keyClaim, binding),
      signCurrent: (keyClaim, payload) => this.#signCurrent(keyClaim, keyHandle, payload),
    });
  }

  #signCurrent(keyClaim: string, keyHandle: string, payload: Uint8Array): Uint8Array {
    const sign = () => {
      this.#assertPersistedCurrent(keyClaim);
      const currentProviderClaim = resolveProviderBackedEd25519Claim({
        deploymentMode: this.#deploymentMode,
        keyHandle,
        provider: this.#provider,
      });
      if (currentProviderClaim !== keyClaim) {
        throw new Error("Provider public key no longer matches persisted current authority");
      }
      return Uint8Array.from(this.#provider.sign(keyHandle, Uint8Array.from(payload)));
    };
    if (this.database.inTransaction) {
      if (!this.#rotationSigning) {
        throw new Error("Production signing refuses a caller-owned database transaction");
      }
      return sign();
    }
    return this.database.transaction(sign).immediate();
  }

  #assertPersistedCurrent(keyClaim: string): void {
    const current = this.#currentRow();
    if (current === null || current.keyClaim !== keyClaim || current.revokedAt !== null) {
      throw new Error("Production signing capability is not the persisted current key");
    }
    this.#assertProviderBinding(current);
  }

  #assertNoCallerTransaction(operation: string): void {
    if (this.database.inTransaction) {
      throw new Error(`${operation} refuses a caller-owned database transaction`);
    }
  }
}

function validateResolution(resolution: KeyCurrentnessResolution, checkedAt: number): void {
  if (resolution === null || typeof resolution !== "object"
    || !Number.isSafeInteger(resolution.recipeVersion) || resolution.recipeVersion < 1
    || resolution.checkedAt !== checkedAt
    || !["current", "superseded", "revoked", "indeterminate"].includes(resolution.disposition)
    || (resolution.disposition !== "indeterminate"
      && !KEY_CLAIM.test(resolution.currentClaim))) {
    throw new TypeError("DACS-2 key currentness resolution is invalid");
  }
}

function validateListing(binding: RetainedListingKeyBinding): void {
  assertExactKeys(binding, ["contentHash", "listingId", "listingVersion"]);
  validateHash(binding.contentHash, "contentHash");
  validateText(binding.listingId, "listingId");
  if (!Number.isSafeInteger(binding.listingVersion) || binding.listingVersion < 1) {
    throw new TypeError("listingVersion must be a positive safe integer");
  }
}

function validateKeyClaim(value: unknown): asserts value is string {
  if (typeof value !== "string" || !KEY_CLAIM.test(value)) {
    throw new TypeError("keyClaim must be a canonical direct Ed25519 key ClaimReference");
  }
}

function validateHash(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !LOWER_HEX_64.test(value)) {
    throw new TypeError(`${label} must be lowercase SHA-256`);
  }
}

function validateTime(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
}

function validateText(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4_096
    || value !== value.normalize("NFC")) {
    throw new TypeError(`${label} must be bounded NFC text`);
  }
}

function assertExactKeys(value: object, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new TypeError(`Object requires exactly ${canonical.join(", ")}`);
  }
}

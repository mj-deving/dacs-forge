import type { DacsDatabase } from "./database.ts";

const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

export interface ListingVersionRecord {
  readonly sellerPrimaryClaim: string;
  readonly listingId: string;
  readonly listingVersion: number;
  readonly contentHash: string;
  readonly canonicalJson: string;
  readonly logicalAddress: string;
  readonly nativeAddress: string;
  readonly anchorTx: string;
  readonly anchorVerifiedAt: number;
  readonly createdAt: string;
}

export interface ListingReference {
  readonly sellerPrimaryClaim: string;
  readonly listingId: string;
  readonly listingVersion: number;
  readonly contentHash: string;
}

export interface ListingRevocationRecord extends ListingReference {
  readonly revocationContentHash: string;
  readonly canonicalJson: string;
  readonly logicalAddress: string;
  readonly nativeAddress: string;
  readonly anchorTx: string;
  readonly anchorVerifiedAt: number;
  readonly createdAt: string;
}

interface VersionRow {
  readonly sellerPrimaryClaim: string;
  readonly listingId: string;
  readonly listingVersion: bigint;
  readonly contentHash: string;
  readonly revocationContentHash?: string;
  readonly canonicalJson: string;
  readonly logicalAddress: string;
  readonly nativeAddress: string;
  readonly anchorTx: string;
  readonly anchorVerifiedAt: bigint;
  readonly createdAt: string;
}

export class ListingStore {
  constructor(private readonly database: DacsDatabase) {}

  publish(record: ListingVersionRecord): ListingReference {
    validateVersionRecord(record);
    return this.database.transaction((snapshot: ListingVersionRecord) => {
      const latest = this.database.query<{ version: bigint }, {
        sellerPrimaryClaim: string; listingId: string;
      }>(`
        SELECT max(listing_version) AS version FROM fixture_listing_lifecycle_versions
        WHERE seller_primary_claim = $sellerPrimaryClaim AND listing_id = $listingId
      `).get({ sellerPrimaryClaim: snapshot.sellerPrimaryClaim, listingId: snapshot.listingId });
      const expected = latest?.version === null || latest?.version === undefined
        ? 1 : Number(latest.version) + 1;
      if (snapshot.listingVersion !== expected) {
        throw new Error(`Listing version must advance exactly to ${expected}`);
      }
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.reserve-anchor */
        INSERT INTO fixture_listing_anchor_registry (
          native_address, logical_address, artifact_kind, content_hash
        ) VALUES ($nativeAddress, $logicalAddress, 'listing', $contentHash)
      `).run({ ...snapshot });
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.publish-version */
        INSERT INTO fixture_listing_lifecycle_versions (
          seller_primary_claim, listing_id, listing_version, listing_content_hash, canonical_json,
          logical_address, native_address, anchor_tx, anchor_verified_at, created_at
        ) VALUES (
          $sellerPrimaryClaim, $listingId, $listingVersion, $contentHash, $canonicalJson,
          $logicalAddress, $nativeAddress, $anchorTx, $anchorVerifiedAt, $createdAt
        )
      `).run({ ...snapshot });
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.advance-discovery */
        INSERT INTO fixture_listing_discovery (
          seller_primary_claim, listing_id, listing_version, listing_content_hash,
          native_address, published_at
        ) VALUES (
          $sellerPrimaryClaim, $listingId, $listingVersion, $contentHash, $nativeAddress, $createdAt
        )
        ON CONFLICT(seller_primary_claim, listing_id) DO UPDATE SET
          listing_version = excluded.listing_version,
          listing_content_hash = excluded.listing_content_hash,
          native_address = excluded.native_address,
          published_at = excluded.published_at
      `).run({ ...snapshot });
      return reference(snapshot);
    }).immediate(record);
  }

  get(sellerPrimaryClaim: string, listingId: string, listingVersion: number): ListingVersionRecord | null {
    validateText(sellerPrimaryClaim, "sellerPrimaryClaim");
    validateIdentity(listingId, listingVersion);
    const row = this.database.query<VersionRow, {
      sellerPrimaryClaim: string; listingId: string; listingVersion: number;
    }>(`
      SELECT seller_primary_claim AS sellerPrimaryClaim,
        listing_id AS listingId, listing_version AS listingVersion,
        listing_content_hash AS contentHash, canonical_json AS canonicalJson,
        logical_address AS logicalAddress, native_address AS nativeAddress,
        anchor_tx AS anchorTx, anchor_verified_at AS anchorVerifiedAt, created_at AS createdAt
      FROM fixture_listing_lifecycle_versions
      WHERE seller_primary_claim = $sellerPrimaryClaim
        AND listing_id = $listingId AND listing_version = $listingVersion
    `).get({ sellerPrimaryClaim, listingId, listingVersion });
    return row === null ? null : versionRecord(row);
  }

  current(sellerPrimaryClaim: string, listingId: string): ListingReference | null {
    const row = this.database.query<{
      sellerPrimaryClaim: string; listingId: string; listingVersion: bigint; contentHash: string;
    }, { sellerPrimaryClaim: string; listingId: string }>(`
      SELECT seller_primary_claim AS sellerPrimaryClaim,
        listing_id AS listingId, listing_version AS listingVersion,
        listing_content_hash AS contentHash
      FROM fixture_listing_discovery
      WHERE seller_primary_claim = $sellerPrimaryClaim AND listing_id = $listingId
    `).get({ sellerPrimaryClaim, listingId });
    return row === null ? null : Object.freeze({
      sellerPrimaryClaim: row.sellerPrimaryClaim,
      listingId: row.listingId,
      listingVersion: Number(row.listingVersion),
      contentHash: row.contentHash,
    });
  }

  revoke(record: ListingRevocationRecord): void {
    validateRevocationRecord(record);
    this.database.transaction((snapshot: ListingRevocationRecord) => {
      const version = this.get(
        snapshot.sellerPrimaryClaim,
        snapshot.listingId,
        snapshot.listingVersion,
      );
      if (version === null || version.contentHash !== snapshot.contentHash) {
        throw new Error("Revocation does not match a retained Listing version");
      }
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.reserve-revocation-anchor */
        INSERT INTO fixture_listing_anchor_registry (
          native_address, logical_address, artifact_kind, content_hash
        ) VALUES ($nativeAddress, $logicalAddress, 'revocation', $revocationContentHash)
      `).run({ ...snapshot });
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.publish-revocation */
        INSERT INTO fixture_listing_revocations (
          seller_primary_claim, listing_id, listing_version, listing_content_hash,
          revocation_content_hash, canonical_json,
          logical_address, native_address, anchor_tx, anchor_verified_at, created_at
        ) VALUES (
          $sellerPrimaryClaim, $listingId, $listingVersion, $contentHash,
          $revocationContentHash, $canonicalJson,
          $logicalAddress, $nativeAddress, $anchorTx, $anchorVerifiedAt, $createdAt
        )
      `).run({ ...snapshot });
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.withdraw-discovery */
        DELETE FROM fixture_listing_discovery
        WHERE seller_primary_claim = $sellerPrimaryClaim
          AND listing_id = $listingId AND listing_version = $listingVersion
          AND listing_content_hash = $contentHash
      `).run({ ...reference(snapshot) });
    }).immediate(record);
  }

  revocation(
    sellerPrimaryClaim: string,
    listingId: string,
    listingVersion: number,
  ): ListingRevocationRecord | null {
    validateText(sellerPrimaryClaim, "sellerPrimaryClaim");
    validateIdentity(listingId, listingVersion);
    const row = this.database.query<VersionRow, {
      sellerPrimaryClaim: string; listingId: string; listingVersion: number;
    }>(`
      SELECT seller_primary_claim AS sellerPrimaryClaim,
        listing_id AS listingId, listing_version AS listingVersion,
        listing_content_hash AS contentHash, revocation_content_hash AS revocationContentHash,
        canonical_json AS canonicalJson,
        logical_address AS logicalAddress, native_address AS nativeAddress,
        anchor_tx AS anchorTx, anchor_verified_at AS anchorVerifiedAt, created_at AS createdAt
      FROM fixture_listing_revocations
      WHERE seller_primary_claim = $sellerPrimaryClaim
        AND listing_id = $listingId AND listing_version = $listingVersion
    `).get({ sellerPrimaryClaim, listingId, listingVersion });
    return row === null ? null : Object.freeze({
      ...versionRecord(row),
      revocationContentHash: row.revocationContentHash!,
    });
  }

  pinSession(jobId: string, listing: ListingReference, pinnedAt: string): ListingReference {
    validateReference(listing);
    validateText(jobId, "jobId");
    validateTimestamp(pinnedAt, "pinnedAt");
    return this.database.transaction((input: {
      readonly jobId: string;
      readonly listing: ListingReference;
      readonly pinnedAt: string;
    }) => {
      const existing = this.sessionPin(input.jobId);
      if (existing !== null) {
        if (sameReference(existing, input.listing)) return existing;
        throw new Error("Session already pins a different Listing version");
      }
      const retained = this.get(
        input.listing.sellerPrimaryClaim,
        input.listing.listingId,
        input.listing.listingVersion,
      );
      if (retained === null || retained.contentHash !== input.listing.contentHash) {
        throw new Error("Session pin must reference a retained immutable Listing version");
      }
      if (this.revocation(
        input.listing.sellerPrimaryClaim,
        input.listing.listingId,
        input.listing.listingVersion,
      ) !== null) {
        throw new Error("Session pin cannot admit a revoked Listing version");
      }
      this.database.query<never, Record<string, string | number>>(`
        /* atomic-write: listing.pin-session */
        INSERT INTO fixture_session_listing_pins (
          job_id, seller_primary_claim, listing_id, listing_version,
          listing_content_hash, pinned_at
        ) VALUES (
          $jobId, $sellerPrimaryClaim, $listingId, $listingVersion, $contentHash, $pinnedAt
        )
      `).run({ jobId: input.jobId, ...input.listing, pinnedAt: input.pinnedAt });
      return reference(input.listing);
    }).immediate({ jobId, listing, pinnedAt });
  }

  sessionPin(jobId: string): ListingReference | null {
    const row = this.database.query<{
      sellerPrimaryClaim: string; listingId: string; listingVersion: bigint; contentHash: string;
    }, { jobId: string }>(`
      SELECT seller_primary_claim AS sellerPrimaryClaim,
        listing_id AS listingId, listing_version AS listingVersion,
        listing_content_hash AS contentHash
      FROM fixture_session_listing_pins WHERE job_id = $jobId
    `).get({ jobId });
    return row === null ? null : Object.freeze({
      sellerPrimaryClaim: row.sellerPrimaryClaim,
      listingId: row.listingId,
      listingVersion: Number(row.listingVersion),
      contentHash: row.contentHash,
    });
  }
}

function versionRecord(row: VersionRow): ListingVersionRecord {
  return Object.freeze({
    sellerPrimaryClaim: row.sellerPrimaryClaim,
    listingId: row.listingId,
    listingVersion: Number(row.listingVersion),
    contentHash: row.contentHash,
    canonicalJson: row.canonicalJson,
    logicalAddress: row.logicalAddress,
    nativeAddress: row.nativeAddress,
    anchorTx: row.anchorTx,
    anchorVerifiedAt: Number(row.anchorVerifiedAt),
    createdAt: row.createdAt,
  });
}

function reference(input: ListingReference): ListingReference {
  return Object.freeze({
    sellerPrimaryClaim: input.sellerPrimaryClaim,
    listingId: input.listingId,
    listingVersion: input.listingVersion,
    contentHash: input.contentHash,
  });
}

function sameReference(left: ListingReference, right: ListingReference): boolean {
  return left.sellerPrimaryClaim === right.sellerPrimaryClaim
    && left.listingId === right.listingId && left.listingVersion === right.listingVersion
    && left.contentHash === right.contentHash;
}

function validateVersionRecord(record: ListingVersionRecord): void {
  validateReference(record);
  for (const field of ["canonicalJson", "logicalAddress", "nativeAddress", "anchorTx"] as const) {
    validateText(record[field], field);
  }
  if (!Number.isSafeInteger(record.anchorVerifiedAt) || record.anchorVerifiedAt < 0) {
    throw new TypeError("anchorVerifiedAt must be a non-negative safe integer");
  }
  validateTimestamp(record.createdAt, "createdAt");
}

function validateRevocationRecord(record: ListingRevocationRecord): void {
  validateVersionRecord(record);
  if (!LOWER_HEX_64.test(record.revocationContentHash)) {
    throw new TypeError("Revocation content hash must be lowercase SHA-256");
  }
}

function validateReference(record: ListingReference): void {
  validateText(record.sellerPrimaryClaim, "sellerPrimaryClaim");
  validateIdentity(record.listingId, record.listingVersion);
  if (!LOWER_HEX_64.test(record.contentHash)) {
    throw new TypeError("Listing contentHash must be lowercase SHA-256");
  }
}

function validateIdentity(listingId: string, listingVersion: number): void {
  validateText(listingId, "listingId");
  if (!Number.isSafeInteger(listingVersion) || listingVersion < 1) {
    throw new TypeError("listingVersion must be a positive safe integer");
  }
}

function validateText(value: string, field: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 65_536
    || value !== value.normalize("NFC")) {
    throw new TypeError(`${field} must be a bounded NFC string`);
  }
}

function validateTimestamp(value: string, field: string): void {
  validateText(value, field);
  if (new Date(value).toISOString() !== value) throw new TypeError(`${field} must be canonical ISO-8601`);
}

import { canonicalize } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  verifyFixtureBinding,
  type FixtureBindingAuthority,
  type FixtureBindingProof,
} from "../consumer/binding-verifier.ts";
import { verifyCanonicalListingJson } from "../consumer/listing-verifier.ts";
import {
  assertArtifactSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "../producer/fixture-ed25519.ts";
import {
  ListingStore,
  type ListingReference,
  type ListingRevocationRecord,
  type ListingVersionRecord,
} from "../substrate/sqlite/listing-store.ts";

const REVOCATION_DOMAIN = "dacs-revocation:v1:";

export interface PublishListingInput {
  readonly canonicalJson: string;
  readonly bindingProof: FixtureBindingProof;
  readonly bindingAuthority: FixtureBindingAuthority;
  readonly verifiedAt: number;
  readonly createdAt: string;
}

export interface WithdrawListingInput {
  readonly listing: ListingReference;
  readonly revokedAt: number;
  readonly reason?: string;
  readonly signer: ArtifactSigner;
  readonly signingContext: FixtureSigningContext;
  readonly bindingProof: FixtureBindingProof;
  readonly bindingAuthority: FixtureBindingAuthority;
  readonly verifiedAt: number;
  readonly createdAt: string;
}

export interface SignedListingRevocation {
  readonly marker: Readonly<Record<string, unknown>>;
  readonly canonicalJson: string;
}

export class ListingLifecycle {
  constructor(readonly store: ListingStore) {}

  publish(input: PublishListingInput): ListingReference {
    const binding = verifyFixtureBinding(input.bindingProof, input.bindingAuthority);
    if (binding.disposition !== "verified") {
      throw new Error(`Listing anchor binding is invalid: ${binding.reason}`);
    }
    if (binding.canonicalJson !== input.canonicalJson) {
      throw new Error("Listing binding dereferenced different canonical content");
    }
    const verification = verifyCanonicalListingJson(input.canonicalJson, {
      nowMs: input.verifiedAt,
      revocationCheck: () => "absent",
      paymentRailCheck: () => ({ status: "resolved", phaseHandler: "fixture" }),
    });
    if (verification.disposition !== "accepted") {
      throw new Error(`Listing failed verification: ${verification.stage}: ${verification.reason}`);
    }
    const listing = parseObject(input.canonicalJson, "Listing");
    const seller = listing["seller"] as Record<string, unknown>;
    const identity = seller["identity"] as Record<string, unknown>;
    const listingSignature = listing["signature"] as Record<string, unknown>;
    if (input.bindingProof.signer !== listingSignature["signer"]) {
      throw new Error("Listing binding signer is not the authenticated seller authority");
    }
    const logicalAddress = listingLogicalAddress(
      identity["presentedBy"] as string,
      verification.listingId,
      verification.listingVersion,
    );
    if (input.bindingProof.logicalAddress !== logicalAddress
      || input.bindingProof.contentHash !== sha256Hex(input.canonicalJson)) {
      throw new Error("Listing binding does not match its logical address and anchored bytes");
    }
    const record: ListingVersionRecord = {
      sellerPrimaryClaim: identity["presentedBy"] as string,
      listingId: verification.listingId,
      listingVersion: verification.listingVersion,
      contentHash: verification.contentHash,
      canonicalJson: input.canonicalJson,
      logicalAddress,
      nativeAddress: input.bindingProof.nativeAddress,
      anchorTx: input.bindingProof.createdByTx,
      anchorVerifiedAt: input.verifiedAt,
      createdAt: input.createdAt,
    };
    return this.store.publish(record);
  }

  withdraw(input: WithdrawListingInput): ListingRevocationRecord {
    const retained = this.store.get(
      input.listing.sellerPrimaryClaim,
      input.listing.listingId,
      input.listing.listingVersion,
    );
    if (retained === null || retained.contentHash !== input.listing.contentHash) {
      throw new Error("Withdrawal must reference a retained immutable Listing version");
    }
    if (!Number.isSafeInteger(input.revokedAt) || input.revokedAt < 0
      || !Number.isSafeInteger(input.verifiedAt) || input.verifiedAt < input.revokedAt
      || input.revokedAt < retained.anchorVerifiedAt) {
      throw new TypeError(
        "Revocation time must be a safe integer between Listing anchor verification and revocation verification",
      );
    }
    const listing = parseObject(retained.canonicalJson, "Listing");
    const listingSignature = listing["signature"] as Record<string, unknown>;
    if (listingSignature["signer"] !== input.signer.signer) {
      throw new Error("Revocation signer must equal the Listing signer");
    }
    const { canonicalJson } = createSignedListingRevocation({
      listing: input.listing,
      revokedAt: input.revokedAt,
      ...(input.reason === undefined ? {} : { reason: input.reason }),
      signer: input.signer,
      signingContext: input.signingContext,
    });
    const binding = verifyFixtureBinding(input.bindingProof, input.bindingAuthority);
    if (binding.disposition !== "verified") {
      throw new Error(`Revocation anchor binding is invalid: ${binding.reason}`);
    }
    const expectedLogical = listingRevocationLogicalAddress(
      ((listing["seller"] as Record<string, unknown>)["identity"] as Record<string, unknown>)["presentedBy"] as string,
      input.listing.listingId,
      input.listing.listingVersion,
    );
    if (binding.canonicalJson !== canonicalJson || input.bindingProof.logicalAddress !== expectedLogical
      || input.bindingProof.contentHash !== sha256Hex(canonicalJson)
      || input.bindingProof.signer !== input.signer.signer) {
      throw new Error("Revocation binding does not match its logical address and anchored bytes");
    }
    const record: ListingRevocationRecord = {
      ...input.listing,
      revocationContentHash: sha256Hex(canonicalJson),
      canonicalJson,
      logicalAddress: expectedLogical,
      nativeAddress: input.bindingProof.nativeAddress,
      anchorTx: input.bindingProof.createdByTx,
      anchorVerifiedAt: input.verifiedAt,
      createdAt: input.createdAt,
    };
    this.store.revoke(record);
    return Object.freeze(record);
  }
}

export function createSignedListingRevocation(input: {
  readonly listing: ListingReference;
  readonly revokedAt: number;
  readonly reason?: string;
  readonly signer: ArtifactSigner;
  readonly signingContext: FixtureSigningContext;
}): SignedListingRevocation {
  if (!Number.isSafeInteger(input.revokedAt) || input.revokedAt < 0) {
    throw new TypeError("Revocation revokedAt must be a non-negative safe integer");
  }
  assertArtifactSigningAuthority(input.signer, input.signingContext);
  const unsigned = {
    listingId: input.listing.listingId,
    listingVersion: input.listing.listingVersion,
    listingContentHash: input.listing.contentHash,
    revokedAt: input.revokedAt,
    ...(input.reason === undefined ? {} : { reason: input.reason }),
  };
  const signature = input.signer.sign(
    new TextEncoder().encode(`${REVOCATION_DOMAIN}${sha256Hex(canonicalize(unsigned))}`),
    input.signingContext,
  );
  const marker = Object.freeze({ ...unsigned, signature });
  return Object.freeze({ marker, canonicalJson: canonicalize(marker) });
}

export function listingLogicalAddress(
  sellerPrimaryClaim: string,
  listingId: string,
  listingVersion: number,
): string {
  return `dacs1:${encodeURIComponent(sellerPrimaryClaim)}:${listingId}:v${listingVersion}`;
}

export function listingRevocationLogicalAddress(
  sellerPrimaryClaim: string,
  listingId: string,
  listingVersion: number,
): string {
  return `dacs1-revoked:${encodeURIComponent(sellerPrimaryClaim)}:${listingId}:v${listingVersion}`;
}

function parseObject(canonicalJson: string, label: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(canonicalJson) as unknown; }
  catch { throw new TypeError(`${label} must be valid JSON`); }
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || canonicalize(value) !== canonicalJson) {
    throw new TypeError(`${label} must be a canonical JSON object`);
  }
  return value as Record<string, unknown>;
}

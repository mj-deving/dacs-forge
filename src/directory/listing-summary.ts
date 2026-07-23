import { deepFreezeJson } from "../protocol/canonical-json.ts";
import { validateDirectoryListingSummary } from "../protocol/directory-summary-schema.ts";
import {
  assertVerifiedLegacySdkListing,
  type VerifiedLegacySdkListing,
} from "../compat/legacy-listing.ts";

export interface LegacyListingSummaryOptions {
  readonly sellerDisplayName: string;
  readonly catalogObservedAt: number;
  readonly status: "active" | "revoked";
}

export interface DirectoryListingSummary extends Record<string, unknown> {
  readonly listingId: string;
  readonly version: number;
  readonly contentHash: string;
  readonly artifactProfile: "legacy-sdk-v0.1";
}

export function projectLegacyDirectorySummary(
  listing: VerifiedLegacySdkListing,
  options: LegacyListingSummaryOptions,
): Readonly<DirectoryListingSummary> {
  assertVerifiedLegacySdkListing(listing);
  if (typeof options.sellerDisplayName !== "string" || options.sellerDisplayName.length === 0
    || options.sellerDisplayName.length > 200) {
    throw new TypeError("Directory seller display name is invalid");
  }
  if (!Number.isSafeInteger(options.catalogObservedAt) || options.catalogObservedAt < 0) {
    throw new TypeError("Directory catalogObservedAt is invalid");
  }
  if (options.status !== "active" && options.status !== "revoked") {
    throw new TypeError("Directory status is invalid");
  }

  const scope = listing.scope;
  const summary: DirectoryListingSummary = {
    listingId: scope.serviceId,
    version: 1,
    contentHash: listing.contentHash,
    anchor: { kind: "storage-program", locator: listing.storageAddress },
    seller: { primaryClaim: scope.agentId, displayName: options.sellerDisplayName },
    artifactProfile: "legacy-sdk-v0.1",
    offering: {
      title: scope.name,
      description: scope.description.replace(/\s*\[github:[^\]]+\]\s*/g, " ").trim(),
      category: "services.other",
      tags: [],
      rails: [...scope.supportedPaymentRails],
      delivery: [...scope.supportedDelivery],
      negotiation: [...scope.supportedNegotiation],
    },
    pricing: {},
    status: options.status,
    catalogObservedAt: options.catalogObservedAt,
  };
  const validation = validateDirectoryListingSummary(summary);
  if (!validation.valid) {
    const first = validation.errors[0];
    throw new TypeError(`Generated Directory ListingSummary is invalid: ${first?.instancePath || "/"} ${first?.message ?? "unknown schema error"}`);
  }
  return deepFreezeJson(summary);
}

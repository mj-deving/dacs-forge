import {
  verifyCanonicalListingJson,
  type PaymentRailCheck,
  type RevocationCheck,
} from "../consumer/listing-verifier.ts";
import { deepFreezeJson } from "../protocol/canonical-json.ts";
import { validateDirectoryListingSummary } from "../protocol/directory-summary-schema.ts";
import type { LiveEffectStore } from "./effect-store.ts";
import { runRecoverableEffect, type EffectAdapter } from "./effect-runner.ts";
import type { AdmittedExecutionProfile } from "./profile.ts";

interface AnchorPayload extends Record<string, unknown> {
  readonly logicalAddress: string;
  readonly canonicalJson: string;
}

interface AnchorResult extends Record<string, unknown> {
  readonly externalRef: string;
  readonly nativeAddress: string;
  readonly canonicalJson: string;
}

interface DirectoryResult extends Record<string, unknown> {
  readonly externalRef: string;
  readonly projection: Readonly<Record<string, unknown>>;
}

export interface DirectoryEffectPayload extends Record<string, unknown> {
  readonly registration: Readonly<{
    readonly primaryClaim: string;
    readonly displayName: string;
    readonly listingAnchors: readonly string[];
  }>;
  readonly expectedProjection: Readonly<Record<string, unknown>>;
}

export interface LiveListingAnchorAdapter extends EffectAdapter<AnchorPayload, AnchorResult> {
  readonly read: (nativeAddress: string) => Promise<string | null>;
  readonly revocation: (logicalAddress: string) => Promise<RevocationCheck>;
}

export interface LiveDirectoryAdapter extends EffectAdapter<DirectoryEffectPayload, DirectoryResult> {}

export async function publishListingThroughLiveProfile(input: {
  readonly store: LiveEffectStore;
  readonly profile: AdmittedExecutionProfile;
  readonly canonicalJson: string;
  readonly nowMs: number;
  readonly expectedSeller: string;
  readonly paymentRailCheck: (rail: Readonly<{
    readonly railId: string;
    readonly railVersion?: number;
    readonly canonicalJson: string;
    readonly referencedByPhaseKinds: readonly string[];
  }>) => PaymentRailCheck;
  readonly anchorAdapter: LiveListingAnchorAdapter;
  readonly directoryAdapter: LiveDirectoryAdapter;
}): Promise<Readonly<{
  readonly listing: AnchorResult & { readonly contentHash: string };
  readonly directory: DirectoryResult;
}>> {
  const document = parseDocument(input.canonicalJson);
  const listingId = document["listingId"];
  const listingVersion = document["listingVersion"];
  const seller = document["seller"] as Record<string, unknown>;
  const identity = seller["identity"] as Record<string, unknown>;
  if (typeof listingId !== "string" || !Number.isSafeInteger(listingVersion)
    || identity["presentedBy"] !== input.expectedSeller) {
    throw new TypeError("Listing identity does not match the expected seller");
  }
  const logicalAddress = `dacs1:${encodeURIComponent(input.expectedSeller)}:${listingId}:v${String(listingVersion)}`;
  const revocation = await input.anchorAdapter.revocation(logicalAddress);
  const verification = verifyCanonicalListingJson(input.canonicalJson, {
    nowMs: input.nowMs,
    revocationCheck: () => revocation,
    paymentRailCheck: input.paymentRailCheck,
  });
  if (verification.disposition !== "accepted") {
    throw new Error(`Listing verification failed before anchor: ${verification.stage}: ${verification.reason}`);
  }
  const effectKey = `listing-anchor:${verification.listingId}:v${verification.listingVersion}`;
  const anchored = await runRecoverableEffect({
    store: input.store,
    profile: input.profile,
    effectKey,
    kind: "anchor",
    payload: Object.freeze({ logicalAddress, canonicalJson: input.canonicalJson }),
    adapter: input.anchorAdapter,
  });
  const readBack = await input.anchorAdapter.read(anchored.nativeAddress);
  if (readBack !== input.canonicalJson || anchored.canonicalJson !== input.canonicalJson) {
    throw new Error("Listing anchor read-back did not return the exact canonical bytes");
  }
  const readVerification = verifyCanonicalListingJson(readBack, {
    nowMs: input.nowMs,
    revocationCheck: () => revocation,
    paymentRailCheck: input.paymentRailCheck,
  });
  if (readVerification.disposition !== "accepted"
    || readVerification.contentHash !== verification.contentHash) {
    throw new Error("Listing anchor read-back failed independent verification");
  }
  const projection = projectDirectorySummary(document, verification.contentHash, anchored.nativeAddress);
  const sellerProjection = projection["seller"] as Record<string, unknown>;
  const directoryPayload = deepFreezeJson({
    registration: {
      primaryClaim: input.expectedSeller,
      displayName: sellerProjection["displayName"],
      listingAnchors: [anchored.nativeAddress],
    },
    expectedProjection: projection,
  }) as DirectoryEffectPayload;
  const directory = await runRecoverableEffect({
    store: input.store,
    profile: input.profile,
    effectKey: `directory-register:${verification.listingId}:v${verification.listingVersion}`,
    kind: "directory-register",
    payload: directoryPayload,
    adapter: input.directoryAdapter,
  });
  return Object.freeze({
    listing: Object.freeze({ ...anchored, contentHash: verification.contentHash }),
    directory,
  });
}

function projectDirectorySummary(
  listing: Record<string, unknown>,
  contentHash: string,
  nativeAddress: string,
): Readonly<Record<string, unknown>> {
  const seller = listing["seller"] as Record<string, unknown>;
  const identity = seller["identity"] as Record<string, unknown>;
  const offering = listing["offering"] as Record<string, unknown>;
  const pricing = listing["pricing"] as Record<string, unknown>;
  const presentedAt = identity["presentedAt"];
  if (!Number.isSafeInteger(presentedAt) || (presentedAt as number) < 0) {
    throw new TypeError("Listing seller presentation time is invalid");
  }
  const acceptedRails = Array.isArray(listing["acceptedRails"])
    ? (listing["acceptedRails"] as Record<string, unknown>[]).map((rail) => rail["railId"] as string)
    : [];
  const projection = {
    listingId: listing["listingId"],
    version: listing["listingVersion"],
    contentHash,
    anchor: { kind: "storage-program", locator: nativeAddress },
    seller: { primaryClaim: identity["presentedBy"], displayName: seller["displayName"] },
    artifactProfile: "dacs-v0.1",
    publicEndpoint: seller["publicEndpoint"],
    offering: {
      title: offering["title"],
      description: offering["description"],
      category: offering["category"],
      tags: offering["tags"],
      rails: acceptedRails,
      delivery: (listing["pipeline"] as Record<string, unknown>[])
        .map((phase) => phase["kind"] as string).filter((kind) => kind.startsWith("deliver-")),
      negotiation: (listing["pipeline"] as Record<string, unknown>[])
        .map((phase) => phase["kind"] as string).filter((kind) => kind.startsWith("negotiate-")),
      deliverable: offering["deliverable"],
    },
    pricing,
    status: "active",
    catalogObservedAt: presentedAt,
  };
  const validation = validateDirectoryListingSummary(projection);
  if (!validation.valid) throw new TypeError(`Directory projection is invalid: ${validation.errors[0]?.message ?? "unknown"}`);
  return deepFreezeJson(projection);
}

function parseDocument(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("Listing must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

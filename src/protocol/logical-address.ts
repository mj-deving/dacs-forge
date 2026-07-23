import { canonicalizeClaimReference } from "./claim-reference.ts";

const LISTING_ID = /^[A-Za-z0-9._~-]{1,128}$/;
const CF4_RESERVED = /[:?&=%]/g;
const CF4_ESCAPE = /%(?:3A|3F|26|3D|25)/g;
const CF4_VALUES: Readonly<Record<string, string>> = Object.freeze({
  "%3A": ":", "%3F": "?", "%26": "&", "%3D": "=", "%25": "%",
});

export interface ListingLogicalAddress {
  readonly sellerPrimaryClaim: string;
  readonly listingId: string;
  readonly listingVersion: number;
}

export function listingLogicalAddress(
  sellerPrimaryClaim: string,
  listingId: string,
  listingVersion: number,
): string {
  const claim = canonicalizeClaimReference(sellerPrimaryClaim).canonicalReference;
  if (!LISTING_ID.test(listingId)) {
    throw new TypeError("listingId must be 1-128 URL-safe ASCII characters");
  }
  if (!Number.isSafeInteger(listingVersion) || listingVersion < 1) {
    throw new TypeError("listingVersion must be a positive safe integer");
  }
  return `dacs1:${encodeCf4Segment(claim)}:${listingId}:v${listingVersion}`;
}

export function encodeCf4Segment(value: string): string {
  return value.replace(CF4_RESERVED, (character) =>
    `%${character.codePointAt(0)?.toString(16).toUpperCase().padStart(2, "0")}`,
  );
}

export function parseListingLogicalAddress(value: string): ListingLogicalAddress {
  const match = /^dacs1:([^:]+):([A-Za-z0-9._~-]{1,128}):v([1-9]\d*)$/.exec(value);
  if (match === null || /%(?!(?:3A|3F|26|3D|25))/.test(match[1] as string)) {
    throw new TypeError("Listing logical address is not canonical CF-4");
  }
  const listingVersion = Number(match[3]);
  if (!Number.isSafeInteger(listingVersion)) {
    throw new TypeError("Listing logical address version exceeds the safe integer range");
  }
  const sellerPrimaryClaim = (match[1] as string).replace(
    CF4_ESCAPE,
    (escape) => CF4_VALUES[escape] as string,
  );
  const canonicalClaim = canonicalizeClaimReference(sellerPrimaryClaim).canonicalReference;
  const parsed = Object.freeze({
    sellerPrimaryClaim: canonicalClaim,
    listingId: match[2] as string,
    listingVersion,
  });
  if (listingLogicalAddress(parsed.sellerPrimaryClaim, parsed.listingId, parsed.listingVersion) !== value) {
    throw new TypeError("Listing logical address is not in canonical form");
  }
  return parsed;
}

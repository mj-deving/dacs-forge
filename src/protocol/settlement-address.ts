import { encodeCf4Segment } from "./logical-address.ts";

const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const RAIL_ID = /^[a-z0-9]+(?:[.:_-][A-Za-z0-9]+)*$/;

export function paymentEvidenceLogicalAddress(
  jobId: string,
  railId: string,
  phaseIndex: number,
  resolved = false,
): string {
  if (!ULID.test(jobId)) throw new TypeError("Payment evidence jobId must be a canonical ULID");
  if (!RAIL_ID.test(railId) || railId.length > 64) {
    throw new TypeError("Payment evidence railId is invalid");
  }
  if (!Number.isSafeInteger(phaseIndex) || phaseIndex < 0) {
    throw new TypeError("Payment evidence phaseIndex must be a non-negative safe integer");
  }
  return `dacs4:payment:${jobId}:${encodeCf4Segment(railId)}:${phaseIndex}${resolved ? ":resolved" : ""}`;
}

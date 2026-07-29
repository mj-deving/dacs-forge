import { canonicalize } from "./canonical-json.ts";
import { sha256Hex } from "./hash.ts";

const HASH = /^[0-9a-f]{64}$/;

export function integratedServiceLifecycleRequestHash(
  agreementRequestHash: string,
  serviceRequestHash: string,
): string {
  if (!HASH.test(agreementRequestHash) || !HASH.test(serviceRequestHash)) {
    throw new TypeError("Integrated service request components must be lowercase SHA-256 hashes");
  }
  return sha256Hex(canonicalize({
    integratedServiceLifecycleRequestVersion: "1",
    agreementRequestHash,
    serviceRequestHash,
  }));
}

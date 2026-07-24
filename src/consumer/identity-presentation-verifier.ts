import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { consumerCanonicalize } from "./canonical-json.ts";
import { canonicalizeClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";

const BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

export interface PresentationNonceAttempt {
  readonly jobId: string;
  readonly presentedNonce: string | null;
}

export interface PresentationNonceAuthority {
  /** Atomically rejects without consumption unless jobId and presentedNonce exactly match. */
  readonly consumeMatching: (attempt: PresentationNonceAttempt) =>
    | { readonly disposition: "accepted" }
    | { readonly disposition: "rejected"; readonly reason: string };
}

export interface SiwdAuthority {
  readonly verifySignature: (input: {
    readonly address: string;
    readonly message: string;
    readonly signature: string;
  }) => boolean;
  readonly controlsPresentedBy: (input: {
    readonly address: string;
    readonly presentedBy: string;
  }) => boolean;
}

export interface IdentityPresentationOptions {
  readonly jobId: string;
  readonly nonceAuthority: PresentationNonceAuthority;
  readonly siwdAuthority?: SiwdAuthority;
  readonly siwdAudience?: {
    readonly domain: string;
    readonly uri: string;
  };
}

export type IdentityPresentationResult =
  | { readonly disposition: "accepted"; readonly bundleHash: string; readonly kind: string }
  | { readonly disposition: "rejected" | "refused-unsupported"; readonly reason: string };

export function verifySessionIdentityPresentation(
  bundle: Readonly<Record<string, unknown>>,
  options: IdentityPresentationOptions,
): IdentityPresentationResult {
  try {
    validateBundleHeader(bundle);
    const presentation = bundle["presentation"] as Record<string, unknown>;
    const kind = presentation["kind"];
    if (typeof kind !== "string") return rejected("IdentityBundle presentation kind is missing");
    const unsigned = { ...bundle };
    delete unsigned["presentation"];
    const bundleHash = sha256Hex(consumerCanonicalize(unsigned));
    const signedBytes = `${BUNDLE_DOMAIN}${bundleHash}`;
    const presentedBy = bundle["presentedBy"] as string;
    const presentedNonce = kind === "siwd"
      ? parseSiwdNonce(presentation["message"])
      : typeof bundle["sessionNonce"] === "string" ? bundle["sessionNonce"] : null;
    const nonce = options.nonceAuthority.consumeMatching({ jobId: options.jobId, presentedNonce });
    // CORE B.8 SN-4 deliberately consumes a matching issued nonce on every
    // presentation attempt, including one that later fails cryptographic checks.
    if (nonce.disposition !== "accepted") return rejected(nonce.reason);

    if (kind === "per-claim") {
      const signatures = presentation["signatures"];
      if (!Array.isArray(signatures) || signatures.length === 0) {
        return rejected("Per-claim presentation is empty");
      }
      let primaryVerified = false;
      const seen = new Set<string>();
      const claimIdentities = new Set((bundle["claims"] as Record<string, unknown>[]).map((claim) => {
        if (!isObject(claim) || typeof claim["ref"] !== "string") {
          throw new TypeError("IdentityBundle claim reference is malformed");
        }
        const parsed = canonicalizeClaimReference(claim["ref"]);
        if (parsed.canonicalReference !== claim["ref"]) {
          throw new TypeError("IdentityBundle claim reference is not canonical");
        }
        return claimIdentity(parsed.canonicalReference);
      }));
      for (const entry of signatures) {
        if (!isObject(entry) || typeof entry["ref"] !== "string"
          || typeof entry["signature"] !== "string") {
          return rejected("Per-claim presentation entry is malformed");
        }
        const ref = canonicalizeClaimReference(entry["ref"]);
        const identity = claimIdentity(ref.canonicalReference);
        if (ref.canonicalReference !== entry["ref"] || seen.has(identity)
          || !claimIdentities.has(identity)
          || !verifyDirectEd25519(entry["ref"], entry["signature"], signedBytes)) {
          return rejected("Per-claim presentation signature is invalid");
        }
        seen.add(identity);
        if (sameClaimIdentity(entry["ref"], presentedBy)) primaryVerified = true;
      }
      if (!primaryVerified || seen.size !== claimIdentities.size) {
        return rejected("Per-claim presentation does not prove every contained claim");
      }
      return accepted(bundleHash, kind);
    }

    if (kind === "session-key") {
      if (!hasOnlyAuthenticatedPrimaryClaim(bundle, presentedBy)) {
        return rejected("Session-key presentation supports only its authenticated primary claim");
      }
      const key = presentation["key"];
      const signature = presentation["signature"];
      const rootBinding = presentation["rootBinding"];
      let canonicalKey = false;
      if (typeof key === "string") {
        canonicalKey = canonicalizeClaimReference(key).canonicalReference === key;
      }
      if (typeof key !== "string" || !canonicalKey || typeof signature !== "string"
        || typeof rootBinding !== "string"
        || !verifyDirectEd25519(key, signature, signedBytes)
        || !verifyDirectEd25519(
          presentedBy,
          rootBinding,
          `dacs-session-binding:v1:${key}${bundleHash}`,
        )) {
        return rejected("Session-key presentation signature is invalid");
      }
      return accepted(bundleHash, kind);
    }

    if (kind === "siwd") {
      if (!hasOnlyAuthenticatedPrimaryClaim(bundle, presentedBy)) {
        return rejected("SIWD presentation supports only its authenticated primary claim");
      }
      const message = presentation["message"];
      const signature = presentation["signature"];
      const address = presentation["address"];
      if (typeof message !== "string" || typeof signature !== "string" || typeof address !== "string") {
        return rejected("SIWD presentation is malformed");
      }
      if (options.siwdAudience === undefined
        || parseSiwdDomain(message) !== options.siwdAudience.domain
        || parseSiwdField(message, "URI") !== options.siwdAudience.uri) {
        return rejected("SIWD verifier audience does not match the expected domain and URI");
      }
      const expectedResource = `dacs:${Buffer.from(signedBytes).toString("hex")}`;
      if (!parseSiwdResources(message).includes(expectedResource)) {
        return rejected("SIWD Resources omit the exact DACS bundle binding");
      }
      if (options.siwdAuthority === undefined) {
        return Object.freeze({ disposition: "refused-unsupported", reason: "SIWD authority is unavailable" });
      }
      if (options.siwdAuthority.verifySignature({ address, message, signature }) !== true
        || options.siwdAuthority.controlsPresentedBy({ address, presentedBy }) !== true) {
        return rejected("SIWD signature or presentedBy control proof is invalid");
      }
      return accepted(bundleHash, kind);
    }

    return Object.freeze({
      disposition: "refused-unsupported",
      reason: `Unsupported IdentityBundle presentation kind: ${kind}`,
    });
  } catch (error) {
    return rejected(error instanceof Error ? error.message : "IdentityBundle presentation is invalid");
  }
}

function validateBundleHeader(bundle: Readonly<Record<string, unknown>>): void {
  if (!isObject(bundle) || bundle["bundleVersion"] !== "1"
    || typeof bundle["presentedBy"] !== "string"
    || !Number.isSafeInteger(bundle["presentedAt"])
    || !Array.isArray(bundle["claims"]) || bundle["claims"].length === 0
    || !isObject(bundle["presentation"])) {
    throw new TypeError("IdentityBundle header is invalid");
  }
  const presentedBy = canonicalizeClaimReference(bundle["presentedBy"]);
  if (presentedBy.canonicalReference !== bundle["presentedBy"]
    || !bundle["claims"].some((claim) => isObject(claim)
      && typeof claim["ref"] === "string" && sameClaimIdentity(claim["ref"], presentedBy.canonicalReference))) {
    throw new TypeError("IdentityBundle presentedBy is not a canonical contained claim");
  }
}

function parseSiwdNonce(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return parseSiwdField(value, "Nonce");
}

function parseSiwdField(message: string, field: string): string | null {
  const prefix = `${field}: `;
  const matches = message.split(/\r?\n/).filter((line) => line.startsWith(prefix));
  return matches.length === 1 && matches[0]!.length > prefix.length
    ? matches[0]!.slice(prefix.length) : null;
}

function parseSiwdDomain(message: string): string | null {
  const firstLine = message.split(/\r?\n/, 1)[0] ?? "";
  const suffix = " wants you to sign in";
  return firstLine.endsWith(suffix) && firstLine.length > suffix.length
    ? firstLine.slice(0, -suffix.length) : null;
}

function parseSiwdResources(message: string): readonly string[] {
  const lines = message.split(/\r?\n/);
  const marker = lines.indexOf("Resources:");
  if (marker < 0) return [];
  const resources: string[] = [];
  for (let index = marker + 1; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (!line.startsWith("- ")) break;
    resources.push(line.slice(2));
  }
  return resources;
}

function verifyDirectEd25519(claim: string, signature: string, payload: string): boolean {
  try {
    const parsed = canonicalizeClaimReference(claim);
    if (parsed.scheme !== "key" || !LOWER_HEX_64.test(parsed.identifier)) return false;
    const bytes = Buffer.from(signature, "base64");
    if (bytes.byteLength !== 64 || bytes.toString("base64") !== signature) return false;
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(parsed.identifier, "hex")]),
      format: "der",
      type: "spki",
    });
    return verifyBytes(null, Buffer.from(payload), key, bytes);
  } catch {
    return false;
  }
}

function accepted(bundleHash: string, kind: string): IdentityPresentationResult {
  return Object.freeze({ disposition: "accepted", bundleHash, kind });
}

function rejected(reason: string): IdentityPresentationResult {
  return Object.freeze({ disposition: "rejected", reason });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function claimIdentity(reference: string): string {
  const claim = canonicalizeClaimReference(reference);
  return `${claim.scheme.length}:${claim.scheme}${claim.identifier}`;
}

function hasOnlyAuthenticatedPrimaryClaim(
  bundle: Readonly<Record<string, unknown>>,
  presentedBy: string,
): boolean {
  const claims = bundle["claims"];
  return Array.isArray(claims) && claims.length === 1 && isObject(claims[0])
    && typeof claims[0]["ref"] === "string"
    && canonicalizeClaimReference(claims[0]["ref"]).canonicalReference === claims[0]["ref"]
    && sameClaimIdentity(claims[0]["ref"], presentedBy);
}

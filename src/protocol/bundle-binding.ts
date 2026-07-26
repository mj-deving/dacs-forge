import { createPublicKey, verify as verifySignature } from "node:crypto";

import { canonicalize, withoutFields } from "./canonical-json.ts";
import { decodeComponentSignatureValue } from "./component-signature-codec.ts";
import { sha256Hex } from "./hash.ts";

/**
 * DACS-5 §10.4.2 — the normative `BundleBinding` object and its BB-4/BB-5 verification,
 * pinned to DACS-Standard origin/next 9a1ca624e8cc68361cff35c85a919cd72ba25199 (PR #248).
 *
 * On a write-input-mapping substrate the native bundle address folds opaque write inputs
 * (deployer address, storage-program name, nonce, salt) and is therefore NOT recomputable
 * from the logical form. A consumer resolves it through the anchoring party's published,
 * self-authenticating `BundleBinding` — never by recomputation (BB-7).
 */

export const BUNDLE_BINDING_DOMAIN = "dacs-bundle-binding:v1:";
export const SUPPORTED_BINDING_VERSIONS: ReadonlySet<string> = new Set(["1"]);
export const SUPPORTED_BINDING_SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set(["ed25519"]);

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export type BundleBindingRole = "buyer" | "seller" | "orchestrator";

export interface BundleBinding extends Record<string, unknown> {
  readonly bindingVersion: string;
  readonly jobId: string;
  readonly role: BundleBindingRole;
  readonly logicalAddress: string;
  readonly nativeAddress: string;
  readonly bundleContentHash: string;
  readonly anchorTx?: string;
  readonly signer: string;
  readonly signature: Readonly<Record<string, unknown>>;
}

export type BundleBindingCheck =
  | { readonly ok: true; readonly reason: string }
  | { readonly ok: false; readonly reason: string };

export interface BundleBindingVerificationOptions {
  readonly expectedJobId: string;
  readonly expectedRole: string;
  /** Signer claim -> raw 32-byte ed25519 public key. BB-4 never has a structural-only mode. */
  readonly publicKeys: ReadonlyMap<string, Uint8Array>;
  /** BB-5 check 8: byte-for-byte content-hash equality, when the expected value is known. */
  readonly expectedContentHash?: string;
}

/**
 * §10.4.2 — the logical bundle address `stor-{sha256(jobId + "-bundle-" + role)}`. This is
 * substrate-independent and derivable offline by any party from `(jobId, role)` alone. It
 * carries 64 hex characters; a write-input native address carries 40.
 */
export function bundleLogicalAddress(jobId: string, role: string): string {
  if (typeof jobId !== "string" || jobId.length === 0) {
    throw new TypeError("Bundle jobId is required");
  }
  if (typeof role !== "string" || role.length === 0) {
    throw new TypeError("Bundle role is required");
  }
  return `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`;
}

/** §B.2 canonical form of a binding, omitting `signature` — the BB-4 signing scope. */
export function bundleBindingHash(binding: Readonly<Record<string, unknown>>): string {
  return sha256Hex(canonicalize(withoutFields(binding, "signature")));
}

/**
 * BB-4 plus the BB-5 checks that are decidable without a fetch (checks 3, 4, 5 and — when
 * an expected value is supplied — check 8).
 *
 * Structural ingress runs first and unconditionally, so no binding-controlled member
 * reaches a string concatenation, a set membership test, or a map key unchecked: a
 * malformed binding refuses deterministically instead of throwing. A validly-signed but
 * internally inconsistent binding MUST be rejected, never accepted as a resolution context.
 */
export function verifyBundleBinding(
  binding: unknown,
  options: BundleBindingVerificationOptions,
): BundleBindingCheck {
  if (!isObject(binding)) return fail("binding is not an object");
  if (options.publicKeys === undefined || typeof options.publicKeys.get !== "function") {
    return fail("BB-4: binding signature authority is unavailable");
  }

  for (const field of [
    "bindingVersion", "jobId", "role", "signer", "nativeAddress", "bundleContentHash",
  ] as const) {
    if (typeof binding[field] !== "string") {
      return fail(`BB-5: binding.${field} must be a string`);
    }
  }
  if (typeof binding["logicalAddress"] !== "string") {
    return fail("BB-5: binding.logicalAddress must be a string");
  }

  const signature = binding["signature"];
  if (signature !== undefined && !isObject(signature)) {
    return fail("BB-4: binding.signature must be an object");
  }
  if (isObject(signature)) {
    // An explicitly-null member is NOT exempt: it must not clear structural ingress and
    // reach the crypto-gated path as though it were absent.
    for (const field of ["signer", "algorithm", "value"] as const) {
      if (typeof signature[field] !== "string") {
        return fail(`BB-4: binding.signature.${field} must be a string`);
      }
    }
  }

  // BB-4: the signature's declared signer must be the binding's own signer.
  const signatureSigner = isObject(signature) ? signature["signer"] : undefined;
  if (signatureSigner !== binding["signer"]) {
    return fail("BB-4: signature.signer != binding.signer");
  }
  // BB-5 check 3: unsupported binding versions are rejected, not ignored.
  if (!SUPPORTED_BINDING_VERSIONS.has(binding["bindingVersion"] as string)) {
    return fail(`BB-5 check 3: unsupported bindingVersion ${JSON.stringify(binding["bindingVersion"])}`);
  }
  // BB-5 check 4: the signed tuple must be the requested tuple.
  if (binding["jobId"] !== options.expectedJobId) {
    return fail("BB-5 check 4: binding.jobId != requested jobId");
  }
  if (binding["role"] !== options.expectedRole) {
    return fail("BB-5 check 4: binding.role != requested role");
  }
  // BB-5 check 5: the carried logical address must equal the address derived from the
  // binding's OWN signed jobId and role.
  if (binding["logicalAddress"]
    !== bundleLogicalAddress(binding["jobId"] as string, binding["role"] as string)) {
    return fail("BB-5 check 5: logicalAddress != derive(jobId, role)");
  }
  if (options.expectedContentHash !== undefined
    && binding["bundleContentHash"] !== options.expectedContentHash) {
    return fail("BB-5 check 8: binding.bundleContentHash != expected");
  }

  const publicKey = options.publicKeys.get(binding["signer"] as string);
  if (publicKey === undefined) {
    return fail(`BB-4: no public key for signer ${JSON.stringify(binding["signer"])}`);
  }
  const algorithm = (signature as Record<string, unknown>)["algorithm"];
  if (typeof algorithm !== "string" || !SUPPORTED_BINDING_SIGNATURE_ALGORITHMS.has(algorithm)) {
    return fail(`BB-4/SIG-6: unsupported binding signature algorithm ${JSON.stringify(algorithm)}`);
  }
  let decoded: Uint8Array;
  try {
    // SIG-6 canonical-value checking runs BEFORE any cryptographic verification.
    decoded = decodeComponentSignatureValue(
      (signature as Record<string, unknown>)["value"] as string,
      64,
    );
  } catch {
    return fail("BB-4/SIG-6: binding signature value is not canonical unpadded base64url");
  }
  if (publicKey.byteLength !== 32) {
    return fail("BB-4: binding signer key is not a 32-byte ed25519 public key");
  }
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    const payload = Buffer.from(`${BUNDLE_BINDING_DOMAIN}${bundleBindingHash(binding)}`);
    if (!verifySignature(null, payload, key, decoded)) {
      return fail("BB-4: binding signature does not verify");
    }
  } catch {
    return fail("BB-4: binding signing scope is not canonically verifiable");
  }

  return { ok: true, reason: "binding valid" };
}

function fail(reason: string): BundleBindingCheck {
  return { ok: false, reason };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

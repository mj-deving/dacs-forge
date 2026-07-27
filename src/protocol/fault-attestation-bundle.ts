import { createPublicKey, verify as verifySignature } from "node:crypto";

import { canonicalize, withoutFields } from "./canonical-json.ts";
import { decodeComponentSignatureValue } from "./component-signature-codec.ts";
import { sha256Hex } from "./hash.ts";
import {
  EVIDENCE_BOUND_FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN,
  EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN,
} from "./evidence-bound-fault-bundle.ts";

/**
 * DACS-5 §10.4 / §10.4.1 — the v0.3 `FaultAttestationBundle` production type and the
 * shared bundle-hash identity, pinned to DACS-Standard origin/next
 * 9a1ca624e8cc68361cff35c85a919cd72ba25199 (PR #248).
 *
 * The legacy `AttestationBundle` (`bundleVersion`) and the `FaultAttestationBundle`
 * (`faultBundleVersion`) share every rule in §10.4–§10.5 except where a rule names one
 * type. They differ in exactly two ways: the version literal, which is the structural
 * discriminator, and the REQUIRED hashed `faultedParty`.
 */

export const ATTESTATION_BUNDLE_SIGNATURE_DOMAIN = "dacs-bundle:v1:";
export const FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN = "dacs-fault-bundle:v1:";
export const FAULT_BUNDLE_POINTER_DOMAIN = "dacs-fault-bundle-pointer:v1:";
export {
  EVIDENCE_BOUND_FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN,
  EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN,
};

export type BundleFaultRole = "buyer" | "seller" | "orchestrator";
export type BundleFaultedParty = BundleFaultRole | "none";
export type BundleOutcomeClass = "completed" | "failed-substrate" | "abort" | "failure";

const ABORT_OUTCOMES = new Set(["aborted-by-self", "aborted-by-other"]);
const FAILURE_OUTCOMES = new Set(["failed-perm", "failed-counterparty"]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function validBundleTypeDiscriminator(bundle: unknown): boolean {
  if (!isObject(bundle)) return false;
  const versions = ["bundleVersion", "faultBundleVersion", "evidenceBoundFaultBundleVersion"]
    .filter((field) => Object.hasOwn(bundle, field));
  return versions.length === 1 && bundle[versions[0]!] === "1";
}

export function isEvidenceBoundFaultAttestationBundle(bundle: unknown): boolean {
  return isObject(bundle) && Object.hasOwn(bundle, "evidenceBoundFaultBundleVersion");
}

/**
 * §10.4.1 structural discriminator. A `FaultAttestationBundle` carries `faultBundleVersion`
 * and never `bundleVersion`; the CORE §11.1.2 new-type refusal keys on exactly this.
 */
export function isFaultAttestationBundle(bundle: unknown): boolean {
  return isObject(bundle) && (Object.hasOwn(bundle, "faultBundleVersion")
    || Object.hasOwn(bundle, "evidenceBoundFaultBundleVersion"));
}

/**
 * §10.4.1 — the signature domain for a copy, selected by its version literal. The two
 * domains are distinct §B.7 registry entries: a signature over one type MUST NOT validate
 * as a signature over the other.
 */
export function bundleSignatureDomain(bundle: unknown): string {
  return isEvidenceBoundFaultAttestationBundle(bundle)
    ? EVIDENCE_BOUND_FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN
    : isFaultAttestationBundle(bundle)
    ? FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN
    : ATTESTATION_BUNDLE_SIGNATURE_DOMAIN;
}

/**
 * §10.4.1 `attestation_bundle_hash` — sha256 of the §B.2 canonical form omitting
 * `signatures` and `anchoredByRole`, computed identically for both bundle types. Every
 * other field is hashed, including the version literal and, on a FaultAttestationBundle,
 * `faultedParty`.
 */
export function attestationBundleHash(bundle: Readonly<Record<string, unknown>>): string {
  return sha256Hex(canonicalize(withoutFields(bundle, "signatures", "anchoredByRole")));
}

export function outcomeClass(outcome: unknown): BundleOutcomeClass {
  if (outcome === "completed") return "completed";
  if (outcome === "failed-substrate") return "failed-substrate";
  if (typeof outcome === "string" && ABORT_OUTCOMES.has(outcome)) return "abort";
  if (typeof outcome === "string" && FAILURE_OUTCOMES.has(outcome)) return "failure";
  throw new TypeError(`Unknown bundle outcome ${JSON.stringify(outcome)}`);
}

/**
 * §10.5.1 legacy-only perspective mapping. Buyer↔seller involution; `completed` and
 * `failed-substrate` are perspective-independent and pass through unchanged.
 */
export function perspectiveFlip(outcome: string): string {
  switch (outcome) {
    case "aborted-by-self": return "aborted-by-other";
    case "aborted-by-other": return "aborted-by-self";
    case "failed-perm": return "failed-counterparty";
    case "failed-counterparty": return "failed-perm";
    default: return outcome;
  }
}

/** The session `parties[]` roster carried on both bundle types. */
export function rosterRoles(bundle: Readonly<Record<string, unknown>>): ReadonlySet<string> {
  const parties = bundle["parties"];
  const roles = new Set<string>();
  if (Array.isArray(parties)) {
    for (const party of parties) {
      if (isObject(party) && typeof party["role"] === "string") roles.add(party["role"]);
    }
  }
  return roles;
}

/**
 * §10.4.1 permissible-`faultedParty` set for `(outcome, anchoredByRole)`, expressed as the
 * set of session parties the outcome permits as faulted. It is a singleton in a two-party
 * session — preserving the prior exact buyer↔seller mapping byte-for-byte — and admits
 * both non-R roles in a session with a distinct orchestrator.
 */
export function impliedFaultSet(
  outcome: unknown,
  anchoredByRole: unknown,
  roster: ReadonlySet<string>,
): ReadonlySet<string> {
  if (outcome === "completed" || outcome === "failed-substrate") return new Set(["none"]);
  if (typeof anchoredByRole !== "string") {
    throw new TypeError("anchoredByRole must be a role string");
  }
  if (outcome === "failed-perm" || outcome === "aborted-by-self") {
    return new Set([anchoredByRole]);
  }
  if (outcome === "failed-counterparty" || outcome === "aborted-by-other") {
    const others = new Set([...roster].filter((role) => role !== anchoredByRole));
    return others.size > 0 ? others : new Set([otherPartyRole(anchoredByRole)]);
  }
  throw new TypeError(`Unknown bundle outcome ${JSON.stringify(outcome)}`);
}

/**
 * §10.4.1 — a consumer MUST reject a `FaultAttestationBundle` copy that omits
 * `faultedParty` or whose `faultedParty` falls outside the permissible set for its
 * `(outcome, anchoredByRole)`. A copy re-anchored under the wrong role fails this check,
 * since `faultedParty` is hashed and absolute.
 */
export function faultedPartyPermitted(
  bundle: Readonly<Record<string, unknown>>,
): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  if (!isFaultAttestationBundle(bundle)) return { ok: true };
  const faulted = bundle["faultedParty"];
  if (typeof faulted !== "string") {
    return { ok: false, reason: "§10.4.1: FaultAttestationBundle omits the REQUIRED faultedParty" };
  }
  let permitted: ReadonlySet<string>;
  try {
    permitted = impliedFaultSet(bundle["outcome"], bundle["anchoredByRole"], rosterRoles(bundle));
  } catch (error) {
    return { ok: false, reason: `§10.4.1: ${(error as Error).message}` };
  }
  if (!permitted.has(faulted)) {
    return {
      ok: false,
      reason: `§10.4.1: faultedParty ${JSON.stringify(faulted)} is outside the permissible set `
        + `${JSON.stringify([...permitted].sort())} for (${JSON.stringify(bundle["outcome"])}, `
        + `${JSON.stringify(bundle["anchoredByRole"])})`,
    };
  }
  return { ok: true };
}

/**
 * §10.4.1 — the role-relative `outcome` spelling a copy anchored by `anchoredByRole` must
 * carry, given the session's outcome class and the ABSOLUTE responsible party. This is the
 * production-side inverse of the §10.5.1 scored read: the pair names one `faultedParty` and
 * spells `outcome` from each anchoring party's own perspective, which is exactly why a
 * FaultAttestationBundle perspective pair converges despite unequal canonical forms.
 */
export function roleRelativeOutcome(
  klass: BundleOutcomeClass,
  faultedParty: string,
  anchoredByRole: string,
): string {
  if (klass === "completed") return "completed";
  if (klass === "failed-substrate") return "failed-substrate";
  const atFault = faultedParty === anchoredByRole;
  if (klass === "abort") return atFault ? "aborted-by-self" : "aborted-by-other";
  return atFault ? "failed-perm" : "failed-counterparty";
}

export interface FaultBundleExtendedPointerResolution {
  readonly ok: boolean;
  readonly reason: string;
  readonly recomputedHash: string | null;
}

export type FaultBundleDereferencedAdmission = (
  dereferenced: unknown,
  binding: Readonly<Record<string, unknown>>,
  publicKeys: ReadonlyMap<string, Uint8Array>,
) => { readonly ok: true } | { readonly ok: false; readonly reason: string };

/**
 * §10.4.2 extended-pointer triple identity. For an extended-pointer anchoring the record at
 * the resolved `nativeAddress` is the pointer; BB-5 check 8 and the §10.4.1 comparison apply
 * to the DEREFERENCED full bundle:
 *
 *   binding.bundleContentHash == pointer.fullBundleContentHash == §10.4.1 hash(dereferenced)
 *
 * — three values, one identity. A pointer whose dereferenced content hash mismatches is
 * rejected content (BB-7), never absence.
 */
export function resolveFaultBundleExtendedPointer(
  pointer: unknown,
  dereferenced: unknown,
  binding: Readonly<Record<string, unknown>>,
  publicKeys: ReadonlyMap<string, Uint8Array>,
  admitDereferenced: FaultBundleDereferencedAdmission,
): FaultBundleExtendedPointerResolution {
  return resolveAbsoluteFaultBundleExtendedPointer(
    pointer,
    dereferenced,
    binding,
    publicKeys,
    admitDereferenced,
    {
      discriminator: "faultBundleVersion",
      domain: FAULT_BUNDLE_POINTER_DOMAIN,
      label: "FaultBundleExtendedPointer",
      admitsBundle: (value) => isObject(value)
        && Object.hasOwn(value, "faultBundleVersion")
        && !Object.hasOwn(value, "evidenceBoundFaultBundleVersion"),
    },
  );
}

export function resolveEvidenceBoundFaultBundleExtendedPointer(
  pointer: unknown,
  dereferenced: unknown,
  binding: Readonly<Record<string, unknown>>,
  publicKeys: ReadonlyMap<string, Uint8Array>,
  admitDereferenced: FaultBundleDereferencedAdmission,
): FaultBundleExtendedPointerResolution {
  return resolveAbsoluteFaultBundleExtendedPointer(
    pointer,
    dereferenced,
    binding,
    publicKeys,
    admitDereferenced,
    {
      discriminator: "evidenceBoundFaultBundleVersion",
      domain: EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN,
      label: "EvidenceBoundFaultBundleExtendedPointer",
      admitsBundle: isEvidenceBoundFaultAttestationBundle,
    },
  );
}

function resolveAbsoluteFaultBundleExtendedPointer(
  pointer: unknown,
  dereferenced: unknown,
  binding: Readonly<Record<string, unknown>>,
  publicKeys: ReadonlyMap<string, Uint8Array>,
  admitDereferenced: FaultBundleDereferencedAdmission,
  type: Readonly<{
    discriminator: "faultBundleVersion" | "evidenceBoundFaultBundleVersion";
    domain: string;
    label: string;
    admitsBundle: (value: unknown) => boolean;
  }>,
): FaultBundleExtendedPointerResolution {
  if (!isObject(pointer)) {
    return { ok: false, reason: "pointer is not an object", recomputedHash: null };
  }
  const versionFields = ["bundleVersion", "faultBundleVersion", "evidenceBoundFaultBundleVersion"]
    .filter((field) => Object.hasOwn(pointer, field));
  if (versionFields.length !== 1 || versionFields[0] !== type.discriminator
    || pointer[type.discriminator] !== "1") {
    return {
      ok: false,
      reason: `not a ${type.label} discriminator`,
      recomputedHash: null,
    };
  }
  if (pointer["pointerKind"] !== "extended") {
    return { ok: false, reason: "pointerKind must be \"extended\"", recomputedHash: null };
  }
  if (publicKeys === undefined || typeof publicKeys.get !== "function") {
    return { ok: false, reason: "pointer signature authority is unavailable", recomputedHash: null };
  }
  const signature = pointer["signature"];
  if (!isObject(signature) || typeof signature["signer"] !== "string"
    || signature["algorithm"] !== "ed25519" || typeof signature["value"] !== "string") {
    return { ok: false, reason: "pointer signature envelope is invalid", recomputedHash: null };
  }
  if (!isObject(binding)) {
    return { ok: false, reason: "pointer binding is unavailable", recomputedHash: null };
  }
  if (signature["signer"] !== binding["signer"]) {
    return { ok: false, reason: "pointer signer differs from binding signer", recomputedHash: null };
  }
  let pointerHash: string;
  try {
    pointerHash = sha256Hex(canonicalize(withoutFields(pointer, "signature")));
  } catch {
    return { ok: false, reason: "pointer signing scope is not canonically hashable", recomputedHash: null };
  }
  if (!validEd25519Signature(
    publicKeys.get(signature["signer"]),
    `${type.domain}${pointerHash}`,
    signature["value"],
  )) {
    return { ok: false, reason: "pointer signature does not verify", recomputedHash: null };
  }
  if (!isObject(dereferenced) || !validBundleTypeDiscriminator(dereferenced)
    || !type.admitsBundle(dereferenced)) {
    return { ok: false, reason: `dereferenced record is not a matching ${type.label} bundle`, recomputedHash: null };
  }
  const permitted = faultedPartyPermitted(dereferenced);
  if (!permitted.ok) return { ok: false, reason: permitted.reason, recomputedHash: null };
  if (typeof admitDereferenced !== "function") {
    return { ok: false, reason: "dereferenced bundle admission is unavailable", recomputedHash: null };
  }
  const admission = admitDereferenced(dereferenced, binding, publicKeys);
  if (!admission.ok) {
    return {
      ok: false,
      reason: `dereferenced bundle admission failed: ${admission.reason}`,
      recomputedHash: null,
    };
  }
  let recomputed: string;
  try {
    recomputed = attestationBundleHash(dereferenced);
  } catch {
    return { ok: false, reason: "dereferenced bundle is not canonically hashable", recomputedHash: null };
  }
  if (pointer["fullBundleContentHash"] !== recomputed) {
    return { ok: false, reason: "dereferenced content hash mismatch", recomputedHash: recomputed };
  }
  if (binding["bundleContentHash"] !== recomputed) {
    return {
      ok: false,
      reason: "binding.bundleContentHash != dereferenced hash",
      recomputedHash: recomputed,
    };
  }
  return { ok: true, reason: "triple-identity holds", recomputedHash: recomputed };
}

function otherPartyRole(role: string): string {
  return role === "buyer" ? "seller" : "buyer";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validEd25519Signature(
  key: Uint8Array | undefined,
  payload: string,
  encoded: string,
): boolean {
  if (key?.byteLength !== 32) return false;
  let signature: Uint8Array;
  try { signature = decodeComponentSignatureValue(encoded, 64); }
  catch { return false; }
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key)]),
      format: "der",
      type: "spki",
    });
    return verifySignature(null, Buffer.from(payload), publicKey, signature);
  } catch {
    return false;
  }
}

export type BundlePairConvergence = "unified" | "divergent";

export interface BundlePairClassification {
  readonly convergence: BundlePairConvergence;
  readonly pairKind: "fault-pair" | "legacy-pair" | "mixed-version";
  readonly authoritativeCopy: Readonly<Record<string, unknown>>;
  readonly authoritativeCopyType: "FaultAttestationBundle" | "AttestationBundle";
  readonly faultedParty?: string;
  readonly reason: string;
}

/**
 * §10.4.3 "canonically diverge", the single normative definition as amended by PR #248.
 *
 * The two copies contradict each other about what happened when their `outcome` classes
 * differ, when a shared-index `phaseSummary` entry's `kind`/`outcome`/`errorClass` differ,
 * or when an entry is present in one copy and absent in the other — the entry set is a
 * normative input, and it is also the guard against a fabricated phase entry that would
 * otherwise escape entry-wise comparison. A difference confined to advisory fields
 * (`finalisedAt` skew, one-sided `ratingRefs`, amendment ordering) is NOT a divergence.
 *
 * The fault limb is read per pair type:
 *   - FaultAttestationBundle pair: the ABSOLUTE hashed `faultedParty` must agree; the
 *     role-relative `outcome` spelling may legitimately differ.
 *   - legacy pair: reconciled through the §10.5.1 `perspective_flip` mapping before
 *     comparison; perspective partners are the same event seen from two sides.
 *   - mixed-version pair: the FaultAttestationBundle's `faultedParty` must be a MEMBER of
 *     the legacy copy's implied-fault set.
 */
export function bundleCopiesDiverge(
  copyA: Readonly<Record<string, unknown>>,
  copyB: Readonly<Record<string, unknown>>,
): boolean {
  // Divergence is defined over two present copies. A missing or non-object copy is not a
  // contradiction to classify — it is a read-disposition question answered by BB-7/BB-8 —
  // so refuse here rather than throwing on an attacker-supplied shape.
  if (!isObject(copyA) || !isObject(copyB)) {
    throw new TypeError("bundleCopiesDiverge requires two present bundle copies");
  }
  if (phaseSummaryDiverges(copyA, copyB)) return true;
  if (outcomeClass(copyA["outcome"]) !== outcomeClass(copyB["outcome"])) return true;

  const aFault = isFaultAttestationBundle(copyA);
  const bFault = isFaultAttestationBundle(copyB);

  if (aFault && bFault) return copyA["faultedParty"] !== copyB["faultedParty"];

  if (!aFault && !bFault) {
    const reconciledB = copyA["anchoredByRole"] === copyB["anchoredByRole"]
      ? copyB["outcome"]
      : perspectiveFlip(copyB["outcome"] as string);
    return copyA["outcome"] !== reconciledB;
  }

  const fault = aFault ? copyA : copyB;
  const legacy = aFault ? copyB : copyA;
  const roster = new Set<string>([...rosterRoles(fault), ...rosterRoles(legacy)]);
  const implied = impliedFaultSet(legacy["outcome"], legacy["anchoredByRole"], roster);
  return !implied.has(fault["faultedParty"] as string);
}

/**
 * §10.4.3(c)/(d) pair classification. Every same-session pair is classified by exactly one
 * of the canonical-equality rule, the FaultAttestationBundle-pair rule, the mixed-version
 * rule, or the legacy `outcome`-spelling rule — there is no unclassified pair.
 *
 * In a mixed-version pair the FaultAttestationBundle copy is authoritative for derivation,
 * matching §10.5.1's reconciliation.
 */
export function classifyBundlePair(
  copyA: Readonly<Record<string, unknown>>,
  copyB: Readonly<Record<string, unknown>>,
): BundlePairClassification {
  const aFault = isFaultAttestationBundle(copyA);
  const bFault = isFaultAttestationBundle(copyB);
  const pairKind = aFault && bFault ? "fault-pair" : !aFault && !bFault ? "legacy-pair" : "mixed-version";
  // The FaultAttestationBundle copy is authoritative in a mixed pair; otherwise either
  // copy is canonical for non-scoring purposes, so the first is reported deterministically.
  const authoritativeCopy = pairKind === "mixed-version" ? (aFault ? copyA : copyB) : copyA;
  const divergent = bundleCopiesDiverge(copyA, copyB);
  const faultedParty = isFaultAttestationBundle(authoritativeCopy)
    ? (authoritativeCopy["faultedParty"] as string)
    : undefined;

  return Object.freeze({
    convergence: divergent ? "divergent" : "unified",
    pairKind,
    authoritativeCopy,
    authoritativeCopyType: isFaultAttestationBundle(authoritativeCopy)
      ? "FaultAttestationBundle"
      : "AttestationBundle",
    ...(faultedParty === undefined ? {} : { faultedParty }),
    reason: divergent
      ? `§10.4.3(d): the ${pairKind} contradicts on the normative fault surface`
      : `§10.4.3(c): the ${pairKind} converges and is the unified session bundle`,
  });
}

/**
 * §10.5.1 `scored_outcome` — the scored party's perspective outcome for an authoritative
 * copy. A FaultAttestationBundle is read from its ABSOLUTE `faultedParty`; a legacy copy is
 * read role-relatively through `anchoredByRole` via the perspective flip.
 */
export function scoredOutcome(
  bundle: Readonly<Record<string, unknown>>,
  roleOfParty: string,
): string {
  const klass = outcomeClass(bundle["outcome"]);
  if (klass === "completed" || klass === "failed-substrate") return bundle["outcome"] as string;
  if (isFaultAttestationBundle(bundle)) {
    const fault = bundle["faultedParty"];
    // An orchestrator fault is neutralised downstream rather than attributed to a party here.
    if (fault === "orchestrator") return bundle["outcome"] as string;
    const atFault = fault === roleOfParty;
    if (klass === "abort") return atFault ? "aborted-by-self" : "aborted-by-other";
    return atFault ? "failed-perm" : "failed-counterparty";
  }
  return bundle["anchoredByRole"] === roleOfParty
    ? (bundle["outcome"] as string)
    : perspectiveFlip(bundle["outcome"] as string);
}

function phaseSummaryDiverges(
  copyA: Readonly<Record<string, unknown>>,
  copyB: Readonly<Record<string, unknown>>,
): boolean {
  const indexed = (bundle: Readonly<Record<string, unknown>>) => {
    const entries = new Map<unknown, Record<string, unknown>>();
    const summary = bundle["phaseSummary"];
    if (Array.isArray(summary)) {
      for (const entry of summary) {
        if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
          entries.set((entry as Record<string, unknown>)["index"], entry as Record<string, unknown>);
        }
      }
    }
    return entries;
  };
  const a = indexed(copyA);
  const b = indexed(copyB);
  if (a.size !== b.size) return true;
  for (const index of a.keys()) if (!b.has(index)) return true;
  for (const [index, entryA] of a) {
    const entryB = b.get(index)!;
    for (const field of ["kind", "outcome", "errorClass"] as const) {
      if (entryA[field] !== entryB[field]) return true;
    }
  }
  return false;
}

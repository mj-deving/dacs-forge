import { createPublicKey, verify as verifySignature } from "node:crypto";

import {
  bundleLogicalAddress,
  verifyBundleBinding,
  type BundleBindingCheck,
} from "../protocol/bundle-binding.ts";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { canonicalize } from "../protocol/canonical-json.ts";
import {
  attestationBundleHash,
  bundleSignatureDomain,
  faultedPartyPermitted,
  resolveFaultBundleExtendedPointer,
  validBundleTypeDiscriminator,
} from "../protocol/fault-attestation-bundle.ts";

/**
 * DACS-5 §10.4.2 BB-5 (post-fetch), BB-6 (multiplicity and authorization), BB-7 (fail
 * closed) and BB-8 (suppression diligence and the one-sided gate), pinned to
 * DACS-Standard origin/next 9a1ca624e8cc68361cff35c85a919cd72ba25199 (PR #248).
 *
 * The load-bearing integrity checks are post-fetch — the content hash, the
 * `anchoredByRole` cross-check, the §10.4.1 permissible fault set, and the §10.4.1
 * signatures — so a wrong or poisoned binding yields at worst a fetch that fails
 * verification. Fetched content that fails validation is rejected content, never absence
 * evidence, and a side is never promoted from `indeterminate` to `absent`.
 */

/** BB-6: N = 8 authorized-or-unresolved candidates per authenticated signer per (jobId, role). */
export const BB6_DEFAULT_FETCH_BUDGET = 8;

const VERIFIED_BINDING_RESOLUTIONS = new WeakSet<object>();
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ABORT_OUTCOMES = new Set(["aborted-by-self", "aborted-by-other"]);
const BUNDLE_OUTCOMES = new Set([
  "completed",
  "failed-perm",
  "failed-counterparty",
  "failed-substrate",
  ...ABORT_OUTCOMES,
]);

export type BundleSideDisposition = "present" | "indeterminate";

export interface BundleBindingResolutionInput {
  readonly jobId: string;
  readonly role: string;
  readonly bindings: readonly unknown[];
  /** nativeAddress -> the record fetched from it. A missing entry models an unfetchable candidate. */
  readonly anchored?: ReadonlyMap<string, Record<string, unknown>>;
  /** fullBundleUrl -> dereferenced full bundle for a fetched extended pointer. */
  readonly dereferenced?: ReadonlyMap<string, Record<string, unknown>>;
  readonly publicKeys: ReadonlyMap<string, Uint8Array>;
  /**
   * The authenticated role -> primary-claim map, inverted to signer -> role. Where it is
   * available the candidate set MUST be pruned to the mapped signer before any fetch; in a
   * reputation-derivation context that map is always constructible, so the prune is
   * mandatory there.
   */
  readonly partyMap?: Readonly<Record<string, string>>;
  readonly budget?: number;
}

export interface BundleBindingResolution {
  readonly disposition: BundleSideDisposition;
  readonly resolvedNativeAddress: string | null;
  readonly fetched: readonly string[];
  readonly authorizedSigners: readonly string[];
  readonly exhaustedSigners: readonly string[];
  readonly reason: string;
}

interface Candidate {
  readonly binding: Record<string, unknown>;
  readonly signer: string;
  readonly nativeAddress: string;
  readonly bundleContentHash: string;
}

interface AuthorizedCopy extends Candidate {
  readonly copy: Record<string, unknown>;
  readonly fullStanding: boolean;
}

export function resolveBundleBindingCandidates(
  input: BundleBindingResolutionInput,
): BundleBindingResolution {
  const budget = input.budget ?? BB6_DEFAULT_FETCH_BUDGET;
  const anchored = input.anchored ?? new Map<string, Record<string, unknown>>();
  const hasPublicKeys = input.publicKeys !== undefined && typeof input.publicKeys.get === "function";
  if (!Number.isSafeInteger(budget) || budget < 1
    || !hasPublicKeys) {
    return Object.freeze({
      disposition: "indeterminate",
      resolvedNativeAddress: null,
      fetched: Object.freeze([]),
      authorizedSigners: Object.freeze([]),
      exhaustedSigners: Object.freeze([]),
      reason: !hasPublicKeys
        ? "BB-4: binding signature authority is unavailable"
        : "BB-6: fetch budget must be a positive safe integer",
    });
  }

  // BB-5 checks 1-5 + BB-4: only bindings surviving verification enter the candidate set.
  const candidates: Candidate[] = [];
  for (const binding of input.bindings) {
    const check: BundleBindingCheck = verifyBundleBinding(binding, {
      expectedJobId: input.jobId,
      expectedRole: input.role,
      publicKeys: input.publicKeys,
    });
    if (!check.ok) continue;
    const record = binding as Record<string, unknown>;
    candidates.push({
      binding: record,
      signer: record["signer"] as string,
      nativeAddress: record["nativeAddress"] as string,
      bundleContentHash: record["bundleContentHash"] as string,
    });
  }

  // BB-6 mandatory pre-fetch prune. Key membership alone is NOT authorization: an insider
  // signer mapped to a DIFFERENT role must not resolve the requested side.
  const pruned = input.partyMap === undefined
    ? candidates
    : candidates.filter((c) => input.partyMap![c.signer] === input.role);

  const bySigner = new Map<string, Candidate[]>();
  for (const candidate of pruned) {
    const bucket = bySigner.get(candidate.signer);
    if (bucket === undefined) bySigner.set(candidate.signer, [candidate]);
    else bucket.push(candidate);
  }

  const fetched: string[] = [];
  const authorizedSigners = new Set<string>();
  const exhaustedSigners = new Set<string>();
  const authorizedCopies: AuthorizedCopy[] = [];

  for (const [signer, bucket] of bySigner) {
    // BB-6 total order: ascending bundleContentHash, ties broken by ascending nativeAddress.
    const ordered = [...bucket].sort(compareCandidates);
    const byAddress = new Map<string, Candidate[]>();
    for (const candidate of ordered) {
      const sameAddress = byAddress.get(candidate.nativeAddress);
      if (sameAddress === undefined) byAddress.set(candidate.nativeAddress, [candidate]);
      else sameAddress.push(candidate);
    }
    if (byAddress.size > budget) {
      // BB-7: this signer's budget exhausts with candidate addresses still unfetched. A
      // signer's candidates never consume another signer's budget.
      exhaustedSigners.add(signer);
    }
    for (const [nativeAddress, addressCandidates] of [...byAddress].slice(0, budget)) {
      fetched.push(nativeAddress);
      const copy = anchored.get(nativeAddress);
      if (copy === undefined) continue; // unfetchable candidate: never absence, never authorized
      for (const candidate of addressCandidates) {
        let admittedCopy = copy;
        if (isFaultBundleExtendedPointer(copy)) {
          const url = copy["fullBundleUrl"];
          const dereferenced = typeof url === "string" ? input.dereferenced?.get(url) : undefined;
          const pointer = resolveFaultBundleExtendedPointer(
            copy,
            dereferenced,
            candidate.binding,
            input.publicKeys,
            postFetchValid,
          );
          if (!pointer.ok || dereferenced === undefined) continue;
          admittedCopy = dereferenced;
        }
        const postFetch = postFetchValid(admittedCopy, candidate.binding, input.publicKeys);
        if (!postFetch.ok) continue; // rejected content is inert: no collapse, precedence, or void
        const authorized = input.partyMap !== undefined
          ? input.partyMap[signer] === candidate.binding["role"]
            && rosterConsistentWithKnownPartyMap(admittedCopy, input.partyMap)
          : holdsRole(admittedCopy, signer, candidate.binding["role"]);
        if (!authorized) continue;
        authorizedSigners.add(signer);
        authorizedCopies.push({
          ...candidate,
          copy: admittedCopy,
          fullStanding: fullSignatureStanding(admittedCopy),
        });
      }
    }
  }

  const emit = (
    disposition: BundleSideDisposition,
    resolvedNativeAddress: string | null,
    reason: string,
  ): BundleBindingResolution => {
    const resolution = Object.freeze({
      disposition,
      resolvedNativeAddress,
      fetched: Object.freeze([...fetched]),
      authorizedSigners: Object.freeze([...authorizedSigners].sort()),
      exhaustedSigners: Object.freeze([...exhaustedSigners].sort()),
      reason,
    });
    VERIFIED_BINDING_RESOLUTIONS.add(resolution);
    return resolution;
  };

  if (exhaustedSigners.size > 0) {
    // BB-7 exhaustion is SIDE-level and precedes the ladder: it overrides any authorized
    // candidate that resolved — never absent, never a void.
    return emit("indeterminate", null,
      "BB-7: a signer's BB-6 fetch budget exhausted with candidate addresses unfetched");
  }
  if (authorizedCopies.length === 0) {
    return emit("indeterminate", null,
      "BB-7: no BB-4-valid authorized binding resolved for the requested (jobId, role)");
  }

  // BB-6 same-role ladder over the surviving authorized, fetched copies.
  const ladder = [...authorizedCopies].sort(compareCandidates);
  const forms = new Map<string, AuthorizedCopy[]>();
  for (const copy of ladder) {
    const bucket = forms.get(copy.bundleContentHash);
    if (bucket === undefined) forms.set(copy.bundleContentHash, [copy]);
    else bucket.push(copy);
  }

  if (forms.size <= 1) {
    // Canonically equal copies collapse to one retrieved copy. Prefer a full-standing copy
    // within that form so the reported address cannot be selected by lesser-copy ordering.
    const only = [...forms.values()][0]!;
    const full = only.filter((copy) => copy.fullStanding);
    const selected = (full.length > 0 ? full : only)[0]!;
    return emit("present", selected.nativeAddress,
      "BB-6: canonically equal authorized copies collapse to one retrieved copy");
  }

  // Full-signature precedence: exactly one full-standing form takes precedence and
  // lesser-signed copies are discarded.
  const fullForms = [...forms.values()].filter((copies) => copies.some((c) => c.fullStanding));
  if (fullForms.length === 1) {
    const selected = fullForms[0]!.filter((copy) => copy.fullStanding)[0]!;
    return emit("present", selected.nativeAddress,
      "BB-6: full-signature precedence retains the fully-signed authorized copy");
  }

  // Equal standing among canonically unequal authorized copies: the side is equivocating
  // without a governing record. The consumer MUST NOT select among them.
  return emit("indeterminate", null,
    "BB-6/BB-7: canonically unequal authorized copies of equal signature standing");
}

export type BundleReadDisposition = "present" | "absent" | "indeterminate";

export interface BundleAddressReadClassification {
  readonly disposition: BundleReadDisposition;
  readonly oneSidedReachable: boolean;
  readonly reason: string;
}

export interface BundleAddressReadInput {
  /** Must be the exact runtime object returned by resolveBundleBindingCandidates. */
  readonly resolution: BundleBindingResolution;
  readonly read: Readonly<Record<string, unknown>> | null | undefined;
  /** Trusted substrate policy selected by the caller, never carried by a BundleBinding. */
  readonly absenceEvidencePolicy?: Readonly<Record<string, unknown>> | null;
  /** Trusted substrate verifier. Omission fails closed to indeterminate. */
  readonly verifyAuthoritativeAbsence?: (input: Readonly<{
    nativeAddress: string;
    policy: Readonly<Record<string, unknown>>;
    read: Readonly<Record<string, unknown>>;
  }>) => boolean;
}

/**
 * BB-8 — the §10.4.3(b) one-sided classification is reachable for a missing side only when
 * BOTH hold: a BB-4-valid, BB-5-consistent binding resolves that side's `nativeAddress`,
 * AND an SR-2 read of that address is authoritatively `absent` under the substrate
 * binding's declared absence-evidence policy (CORE §5).
 *
 * Non-discovery of a binding — on however many surfaces — establishes `indeterminate`,
 * never absence. An ordinary unqualified not-found, or a binding whose substrate declares
 * no absence-evidence policy, is likewise `indeterminate`. No quantity of consulted
 * surfaces converts non-observation into `absent`.
 */
export function classifyBundleAddressRead(
  input: BundleAddressReadInput,
): BundleAddressReadClassification {
  const resolution = input.resolution;
  const read = input.read;

  if (!isObject(resolution) || !VERIFIED_BINDING_RESOLUTIONS.has(resolution)
    || resolution.disposition !== "present" || resolution.resolvedNativeAddress === null) {
    return frozenRead("indeterminate", false,
      "BB-8: no BB-4-valid binding resolved the side's native address; non-discovery is never absence");
  }
  if (!isObject(read)) {
    return frozenRead("indeterminate", false, "BB-8: the side's SR-2 read is unavailable");
  }
  if (read["nativeAddress"] !== resolution.resolvedNativeAddress) {
    return frozenRead("indeterminate", false,
      "BB-8: the SR-2 read is not bound to the resolved native address");
  }
  if (read["response"] === "present") {
    return frozenRead("present", false, "the resolved native address returned a copy");
  }

  const policy = input.absenceEvidencePolicy;
  if (!completeAbsenceEvidencePolicy(policy)) {
    // The current Demos StorageProgram mapping declares no absence-evidence policy, so any
    // not-found has the CORE SR-2 disposition indeterminate regardless of the read result.
    return frozenRead("indeterminate", false,
      "CORE §5: the substrate binding declares no absence-evidence policy, so not-found is indeterminate");
  }
  if (read["response"] !== "authoritative-absent") {
    return frozenRead("indeterminate", false,
      "CORE §5: an ordinary unqualified not-found is not an authenticated finalized non-membership result");
  }
  if (input.verifyAuthoritativeAbsence === undefined) {
    return frozenRead("indeterminate", false,
      "CORE §5: no trusted verifier is available for the declared absence-evidence policy");
  }
  let verified = false;
  try {
    verified = input.verifyAuthoritativeAbsence({
      nativeAddress: resolution.resolvedNativeAddress,
      policy,
      read,
    });
  } catch {
    verified = false;
  }
  if (!verified) {
    return frozenRead("indeterminate", false,
      "CORE §5: the absence evidence does not satisfy the complete declared policy");
  }
  return frozenRead("absent", true,
    "BB-8: a resolved binding plus an authoritatively absent SR-2 read makes §10.4.3(b) reachable");
}

/**
 * BB-5 post-fetch validation of one fetched copy against the binding that resolved it.
 * Any failure makes the copy INERT: the caller discards it and it never reaches the BB-6
 * ladder at any standing.
 */
export function postFetchValid(
  fetched: unknown,
  binding: Readonly<Record<string, unknown>>,
  publicKeys: ReadonlyMap<string, Uint8Array>,
): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  if (!isObject(fetched)) return { ok: false, reason: "fetched copy is not an object" };
  if (!validBundleTypeDiscriminator(fetched)) {
    return { ok: false, reason: "§10.4.1: fetched copy has no recognized bundle discriminator" };
  }
  try { canonicalize(fetched); }
  catch { return { ok: false, reason: "§10.4.1: fetched copy is not canonical JSON data" }; }
  if (!bundlePostFetchShapeValid(fetched)) {
    return { ok: false, reason: "§10.4.1: fetched copy has an invalid BB-5 admission shape" };
  }
  // check 7
  if (fetched["jobId"] !== binding["jobId"]) {
    return { ok: false, reason: "BB-5 check 7: fetched.jobId != binding.jobId" };
  }
  // check 9: authorization is a roster fact, never mere presence at an address
  if (!holdsRole(fetched, binding["signer"], binding["role"])) {
    return { ok: false, reason: "BB-5 check 9: signer does not hold the claimed role in the roster" };
  }
  // check 9: the §10.4.2 anchoredByRole cross-check — what protects an unhashed field from forgery
  if (fetched["anchoredByRole"] !== binding["role"]) {
    return { ok: false, reason: "BB-5 check 9: anchoredByRole != the bound role" };
  }
  // check 9: §10.4.1 permissible fault set — a copy re-anchored under the wrong role fails here
  const permitted = faultedPartyPermitted(fetched);
  if (!permitted.ok) return { ok: false, reason: permitted.reason };
  // check 9: §10.4.1 signature rules. This authenticates the complete canonical signed
  // scope, all required signers, and every roster identity used by BB-5 authorization.
  const signatures = bundleSignaturesValid(fetched, publicKeys);
  if (!signatures.ok) return signatures;
  // check 8: byte-for-byte recompute
  let recomputed: string;
  try { recomputed = attestationBundleHash(fetched); }
  catch { return { ok: false, reason: "BB-5 check 8: fetched copy is not canonically hashable" }; }
  if (recomputed !== binding["bundleContentHash"]) {
    return { ok: false, reason: "BB-5 check 8: recomputed §10.4.1 hash != binding.bundleContentHash" };
  }
  return { ok: true };
}

/**
 * BB-5 consumes the bundle envelope, not the records referenced by it. Keep this gate
 * strict for every field read by BB-5 while leaving AttestationRef dereferencing to the
 * full bundle consumer. The upstream PR #248 candidate vectors intentionally use
 * synthetic reference payloads because reference resolution is not their subject.
 */
function bundlePostFetchShapeValid(bundle: Readonly<Record<string, unknown>>): boolean {
  const listing = bundle["listingRef"];
  const parties = bundle["parties"];
  const phases = bundle["phaseSummary"];
  const outcome = bundle["outcome"];
  return typeof bundle["jobId"] === "string" && bundle["jobId"] !== ""
    && BUNDLE_OUTCOMES.has(outcome as string)
    && ["buyer", "seller", "orchestrator"].includes(bundle["anchoredByRole"] as string)
    && isObject(listing)
    && typeof listing["listingId"] === "string" && listing["listingId"] !== ""
    && Number.isSafeInteger(listing["version"]) && (listing["version"] as number) > 0
    && isHex64(listing["contentHash"])
    && Array.isArray(parties) && parties.length >= 2
    && parties.every((party) => isObject(party)
      && ["buyer", "seller", "orchestrator"].includes(party["role"] as string)
      && typeof party["primaryClaim"] === "string" && party["primaryClaim"] !== ""
      && isHex64(party["bundleHash"]))
    && Array.isArray(phases)
    && phases.every((phase) => isObject(phase)
      && Number.isSafeInteger(phase["index"]) && (phase["index"] as number) >= 0
      && typeof phase["kind"] === "string" && phase["kind"] !== ""
      && (phase["outcome"] === "ok" || phase["outcome"] === "fail")
      && (phase["attestationRef"] === undefined || validEnvelopeReference(phase["attestationRef"])))
    && validReferenceArray(bundle["vetRecords"])
    && validReferenceArray(bundle["settlementEvidence"])
    && (bundle["agreementRef"] === undefined || validEnvelopeReference(bundle["agreementRef"]))
    && (bundle["amendments"] === undefined || validReferenceArray(bundle["amendments"]))
    && (bundle["ratingRefs"] === undefined || validReferenceArray(bundle["ratingRefs"]))
    && Number.isSafeInteger(bundle["recipeRegistryVersion"])
    && (bundle["recipeRegistryVersion"] as number) > 0
    && Number.isSafeInteger(bundle["railRegistryVersion"])
    && (bundle["railRegistryVersion"] as number) > 0
    && Number.isSafeInteger(bundle["finalisedAt"])
    && (bundle["finalisedAt"] as number) >= 0;
}

function validReferenceArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(validEnvelopeReference);
}

function validEnvelopeReference(value: unknown): boolean {
  if (!isObject(value) || !isHex64(value["contentHash"])) return false;
  if (Object.hasOwn(value, "signer") && typeof value["signer"] !== "string") return false;
  if (Object.hasOwn(value, "anchor")) {
    if (!isObject(value["anchor"])) return false;
    return ["storage-program", "ipfs", "https"].includes(value["anchor"]["kind"] as string)
      && typeof value["anchor"]["locator"] === "string"
      && value["anchor"]["locator"] !== ""
      && (value["signer"] === undefined || value["signer"] !== "");
  }
  // PR #248's candidate BB corpora use synthetic artifact references because
  // dereferencing those records is outside the resolution-vector subject.
  return typeof value["kind"] === "string" && value["kind"] !== ""
    && typeof value["id"] === "string" && value["id"] !== "";
}

function isHex64(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

/** §10.4.1 signed-scope authentication, shared by full bundles and pointer targets. */
export function bundleSignaturesValid(
  bundle: Readonly<Record<string, unknown>>,
  publicKeys: ReadonlyMap<string, Uint8Array>,
): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  const roleHolder = new Map<string, string>();
  const parties = bundle["parties"];
  if (!Array.isArray(parties)) return { ok: false, reason: "§10.4.1: bundle roster is missing" };
  for (const party of parties) {
    if (!isObject(party) || typeof party["role"] !== "string"
      || typeof party["primaryClaim"] !== "string" || roleHolder.has(party["role"])) {
      return { ok: false, reason: "§10.4.1: bundle roster is malformed or duplicates a role" };
    }
    roleHolder.set(party["role"], party["primaryClaim"]);
  }
  if (roleHolder.get("buyer") === roleHolder.get("seller")) {
    return { ok: false, reason: "§10.4.1: buyer and seller must be distinct role-holders" };
  }
  const rawSignatures = Array.isArray(bundle["signatures"]) ? bundle["signatures"] : [];
  const rosterClaims = new Set(roleHolder.values());
  const signersPresent = new Set<unknown>();
  for (const entry of rawSignatures) {
    if (!isObject(entry) || typeof entry["party"] !== "string"
      || !rosterClaims.has(entry["party"]) || signersPresent.has(entry["party"])) {
      return { ok: false, reason: "§10.4.1: signature envelope is malformed or duplicated" };
    }
    signersPresent.add(entry["party"]);
  }
  const anchorRole = bundle["anchoredByRole"];
  if (ABORT_OUTCOMES.has(bundle["outcome"] as string)) {
    const required = typeof anchorRole === "string" ? roleHolder.get(anchorRole) : undefined;
    if (required === undefined || !signersPresent.has(required)) {
      return { ok: false, reason: "§10.4.1: the anchoring role-holder has no signature" };
    }
  } else {
    for (const role of requiredBundleSigners(roleHolder)) {
      const claim = roleHolder.get(role);
      if (claim === undefined || !signersPresent.has(claim)) {
        return { ok: false, reason: `§10.4.1: required signer ${role} is absent` };
      }
    }
  }
  try {
    const signedBytes = Buffer.from(`${bundleSignatureDomain(bundle)}${attestationBundleHash(bundle)}`);
    for (const entry of rawSignatures) {
      const party = (entry as Record<string, unknown>)["party"] as string;
      const key = publicKeys.get(party);
      if (key === undefined || key.byteLength !== 32) {
        return { ok: false, reason: `§10.4.1: no valid ed25519 key for ${party}` };
      }
      if ((entry as Record<string, unknown>)["algorithm"] !== "ed25519") {
        return { ok: false, reason: `§10.4.1/SIG-6: unsupported signature algorithm for ${party}` };
      }
      const decoded = decodeComponentSignatureValue(
        (entry as Record<string, unknown>)["value"] as string,
        64,
      );
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key)]),
        format: "der",
        type: "spki",
      });
      if (!verifySignature(null, signedBytes, publicKey, decoded)) {
        return { ok: false, reason: `§10.4.1: bundle signature does not verify for ${party}` };
      }
    }
  } catch {
    return { ok: false, reason: "§10.4.1: bundle signing scope is not canonically verifiable" };
  }
  return { ok: true };
}

function requiredBundleSigners(roleHolder: ReadonlyMap<string, string>): readonly string[] {
  const required = ["buyer", "seller"];
  const orchestrator = roleHolder.get("orchestrator");
  if (orchestrator !== undefined && orchestrator !== roleHolder.get("buyer")
    && orchestrator !== roleHolder.get("seller")) {
    required.push("orchestrator");
  }
  return required;
}

function rosterConsistentWithKnownPartyMap(
  bundle: Readonly<Record<string, unknown>>,
  partyMap: Readonly<Record<string, string>>,
): boolean {
  const parties = bundle["parties"];
  if (!Array.isArray(parties)) return false;
  const rosterByRole = new Map<string, string>();
  const forwardConsistent = parties.every((party) => {
    if (!isObject(party) || typeof party["primaryClaim"] !== "string"
      || typeof party["role"] !== "string") return false;
    rosterByRole.set(party["role"], party["primaryClaim"]);
    const authenticatedRole = partyMap[party["primaryClaim"]];
    return authenticatedRole === undefined || authenticatedRole === party["role"];
  });
  if (!forwardConsistent) return false;
  return Object.entries(partyMap).every(([claim, role]) => rosterByRole.get(role) === claim);
}

/**
 * BB-6 precedence standing: a copy is FULL-standing iff a signature is present for EVERY
 * party in its roster. This is a structural presence count over copies whose signatures
 * have ALREADY been validated — it is never computed on an unvalidated copy — and is
 * distinct from admission's outcome-dependent required-signer set.
 */
export function fullSignatureStanding(bundle: Readonly<Record<string, unknown>>): boolean {
  const parties = bundle["parties"];
  if (!Array.isArray(parties) || parties.length === 0) return false;
  const claims = new Set<unknown>(
    parties.map((party) => (isObject(party) ? party["primaryClaim"] : undefined)),
  );
  const signatures = Array.isArray(bundle["signatures"]) ? bundle["signatures"] : [];
  const signed = new Set<unknown>(
    signatures.map((entry) => (isObject(entry) ? entry["party"] : undefined)),
  );
  for (const claim of claims) if (!signed.has(claim)) return false;
  return true;
}

/** BB-5 check 9: `signer` is the bundle party holding `role` in the fetched roster. */
export function holdsRole(bundle: unknown, signer: unknown, role: unknown): boolean {
  if (!isObject(bundle)) return false;
  const parties = bundle["parties"];
  if (!Array.isArray(parties)) return false;
  return parties.some((party) =>
    isObject(party) && party["primaryClaim"] === signer && party["role"] === role);
}

export { bundleLogicalAddress };

function compareCandidates(a: Candidate, b: Candidate): number {
  if (a.bundleContentHash !== b.bundleContentHash) {
    return a.bundleContentHash < b.bundleContentHash ? -1 : 1;
  }
  if (a.nativeAddress === b.nativeAddress) return 0;
  return a.nativeAddress < b.nativeAddress ? -1 : 1;
}

function frozenRead(
  disposition: BundleReadDisposition,
  oneSidedReachable: boolean,
  reason: string,
): BundleAddressReadClassification {
  return Object.freeze({ disposition, oneSidedReachable, reason });
}

function isFaultBundleExtendedPointer(value: unknown): value is Record<string, unknown> {
  return isObject(value) && value["faultBundleVersion"] === "1"
    && value["pointerKind"] === "extended" && !Object.hasOwn(value, "bundleVersion");
}

function completeAbsenceEvidencePolicy(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  if (!isObject(value)) return false;
  return [
    "finalityRule", "authentication", "independence", "threshold", "freshness", "stateConsistency",
  ].every((field) => typeof value[field] === "string" && value[field].length > 0);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

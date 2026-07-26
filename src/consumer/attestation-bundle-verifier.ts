import { createPublicKey, verify as verifySignature } from "node:crypto";
import { consumerCanonicalize } from "./canonical-json.ts";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { canonicalizeClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";
import type { BundleOutcome, BundleRole } from "../producer/attestation-bundle.ts";
import {
  bundleSignatureDomain,
  faultedPartyPermitted,
  validBundleTypeDiscriminator,
} from "../protocol/fault-attestation-bundle.ts";

const MAX_ATTESTATION_BUNDLE_BYTES = 128 * 1024;

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const OUTCOMES = new Set<BundleOutcome>([
  "completed", "failed-perm", "failed-counterparty", "failed-substrate",
  "aborted-by-self", "aborted-by-other",
]);
const ERROR_CLASSES = new Set([
  "permanent", "transient", "counterparty", "substrate", "settlement-atomicity",
]);

export interface AttestationBundleVerificationOptions {
  readonly expectedAddress: string;
  readonly expectedJobId?: string;
  readonly resolveListingRef: (
    ref: Readonly<Record<string, unknown>>,
  ) => BundleListingAuthorityCheck;
  readonly resolvePartyIdentity: (
    party: Readonly<Record<string, unknown>>,
  ) => BundlePartyIdentityAuthorityCheck;
  readonly resolveExecutedPhasePlan: (
    jobId: string,
  ) => BundleExecutedPhasePlanCheck;
  readonly resolveAttestationRef: (
    ref: Readonly<Record<string, unknown>>,
    context: AttestationReferenceContext,
  ) => AttestationReferenceCheck;
}

export type BundleListingAuthorityCheck =
  | { readonly status: "verified"; readonly contentHash: string; readonly listingId: string; readonly version: number }
  | { readonly status: "absent" }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export type BundlePartyIdentityAuthorityCheck =
  | { readonly status: "verified"; readonly bundleHash: string; readonly primaryClaim: string; readonly publicKey: Uint8Array }
  | { readonly status: "absent" }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export type BundleExecutedPhasePlanCheck =
  | {
    readonly status: "verified";
    readonly phases: readonly Readonly<{ index: number; kind: string }>[];
    readonly railRegistryVersion: number;
    readonly recipeRegistryVersion: number;
  }
  | { readonly status: "absent" }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface AttestationReferenceContext {
  readonly anchoredByRole: BundleRole;
  readonly expectedJobId: string;
  readonly usage: "agreement" | "phase" | "vet" | "settlement" | "amendment" | "rating";
  readonly expectedPhaseIndex?: number;
  readonly expectedPhaseKind?: string;
  readonly expectedPhaseOutcome?: "ok" | "fail";
}

export type AttestationReferenceCheck =
  | {
    readonly status: "verified";
    readonly artifactType: "agreement" | "phase-evidence" | "vet" | "amendment" | "rating";
    readonly anchorKind: string;
    readonly anchorLocator: string;
    readonly contentHash: string;
    readonly jobId: string;
    readonly agreementListingRef?: Readonly<Record<string, unknown>>;
    readonly agreementParties?: readonly Readonly<Record<string, unknown>>[];
    readonly phaseIndex?: number;
    readonly phaseKind?: string;
    readonly evidenceOutcome?: "success" | "failure";
    readonly signer?: string;
  }
  | { readonly status: "absent" }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export type AttestationBundleVerificationResult =
  | {
    readonly disposition: "verified";
    readonly artifact: Readonly<Record<string, unknown>>;
    readonly anchoredByRole: BundleRole;
    readonly bundleHash: string;
    readonly requiredSignatureCount: number;
    readonly referenceAuthorities: readonly ReferenceAuthoritySnapshot[];
    readonly signatureCount: number;
    readonly signedScopeCanonicalJson: string;
  }
  | {
    readonly disposition: "indeterminate";
    readonly stage: "reference-resolution";
    readonly reason: string;
    readonly authenticatedArtifact?: Readonly<Record<string, unknown>>;
    readonly authenticatedReferenceAuthorities?: readonly ReferenceAuthoritySnapshot[];
  }
  | { readonly disposition: "rejected"; readonly stage: string; readonly reason: string };

export type AttestationBundleSignedScopeAuthenticationResult =
  | { readonly disposition: "authenticated"; readonly artifact: Readonly<Record<string, unknown>> }
  | { readonly disposition: "indeterminate"; readonly reason: string }
  | { readonly disposition: "rejected"; readonly reason: string };

export function authenticateCanonicalAttestationBundleSignedScope(
  canonicalJson: string,
  options: Readonly<Pick<
    AttestationBundleVerificationOptions,
    "expectedAddress" | "expectedJobId" | "resolvePartyIdentity"
  >>,
): AttestationBundleSignedScopeAuthenticationResult {
  try {
    if (typeof canonicalJson !== "string" || canonicalJson.length === 0
      || Buffer.byteLength(canonicalJson, "utf8") > MAX_ATTESTATION_BUNDLE_BYTES) {
      return Object.freeze({ disposition: "rejected", reason: "Bundle bytes are invalid" });
    }
    const artifact = JSON.parse(canonicalJson) as unknown;
    if (!isObject(artifact) || consumerCanonicalize(artifact) !== canonicalJson) {
      return Object.freeze({ disposition: "rejected", reason: "Bundle is not canonical JSON" });
    }
    const jobId = artifact["jobId"];
    const role = artifact["anchoredByRole"];
    if (!validBundleTypeDiscriminator(artifact) || typeof jobId !== "string" || jobId.length === 0
      || (role !== "buyer" && role !== "seller" && role !== "orchestrator")
      || (options.expectedJobId !== undefined && jobId !== options.expectedJobId)
      // Pure-mapping address binding only. On a write-input-mapping substrate the native
      // address is resolved through a published BundleBinding and MUST NOT be recomputed
      // from the logical form (BB-7) — that path is bundle-binding-resolver.ts.
      || options.expectedAddress !== `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`
      || !OUTCOMES.has(artifact["outcome"] as BundleOutcome)
      || !validReference(artifact["listingRef"], "listing")
      || (artifact["agreementRef"] !== undefined && !validAttestationReference(artifact["agreementRef"]))
      || !Array.isArray(artifact["phaseSummary"]) || !validPhaseSummary(artifact["phaseSummary"])
      || !Array.isArray(artifact["vetRecords"]) || !artifact["vetRecords"].every(validAttestationReference)
      || !Array.isArray(artifact["settlementEvidence"])
      || !artifact["settlementEvidence"].every(validAttestationReference)
      || !validOptionalReferenceArray(artifact, "amendments")
      || !validOptionalReferenceArray(artifact, "ratingRefs")
      || !positiveSafeInteger(artifact["recipeRegistryVersion"])
      || !positiveSafeInteger(artifact["railRegistryVersion"])
      || !nonNegativeSafeInteger(artifact["finalisedAt"])) {
      return Object.freeze({ disposition: "rejected", reason: "Bundle signed-scope shape or address binding is invalid" });
    }
    const parties = partyClaims(artifact["parties"]);
    if (parties instanceof Error || !parties.has(role)) {
      return Object.freeze({ disposition: "rejected", reason: parties instanceof Error ? parties.message : "Anchor role is not a bundle party" });
    }
    // §10.4.1: a FaultAttestationBundle copy whose hashed faultedParty falls outside the
    // permissible set for its (outcome, anchoredByRole) is rejected — this is what stops a
    // cross-role rebind from silently reversing blame.
    const faultScope = faultedPartyPermitted(artifact);
    if (!faultScope.ok) {
      return Object.freeze({ disposition: "rejected", reason: faultScope.reason });
    }
    const signatures = artifact["signatures"];
    if (!Array.isArray(signatures) || signatures.length === 0) {
      return Object.freeze({ disposition: "rejected", reason: "Bundle has no signatures" });
    }
    const signatureEntries: Array<Readonly<{ role: BundleRole; value: Uint8Array }>> = [];
    const signedRoles = new Set<BundleRole>();
    for (const signature of signatures) {
      if (!isObject(signature) || signature["algorithm"] !== "ed25519"
        || typeof signature["party"] !== "string" || typeof signature["value"] !== "string") {
        return Object.freeze({ disposition: "rejected", reason: "Bundle signature envelope is invalid" });
      }
      const match = [...parties].find(([, claim]) => sameClaimIdentity(claim, signature["party"] as string));
      if (match === undefined || match[1] !== signature["party"] || signedRoles.has(match[0])) {
        return Object.freeze({ disposition: "rejected", reason: "Bundle signature party is unauthorized or duplicated" });
      }
      let value: Uint8Array;
      try { value = decodeComponentSignatureValue(signature["value"], 64); }
      catch { return Object.freeze({ disposition: "rejected", reason: "Bundle signature value is not canonical base64url" }); }
      signedRoles.add(match[0]);
      signatureEntries.push(Object.freeze({ role: match[0], value }));
    }
    const required = new Set<BundleRole>(["buyer", "seller"]);
    if (parties.has("orchestrator")) required.add("orchestrator");
    const isAbort = artifact["outcome"] === "aborted-by-self" || artifact["outcome"] === "aborted-by-other";
    if (!isAbort && [...required].some((requiredRole) => !signedRoles.has(requiredRole))) {
      return Object.freeze({ disposition: "rejected", reason: "Non-abort bundle lacks all required signatures" });
    }
    if (isAbort && signedRoles.size !== 1 && [...required].some((requiredRole) => !signedRoles.has(requiredRole))) {
      return Object.freeze({ disposition: "rejected", reason: "Abort bundle must be single-signed or fully signed" });
    }
    if (isAbort && signedRoles.size === 1 && (!signedRoles.has(role)
      || (!signedRoles.has("buyer") && !signedRoles.has("seller")))) {
      return Object.freeze({ disposition: "rejected", reason: "Single-signed abort has invalid signer-role binding" });
    }
    const partyKeys = new Map<BundleRole, Uint8Array>();
    for (const party of artifact["parties"] as Record<string, unknown>[]) {
      let authority: BundlePartyIdentityAuthorityCheck;
      try { authority = options.resolvePartyIdentity(party); }
      catch { return Object.freeze({ disposition: "indeterminate", reason: "IdentityBundle resolver failed" }); }
      if (authority.status === "indeterminate") return Object.freeze({ disposition: "indeterminate", reason: authority.reason });
      if (authority.status !== "verified" || authority.bundleHash !== party["bundleHash"]
        || authority.primaryClaim !== party["primaryClaim"] || authority.publicKey.byteLength !== 32) {
        return Object.freeze({ disposition: "rejected", reason: "Party IdentityBundle authority differs from the signed bundle" });
      }
      partyKeys.set(party["role"] as BundleRole, authority.publicKey);
    }
    const signedScope = { ...artifact };
    delete signedScope["anchoredByRole"];
    delete signedScope["signatures"];
    const bundleHash = sha256Hex(consumerCanonicalize(signedScope));
    for (const signature of signatureEntries) {
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(partyKeys.get(signature.role)!)]),
        format: "der",
        type: "spki",
      });
      if (!verifySignature(null, Buffer.from(`${bundleSignatureDomain(artifact)}${bundleHash}`), publicKey, signature.value)) {
        return Object.freeze({ disposition: "rejected", reason: "Bundle signature verification failed" });
      }
    }
    return Object.freeze({ disposition: "authenticated", artifact: Object.freeze(artifact) });
  } catch {
    return Object.freeze({ disposition: "rejected", reason: "Bundle signed-scope authentication failed" });
  }
}

export function verifyCanonicalAttestationBundleJson(
  canonicalJson: string,
  options: AttestationBundleVerificationOptions,
): AttestationBundleVerificationResult {
  try {
    if (typeof canonicalJson !== "string" || canonicalJson.length === 0) return rejected("shape", "Bundle JSON is required");
    if (Buffer.byteLength(canonicalJson, "utf8") > MAX_ATTESTATION_BUNDLE_BYTES) {
      return rejected("size", `AttestationBundle exceeds ${MAX_ATTESTATION_BUNDLE_BYTES} bytes`);
    }
    const artifact = JSON.parse(canonicalJson) as unknown;
    if (!isObject(artifact) || consumerCanonicalize(artifact) !== canonicalJson) {
      return rejected("canonical-form", "Bundle is not canonical JSON");
    }
    const jobId = artifact["jobId"];
    const role = artifact["anchoredByRole"];
    if (!validBundleTypeDiscriminator(artifact) || typeof jobId !== "string" || jobId.length === 0
      || (role !== "buyer" && role !== "seller" && role !== "orchestrator")) {
      return rejected("shape", "Bundle version, jobId, or anchor role is invalid");
    }
    if (options.expectedJobId !== undefined && jobId !== options.expectedJobId) {
      return rejected("session-binding", "Bundle jobId differs from the expected session");
    }
    // Pure-mapping address binding only; the write-input path resolves through a published
    // BundleBinding and never recomputes the native address (BB-7).
    if (options.expectedAddress !== `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`) {
      return rejected("anchor-binding", "Bundle anchor address does not match anchoredByRole");
    }
    const faultScope = faultedPartyPermitted(artifact);
    if (!faultScope.ok) return rejected("fault-attribution", faultScope.reason);
    if (!OUTCOMES.has(artifact["outcome"] as BundleOutcome)) return rejected("shape", "Bundle outcome is unsupported");
    if (!validReference(artifact["listingRef"], "listing")
      || (artifact["agreementRef"] !== undefined && !validAttestationReference(artifact["agreementRef"]))
      || !Array.isArray(artifact["phaseSummary"]) || !validPhaseSummary(artifact["phaseSummary"])
      || !Array.isArray(artifact["vetRecords"]) || !artifact["vetRecords"].every(validAttestationReference)
      || !Array.isArray(artifact["settlementEvidence"])
      || !artifact["settlementEvidence"].every(validAttestationReference)
      || !validOptionalReferenceArray(artifact, "amendments")
      || !validOptionalReferenceArray(artifact, "ratingRefs")
      || !positiveSafeInteger(artifact["recipeRegistryVersion"])
      || !positiveSafeInteger(artifact["railRegistryVersion"])
      || !nonNegativeSafeInteger(artifact["finalisedAt"])) {
      return rejected("shape", "Bundle references, phases, registries, or finalisation time are invalid");
    }
    const phaseSummary = artifact["phaseSummary"] as Record<string, unknown>[];
    const requiresAgreement = artifact["outcome"] === "completed" || phaseSummary.some((phase) =>
      typeof phase["kind"] === "string" && (phase["kind"].startsWith("commit-")
        || phase["kind"].startsWith("pay-") || phase["kind"].startsWith("deliver-")));
    if (requiresAgreement && artifact["agreementRef"] === undefined) {
      return rejected("agreement-binding", "Post-commit bundle lacks its authenticated Agreement reference");
    }
    const isFaultBundle = Object.hasOwn(artifact, "faultBundleVersion");
    const outcomeErrorClasses = artifact["outcome"] === "failed-perm"
      ? new Set(isFaultBundle
        ? ["permanent", "transient", "counterparty", "settlement-atomicity"]
        : ["permanent", "transient"])
      : artifact["outcome"] === "failed-counterparty"
        ? new Set(isFaultBundle
          ? ["permanent", "transient", "counterparty", "settlement-atomicity"]
          : ["counterparty", "settlement-atomicity"])
        : artifact["outcome"] === "failed-substrate"
          ? new Set(["substrate"])
          : null;
    if (artifact["outcome"] === "completed" && phaseSummary.some((phase) => phase["outcome"] !== "ok")) {
      return rejected("outcome", "Completed bundle contains a non-successful phase");
    }
    if (outcomeErrorClasses !== null && !phaseSummary.some((phase) =>
      phase["outcome"] === "fail" && outcomeErrorClasses.has(phase["errorClass"] as string))) {
      return rejected("outcome", "Failed bundle outcome has no matching failed phase");
    }
    const settlementReferenceKeys = (artifact["settlementEvidence"] as Record<string, unknown>[])
      .map((ref) => consumerCanonicalize(ref));
    const settlementReferenceSet = new Set(settlementReferenceKeys);
    const expectedSettlementPhases = phaseSummary
      .filter((phase) => isSettlementEvidencePhase(phase["kind"] as string))
      .map((phase) => ({ index: phase["index"], kind: phase["kind"] }));
    if (settlementReferenceSet.size !== settlementReferenceKeys.length) {
      return rejected("reference-resolution", "SettlementEvidence contains a duplicate reference");
    }
    if (settlementReferenceKeys.length !== expectedSettlementPhases.length) {
      return rejected("reference-resolution", "SettlementEvidence does not match the evidence-bearing phase count");
    }
    if (phaseSummary.some((phase) => phase["attestationRef"] !== undefined
      && !settlementReferenceSet.has(consumerCanonicalize(phase["attestationRef"])))) {
      return rejected("reference-resolution", "Phase AttestationRef is absent from top-level SettlementEvidence");
    }
    const parties = partyClaims(artifact["parties"]);
    if (parties instanceof Error) return rejected("parties", parties.message);
    if (!parties.has(role)) return rejected("anchor-binding", "Anchor role is not a bundle party");
    let topLevelUncertainty: string | null = null;
    const listingAuthority = resolveListingAuthority(options, artifact["listingRef"] as Record<string, unknown>);
    if (listingAuthority.disposition === "indeterminate") topLevelUncertainty ??= listingAuthority.reason;
    else if (listingAuthority.disposition !== "verified") return listingAuthority;
    const phasePlanAuthority = resolveExecutedPhasePlan(
      options,
      jobId,
      artifact["outcome"] as BundleOutcome,
      phaseSummary,
      artifact["recipeRegistryVersion"] as number,
      artifact["railRegistryVersion"] as number,
    );
    if (phasePlanAuthority.disposition === "indeterminate") topLevelUncertainty ??= phasePlanAuthority.reason;
    else if (phasePlanAuthority.disposition !== "verified") return phasePlanAuthority;
    const partyKeys = new Map<BundleRole, Uint8Array>();
    for (const party of artifact["parties"] as Record<string, unknown>[]) {
      const partyRole = party["role"] as BundleRole;
      const authority = resolvePartyAuthority(options, party);
      if (authority.disposition === "indeterminate") topLevelUncertainty ??= authority.reason;
      else if (!("publicKey" in authority)) return authority;
      else partyKeys.set(partyRole, authority.publicKey);
    }
    const references = collectAttestationReferences(artifact, jobId, role);
    const phaseEvidenceSigners = new Set<string>();
    const authenticatedSettlementPhases = new Map<number, string>();
    const referenceAuthorities = new Map<string, string>();
    let referenceUncertainty: string | null = null;
    let settlementReferenceUncertainty: string | null = null;
    for (const { context, ref } of references) {
      let resolved: AttestationReferenceCheck;
      try { resolved = options.resolveAttestationRef(ref, context); }
      catch (error) {
        const reason = `AttestationRef resolver failed: ${message(error)}`;
        referenceUncertainty ??= reason;
        if (context.usage === "settlement") settlementReferenceUncertainty ??= reason;
        continue;
      }
      if (resolved === null || typeof resolved !== "object") {
        const reason = "AttestationRef resolver returned a malformed result";
        referenceUncertainty ??= reason;
        if (context.usage === "settlement") settlementReferenceUncertainty ??= reason;
        continue;
      }
      if (resolved.status === "indeterminate") {
        referenceUncertainty ??= resolved.reason;
        if (context.usage === "settlement") settlementReferenceUncertainty ??= resolved.reason;
        continue;
      }
      if (resolved.status === "rejected") return rejected("reference-resolution", resolved.reason);
      if (resolved.status === "absent") return rejected("reference-resolution", "AttestationRef is authoritatively absent");
      const anchor = ref["anchor"] as Record<string, unknown>;
      if (resolved.status !== "verified" || resolved.contentHash !== ref["contentHash"]
        || resolved.jobId !== jobId || resolved.anchorKind !== anchor["kind"]
        || resolved.anchorLocator !== anchor["locator"]
        || !artifactTypeMatchesUsage(resolved.artifactType, context.usage)
        || (context.expectedPhaseIndex !== undefined && (resolved.phaseIndex !== context.expectedPhaseIndex
          || resolved.phaseKind !== context.expectedPhaseKind
          || resolved.evidenceOutcome !== (context.expectedPhaseOutcome === "ok" ? "success" : "failure")))) {
        return rejected("reference-resolution", "AttestationRef content hash is not independently verified");
      }
      const referenceKey = consumerCanonicalize(ref);
      const authoritySnapshot = consumerCanonicalize({
        artifactType: resolved.artifactType,
        anchorKind: resolved.anchorKind,
        anchorLocator: resolved.anchorLocator,
        contentHash: resolved.contentHash,
        jobId: resolved.jobId,
        ...(resolved.phaseIndex === undefined ? {} : { phaseIndex: resolved.phaseIndex }),
        ...(resolved.phaseKind === undefined ? {} : { phaseKind: resolved.phaseKind }),
        ...(resolved.evidenceOutcome === undefined ? {} : { evidenceOutcome: resolved.evidenceOutcome }),
        ...(resolved.signer === undefined ? {} : { signer: resolved.signer }),
        ...(resolved.agreementListingRef === undefined ? {} : { agreementListingRef: resolved.agreementListingRef }),
        ...(resolved.agreementParties === undefined ? {} : { agreementParties: resolved.agreementParties }),
      });
      const priorAuthority = referenceAuthorities.get(referenceKey);
      if (priorAuthority !== undefined && priorAuthority !== authoritySnapshot) {
        return rejected("reference-resolution", "Repeated AttestationRef resolution returned inconsistent authority");
      }
      referenceAuthorities.set(referenceKey, authoritySnapshot);
      if (context.usage === "agreement" && !agreementBindingsMatch(
        artifact,
        resolved.agreementListingRef,
        resolved.agreementParties,
      )) {
        return rejected("agreement-binding", "Agreement authority differs from bundle Listing or parties");
      }
      if (resolved.artifactType === "phase-evidence" && resolved.signer === undefined) {
        return rejected("reference-resolution", "Phase evidence lacks an authenticated signer");
      }
      if (context.usage === "settlement") {
        const matchingPhase = phaseSummary.find((phase) => phase["index"] === resolved.phaseIndex);
        const expectedEvidenceOutcome = matchingPhase?.["outcome"] === "ok" ? "success" : "failure";
        if (matchingPhase === undefined || matchingPhase["kind"] !== resolved.phaseKind
          || !isSettlementEvidencePhase(matchingPhase["kind"] as string)
          || resolved.evidenceOutcome !== expectedEvidenceOutcome
          || (matchingPhase["attestationRef"] !== undefined
            && consumerCanonicalize(matchingPhase["attestationRef"]) !== consumerCanonicalize(ref))
          || authenticatedSettlementPhases.has(resolved.phaseIndex!)) {
          return rejected("reference-resolution", "SettlementEvidence does not map uniquely to an authenticated phase");
        }
        authenticatedSettlementPhases.set(resolved.phaseIndex!, resolved.phaseKind!);
      }
      if (resolved.signer !== undefined) {
        let canonicalSigner: string;
        try { canonicalSigner = canonicalizeClaimReference(resolved.signer).canonicalReference; }
        catch { return rejected("reference-resolution", "Resolved AttestationRef signer is invalid"); }
        if (canonicalSigner !== resolved.signer) {
          return rejected("reference-resolution", "Resolved AttestationRef signer is non-canonical");
        }
        if (ref["signer"] !== undefined && ref["signer"] !== resolved.signer) {
          return rejected("reference-resolution", "AttestationRef signer hint differs from authenticated evidence signer");
        }
        if (resolved.artifactType === "phase-evidence") phaseEvidenceSigners.add(resolved.signer);
      } else if (ref["signer"] !== undefined) {
        return rejected("reference-resolution", "AttestationRef signer hint lacks authenticated signer evidence");
      }
    }
    const authenticatedPhaseSet = [...authenticatedSettlementPhases]
      .map(([index, kind]) => ({ index, kind })).sort((left, right) => left.index - right.index);
    const expectedPhaseSet = [...expectedSettlementPhases]
      .sort((left, right) => (left.index as number) - (right.index as number));
    if (settlementReferenceUncertainty === null
      && consumerCanonicalize(authenticatedPhaseSet) !== consumerCanonicalize(expectedPhaseSet)) {
      return rejected("reference-resolution", "SettlementEvidence does not cover every executed phase exactly once");
    }
    const buyerSeller = new Set([parties.get("buyer")!, parties.get("seller")!]);
    const thirdPartySigners = [...phaseEvidenceSigners].filter((signer) => !buyerSeller.has(signer));
    if (new Set(thirdPartySigners).size > 1
      || (thirdPartySigners.length > 0 && parties.get("orchestrator") !== thirdPartySigners[0])) {
      return rejected("parties", "Distinct phase-evidence authority must be the declared orchestrator");
    }
    const signedScope = { ...artifact };
    delete signedScope["anchoredByRole"];
    delete signedScope["signatures"];
    const signedScopeCanonicalJson = consumerCanonicalize(signedScope);
    const bundleHash = sha256Hex(signedScopeCanonicalJson);
    const signatures = artifact["signatures"];
    if (!Array.isArray(signatures) || signatures.length === 0) return rejected("signatures", "Bundle has no signatures");
    const signedRoles = new Set<BundleRole>();
    let everySignatureVerified = true;
    for (const signature of signatures) {
      if (!isObject(signature) || signature["algorithm"] !== "ed25519"
        || typeof signature["party"] !== "string" || typeof signature["value"] !== "string") {
        return rejected("signatures", "Bundle signature envelope is invalid");
      }
      const match = [...parties].find(([, claim]) => sameClaimIdentity(claim, signature["party"] as string));
      if (match === undefined || match[1] !== signature["party"] || signedRoles.has(match[0])) {
        return rejected("signatures", "Bundle signature party is unauthorized or duplicated");
      }
      let value: Uint8Array;
      try { value = decodeComponentSignatureValue(signature["value"], 64); }
      catch { return rejected("signatures", "Bundle signature value is not canonical base64url"); }
      const key = partyKeys.get(match[0]);
      if (key === undefined) {
        everySignatureVerified = false;
        topLevelUncertainty ??= "Bundle signer IdentityBundle authority is unavailable";
        signedRoles.add(match[0]);
        continue;
      }
      if (key.byteLength !== 32) return rejected("signatures", "Bundle signer key is unavailable");
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key)]), format: "der", type: "spki",
      });
      if (!verifySignature(null, Buffer.from(`${bundleSignatureDomain(artifact)}${bundleHash}`), publicKey, value)) {
        return rejected("signatures", "Bundle signature verification failed");
      }
      signedRoles.add(match[0]);
    }
    const required = new Set<BundleRole>(["buyer", "seller"]);
    if (parties.has("orchestrator")) required.add("orchestrator");
    const isAbort = artifact["outcome"] === "aborted-by-self" || artifact["outcome"] === "aborted-by-other";
    if (!isAbort && [...required].some((requiredRole) => !signedRoles.has(requiredRole))) {
      return rejected("signatures", "Non-abort bundle lacks all required signatures");
    }
    if (isAbort && signedRoles.size !== 1 && [...required].some((requiredRole) => !signedRoles.has(requiredRole))) {
      return rejected("signatures", "Abort bundle must be single-signed or fully signed");
    }
    if (isAbort && signedRoles.size === 1 && !signedRoles.has("buyer") && !signedRoles.has("seller")) {
      return rejected("signatures", "Single-signed abort must be authorized by buyer or seller");
    }
    if (isAbort && signedRoles.size === 1 && !signedRoles.has(role)) {
      return rejected("signatures", "Single-signed abort must be anchored by its signer role");
    }
    const authenticatedReferenceAuthorities = freezeReferenceAuthorities(referenceAuthorities);
    if (topLevelUncertainty !== null || referenceUncertainty !== null) {
      return indeterminate(
        topLevelUncertainty ?? referenceUncertainty!,
        everySignatureVerified ? artifact : undefined,
        everySignatureVerified ? authenticatedReferenceAuthorities : undefined,
      );
    }
    return Object.freeze({
      disposition: "verified", artifact: Object.freeze(artifact), anchoredByRole: role,
      bundleHash, referenceAuthorities: authenticatedReferenceAuthorities,
      requiredSignatureCount: required.size, signatureCount: signedRoles.size,
      signedScopeCanonicalJson,
    });
  } catch (error) {
    return rejected("parse", error instanceof Error ? error.message : "Bundle parsing failed");
  }
}

function isSettlementEvidencePhase(kind: string): boolean {
  return kind.startsWith("pay-") || kind.startsWith("deliver-");
}

function resolveExecutedPhasePlan(
  options: AttestationBundleVerificationOptions,
  jobId: string,
  outcome: BundleOutcome,
  phaseSummary: readonly Record<string, unknown>[],
  recipeRegistryVersion: number,
  railRegistryVersion: number,
): AttestationBundleVerificationResult | { readonly disposition: "verified" } {
  let authority: BundleExecutedPhasePlanCheck;
  try { authority = options.resolveExecutedPhasePlan(jobId); }
  catch (error) { return indeterminate(`Executed phase plan resolver failed: ${message(error)}`); }
  if (authority.status === "indeterminate") return indeterminate(authority.reason);
  if (authority.status === "rejected") return rejected("phase-plan", authority.reason);
  if (authority.status === "absent") return rejected("phase-plan", "Executed phase plan is authoritatively absent");
  const actual = phaseSummary.map((phase) => ({ index: phase["index"], kind: phase["kind"] }));
  const expectedPrefix = authority.phases.slice(0, actual.length);
  const isAbort = outcome === "aborted-by-self" || outcome === "aborted-by-other";
  const complete = outcome === "completed";
  const failurePrefixIsValid = phaseSummary.length > 0
    && phaseSummary.slice(0, -1).every((phase) => phase["outcome"] === "ok")
    && phaseSummary.at(-1)?.["outcome"] === "fail";
  if ((complete && actual.length !== authority.phases.length)
    || (!complete && !isAbort && !failurePrefixIsValid)
    || (isAbort && (actual.length >= authority.phases.length
      || phaseSummary.some((phase) => phase["outcome"] !== "ok")))
    || actual.length > authority.phases.length
    || consumerCanonicalize(expectedPrefix) !== consumerCanonicalize(actual)) {
    return rejected("phase-plan", "Bundle phaseSummary differs from the authenticated executed phase plan");
  }
  if (authority.recipeRegistryVersion !== recipeRegistryVersion
    || authority.railRegistryVersion !== railRegistryVersion) {
    return rejected("registry-binding", "Bundle registry versions differ from authenticated session authority");
  }
  return Object.freeze({ disposition: "verified" as const });
}

function agreementBindingsMatch(
  bundle: Readonly<Record<string, unknown>>,
  listingRef: Readonly<Record<string, unknown>> | undefined,
  agreementParties: readonly Readonly<Record<string, unknown>>[] | undefined,
): boolean {
  if (listingRef === undefined || agreementParties === undefined
    || consumerCanonicalize(listingRef) !== consumerCanonicalize(bundle["listingRef"])) return false;
  const bundleParties = bundle["parties"] as readonly Readonly<Record<string, unknown>>[];
  return (["buyer", "seller"] as const).every((role) => {
    const expected = agreementParties.filter((party) => party["role"] === role);
    const actual = bundleParties.filter((party) => party["role"] === role);
    return expected.length === 1 && actual.length === 1
      && expected[0]!["bundleHash"] === actual[0]!["bundleHash"]
      && expected[0]!["primaryClaim"] === actual[0]!["primaryClaim"];
  });
}

function resolveListingAuthority(
  options: AttestationBundleVerificationOptions,
  ref: Record<string, unknown>,
): AttestationBundleVerificationResult | { readonly disposition: "verified" } {
  let authority: BundleListingAuthorityCheck;
  try { authority = options.resolveListingRef(ref); }
  catch (error) { return indeterminate(`Listing resolver failed: ${message(error)}`); }
  if (authority.status === "indeterminate") return indeterminate(authority.reason);
  if (authority.status === "rejected") return rejected("listing", authority.reason);
  if (authority.status === "absent") return rejected("listing", "Referenced Listing is authoritatively absent");
  if (authority.contentHash !== ref["contentHash"] || authority.listingId !== ref["listingId"]
    || authority.version !== ref["version"]) {
    return rejected("listing", "Referenced Listing authority differs from the signed bundle");
  }
  return Object.freeze({ disposition: "verified" as const });
}

function resolvePartyAuthority(
  options: AttestationBundleVerificationOptions,
  party: Record<string, unknown>,
): AttestationBundleVerificationResult | { readonly disposition: "verified"; readonly publicKey: Uint8Array } {
  let authority: BundlePartyIdentityAuthorityCheck;
  try { authority = options.resolvePartyIdentity(party); }
  catch (error) { return indeterminate(`IdentityBundle resolver failed: ${message(error)}`); }
  if (authority.status === "indeterminate") return indeterminate(authority.reason);
  if (authority.status === "rejected") return rejected("parties", authority.reason);
  if (authority.status === "absent") return rejected("parties", "Party IdentityBundle is authoritatively absent");
  if (authority.bundleHash !== party["bundleHash"] || authority.primaryClaim !== party["primaryClaim"]
    || authority.publicKey.byteLength !== 32) {
    return rejected("parties", "Party IdentityBundle authority differs from the signed bundle");
  }
  return Object.freeze({ disposition: "verified" as const, publicKey: authority.publicKey });
}

function partyClaims(value: unknown): Map<BundleRole, string> | Error {
  if (!Array.isArray(value)) return new Error("Bundle parties are required");
  const claims = new Map<BundleRole, string>();
  for (const party of value) {
    if (!isObject(party)) return new Error("Bundle party is invalid");
    const role = party["role"];
    const claim = party["primaryClaim"];
    const bundleHash = party["bundleHash"];
    if ((role !== "buyer" && role !== "seller" && role !== "orchestrator")
      || typeof claim !== "string" || !hex64(bundleHash) || claims.has(role)) return new Error("Bundle party is invalid");
    let canonical: string;
    try { canonical = canonicalizeClaimReference(claim).canonicalReference; }
    catch { return new Error("Bundle party claim is invalid"); }
    if (canonical !== claim || [...claims.values()].some((other) => sameClaimIdentity(other, claim))) {
      return new Error("Bundle party claim is non-canonical or duplicated");
    }
    claims.set(role, claim);
  }
  return claims.has("buyer") && claims.has("seller") ? claims : new Error("Bundle requires buyer and seller parties");
}

function validPhaseSummary(value: readonly unknown[]): boolean {
  const indices = new Set<number>();
  let previousIndex = -1;
  return value.every((phase) => {
    if (!isObject(phase) || !nonNegativeSafeInteger(phase["index"])
      || (phase["index"] as number) <= previousIndex || indices.has(phase["index"] as number)
      || typeof phase["kind"] !== "string" || phase["kind"].length === 0
      || (phase["outcome"] !== "ok" && phase["outcome"] !== "fail")
      || (phase["outcome"] === "ok" && phase["errorClass"] !== undefined)
      || (phase["outcome"] === "fail" && !ERROR_CLASSES.has(phase["errorClass"] as string))
      || (phase["attestationRef"] !== undefined && !validAttestationReference(phase["attestationRef"]))) return false;
    previousIndex = phase["index"] as number;
    indices.add(previousIndex);
    return true;
  });
}

function validReference(value: unknown, kind: "listing" | "artifact"): boolean {
  if (!isObject(value) || !hex64(value["contentHash"])) return false;
  return kind === "listing"
    ? typeof value["listingId"] === "string" && positiveSafeInteger(value["version"])
    : typeof value["kind"] === "string" && typeof value["id"] === "string";
}
function validAttestationReference(value: unknown): boolean {
  if (!isObject(value) || !hex64(value["contentHash"]) || !isObject(value["anchor"])) return false;
  const anchorKind = value["anchor"]["kind"];
  if ((anchorKind !== "storage-program" && anchorKind !== "ipfs" && anchorKind !== "https")
    || typeof value["anchor"]["locator"] !== "string" || value["anchor"]["locator"].length === 0
    || (value["signer"] !== undefined && typeof value["signer"] !== "string")) return false;
  if (typeof value["signer"] === "string") {
    try {
      if (canonicalizeClaimReference(value["signer"]).canonicalReference !== value["signer"]) return false;
    } catch { return false; }
  }
  return true;
}
function validOptionalReferenceArray(artifact: Readonly<Record<string, unknown>>, field: string): boolean {
  if (!Object.hasOwn(artifact, field)) return true;
  const values = artifact[field];
  return Array.isArray(values) && values.every(validAttestationReference);
}
function collectAttestationReferences(
  artifact: Readonly<Record<string, unknown>>,
  jobId: string,
  anchoredByRole: BundleRole,
) {
  const references: { ref: Record<string, unknown>; context: AttestationReferenceContext }[] = [];
  const phasesByReference = new Map<string, { index: number; kind: string; outcome: "ok" | "fail" }[]>();
  for (const phase of artifact["phaseSummary"] as Record<string, unknown>[]) {
    if (!isObject(phase["attestationRef"])) continue;
    const key = consumerCanonicalize(phase["attestationRef"]);
    const phases = phasesByReference.get(key) ?? [];
    if (phases.length > 0) {
      throw new TypeError("One AttestationRef cannot authenticate multiple distinct phases");
    }
    phases.push({
      index: phase["index"] as number,
      kind: phase["kind"] as string,
      outcome: phase["outcome"] as "ok" | "fail",
    });
    phasesByReference.set(key, phases);
  }
  const add = (ref: Record<string, unknown>, context: AttestationReferenceContext) => {
    references.push({ ref, context });
  };
  if (isObject(artifact["agreementRef"])) {
    add(artifact["agreementRef"], { anchoredByRole, expectedJobId: jobId, usage: "agreement" });
  }
  const fields = [
    ["vetRecords", "vet"], ["settlementEvidence", "settlement"],
    ["amendments", "amendment"], ["ratingRefs", "rating"],
  ] as const;
  for (const [field, usage] of fields) {
    const values = artifact[field];
    if (Array.isArray(values)) {
      for (const ref of values as Record<string, unknown>[]) {
        if (usage !== "settlement") {
          add(ref, { anchoredByRole, expectedJobId: jobId, usage });
          continue;
        }
        const phases = phasesByReference.get(consumerCanonicalize(ref)) ?? [];
        add(ref, {
          anchoredByRole,
          expectedJobId: jobId,
          usage,
          ...(phases.length === 1 ? {
            expectedPhaseIndex: phases[0]!.index,
            expectedPhaseKind: phases[0]!.kind,
            expectedPhaseOutcome: phases[0]!.outcome,
          } : {}),
        });
      }
    }
  }
  for (const phase of artifact["phaseSummary"] as Record<string, unknown>[]) {
    if (isObject(phase["attestationRef"])) add(phase["attestationRef"], {
      anchoredByRole,
      expectedJobId: jobId,
      usage: "phase",
      expectedPhaseIndex: phase["index"] as number,
      expectedPhaseKind: phase["kind"] as string,
      expectedPhaseOutcome: phase["outcome"] as "ok" | "fail",
    });
  }
  return references;
}
function artifactTypeMatchesUsage(
  artifactType: Extract<AttestationReferenceCheck, { status: "verified" }>["artifactType"],
  usage: AttestationReferenceContext["usage"],
): boolean {
  if (usage === "agreement") return artifactType === "agreement";
  if (usage === "phase" || usage === "settlement") return artifactType === "phase-evidence";
  return artifactType === usage;
}
function isObject(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function positiveSafeInteger(value: unknown): boolean { return Number.isSafeInteger(value) && (value as number) > 0; }
function nonNegativeSafeInteger(value: unknown): boolean { return Number.isSafeInteger(value) && (value as number) >= 0; }
function hex64(value: unknown): boolean { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
function rejected(stage: string, reason: string): AttestationBundleVerificationResult { return Object.freeze({ disposition: "rejected", stage, reason }); }
function indeterminate(
  reason: string,
  authenticatedArtifact?: Readonly<Record<string, unknown>>,
  authenticatedReferenceAuthorities?: readonly ReferenceAuthoritySnapshot[],
): AttestationBundleVerificationResult {
  return Object.freeze({
    disposition: "indeterminate", stage: "reference-resolution", reason,
    ...(authenticatedArtifact === undefined ? {} : { authenticatedArtifact }),
    ...(authenticatedReferenceAuthorities === undefined ? {} : { authenticatedReferenceAuthorities }),
  });
}
interface ReferenceAuthoritySnapshot {
  readonly reference: string;
  readonly authority: string;
}
function freezeReferenceAuthorities(
  authorities: ReadonlyMap<string, string>,
): readonly ReferenceAuthoritySnapshot[] {
  return Object.freeze([...authorities].map(([reference, authority]) =>
    Object.freeze({ reference, authority })));
}
function message(error: unknown): string { return error instanceof Error ? error.message : "unknown resolver failure"; }

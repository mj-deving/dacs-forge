import {
  authenticateCanonicalAttestationBundleSignedScope,
  verifyCanonicalAttestationBundleJson,
  type AttestationBundleVerificationOptions,
} from "./attestation-bundle-verifier.ts";
import type { BundleOutcome, BundleRole } from "../producer/attestation-bundle.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { consumerCanonicalize } from "./canonical-json.ts";
import {
  gateReputationOutputCandidate,
  type ReputationOutputGateResult,
} from "./reputation-eligibility.ts";
import { bundleCopiesDiverge } from "../protocol/fault-attestation-bundle.ts";

// §10.4.3 pair classification is pure protocol semantics and lives with the bundle types;
// it is re-exported here so consumers keep one reconciliation entry point.
export {
  bundleCopiesDiverge,
  classifyBundlePair,
  scoredOutcome,
  type BundlePairClassification,
  type BundlePairConvergence,
} from "../protocol/fault-attestation-bundle.ts";

export type BundleAddressRead =
  | { readonly status: "present"; readonly canonicalJson: string }
  | { readonly status: "absent"; readonly authority: "authoritative" }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export type BundleLookupDisposition = "absent" | "indeterminate" | "one-sided" | "unified" | "divergent";
export type BundleReconciliationDisposition = BundleLookupDisposition | "rejected";

export interface BundleConsistencyResult {
  readonly disposition: BundleReconciliationDisposition;
  readonly reputationEligibility: "eligible" | "excluded" | "indeterminate" | "not-applicable";
  readonly reason: string;
  readonly attribution?: Readonly<Record<"buyer" | "seller", "self" | "counterparty">>;
  readonly preferredRole?: "buyer" | "seller";
}

export function gateBundleReputationOutput(
  result: BundleConsistencyResult,
  candidate: Readonly<{ readonly artifact: unknown; readonly provenance: unknown }>,
): ReputationOutputGateResult {
  return gateReputationOutputCandidate({
    artifact: candidate.artifact,
    protocolEligibility: result.reputationEligibility,
    provenance: candidate.provenance,
  });
}

export function reconcileAttestationBundleReads(
  jobId: string,
  reads: Readonly<Record<"buyer" | "seller", BundleAddressRead> & { readonly orchestrator?: BundleAddressRead }>,
  options: Omit<AttestationBundleVerificationOptions, "expectedAddress" | "expectedJobId">,
  scoredRole?: "buyer" | "seller",
): BundleConsistencyResult {
  type CachedPartyAuthority =
    | { readonly status: "returned"; readonly value: ReturnType<typeof options.resolvePartyIdentity> }
    | { readonly status: "threw"; readonly error: unknown };
  const partyAuthorityCache = new Map<string, CachedPartyAuthority>();
  const resolvePartyIdentity = (party: Readonly<Record<string, unknown>>) => {
    const key = consumerCanonicalize(party);
    const cached = partyAuthorityCache.get(key);
    if (cached?.status === "returned") return cached.value;
    if (cached?.status === "threw") throw cached.error;
    try {
      const resolved = options.resolvePartyIdentity(party);
      partyAuthorityCache.set(key, { status: "returned", value: resolved });
      return resolved;
    } catch (error) {
      partyAuthorityCache.set(key, { status: "threw", error });
      throw error;
    }
  };
  const verificationOptions = { ...options, resolvePartyIdentity };
  const verified = new Map<BundleRole, Extract<ReturnType<typeof verifyCanonicalAttestationBundleJson>, { disposition: "verified" }>>();
  const partyVerificationUncertainty = new Map<"buyer" | "seller", string>();
  const authenticatedUncertain = new Map<"buyer" | "seller", Readonly<Record<string, unknown>>>();
  const reconciledReferenceAuthorities = new Map<string, string>();
  let referenceAuthorityConflict: string | null = null;
  for (const role of ["buyer", "seller"] as const) {
    if (reads[role].status === "rejected") {
      return outcome("rejected", "excluded", `${role} copy rejected: ${reads[role].reason}`);
    }
  }
  const authenticatedPartyCopies = (["buyer", "seller"] as const).flatMap((role) => {
    const read = reads[role];
    if (read.status !== "present") return [];
    const result = authenticateCanonicalAttestationBundleSignedScope(read.canonicalJson, {
      expectedAddress: bundleAddress(jobId, role),
      expectedJobId: jobId,
      resolvePartyIdentity,
    });
    return result.disposition === "authenticated" ? [{ role, artifact: result.artifact }] : [];
  });
  if (authenticatedPartyCopies.length === 2
    && normativelyDiverges(authenticatedPartyCopies[0]!.artifact, authenticatedPartyCopies[1]!.artifact)) {
    return outcome("divergent", "excluded", "Authenticated party copies contradict on outcome or phaseSummary");
  }
  for (const role of ["buyer", "seller"] as const) {
    const read = reads[role];
    if (read.status !== "present") continue;
    const result = verifyCanonicalAttestationBundleJson(read.canonicalJson, {
      ...verificationOptions, expectedJobId: jobId,
      expectedAddress: bundleAddress(jobId, role),
    });
    referenceAuthorityConflict ??= mergeReferenceAuthorities(
      reconciledReferenceAuthorities,
      referenceAuthorities(result),
    );
    if (result.disposition !== "verified") {
      if (result.disposition === "indeterminate") {
        partyVerificationUncertainty.set(role, result.reason);
        if (result.authenticatedArtifact !== undefined) {
          authenticatedUncertain.set(role, result.authenticatedArtifact);
        }
        continue;
      }
      return outcome("rejected", "excluded", `${role} copy rejected: ${result.stage}: ${result.reason}`);
    }
    verified.set(role, result);
  }
  const partyCopy = verified.get("buyer") ?? verified.get("seller");
  const comparableCopies = (["buyer", "seller"] as const).flatMap((role) => {
    const certain = verified.get(role)?.artifact;
    const uncertain = authenticatedUncertain.get(role);
    return certain === undefined && uncertain === undefined ? [] : [{ role, artifact: certain ?? uncertain! }];
  });
  if (comparableCopies.length === 2
    && canonicallyDiverges(comparableCopies[0]!.artifact, comparableCopies[1]!.artifact)) {
    return outcome("divergent", "excluded", "Authenticated party copies contradict on required shared authority fields");
  }
  if (referenceAuthorityConflict !== null) {
    return outcome("rejected", "excluded", referenceAuthorityConflict);
  }
  if (partyCopy === undefined) {
    if (reads.orchestrator?.status === "rejected") {
      return outcome("rejected", "excluded", `orchestrator copy rejected: ${reads.orchestrator.reason}`);
    }
    if (reads.orchestrator?.status === "present") {
      const orchestrator = verifyCanonicalAttestationBundleJson(reads.orchestrator.canonicalJson, {
        ...verificationOptions, expectedJobId: jobId, expectedAddress: bundleAddress(jobId, "orchestrator"),
      });
      referenceAuthorityConflict ??= mergeReferenceAuthorities(
        reconciledReferenceAuthorities,
        referenceAuthorities(orchestrator),
      );
      const orchestratorArtifact = authenticatedArtifact(orchestrator);
      if (orchestratorArtifact !== undefined && comparableCopies.some((copy) =>
        canonicallyDiverges(copy.artifact, orchestratorArtifact))) {
        return outcome("divergent", "excluded", "Authenticated party and orchestrator copies contradict");
      }
      if (referenceAuthorityConflict !== null) {
        return outcome("rejected", "excluded", referenceAuthorityConflict);
      }
      if (orchestrator.disposition === "rejected") {
        return outcome("rejected", "excluded", `orchestrator copy rejected: ${orchestrator.stage}: ${orchestrator.reason}`);
      }
      if (orchestrator.disposition === "indeterminate") {
        return outcome("indeterminate", "indeterminate", `orchestrator copy unresolved: ${orchestrator.reason}`);
      }
      if ([reads.buyer, reads.seller].some((read) => read.status === "indeterminate")
        || partyVerificationUncertainty.size > 0) {
        return outcome("indeterminate", "indeterminate", "Party copies remain unresolved beside the orchestrator copy");
      }
      return outcome("divergent", "excluded", "Orchestrator-only bundle copy lacks both party anchors");
    }
    if (reads.orchestrator?.status === "indeterminate") {
      return outcome("indeterminate", "indeterminate", "Orchestrator address is indeterminate while both party copies are absent");
    }
    if ([reads.buyer, reads.seller].some((read) => read.status === "indeterminate")
      || partyVerificationUncertainty.size > 0) {
      return outcome("indeterminate", "indeterminate", "At least one expected party address is indeterminate");
    }
    return outcome("absent", "not-applicable", "Both expected party addresses are authoritatively absent");
  }
  const verifiedParties = (["buyer", "seller"] as const).filter((role) => verified.has(role));
  if (verifiedParties.length === 2) {
    const buyer = verified.get("buyer")!;
    const seller = verified.get("seller")!;
    if (buyer.signatureCount !== buyer.requiredSignatureCount
      || seller.signatureCount !== seller.requiredSignatureCount) {
      return outcome("divergent", "excluded", "Two present unilateral copies lack full shared authorization");
    }
    if (canonicallyDiverges(buyer.artifact, seller.artifact)) {
      return outcome("divergent", "excluded", "Copies contradict on required shared authority fields");
    }
  }
  const requiresOrchestrator = (partyCopy.artifact["parties"] as Record<string, unknown>[])
    .some((party) => party["role"] === "orchestrator");
  const orchestratorRead = reads.orchestrator;
  if (!requiresOrchestrator && (orchestratorRead?.status === "present" || orchestratorRead?.status === "rejected")) {
    return outcome("rejected", "excluded", "Unexpected orchestrator copy exists for a two-party bundle");
  }
  if (requiresOrchestrator && orchestratorRead === undefined) {
    return outcome("indeterminate", "indeterminate", "Declared orchestrator address was not read");
  }
  if (requiresOrchestrator && orchestratorRead?.status === "rejected") {
    return outcome("rejected", "excluded", `orchestrator copy rejected: ${orchestratorRead.reason}`);
  }
  if (requiresOrchestrator && orchestratorRead?.status === "present") {
    const result = verifyCanonicalAttestationBundleJson(orchestratorRead.canonicalJson, {
      ...verificationOptions, expectedJobId: jobId, expectedAddress: bundleAddress(jobId, "orchestrator"),
    });
    referenceAuthorityConflict ??= mergeReferenceAuthorities(
      reconciledReferenceAuthorities,
      referenceAuthorities(result),
    );
    const orchestratorArtifact = authenticatedArtifact(result);
    if (orchestratorArtifact !== undefined && canonicallyDiverges(partyCopy.artifact, orchestratorArtifact)) {
      return outcome("divergent", "excluded", "Authenticated party and orchestrator copies contradict");
    }
    if (referenceAuthorityConflict !== null) {
      return outcome("rejected", "excluded", referenceAuthorityConflict);
    }
    if (result.disposition === "rejected") {
      return outcome("rejected", "excluded", `orchestrator copy rejected: ${result.stage}: ${result.reason}`);
    }
    if (result.disposition === "indeterminate") {
      return outcome("indeterminate", "indeterminate", `orchestrator copy unresolved: ${result.reason}`);
    }
    verified.set("orchestrator", result);
  }
  if ([reads.buyer, reads.seller].some((read) => read.status === "indeterminate")) {
    return outcome("indeterminate", "indeterminate", "At least one expected address is indeterminate");
  }
  if (partyVerificationUncertainty.size > 0) {
    const [role, reason] = partyVerificationUncertainty.entries().next().value!;
    return outcome("indeterminate", "indeterminate", `${role} copy unresolved: ${reason}`);
  }
  if (requiresOrchestrator && orchestratorRead?.status === "indeterminate") {
    return outcome("indeterminate", "indeterminate", "Declared orchestrator address is indeterminate");
  }
  if (verifiedParties.length === 1) {
    const role = verifiedParties[0]!;
    const bundle = verified.get(role)!;
    const other = role === "buyer" ? "seller" : "buyer";
    if (reads[other].status !== "absent") return outcome("indeterminate", "indeterminate", "Missing copy lacks qualified absence");
    if (bundle.signatureCount === bundle.requiredSignatureCount) {
      if (!requiresOrchestrator) {
        return { ...outcome("unified", "eligible", "Fully signed copy with qualified counterpart absence"), preferredRole: role };
      }
      const orchestrator = verified.get("orchestrator");
      if (orchestrator !== undefined && orchestrator.signatureCount === orchestrator.requiredSignatureCount
        && !canonicallyDiverges(bundle.artifact, orchestrator.artifact)) {
        return {
          ...outcome("unified", "eligible", "Fully signed party and orchestrator copies with qualified counterpart absence"),
          preferredRole: role,
        };
      }
      if (orchestratorRead?.status === "absent") {
        return outcome("divergent", "excluded", "Declared orchestrator copy is authoritatively absent");
      }
      if (orchestratorRead?.status === "present") {
        return outcome("divergent", "excluded", "Orchestrator copy lacks full shared convergence");
      }
    }
    const bundleOutcome = bundle.artifact["outcome"] as BundleOutcome;
    if ((bundleOutcome !== "aborted-by-self" && bundleOutcome !== "aborted-by-other") || bundle.signatureCount !== 1) {
      return outcome("rejected", "excluded", "Single-signed non-abort bundle is invalid");
    }
    if (requiresOrchestrator && orchestratorRead?.status === "present") {
      return outcome("divergent", "excluded", "Single-signed abort contradicts a present orchestrator copy");
    }
    if (requiresOrchestrator && orchestratorRead?.status !== "absent") {
      return outcome("indeterminate", "indeterminate", "Single-signed abort lacks qualified orchestrator absence");
    }
    const signerFault = bundleOutcome === "aborted-by-other" ? "counterparty" : "self";
    return {
      ...outcome("one-sided", "eligible", "Single-signed abort with qualified counterpart absence"),
      preferredRole: role,
      attribution: Object.freeze({
        [role]: signerFault,
        [other]: signerFault === "self" ? "counterparty" : "self",
      }) as Readonly<Record<"buyer" | "seller", "self" | "counterparty">>,
    };
  }
  const buyer = verified.get("buyer")!;
  if (requiresOrchestrator) {
    if (orchestratorRead?.status === "absent") {
      return outcome("divergent", "excluded", "Declared orchestrator role-local copy is authoritatively absent");
    }
    const orchestrator = verified.get("orchestrator");
    if (orchestrator === undefined || orchestrator.signatureCount !== orchestrator.requiredSignatureCount
      || canonicallyDiverges(buyer.artifact, orchestrator.artifact)) {
      return outcome("divergent", "excluded", "Orchestrator copy lacks full shared convergence");
    }
  }
  return {
    ...outcome("unified", "eligible", "Copies agree on all contradiction-bearing fields"),
    preferredRole: scoredRole ?? "buyer",
  };
}

function canonicallyDiverges(left: Readonly<Record<string, unknown>>, right: Readonly<Record<string, unknown>>): boolean {
  return bundleCopiesDiverge(left, right)
    || consumerCanonicalize(sharedAuthorityScope(left)) !== consumerCanonicalize(sharedAuthorityScope(right));
}

function normativelyDiverges(
  left: Readonly<Record<string, unknown>>,
  right: Readonly<Record<string, unknown>>,
): boolean {
  return bundleCopiesDiverge(left, right);
}

function mergeReferenceAuthorities(
  reconciled: Map<string, string>,
  snapshots: readonly Readonly<{ reference: string; authority: string }>[],
): string | null {
  for (const snapshot of snapshots) {
    const prior = reconciled.get(snapshot.reference);
    if (prior !== undefined && prior !== snapshot.authority) {
      return "Role-local copies resolved one AttestationRef to inconsistent authenticated authority";
    }
    reconciled.set(snapshot.reference, snapshot.authority);
  }
  return null;
}

function referenceAuthorities(
  result: ReturnType<typeof verifyCanonicalAttestationBundleJson>,
): readonly Readonly<{ reference: string; authority: string }>[] {
  if (result.disposition === "verified") return result.referenceAuthorities;
  return result.disposition === "indeterminate"
    ? result.authenticatedReferenceAuthorities ?? [] : [];
}

function authenticatedArtifact(
  result: ReturnType<typeof verifyCanonicalAttestationBundleJson>,
): Readonly<Record<string, unknown>> | undefined {
  if (result.disposition === "verified") return result.artifact;
  return result.disposition === "indeterminate" ? result.authenticatedArtifact : undefined;
}

function sharedAuthorityScope(artifact: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const scope = { ...artifact };
  for (const field of [
    "anchoredByRole", "signatures", "finalisedAt", "ratingRefs",
    "bundleVersion", "faultBundleVersion", "faultedParty", "outcome",
  ]) delete scope[field];
  if (Array.isArray(scope["amendments"])) {
    scope["amendments"] = [...scope["amendments"]].sort((left, right) => {
      const leftCanonical = consumerCanonicalize(left);
      const rightCanonical = consumerCanonicalize(right);
      return leftCanonical < rightCanonical ? -1 : leftCanonical > rightCanonical ? 1 : 0;
    });
  }
  return scope;
}

function bundleAddress(jobId: string, role: BundleRole): string {
  // Kept local so the consumer does not rely on producer implementation details.
  return `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`;
}
function outcome(
  disposition: BundleReconciliationDisposition,
  reputationEligibility: BundleConsistencyResult["reputationEligibility"],
  reason: string,
): BundleConsistencyResult { return Object.freeze({ disposition, reputationEligibility, reason }); }

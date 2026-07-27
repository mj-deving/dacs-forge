import { createHash } from "node:crypto";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../../src/protocol/component-signature-codec.ts";
import {
  ATTESTATION_BUNDLE_DOMAIN,
  signAttestationBundle,
  type BundlePartySigner,
  type UnsignedAttestationBundle,
} from "../../src/producer/attestation-bundle.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import type {
  AttestationReferenceCheck,
  AttestationReferenceContext,
} from "../../src/consumer/attestation-bundle-verifier.ts";
import { buyerFixtureSigner, FIXTURE_JOB_ID } from "./reference-agreement.ts";
import { fixtureSigner, FIXTURE_SIGNING_CONTEXT } from "./reference-listing.ts";

export function orchestratorFixtureSigner() {
  return createFixtureEd25519Signer(
    createHash("sha256").update("reference-dacs-template-orchestrator-v1").digest(),
    { deploymentMode: "fixture", authorityMode: "fixture" },
  );
}

export function orchestratorFixtureIdentity() {
  const signer = orchestratorFixtureSigner();
  return signPerClaimIdentityBundle({
    bundleVersion: "1",
    presentedBy: signer.signer,
    presentedAt: 1_784_073_600_000,
    claims: [{ ref: signer.signer }],
  }, signer, FIXTURE_SIGNING_CONTEXT);
}

export function fixtureUnsignedBundle(
  overrides: Partial<UnsignedAttestationBundle> = {},
): UnsignedAttestationBundle {
  const buyer = buyerFixtureSigner();
  const seller = fixtureSigner();
  const paymentRef = {
    anchor: { kind: "storage-program", locator: `dacs4:payment-evidence:${FIXTURE_JOB_ID}:2` },
    contentHash: "5".repeat(64),
  };
  const deliveryRef = {
    anchor: { kind: "storage-program", locator: `dacs4:delivery-evidence:${FIXTURE_JOB_ID}:3` },
    contentHash: "6".repeat(64),
  };
  return {
    bundleVersion: "1",
    jobId: FIXTURE_JOB_ID,
    outcome: "completed",
    listingRef: { listingId: "reference-json-transform-paid", version: 1, contentHash: "1".repeat(64) },
    agreementRef: {
      anchor: { kind: "storage-program", locator: `dacs3:agreement:${FIXTURE_JOB_ID}` },
      contentHash: "2".repeat(64),
    },
    parties: [
      { role: "buyer", bundleHash: "3".repeat(64), primaryClaim: buyer.signer },
      { role: "seller", bundleHash: "4".repeat(64), primaryClaim: seller.signer },
    ],
    phaseSummary: [
      { index: 2, kind: "pay-x402", outcome: "ok", txRefs: [{ rail: "x402", txHash: "fixture:tx" }], attestationRef: paymentRef },
      { index: 3, kind: "deliver-attested-payload", outcome: "ok", attestationRef: deliveryRef },
    ],
    vetRecords: [],
    settlementEvidence: [
      paymentRef,
      deliveryRef,
    ],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: 1_784_073_620_000,
    ...overrides,
  };
}

export function fixtureBundleSigners(withOrchestrator = false): readonly BundlePartySigner[] {
  return [
    { role: "buyer", signer: buyerFixtureSigner() },
    { role: "seller", signer: fixtureSigner() },
    ...(withOrchestrator ? [{ role: "orchestrator" as const, signer: orchestratorFixtureSigner() }] : []),
  ];
}

export function fixtureSignedBundle(overrides: Partial<UnsignedAttestationBundle> = {}) {
  const input = fixtureUnsignedBundle(overrides);
  return signAttestationBundle(
    input, fixtureBundleSigners(), ["buyer", "seller"], FIXTURE_SIGNING_CONTEXT,
    fixtureReferenceResolver, fixtureBundleAuthorityOptions,
  );
}

export function signUncheckedBundle(
  input: UnsignedAttestationBundle,
  roles: readonly ("buyer" | "seller" | "orchestrator")[],
  anchoredByRole: "buyer" | "seller" | "orchestrator",
): string {
  const scope = canonicalize(withoutFields(input, "anchoredByRole", "signatures"));
  const hash = sha256Hex(scope);
  const all = new Map(fixtureBundleSigners(input.parties.some((party) => party.role === "orchestrator"))
    .map((entry) => [entry.role, entry]));
  const signatures = roles.map((role) => {
    const entry = all.get(role)!;
    const party = input.parties.find((candidate) => candidate.role === role)!;
    return {
      party: party.primaryClaim,
      algorithm: "ed25519",
      value: encodeComponentSignatureValue(importLegacyComponentSignatureValue(
        entry.signer.sign(new TextEncoder().encode(`${ATTESTATION_BUNDLE_DOMAIN}${hash}`), FIXTURE_SIGNING_CONTEXT),
        "standard-base64-padded", 64,
      )),
    };
  });
  return canonicalize({ ...JSON.parse(scope), anchoredByRole, signatures });
}

export function fixtureKeyResolver(claim: string): Uint8Array | null {
  return claim.startsWith("key:") ? Uint8Array.from(Buffer.from(claim.slice(4), "hex")) : null;
}

export function fixtureListingAuthorityResolver(ref: Readonly<Record<string, unknown>>) {
  return {
    status: "verified" as const,
    contentHash: ref["contentHash"] as string,
    listingId: ref["listingId"] as string,
    version: ref["version"] as number,
  };
}

export function fixturePartyIdentityAuthorityResolver(party: Readonly<Record<string, unknown>>) {
  const primaryClaim = party["primaryClaim"] as string;
  const publicKey = fixtureKeyResolver(primaryClaim);
  return publicKey === null
    ? { status: "rejected" as const, reason: "Fixture identity key is unavailable" }
    : {
      status: "verified" as const,
      bundleHash: party["bundleHash"] as string,
      primaryClaim,
      publicKey,
    };
}

export const fixtureBundleAuthorityOptions = Object.freeze({
  resolveListingRef: fixtureListingAuthorityResolver,
  resolveExecutedPhasePlan: () => ({
    status: "verified" as const,
    railRegistryVersion: 1,
    recipeRegistryVersion: 1,
    phases: Object.freeze([
      { index: 2, kind: "pay-x402" },
      { index: 3, kind: "deliver-attested-payload" },
    ]),
  }),
  resolvePartyIdentity: fixturePartyIdentityAuthorityResolver,
});

export function fixtureReferenceResolver(
  ref: Readonly<Record<string, unknown>>,
  context: AttestationReferenceContext,
): Extract<AttestationReferenceCheck, { readonly status: "verified" }> {
  const anchor = ref["anchor"] as Record<string, unknown>;
  const locator = anchor["locator"] as string;
  const inferredPhase = locator.includes(":payment-evidence:")
    ? { phaseIndex: 2, phaseKind: "pay-x402" }
    : locator.includes(":delivery-evidence:")
      ? { phaseIndex: 3, phaseKind: "deliver-attested-payload" }
      : null;
  const phaseIndex = context.expectedPhaseIndex ?? inferredPhase?.phaseIndex;
  const phaseKind = context.expectedPhaseKind ?? inferredPhase?.phaseKind;
  const artifactType = locator.includes(":agreement:") ? "agreement" as const
    : locator.includes(":vet:") ? "vet" as const
      : locator.includes(":amendment:") ? "amendment" as const
        : locator.includes(":rating:") ? "rating" as const
          : "phase-evidence" as const;
  const bundle = fixtureUnsignedBundle();
  return {
    status: "verified" as const,
    artifactType,
    anchorKind: anchor["kind"] as string,
    anchorLocator: locator,
    contentHash: ref["contentHash"] as string,
    jobId: context.expectedJobId,
    ...(artifactType === "agreement" ? {
      agreementListingRef: bundle.listingRef,
      agreementParties: bundle.parties,
    } : {}),
    ...(phaseIndex !== undefined && phaseKind !== undefined ? {
      phaseIndex,
      phaseKind,
      evidenceOutcome: context.expectedPhaseOutcome === "fail" ? "failure" as const : "success" as const,
    } : {}),
    ...(artifactType === "phase-evidence"
      ? {
        recordClass: "ordinary-terminal" as const,
        signer: typeof ref["signer"] === "string" ? ref["signer"] : fixtureSigner().signer,
      }
      : typeof ref["signer"] === "string" ? { signer: ref["signer"] } : {}),
  };
}

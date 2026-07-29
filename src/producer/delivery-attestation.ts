import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { VERIFY_RESULT_DOMAIN } from "../protocol/vet.ts";
import {
  deliveryAssertionLogicalAddress,
  deliveryVerifyResultLogicalAddress,
  verifyDeliveryAttestation,
  type DeliveryAttestationExpectation,
} from "../consumer/delivery-attestation-verifier.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const DELIVERY_ASSERTION_DOMAIN = "dacs-delivery-assertion:v1:";
export { VERIFY_RESULT_DOMAIN } from "../protocol/vet.ts";

export interface SignedFixtureDeliveryAttestation {
  readonly assertion: Readonly<Record<string, unknown>>;
  readonly assertionArtifactHash: string;
  readonly assertionCanonicalJson: string;
  readonly assertionLogicalAddress: string;
  readonly verifyResult: Readonly<Record<string, unknown>>;
  readonly verifyResultArtifactHash: string;
  readonly verifyResultCanonicalJson: string;
  readonly verifyResultContentHash: string;
  readonly verifyResultLogicalAddress: string;
  readonly verifyResultRef: Readonly<Record<string, unknown>>;
}

export function signFixtureDeliveryAttestation(
  input: DeliveryAttestationExpectation & Readonly<{ readonly observedAt: number }>,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedFixtureDeliveryAttestation {
  assertFixtureSigningAuthority(signer, context);
  if (input.signer !== signer.signer || !Number.isSafeInteger(input.observedAt) || input.observedAt < 0) {
    throw new TypeError("Fixture delivery attestation signer or observedAt is invalid");
  }
  const assertionLogicalAddress = deliveryAssertionLogicalAddress(input.jobId, input.phaseIndex);
  const assertion = signArtifact({
    assertionVersion: "1",
    agreementHash: input.agreementHash,
    deliverableContentHash: input.deliverableContentHash,
    jobId: input.jobId,
    observedAt: input.observedAt,
    payloadFormat: input.payloadFormat,
    phaseIndex: input.phaseIndex,
    sessionBindingHash: input.sessionBindingHash,
  }, DELIVERY_ASSERTION_DOMAIN, signer, context);
  const verifyResultLogicalAddress = deliveryVerifyResultLogicalAddress(input.jobId, input.phaseIndex);
  const verifyResult = signArtifact({
    resultVersion: "1",
    scheme: "key",
    identifier: signer.signer.slice("key:".length),
    recipeVersion: 1,
    method: "self-signed",
    decision: "pass",
    reason: "fixture delivery assertion verified",
    attestation: {
      anchor: { kind: "storage-program", locator: assertionLogicalAddress },
      contentHash: assertion.artifactHash,
      signer: signer.signer,
    },
    data: {
      agreementHash: input.agreementHash,
      deliverableContentHash: input.deliverableContentHash,
      jobId: input.jobId,
      payloadFormat: input.payloadFormat,
      phaseIndex: input.phaseIndex,
      sessionBindingHash: input.sessionBindingHash,
    },
    fetchedAt: input.observedAt,
    verifiedAt: input.observedAt,
  }, VERIFY_RESULT_DOMAIN, signer, context);
  const verification = verifyDeliveryAttestation(assertion.canonicalJson, verifyResult.canonicalJson, {
    ...input,
    anchorContext: { mode: "pre-anchor" },
  });
  if (verification.disposition !== "provisionally-verified") {
    const reason = "reason" in verification ? verification.reason : verification.disposition;
    throw new TypeError(`Fixture DACS-2 delivery attestation failed independent verification: ${reason}`);
  }
  return Object.freeze({
    assertion: assertion.value,
    assertionArtifactHash: assertion.artifactHash,
    assertionCanonicalJson: assertion.canonicalJson,
    assertionLogicalAddress,
    verifyResult: verifyResult.value,
    verifyResultArtifactHash: verifyResult.artifactHash,
    verifyResultCanonicalJson: verifyResult.canonicalJson,
    verifyResultContentHash: verifyResult.contentHash,
    verifyResultLogicalAddress,
    verifyResultRef: deepFreezeJson({
      anchor: { kind: "storage-program", locator: verifyResultLogicalAddress },
      contentHash: verifyResult.contentHash,
      signer: signer.signer,
    }) as Readonly<Record<string, unknown>>,
  });
}

function signArtifact(
  unsigned: Readonly<Record<string, unknown>>,
  domain: string,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): Readonly<{
  value: Readonly<Record<string, unknown>>;
  canonicalJson: string;
  artifactHash: string;
  contentHash: string;
}> {
  const normalized = JSON.parse(canonicalize(unsigned)) as Record<string, unknown>;
  const semanticHash = sha256Hex(canonicalize(withoutFields(normalized, "signature")));
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${domain}${semanticHash}`), context),
    "standard-base64-padded",
    64,
  ));
  const value = deepFreezeJson({
    ...normalized,
    signature: { algorithm: "ed25519", signer: signer.signer, value: signature },
  }) as Readonly<Record<string, unknown>>;
  const canonicalJson = canonicalize(value);
  return Object.freeze({
    value,
    canonicalJson,
    artifactHash: sha256Hex(canonicalJson),
    contentHash: semanticHash,
  });
}

import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { canonicalize } from "../src/protocol/canonical-json.ts";
import { sha256Hex } from "../src/protocol/hash.ts";
import { signEvidenceBoundFaultAttestationBundleCopies } from "../src/producer/attestation-bundle.ts";
import { signSettlementEvidence } from "../src/producer/settlement-evidence.ts";
import { FIXTURE_SIGNING_CONTEXT, fixtureSigner } from "../test/fixtures/reference-listing.ts";
import {
  fixtureBundleAuthorityOptions,
  fixtureBundleSigners,
  fixtureReferenceResolver,
  fixtureUnsignedBundle,
} from "../test/fixtures/reference-bundle.ts";

const outputArg = process.argv.indexOf("--output");
if (outputArg < 0 || outputArg + 1 >= process.argv.length) {
  throw new TypeError("Usage: bun scripts/emit-evidence-bound-fault-bundle-fixture.ts --output <path>");
}

const base = fixtureUnsignedBundle();
const evidenceSigner = fixtureSigner();
const signedEvidence = signSettlementEvidence({
  evidenceVersion: "1",
  jobId: base.jobId,
  phase: "deliver-storage-program",
  outcome: "success",
  deliverableContentHash: "7".repeat(64),
  deliverableAnchor: { kind: "storage-program", locator: "stor:fixture-deliverable" },
  paymentAmount: { amount: "1", currency: "DEM" },
  observedAt: base.finalisedAt - 1,
}, evidenceSigner, {
  agreementHash: (base.agreementRef as Record<string, string>).contentHash!,
  deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
  deploymentMode: "fixture",
  evidenceMode: "fixture",
  expectedEvidenceLogicalAddress: `dacs4:delivery-evidence:${base.jobId}:3`,
  expectedJobId: base.jobId,
  expectedPaymentAmount: { amount: "1", currency: "DEM" },
  expectedPhase: "deliver-storage-program",
  expectedSessionBindingHash: "8".repeat(64),
  phaseIndex: 3,
  requestMode: "fixture",
});
const evidenceRef = {
  anchor: { kind: "storage-program", locator: signedEvidence.logicalAddress },
  contentHash: signedEvidence.evidenceHash,
  signer: signedEvidence.evidence.signature.signer,
} as const;
const { bundleVersion: _bundleVersion, outcome: _outcome, ...shared } = base;
const scope = {
  ...shared,
  evidenceBoundFaultBundleVersion: "1" as const,
  faultedParty: "none" as const,
  phaseSummary: [{
    index: 3,
    kind: "deliver-storage-program",
    outcome: "ok",
    attestationRef: evidenceRef,
  }],
  settlementEvidence: [evidenceRef],
};
const resolveReference = (ref: Readonly<Record<string, unknown>>, context: Parameters<typeof fixtureReferenceResolver>[1]) =>
  canonicalize(ref) === canonicalize(evidenceRef)
    ? {
      status: "verified" as const,
      artifactType: "phase-evidence" as const,
      anchorKind: evidenceRef.anchor.kind,
      anchorLocator: evidenceRef.anchor.locator,
      contentHash: evidenceRef.contentHash,
      jobId: base.jobId,
      phaseIndex: 3,
      phaseKind: "deliver-storage-program",
      evidenceOutcome: "success" as const,
      recordClass: "ordinary-terminal" as const,
      signer: evidenceSigner.signer,
    }
    : fixtureReferenceResolver(ref, context);
const signed = signEvidenceBoundFaultAttestationBundleCopies(
  scope,
  "completed",
  fixtureBundleSigners(),
  ["buyer", "seller"],
  FIXTURE_SIGNING_CONTEXT,
  resolveReference,
  {
    ...fixtureBundleAuthorityOptions,
    resolveExecutedPhasePlan: () => ({
      status: "verified" as const,
      railRegistryVersion: 1,
      recipeRegistryVersion: 1,
      phases: Object.freeze([{ index: 3, kind: "deliver-storage-program" }]),
    }),
  },
);
const copy = signed.copies.find((candidate) => candidate.anchoredByRole === "buyer")!;
const resolvedEvidenceByRef = {
  [canonicalize(evidenceRef)]: {
    artifactCanonicalJson: signedEvidence.canonicalJson,
    phaseKey: "3:deliver-storage-program",
  },
};
const publicKeys = Object.fromEntries(base.parties.map((party) => [
  party.primaryClaim,
  Buffer.from(party.primaryClaim.slice("key:".length), "hex").toString("base64url"),
]));
const fixture = {
  schemaVersion: 1,
  source: {
    candidateCommit: "2567c6c357d3fd28f75034b920258f2fd7da20d7",
    candidatePr: 290,
    releasedBase: "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
  },
  artifactCanonicalJson: copy.canonicalJson,
  artifactContentHash: copy.artifactContentHash,
  bundleHash: copy.bundleHash,
  expectedAnchoredByRole: copy.anchoredByRole,
  expectedJobId: base.jobId,
  expectedPhaseKeys: ["3:deliver-storage-program"],
  publicKeys,
  resolvedEvidenceByRef,
  unrelatedAuthorityDisposition: "verified",
};
const canonicalFixture = canonicalize(fixture);
const output = resolve(process.argv[outputArg + 1]!);
const outputDirectory = dirname(output);
await mkdir(outputDirectory, { recursive: true });
const temporaryDirectory = await mkdtemp(join(outputDirectory, `.${basename(output)}.`));
const temporaryOutput = join(temporaryDirectory, basename(output));
try {
  await writeFile(temporaryOutput, `${JSON.stringify({
  ...fixture,
  fixtureHash: sha256Hex(canonicalFixture),
  }, null, 2)}\n`, { mode: 0o644 });
  await rename(temporaryOutput, output);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

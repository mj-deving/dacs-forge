import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { withoutFields } from "../../src/protocol/canonical-json.ts";
import {
  EVIDENCE_BOUND_FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN,
  EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN,
  evaluateEvidenceBoundSettlementSet,
} from "../../src/protocol/evidence-bound-fault-bundle.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { verifyCanonicalAttestationBundleJson } from "../../src/consumer/attestation-bundle-verifier.ts";
import { encodeComponentSignatureValue, importLegacyComponentSignatureValue } from "../../src/protocol/component-signature-codec.ts";
import { resolveEvidenceBoundFaultBundleExtendedPointer } from "../../src/protocol/fault-attestation-bundle.ts";
import { signEvidenceBoundFaultAttestationBundleCopies } from "../../src/producer/attestation-bundle.ts";
import { FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";
import {
  fixtureBundleAuthorityOptions,
  fixtureBundleSigners,
  fixtureReferenceResolver,
  fixtureUnsignedBundle,
} from "../fixtures/reference-bundle.ts";

interface CandidateVectorSet {
  readonly artifactType: string;
  readonly count: number;
  readonly hash: string;
  readonly set: string;
  readonly vectors: readonly {
    readonly name: string;
    readonly input: Parameters<typeof evaluateEvidenceBoundSettlementSet>[0];
    readonly want: ReturnType<typeof evaluateEvidenceBoundSettlementSet>;
  }[];
}

const bytes = readFileSync(join(
  import.meta.dir,
  "../../vectors/dacs-standard-pr290/bundle-settlement-evidence-bijection-v0.4.json",
));
const set = JSON.parse(bytes.toString("utf8")) as CandidateVectorSet;

describe("DACS-5 PR #290 candidate — EvidenceBoundFaultAttestationBundle", () => {
  test("pins the exact candidate vector set and distinct signature domains", () => {
    expect(set.set).toBe("bundle-settlement-evidence-bijection-v0.4");
    expect(set.artifactType).toBe("EvidenceBoundFaultAttestationBundle");
    expect(set.vectors).toHaveLength(set.count);
    expect(sha256Hex(canonicalize(set.vectors))).toBe(set.hash);
    expect(EVIDENCE_BOUND_FAULT_ATTESTATION_BUNDLE_SIGNATURE_DOMAIN)
      .toBe("dacs-evidence-bound-fault-bundle:v1:");
    expect(EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN)
      .toBe("dacs-evidence-bound-fault-bundle-pointer:v1:");
  });

  for (const vector of set.vectors) {
    test(`${vector.name} -> ${vector.want.disposition}/${vector.want.reasonCode}`, () => {
      expect(evaluateEvidenceBoundSettlementSet(vector.input)).toEqual(vector.want);
    });
  }

  test("uses the distinct pointer domain and rejects fault-pointer replay", () => {
    const copy = candidateCopy();
    const buyer = fixtureBundleSigners()[0]!.signer;
    const unsignedPointer = {
      evidenceBoundFaultBundleVersion: "1",
      pointerKind: "extended",
      fullBundleUrl: "https://example.invalid/evidence-bound-bundle.json",
      fullBundleContentHash: copy.bundleHash,
    } as const;
    const pointerHash = sha256Hex(canonicalize(withoutFields(unsignedPointer, "signature")));
    const pointer = {
      ...unsignedPointer,
      signature: {
        algorithm: "ed25519",
        signer: buyer.signer,
        value: encodeComponentSignatureValue(importLegacyComponentSignatureValue(
          buyer.sign(
            new TextEncoder().encode(`${EVIDENCE_BOUND_FAULT_BUNDLE_POINTER_DOMAIN}${pointerHash}`),
            FIXTURE_SIGNING_CONTEXT,
          ),
          "standard-base64-padded",
          64,
        )),
      },
    };
    const binding = { signer: buyer.signer, bundleContentHash: copy.bundleHash };
    const keys = new Map([[buyer.signer, Uint8Array.from(Buffer.from(buyer.signer.slice(4), "hex"))]]);
    expect(resolveEvidenceBoundFaultBundleExtendedPointer(
      pointer,
      copy.artifact,
      binding,
      keys,
      () => ({ ok: true }),
    )).toMatchObject({ ok: true, recomputedHash: copy.bundleHash });
    const replay = structuredClone(pointer);
    replay.signature.value = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
      buyer.sign(new TextEncoder().encode(`dacs-fault-bundle-pointer:v1:${pointerHash}`), FIXTURE_SIGNING_CONTEXT),
      "standard-base64-padded",
      64,
    ));
    expect(resolveEvidenceBoundFaultBundleExtendedPointer(
      replay,
      copy.artifact,
      binding,
      keys,
      () => ({ ok: true }),
    )).toMatchObject({ ok: false, reason: "pointer signature does not verify" });
  });

  test("rejects an ST-8 record class that contradicts authenticated phase evidence", () => {
    const copy = candidateCopy();
    const staleRef = fixtureUnsignedBundle().settlementEvidence[0]!;
    const stale = verifyCanonicalAttestationBundleJson(copy.canonicalJson, {
      expectedAddress: copy.logicalAddress,
      ...fixtureBundleAuthorityOptions,
      resolveAttestationRef: (ref, context) => canonicalize(ref) === canonicalize(staleRef)
        ? {
          ...fixtureReferenceResolver(ref, context),
          recordClass: "st8-expired-interim-failure" as const,
          supersedingEvidenceRef: {
            anchor: { kind: "storage-program", locator: "dacs4:payment-evidence:resolved" },
            contentHash: "7".repeat(64),
          },
        }
        : fixtureReferenceResolver(ref, context),
    });
    expect(stale).toMatchObject({ disposition: "rejected", stage: "settlement-evidence" });
  });
});

function candidateCopy() {
  const base = fixtureUnsignedBundle();
  const { bundleVersion: _bundleVersion, outcome: _outcome, ...shared } = base;
  return signEvidenceBoundFaultAttestationBundleCopies(
    { ...shared, evidenceBoundFaultBundleVersion: "1", faultedParty: "none" },
    "completed",
    fixtureBundleSigners(),
    ["buyer", "seller"],
    FIXTURE_SIGNING_CONTEXT,
    fixtureReferenceResolver,
    fixtureBundleAuthorityOptions,
  ).copies[0]!;
}

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  BUNDLE_BINDING_DOMAIN,
  bundleBindingHash,
  verifyBundleBinding,
} from "../../src/protocol/bundle-binding.ts";
import {
  attestationBundleHash,
  impliedFaultSet,
  isFaultAttestationBundle,
  outcomeClass,
  resolveFaultBundleExtendedPointer,
  rosterRoles,
} from "../../src/protocol/fault-attestation-bundle.ts";
import {
  classifyBundleAddressRead,
  postFetchValid,
  resolveBundleBindingCandidates,
} from "../../src/consumer/bundle-binding-resolver.ts";
import {
  bundleCopiesDiverge,
  classifyBundlePair,
  scoredOutcome,
} from "../../src/consumer/bundle-consistency.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  fixtureBundleAuthorityOptions,
  fixtureUnsignedBundle,
  signUncheckedBundle,
} from "../fixtures/reference-bundle.ts";

const CORPUS_DIR = join(import.meta.dir, "../../vectors/dacs-standard-pr248");
const CORPUS_SHA256: Readonly<Record<string, string>> = Object.freeze({
  "bundle-binding-v0.1": "c0f7547e5dfea96232c3c761022ed194795a00bcf661e71f4ca807bec98f9461",
  "fab-bundle-extended-pointer-v0.3": "2481a26d95d47643c549bfdca5b381fb006dca2e92fec19f04e669d68906a70d",
  "fault-bundle-perspective-pair-v0.3": "f56586a27afa851202a121576814eb0a68bddc4bdc9ce675740ba085870ed285",
  "mixed-version-reconciliation-v0.3": "41c1bc7eee95ac3bf625eaea4db88929e2eb6cb20c6bade9c3192dc3337a9e0b",
  "outsider-binding-flooding-v0.3": "dc21789a945b07d377c99e295ba53e5bcabc7a3d944c36afcd219ec69d7ba97a",
  "receipt-rederivation-v0.3": "ec9d6b9714fdd5ac6a8aaf13320c44a1a8231f2876bd030031b1865a867d3373",
  "unresolved-vs-absent-v0.3": "8a543319798cb60073631a9a2431f45e866f89db8b136a76b679780718a15b91",
});

/**
 * Pinned DACS-Standard PR #248 development corpora, exactly as published at
 * origin/next 9a1ca624e8cc68361cff35c85a919cd72ba25199.
 *
 * Scope boundary (DACS Forge lane): the MANDATORY DACS-5 bundle-verification surface is
 * implemented and driven here. The OPTIONAL replayable-reputation publication surface
 * (§10.5 derive()/receipt replay) is deliberately NOT implemented — it stays unsupported,
 * ISC-35.5 stays open, and the corresponding vectors are recorded as unsupported rather
 * than silently passed.
 */
interface Corpus {
  readonly set: string;
  readonly count: number;
  readonly hash: string;
  readonly vectors: any[];
  readonly publicKeys?: Record<string, string>;
}

function corpus(name: string): Corpus {
  const bytes = readFileSync(join(CORPUS_DIR, `${name}.json`));
  const parsed = JSON.parse(bytes.toString("utf8")) as Corpus;
  // The receipt corpus intentionally carries JSON `0.0` values. JSON.parse collapses those
  // lexical forms to `0`, so only its stronger whole-file byte pin is rechecked here.
  const vectorDigestMatches = name === "receipt-rederivation-v0.3"
    || sha256Hex(canonicalize(parsed.vectors)) === parsed.hash;
  if (sha256Hex(bytes) !== CORPUS_SHA256[name] || !vectorDigestMatches) {
    throw new Error(`Pinned upstream corpus ${name} failed its byte or vector-set digest`);
  }
  return parsed;
}

function publicKeys(set: Corpus): Map<string, Uint8Array> {
  const keys = new Map<string, Uint8Array>();
  for (const [claim, value] of Object.entries(set.publicKeys ?? {})) {
    keys.set(claim, new Uint8Array(Buffer.from(value, "base64url")));
  }
  return keys;
}

describe("DACS-5 PR #248 — bundle-binding-v0.1 (BB-1..BB-8)", () => {
  const set = corpus("bundle-binding-v0.1");
  const keys = publicKeys(set);

  test("corpus is the pinned upstream set", () => {
    expect(set.set).toBe("bundle-binding-v0.1");
    expect(set.vectors.length).toBe(set.count);
  });

  for (const vector of set.vectors) {
    test(`${vector.name} → ${vector.expected}`, () => {
      const anchored = new Map<string, Record<string, unknown>>(
        Object.entries(vector.anchored ?? {}) as [string, Record<string, unknown>][],
      );
      const result = resolveBundleBindingCandidates({
        jobId: vector.request.jobId,
        role: vector.request.role,
        bindings: vector.bindings ?? [],
        anchored,
        publicKeys: keys,
        partyMap: vector.partyMap ?? undefined,
      });

      if (vector.expected === "pass") {
        expect(result.disposition).toBe("present");
        if (vector.want?.resolvedNativeAddress !== undefined) {
          expect(result.resolvedNativeAddress).toBe(vector.want.resolvedNativeAddress);
        }
      } else if (vector.expected === "indeterminate") {
        expect(result.disposition).toBe("indeterminate");
        expect(result.resolvedNativeAddress).toBeNull();
      } else {
        // `fail`: the binding is present but invalid — the side must never resolve to a
        // copy, and rejected content is never absence (BB-7).
        expect(result.disposition).not.toBe("present");
        expect(result.resolvedNativeAddress).toBeNull();
      }
      if (vector.want?.exhaustedSigners !== undefined) {
        expect(result.exhaustedSigners).toEqual(vector.want.exhaustedSigners);
      }
      if (vector.want?.fetched !== undefined) expect(result.fetched).toHaveLength(vector.want.fetched);
    });
  }

  test("BB-4 binding signature is verified over the binding domain", () => {
    const valid = set.vectors.find((v: any) => v.name === "bb-valid-resolution");
    const binding = valid.bindings[0];
    expect(BUNDLE_BINDING_DOMAIN).toBe("dacs-bundle-binding:v1:");
    expect(bundleBindingHash(binding)).toMatch(/^[0-9a-f]{64}$/);
    const check = verifyBundleBinding(binding, {
      expectedJobId: valid.request.jobId,
      expectedRole: valid.request.role,
      publicKeys: keys,
    });
    expect(check.ok).toBe(true);
    expect(verifyBundleBinding(binding, {
      expectedJobId: valid.request.jobId,
      expectedRole: valid.request.role,
    } as any).ok).toBe(false);
  });

  test("BB-6 budgets distinct native addresses, not duplicate discovery entries", () => {
    const valid = set.vectors.find((v: any) => v.name === "bb-valid-resolution");
    const binding = valid.bindings[0];
    const result = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: Array.from({ length: 9 }, () => binding),
      anchored: new Map(Object.entries(valid.anchored)),
      publicKeys: keys,
      partyMap: valid.partyMap,
    });
    expect(result).toMatchObject({ disposition: "present", exhaustedSigners: [] });
    expect(result.fetched).toEqual([binding.nativeAddress]);
  });

  test("BB-7 forbids recomputing a native address from the logical form", () => {
    const valid = set.vectors.find((v: any) => v.name === "bb-valid-resolution");
    const binding = valid.bindings[0];
    // The native address is write-input derived (40 hex) and is NOT the logical form (64 hex).
    expect(binding.nativeAddress).not.toBe(binding.logicalAddress);
    expect(binding.nativeAddress).toMatch(/^stor-[0-9a-f]{40}$/);
    expect(binding.logicalAddress).toMatch(/^stor-[0-9a-f]{64}$/);
  });

  test("authenticated party maps reject reverse role-holder substitution", () => {
    const valid = set.vectors.find((v: any) => v.name === "bb-valid-resolution");
    const result = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: valid.bindings,
      anchored: new Map(Object.entries(valid.anchored)),
      publicKeys: keys,
      partyMap: {
        "did:demos:authenticated-buyer": "buyer",
        "did:demos:seller": "seller",
      },
    });
    expect(result.disposition).toBe("indeterminate");
    expect(result.resolvedNativeAddress).toBeNull();
  });

  test("authenticated party maps reject an omitted mapped role", () => {
    const valid = set.vectors.find((v: any) => v.name === "bb-valid-resolution");
    const result = resolveBundleBindingCandidates({
      jobId: valid.request.jobId,
      role: valid.request.role,
      bindings: valid.bindings,
      anchored: new Map(Object.entries(valid.anchored)),
      publicKeys: keys,
      partyMap: {
        "did:demos:seller": "seller",
        "did:demos:authenticated-orchestrator": "orchestrator",
      },
    });
    expect(result.disposition).toBe("indeterminate");
    expect(result.resolvedNativeAddress).toBeNull();
  });

  test("BB-5 rejects signed copies with unsupported outcomes or missing envelope references", () => {
    const admit = (candidate: Record<string, unknown>) => {
      const copy = JSON.parse(signUncheckedBundle(
        candidate as ReturnType<typeof fixtureUnsignedBundle>,
        ["buyer", "seller"],
        "buyer",
      )) as Record<string, unknown>;
      const parties = copy["parties"] as Record<string, unknown>[];
      const fixtureKeys = new Map<string, Uint8Array>();
      for (const party of parties) {
        const resolved = fixtureBundleAuthorityOptions.resolvePartyIdentity(party);
        if (resolved.status === "verified") fixtureKeys.set(resolved.primaryClaim, resolved.publicKey);
      }
      return postFetchValid(copy, {
        jobId: copy["jobId"],
        role: "buyer",
        bundleContentHash: attestationBundleHash(copy),
      }, fixtureKeys);
    };

    expect(admit({ ...fixtureUnsignedBundle(), outcome: "invented-terminal" }).ok).toBe(false);
    const missingListing = { ...fixtureUnsignedBundle() } as Record<string, unknown>;
    delete missingListing["listingRef"];
    expect(admit(missingListing).ok).toBe(false);
    const missingSettlement = { ...fixtureUnsignedBundle() } as Record<string, unknown>;
    delete missingSettlement["settlementEvidence"];
    expect(admit(missingSettlement).ok).toBe(false);
    expect(admit({ ...fixtureUnsignedBundle(), agreementRef: null }).ok).toBe(false);
    expect(admit({ ...fixtureUnsignedBundle(), settlementEvidence: [null] }).ok).toBe(false);
    expect(admit({
      ...fixtureUnsignedBundle(),
      agreementRef: {
        kind: "dacs-3-agreement",
        id: "synthetic",
        contentHash: "2".repeat(64),
        anchor: null,
      },
    }).ok).toBe(false);
    expect(admit({
      ...fixtureUnsignedBundle(),
      agreementRef: {
        kind: "dacs-3-agreement",
        id: "synthetic",
        contentHash: "2".repeat(64),
        signer: 7,
      },
    }).ok).toBe(false);

    const sameHolder = fixtureUnsignedBundle();
    const sellerClaim = sameHolder.parties.find((party) => party.role === "seller")!.primaryClaim;
    const duplicateRoles = {
      ...sameHolder,
      parties: sameHolder.parties.map((party) => ({ ...party, primaryClaim: sellerClaim })),
    };
    const oneSignature = JSON.parse(signUncheckedBundle(
      duplicateRoles,
      ["seller"],
      "seller",
    )) as Record<string, unknown>;
    const sellerAuthority = fixtureBundleAuthorityOptions.resolvePartyIdentity(
      (oneSignature["parties"] as Record<string, unknown>[])[1]!,
    );
    expect(postFetchValid(oneSignature, {
      jobId: oneSignature["jobId"],
      role: "seller",
      signer: sellerClaim,
      bundleContentHash: attestationBundleHash(oneSignature),
    }, new Map(sellerAuthority.status === "verified"
      ? [[sellerAuthority.primaryClaim, sellerAuthority.publicKey]] : [])).ok).toBe(false);
  });
});

describe("DACS-5 PR #248 — outsider-binding-flooding-v0.3 (BB-6 authorization, BB-7 exhaustion)", () => {
  const set = corpus("outsider-binding-flooding-v0.3");
  const keys = publicKeys(set);

  for (const vector of set.vectors) {
    test(`${vector.name} → ${vector.expected}`, () => {
      const anchored = new Map<string, Record<string, unknown>>(
        Object.entries(vector.anchored ?? {}) as [string, Record<string, unknown>][],
      );
      const result = resolveBundleBindingCandidates({
        jobId: vector.request.jobId,
        role: vector.request.role,
        bindings: vector.bindings ?? [],
        anchored,
        publicKeys: keys,
        partyMap: vector.partyMap ?? undefined,
      });

      if (vector.expected === "pass") {
        expect(result.disposition).toBe("present");
        if (vector.want?.resolvedNativeAddress !== undefined) {
          expect(result.resolvedNativeAddress).toBe(vector.want.resolvedNativeAddress);
        }
      } else {
        expect(result.disposition).toBe("indeterminate");
        expect(result.resolvedNativeAddress).toBeNull();
      }
      // BB-7: an exhaustion or void disposition is never promoted to absence.
      expect(result.disposition).not.toBe("absent");
      expect(result.exhaustedSigners).toEqual(vector.want.exhaustedSigners);
      if (vector.want.fetched !== undefined) expect(result.fetched).toHaveLength(vector.want.fetched);
    });
  }
});

describe("DACS-5 PR #248 — unresolved-vs-absent-v0.3 (BB-8 one-sided gate)", () => {
  const set = corpus("unresolved-vs-absent-v0.3");
  const bindingSet = corpus("bundle-binding-v0.1");
  const validBinding = bindingSet.vectors.find((v: any) => v.name === "bb-valid-resolution");

  const resolved = () => resolveBundleBindingCandidates({
    jobId: validBinding.request.jobId,
    role: validBinding.request.role,
    bindings: validBinding.bindings,
    anchored: new Map(Object.entries(validBinding.anchored)),
    publicKeys: publicKeys(bindingSet),
    partyMap: validBinding.partyMap,
  });
  const unresolved = () => resolveBundleBindingCandidates({
    jobId: validBinding.request.jobId,
    role: validBinding.request.role,
    bindings: [],
    publicKeys: publicKeys(bindingSet),
  });

  for (const vector of set.vectors) {
    test(`${vector.name} → ${vector.want.readDisposition}`, () => {
      const resolution = vector.binding.resolved ? resolved() : unresolved();
      const vectorRead = vector.reads[vector.scoredRole];
      const read = classifyBundleAddressRead({
        resolution,
        read: {
          ...vectorRead,
          nativeAddress: resolution.resolvedNativeAddress,
        },
        absenceEvidencePolicy: vector.binding.absenceEvidencePolicy,
        verifyAuthoritativeAbsence: ({ nativeAddress, policy, read: evidence }) =>
          nativeAddress === resolution.resolvedNativeAddress
          && evidence["authenticated"] === true
          && evidence["finalizedState"] === policy["finalityRule"]
          && ["authentication", "independence", "threshold", "freshness", "stateConsistency"]
            .every((field) => typeof policy[field] === "string" && policy[field].length > 0),
      });
      expect(read.disposition).toBe(vector.want.readDisposition);
      expect(read.oneSidedReachable).toBe(vector.want.oneSidedReachable);
    });
  }

  test("rejects a caller-forged resolved marker even with asserted absence flags", () => {
    expect(classifyBundleAddressRead({
      resolution: {
        disposition: "present",
        resolvedNativeAddress: "stor-forged",
        fetched: [],
        authorizedSigners: [],
        exhaustedSigners: [],
        reason: "caller assertion",
      },
      read: {
        nativeAddress: "stor-forged",
        response: "authoritative-absent",
        authenticated: true,
      },
      absenceEvidencePolicy: {
        finalityRule: "finalized-head",
        authentication: "signed-response",
        independence: "distinct-endpoints",
        threshold: "2-of-3",
        freshness: "<=finality",
        stateConsistency: "single-view",
      },
      verifyAuthoritativeAbsence: () => true,
    })).toMatchObject({ disposition: "indeterminate", oneSidedReachable: false });
  });
});

describe("DACS-5 PR #248 — fab-bundle-extended-pointer-v0.3 (triple identity)", () => {
  const set = corpus("fab-bundle-extended-pointer-v0.3");

  for (const vector of set.vectors) {
    test(`${vector.name} → ${vector.expected}`, () => {
      const result = resolveFaultBundleExtendedPointer(
        vector.pointer,
        vector.dereferenced,
        vector.binding,
        publicKeys(set),
        postFetchValid,
      );
      expect(result.ok).toBe(vector.expected === "pass");
      if (vector.expected === "pass") {
        expect(result.recomputedHash).toBe(vector.pointer.fullBundleContentHash);
      }
    });
  }

  test("rejects a pointer whose signature no longer authenticates its pointer scope", () => {
    const vector = set.vectors.find((v: any) => v.name === "fab-pointer-valid");
    const pointer = structuredClone(vector.pointer);
    pointer.signature.value = `${pointer.signature.value.slice(0, -1)}A`;
    expect(resolveFaultBundleExtendedPointer(
      pointer,
      vector.dereferenced,
      vector.binding,
      publicKeys(set),
      postFetchValid,
    ).ok).toBe(false);
  });

  test("fails closed when an untrusted pointer is not canonically hashable", () => {
    const vector = set.vectors.find((v: any) => v.name === "fab-pointer-valid");
    const pointer = structuredClone(vector.pointer);
    pointer.nonJson = 1n;
    expect(() => resolveFaultBundleExtendedPointer(
      pointer,
      vector.dereferenced,
      vector.binding,
      publicKeys(set),
      postFetchValid,
    )).not.toThrow();
    expect(resolveFaultBundleExtendedPointer(
      pointer,
      vector.dereferenced,
      vector.binding,
      publicKeys(set),
      postFetchValid,
    )).toEqual({
      ok: false,
      reason: "pointer signing scope is not canonically hashable",
      recomputedHash: null,
    });
  });

  test("resolves a valid extended pointer through the actual BB-6 pipeline", () => {
    const vector = set.vectors.find((v: any) => v.name === "fab-pointer-valid");
    const result = resolveBundleBindingCandidates({
      jobId: vector.binding.jobId,
      role: vector.binding.role,
      bindings: [vector.binding],
      anchored: new Map([[vector.binding.nativeAddress, vector.pointer]]),
      dereferenced: new Map([[vector.pointer.fullBundleUrl, vector.dereferenced]]),
      publicKeys: publicKeys(set),
      partyMap: { [vector.binding.signer]: vector.binding.role },
    });
    expect(result).toMatchObject({
      disposition: "present",
      resolvedNativeAddress: vector.binding.nativeAddress,
    });
  });
});

describe("DACS-5 PR #248 — fault-bundle-perspective-pair-v0.3", () => {
  const set = corpus("fault-bundle-perspective-pair-v0.3");

  for (const vector of set.vectors) {
    test(`${vector.name} → ${vector.expected}`, () => {
      const buyer = vector.copies.buyer;
      const seller = vector.copies.seller;

      if (buyer === undefined || seller === undefined) {
        // A single-copy vector is a COPY-level rejection, not a pair classification: the
        // §10.4.1 permissible set alone must reject it before any pair rule runs.
        const only = buyer ?? seller;
        expect(vector.expected).toBe("fail");
        const permitted = impliedFaultSet(only.outcome, only.anchoredByRole, rosterRoles(only));
        expect(permitted.has(only.faultedParty)).toBe(false);
        if (vector.want?.faultedPartyPermissible !== undefined) {
          expect([...permitted].sort()).toEqual(vector.want.faultedPartyPermissible);
        }
        return;
      }

      const pair = classifyBundlePair(buyer, seller);

      if (vector.expected === "pass") {
        expect(pair.convergence).toBe("unified");
        expect(bundleCopiesDiverge(buyer, seller)).toBe(false);
        if (vector.want?.faultedParty !== undefined) {
          expect(pair.faultedParty).toBe(vector.want.faultedParty);
        }
      } else {
        // Either the pair diverges, or a copy is rejected outright for an
        // out-of-set faultedParty (§10.4.1 permissible set).
        const buyerSetOk = !isFaultAttestationBundle(buyer)
          || impliedFaultSet(buyer.outcome, buyer.anchoredByRole, rosterRoles(buyer)).has(buyer.faultedParty);
        const sellerSetOk = !isFaultAttestationBundle(seller)
          || impliedFaultSet(seller.outcome, seller.anchoredByRole, rosterRoles(seller)).has(seller.faultedParty);
        const rejected = !buyerSetOk || !sellerSetOk;
        expect(rejected || pair.convergence === "divergent").toBe(true);
      }
    });
  }
});

describe("DACS-5 PR #248 — mixed-version-reconciliation-v0.3", () => {
  const set = corpus("mixed-version-reconciliation-v0.3");

  for (const vector of set.vectors) {
    test(`${vector.name} → ${vector.expected}`, () => {
      const [a, b] = Object.values(vector.copies) as [any, any];
      const pair = classifyBundlePair(a, b);

      if (vector.expected === "pass") {
        expect(pair.convergence).toBe("unified");
        if (vector.want?.authoritativeCopyType !== undefined) {
          expect(pair.authoritativeCopyType).toBe(vector.want.authoritativeCopyType);
        }
        if (vector.want?.scoredOutcome !== undefined && vector.want?.scoredRole !== undefined) {
          expect(scoredOutcome(pair.authoritativeCopy, vector.want.scoredRole)).toBe(
            vector.want.scoredOutcome,
          );
        }
      } else {
        expect(pair.convergence).toBe("divergent");
        expect(bundleCopiesDiverge(a, b)).toBe(true);
      }
    });
  }

  test("outcome classes are read on the class, not the role-relative spelling", () => {
    expect(outcomeClass("aborted-by-self")).toBe("abort");
    expect(outcomeClass("aborted-by-other")).toBe("abort");
    expect(outcomeClass("failed-perm")).toBe("failure");
    expect(outcomeClass("failed-counterparty")).toBe("failure");
    expect(outcomeClass("completed")).toBe("completed");
    expect(outcomeClass("failed-substrate")).toBe("failed-substrate");
  });
});

describe("DACS-5 PR #248 — receipt-rederivation-v0.3 (unsupported optional surface)", () => {
  const set = corpus("receipt-rederivation-v0.3");

  test("corpus is the pinned upstream set", () => {
    expect(set.set).toBe("receipt-rederivation-v0.3");
    expect(set.vectors.length).toBe(set.count);
  });

  test("optional replayable-reputation publication is unsupported and fails closed", async () => {
    // The lane exposes no replayable-derivation publication entry point at all. This is the
    // ISC-A6 boundary: absence of the surface, not a permissive stub that could be mistaken
    // for one.
    const consistency: Record<string, unknown> = await import(
      "../../src/consumer/bundle-consistency.ts"
    );
    for (const symbol of [
      "deriveReplayableReputation",
      "publishReplayableDerivation",
      "replayReceipt",
      "buildResolutionContext",
    ]) {
      expect(consistency[symbol]).toBeUndefined();
    }
    expect(set.vectors).toHaveLength(set.count);
  });
});

describe("DACS-5 PR #248 — §10.4.1 shared hash identity", () => {
  test("attestation_bundle_hash omits signatures and anchoredByRole for both bundle types", () => {
    const set = corpus("bundle-binding-v0.1");
    const vector = set.vectors.find((v: any) => v.name === "bb-valid-resolution");
    const anchored = Object.values(vector.anchored)[0] as Record<string, unknown>;
    expect(attestationBundleHash(anchored)).toBe(vector.bindings[0].bundleContentHash);
    expect(isFaultAttestationBundle(anchored)).toBe(true);
  });
});

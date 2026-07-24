import { describe, expect, test } from "bun:test";
import { verifySessionIdentityPresentation } from "../../src/consumer/identity-presentation-verifier.ts";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import { fixtureSigner, FIXTURE_NOW_MS, FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";
import { consumerCanonicalize } from "../../src/consumer/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";

const NONCE = "0123456789abcdef0123456789abcdef";
const JOB_ID = "01J00000000000000000000000";

function authority(jobId = JOB_ID, nonce = NONCE) {
  let consumed = false;
  return {
    consumeMatching: (attempt: { readonly jobId: string; readonly presentedNonce: string | null }) => {
      if (consumed) return { disposition: "rejected" as const, reason: "consumed challenge" };
      if (attempt.jobId !== jobId || attempt.presentedNonce !== nonce) {
        return { disposition: "rejected" as const, reason: "cross-session or nonce mismatch" };
      }
      consumed = true;
      return { disposition: "accepted" as const };
    },
  };
}

describe("per-claim IdentityBundle session binding", () => {
  test("accepts only the verifier-issued nonce signed into this bundle", () => {
    const signer = fixtureSigner();
    const signed = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: NONCE,
      claims: [{ ref: signer.signer }],
    }, signer, FIXTURE_SIGNING_CONTEXT).bundle;
    expect(verifySessionIdentityPresentation(signed, {
      jobId: JOB_ID,
      nonceAuthority: authority(),
    })).toMatchObject({ disposition: "accepted", kind: "per-claim" });

    const missing = structuredClone(signed) as Record<string, unknown>;
    delete missing["sessionNonce"];
    expect(verifySessionIdentityPresentation(missing, {
      jobId: JOB_ID,
      nonceAuthority: authority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("mismatch") });

    const mutated = structuredClone(signed) as Record<string, unknown>;
    mutated["sessionNonce"] = "f".repeat(32);
    const mismatchAuthority = authority();
    expect(verifySessionIdentityPresentation(mutated, {
      jobId: JOB_ID,
      nonceAuthority: mismatchAuthority,
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("mismatch") });
    expect(verifySessionIdentityPresentation(signed, {
      jobId: JOB_ID,
      nonceAuthority: mismatchAuthority,
    })).toMatchObject({ disposition: "accepted" });

    expect(verifySessionIdentityPresentation(signed, {
      jobId: "01J00000000000000000000001",
      nonceAuthority: authority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("cross-session") });
  });

  test("rejects unsigned claims appended to an otherwise valid per-claim bundle", () => {
    const signer = fixtureSigner();
    const signed = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: NONCE,
      claims: [{ ref: signer.signer }],
    }, signer, FIXTURE_SIGNING_CONTEXT).bundle;
    const injected = structuredClone(signed) as Record<string, unknown>;
    (injected["claims"] as Record<string, unknown>[]).push({ ref: `key:${"b".repeat(64)}` });
    expect(verifySessionIdentityPresentation(injected, {
      jobId: JOB_ID,
      nonceAuthority: authority(),
    })).toMatchObject({ disposition: "rejected" });
  });

  test("rejects a noncanonical claim even when its canonical identity signs", () => {
    const signer = fixtureSigner();
    const noncanonical = `key:${signer.signer.slice(4).toUpperCase()}`;
    const unsigned = {
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: FIXTURE_NOW_MS,
      sessionNonce: NONCE,
      claims: [{ ref: noncanonical }],
    };
    const hash = sha256Hex(consumerCanonicalize(unsigned));
    const bundle = {
      ...unsigned,
      presentation: {
        kind: "per-claim",
        signatures: [{
          ref: signer.signer,
          signature: signer.sign(
            new TextEncoder().encode(`dacs-bundle-presentation:v1:${hash}`),
            FIXTURE_SIGNING_CONTEXT,
          ),
        }],
      },
    };
    expect(verifySessionIdentityPresentation(bundle, {
      jobId: JOB_ID,
      nonceAuthority: authority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("canonical") });
  });
});

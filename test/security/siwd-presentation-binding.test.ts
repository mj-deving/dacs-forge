import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { verifySessionIdentityPresentation } from "../../src/consumer/identity-presentation-verifier.ts";
import { consumerCanonicalize } from "../../src/consumer/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { createFixtureEd25519Signer, type ArtifactSigner } from "../../src/producer/fixture-ed25519.ts";
import { fixtureSigner, FIXTURE_NOW_MS, FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";

const NONCE = "0123456789abcdef0123456789abcdef";
const JOB_ID = "01J00000000000000000000000";

function nonceAuthority(jobId = JOB_ID) {
  return {
    consumeMatching: (attempt: { readonly jobId: string; readonly presentedNonce: string | null }) =>
      attempt.jobId === jobId && attempt.presentedNonce === NONCE
        ? { disposition: "accepted" as const }
        : { disposition: "rejected" as const, reason: "cross-session or nonce mismatch" },
  };
}

function delegatedSessionSigner(): ArtifactSigner {
  return createFixtureEd25519Signer(
    createHash("sha256").update("reference-dacs-template-session-key-v1").digest(),
    { deploymentMode: "fixture", authorityMode: "fixture" },
  );
}

function sessionKeyBundle(rootBindingSigner: ArtifactSigner = fixtureSigner()) {
  const rootSigner = fixtureSigner();
  const sessionSigner = delegatedSessionSigner();
  const unsigned = {
    bundleVersion: "1",
    presentedBy: rootSigner.signer,
    presentedAt: FIXTURE_NOW_MS,
    sessionNonce: NONCE,
    claims: [{ ref: rootSigner.signer }],
  };
  const hash = sha256Hex(consumerCanonicalize(unsigned));
  return {
    ...unsigned,
    presentation: {
      kind: "session-key",
      key: sessionSigner.signer,
      signature: sessionSigner.sign(
        new TextEncoder().encode(`dacs-bundle-presentation:v1:${hash}`),
        FIXTURE_SIGNING_CONTEXT,
      ),
      rootBinding: rootBindingSigner.sign(
        new TextEncoder().encode(`dacs-session-binding:v1:${sessionSigner.signer}${hash}`),
        FIXTURE_SIGNING_CONTEXT,
      ),
    },
  };
}

function siwdBundle(overrides: { readonly nonce?: string; readonly resource?: string } = {}) {
  const signer = fixtureSigner();
  const unsigned = {
    bundleVersion: "1",
    presentedBy: signer.signer,
    presentedAt: FIXTURE_NOW_MS,
    claims: [{ ref: signer.signer }],
  };
  const hash = sha256Hex(consumerCanonicalize(unsigned));
  const signedBytes = `dacs-bundle-presentation:v1:${hash}`;
  const resource = overrides.resource ?? `dacs:${Buffer.from(signedBytes).toString("hex")}`;
  return {
    ...unsigned,
    presentation: {
      kind: "siwd",
      message: `service.example wants you to sign in\nURI: https://service.example/login\nNonce: ${overrides.nonce ?? NONCE}\nResources:\n- ${resource}`,
      signature: "fixture-siwd-signature",
      address: "demos-wallet-fixture",
    },
  };
}

const siwdAuthority = {
  verifySignature: ({ signature }: { readonly signature: string }) => signature === "fixture-siwd-signature",
  controlsPresentedBy: ({ presentedBy }: { readonly presentedBy: string }) => presentedBy === fixtureSigner().signer,
};

describe("session-key and SIWD presentation binding", () => {
  test("binds session-key signatures to the exact verifier nonce", () => {
    const bundle = sessionKeyBundle();
    expect(verifySessionIdentityPresentation(bundle, {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
    })).toMatchObject({ disposition: "accepted", kind: "session-key" });

    expect(verifySessionIdentityPresentation(sessionKeyBundle(delegatedSessionSigner()), {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("Session-key") });
    expect(verifySessionIdentityPresentation({ ...bundle, sessionNonce: "f".repeat(32) }, {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("nonce") });

    const attacker = fixtureSigner();
    const unbound = structuredClone(bundle) as Record<string, unknown>;
    const presentation = unbound["presentation"] as Record<string, unknown>;
    presentation["rootBinding"] = attacker.sign(
      new TextEncoder().encode("not-the-session-binding"),
      FIXTURE_SIGNING_CONTEXT,
    );
    expect(verifySessionIdentityPresentation(unbound, {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("Session-key") });

    const noncanonical = structuredClone(bundle) as Record<string, unknown>;
    const noncanonicalPresentation = noncanonical["presentation"] as Record<string, unknown>;
    const rawKey = `key:${fixtureSigner().signer.slice(4).toUpperCase()}`;
    const hash = sha256Hex(consumerCanonicalize({
      bundleVersion: noncanonical["bundleVersion"],
      presentedBy: noncanonical["presentedBy"],
      presentedAt: noncanonical["presentedAt"],
      sessionNonce: noncanonical["sessionNonce"],
      claims: noncanonical["claims"],
    }));
    noncanonicalPresentation["key"] = rawKey;
    noncanonicalPresentation["rootBinding"] = fixtureSigner().sign(
      new TextEncoder().encode(`dacs-session-binding:v1:${rawKey}${hash}`),
      FIXTURE_SIGNING_CONTEXT,
    );
    expect(verifySessionIdentityPresentation(noncanonical, {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("Session-key") });
  });

  test("requires exact SIWD Nonce, DACS Resource, wallet signature, and job-bound challenge", () => {
    expect(verifySessionIdentityPresentation(siwdBundle(), {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
      siwdAuthority,
      siwdAudience: { domain: "service.example", uri: "https://service.example/login" },
    })).toMatchObject({ disposition: "accepted", kind: "siwd" });

    expect(verifySessionIdentityPresentation(siwdBundle({ nonce: "f".repeat(32) }), {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
      siwdAuthority,
      siwdAudience: { domain: "service.example", uri: "https://service.example/login" },
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("nonce") });

    expect(verifySessionIdentityPresentation(siwdBundle({ resource: `dacs:${"00".repeat(64)}` }), {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
      siwdAuthority,
      siwdAudience: { domain: "service.example", uri: "https://service.example/login" },
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("Resources") });

    expect(verifySessionIdentityPresentation(siwdBundle(), {
      jobId: "01J00000000000000000000001",
      nonceAuthority: nonceAuthority(),
      siwdAuthority,
      siwdAudience: { domain: "service.example", uri: "https://service.example/login" },
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("cross-session") });

    expect(verifySessionIdentityPresentation(siwdBundle(), {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
      siwdAuthority,
      siwdAudience: { domain: "attacker.example", uri: "https://service.example/login" },
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("audience") });

    const injected = structuredClone(siwdBundle()) as Record<string, unknown>;
    (injected["claims"] as Record<string, unknown>[]).push({ ref: `key:${"b".repeat(64)}` });
    expect(verifySessionIdentityPresentation(injected, {
      jobId: JOB_ID,
      nonceAuthority: nonceAuthority(),
      siwdAuthority,
      siwdAudience: { domain: "service.example", uri: "https://service.example/login" },
    })).toMatchObject({ disposition: "rejected", reason: expect.stringContaining("primary claim") });
  });
});

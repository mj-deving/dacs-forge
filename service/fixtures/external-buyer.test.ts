import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fixtureSigner } from "../../test/fixtures/reference-listing.ts";
import { orchestratorFixtureSigner } from "../../test/fixtures/reference-bundle.ts";
import { handler } from "../handler.ts";
import { BASIC_FIXTURE } from "./basic.ts";
import { serviceContract } from "../service.config.ts";
import { ServiceRuntime, serviceRequestHash } from "../../src/service/runtime.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  SessionStore,
  sessionBindingHash,
} from "../../src/substrate/sqlite/session-store.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { signPerClaimIdentityBundle } from "../../src/producer/identity-bundle.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  createExternalBuyerHarness,
  createExternalBuyerServiceRunner,
  verifyBuyerPrincipalProof,
  verifyBuyerSessionAuthorization,
  type BuyerAuthorizationExpectation,
} from "./external-buyer.ts";

const AGREEMENT_HASH = "a".repeat(64);
const AUTHORIZED_AT = "2026-07-17T08:00:00.000Z";
const NOW_MS = Date.parse(AUTHORIZED_AT);
const INSTANCE_ID = "attested-public-data-fixture";
const AUDIENCE = "https://service.example/attested-public-data/v1";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("self-custodied external buyer harness", () => {
  test("binds distinct buyer signing to the exact admitted job and session before handler execution", async () => {
    const requestHash = serviceRequestHash(serviceContract, BASIC_FIXTURE.input, BASIC_FIXTURE.seed);
    const buyer = externalBuyer(requestHash);
    const seller = fixtureSigner().signer;
    const orchestrator = orchestratorFixtureSigner().signer;
    const directory = await mkdtemp(join(tmpdir(), "dacs-attested-public-data-buyer-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    const sessions = new SessionStore(database, {
      audience: AUDIENCE,
      authenticator: {
        verify: ({ principal, proof, signedBytes }) =>
          principal.canonicalReference === buyer.primaryClaim
          && verifyBuyerPrincipalProof(signedBytes, proof, buyer.primaryClaim),
      },
      deploymentMode: "fixture",
      instanceId: INSTANCE_ID,
      jobAuthorizer: {
        authorize: ({ principalIdentity }) => principalIdentity.canonicalReference === buyer.primaryClaim,
      },
      now: () => NOW_MS,
      randomBytes: () => Buffer.alloc(16, 7),
    });
    const signedChallenge = buyer.createChallengeAllocation({
      clientNonce: "1".repeat(32),
      idempotencyKey: "attested-public-data-request",
      requestedAtMs: NOW_MS,
    });
    const allocation = sessions.allocateChallenge(signedChallenge);
    expect(allocation.disposition).toBe("created");
    if (allocation.disposition !== "created") throw new Error("Buyer challenge was not allocated");
    const signedAdmission = buyer.createAdmission({
      nonce: allocation.challenge.nonce,
      idempotencyKey: "attested-public-data-request",
    });
    const admitted = sessions.admit(signedAdmission);
    expect(admitted.disposition).toBe("created");
    if (admitted.disposition !== "created") throw new Error("Buyer session was not admitted");

    const expected: BuyerAuthorizationExpectation = {
      buyer: buyer.primaryClaim,
      seller,
      orchestrator,
      jobId: BASIC_FIXTURE.jobId,
      agreementHash: AGREEMENT_HASH,
      sessionBindingHash: sessionBindingHash(admitted.session),
      phaseIndex: 2,
      railId: "fixture:no-spend",
      authorizedAt: AUTHORIZED_AT,
    };
    const authorization = buyer.authorize(expected);
    expect(buyer.primaryClaim).not.toBe(seller);
    expect(buyer.primaryClaim).not.toBe(orchestrator);
    expect(verifyBuyerSessionAuthorization(authorization.canonicalJson, expected)).toBe(true);

    let handlerCalls = 0;
    const runtime = new ServiceRuntime({
      artifactStore: new ArtifactStore(database),
      contract: {
        ...serviceContract,
        handler: (input, context) => {
          handlerCalls += 1;
          return handler(input, context);
        },
      },
      deploymentMode: "fixture",
      now: () => AUTHORIZED_AT,
      sessionStore: sessions,
      signer: fixtureSigner(),
    });
    const runner = createExternalBuyerServiceRunner({
      authority: { get: (jobId) => jobId === expected.jobId ? expected : null },
      runtime,
      sessions: {
        get: (jobId) => {
          const session = sessions.get(jobId);
          const principal = database.query<{
            principalScheme: string; principalIdentifier: string;
          }, { jobId: string }>(`
            SELECT principal_scheme AS principalScheme, principal_identifier AS principalIdentifier
            FROM admission_consumptions WHERE session_id = $jobId
          `).get({ jobId });
          return session === null || principal === null ? null : {
            session,
            principal: `${principal.principalScheme}:${principal.principalIdentifier}`,
          };
        },
      },
    });
    const request = Object.freeze({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    expect(() => buyer.authorize({
      ...expected,
      jobId: "01J00000000000000000000002",
    })).toThrow("job does not match admission policy");
    for (const mutation of [
      { agreementHash: "c".repeat(64) },
      { sessionBindingHash: "d".repeat(64) },
      { phaseIndex: 3 },
      { railId: "fixture:other" },
      { seller: orchestrator },
    ]) {
      const mismatched = buyer.authorize({ ...expected, ...mutation });
      await expect(runner.run({
        authorizationCanonicalJson: mismatched.canonicalJson,
        request,
      })).rejects.toThrow("execution authorization is invalid");
    }
    const wrongPrincipalRunner = createExternalBuyerServiceRunner({
      authority: { get: () => expected },
      runtime,
      sessions: {
        get: () => ({ session: admitted.session, principal: orchestrator }),
      },
    });
    await expect(wrongPrincipalRunner.run({
      authorizationCanonicalJson: authorization.canonicalJson,
      request,
    })).rejects.toThrow("execution authority is unavailable");
    const tamperedSignature = JSON.parse(authorization.canonicalJson) as Record<string, unknown>;
    const signature = tamperedSignature["signature"] as Record<string, unknown>;
    const originalValue = signature["value"] as string;
    signature["value"] = `${originalValue[0] === "A" ? "B" : "A"}${originalValue.slice(1)}`;
    const tamperedCanonicalJson = canonicalize(tamperedSignature);
    expect(verifyBuyerSessionAuthorization(tamperedCanonicalJson, expected)).toBe(false);
    await expect(runner.run({
      authorizationCanonicalJson: tamperedCanonicalJson,
      request,
    })).rejects.toThrow("execution authorization is invalid");
    signature["value"] = originalValue;
    signature["extra"] = "malleable";
    expect(verifyBuyerSessionAuthorization(canonicalize(tamperedSignature), expected)).toBe(false);
    expect(handlerCalls).toBe(0);
    expect((await runner.run({
      authorizationCanonicalJson: authorization.canonicalJson,
      request,
    })).output).toEqual(BASIC_FIXTURE.output);
    expect(handlerCalls).toBe(1);
    database.close();
  });

  test("exposes identity and signed authorization bytes but no signer or reusable credential", () => {
    const buyer = externalBuyer("f".repeat(64));
    const seller = fixtureSigner().signer;
    const orchestrator = orchestratorFixtureSigner().signer;
    expect(Object.keys(buyer).sort()).toEqual([
      "authorize", "createAdmission", "createChallengeAllocation", "identityCanonicalJson", "primaryClaim",
    ]);
    expect(buyer.identityCanonicalJson).toContain(buyer.primaryClaim);
    const authorization = buyer.authorize({
      seller,
      orchestrator,
      jobId: BASIC_FIXTURE.jobId,
      agreementHash: AGREEMENT_HASH,
      sessionBindingHash: "b".repeat(64),
      phaseIndex: 2,
      railId: "fixture:no-spend",
      authorizedAt: AUTHORIZED_AT,
    });
    const sellerView = `${buyer.identityCanonicalJson}\n${authorization.canonicalJson}`.toLowerCase();
    for (const forbidden of ["privatekey", "private_key", "seed", "bearer", "secret", "token"]) {
      expect(sellerView).not.toContain(forbidden);
    }
    expect(() => buyer.authorize({
      seller: buyer.primaryClaim,
      orchestrator,
      jobId: BASIC_FIXTURE.jobId,
      agreementHash: AGREEMENT_HASH,
      sessionBindingHash: "b".repeat(64),
      phaseIndex: 2,
      railId: "fixture:no-spend",
      authorizedAt: AUTHORIZED_AT,
    })).toThrow("party or rail binding");
    expect(() => buyer.authorize({
      seller,
      orchestrator,
      jobId: BASIC_FIXTURE.jobId,
      agreementHash: AGREEMENT_HASH,
      sessionBindingHash: "b".repeat(64),
      phaseIndex: 2,
      railId: [] as unknown as string,
      authorizedAt: AUTHORIZED_AT,
    })).toThrow("party or rail binding");
    expect(() => buyer.createAdmission({
      idempotencyKey: "attested-public-data-request",
      nonce: "arbitrary bytes",
    })).toThrow("admission request is invalid");
  });

  test("snapshots the exact admission policy before exposing signing operations", () => {
    const signer = createFixtureEd25519Signer(
      createHash("sha256").update("attested-public-data-policy-snapshot-v1").digest(),
      { deploymentMode: "fixture", authorityMode: "fixture" },
    );
    const identity = signPerClaimIdentityBundle({
      bundleVersion: "1",
      presentedBy: signer.signer,
      presentedAt: NOW_MS,
      claims: [{ ref: signer.signer }],
    }, signer, { deploymentMode: "fixture", requestMode: "fixture" });
    const policy = {
      instanceId: INSTANCE_ID,
      audience: AUDIENCE,
      jobId: BASIC_FIXTURE.jobId,
      evidenceMode: "fixture" as const,
      requestHash: "e".repeat(64),
    };
    const buyer = createExternalBuyerHarness(signer, identity.canonicalJson, policy);
    policy.jobId = "01J00000000000000000000002";
    policy.requestHash = "f".repeat(64);

    const challenge = buyer.createChallengeAllocation({
      clientNonce: "1".repeat(32),
      idempotencyKey: "attested-public-data-request",
      requestedAtMs: NOW_MS,
    });
    const admission = buyer.createAdmission({
      idempotencyKey: "attested-public-data-request",
      nonce: "2".repeat(32),
    });

    expect(challenge.jobId).toBe(BASIC_FIXTURE.jobId);
    expect(admission.jobId).toBe(BASIC_FIXTURE.jobId);
    expect(admission.requestHash).toBe("e".repeat(64));
  });
});

function externalBuyer(requestHash: string) {
  const signer = createFixtureEd25519Signer(
    createHash("sha256").update("attested-public-data-external-buyer-v1").digest(),
    { deploymentMode: "fixture", authorityMode: "fixture" },
  );
  const identity = signPerClaimIdentityBundle({
    bundleVersion: "1",
    presentedBy: signer.signer,
    presentedAt: NOW_MS,
    claims: [{ ref: signer.signer }],
  }, signer, { deploymentMode: "fixture", requestMode: "fixture" });
  return createExternalBuyerHarness(signer, identity.canonicalJson, {
    instanceId: INSTANCE_ID,
    audience: AUDIENCE,
    jobId: BASIC_FIXTURE.jobId,
    evidenceMode: "fixture",
    requestHash,
  });
}

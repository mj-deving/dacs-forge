import { afterEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BASIC_FIXTURE } from "../../service/fixtures/basic.ts";
import { serviceContract } from "../../service/service.config.ts";
import { ServiceRuntime, serviceRequestHash } from "../../src/service/runtime.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  SessionStore,
  admissionSigningBytes,
  challengeAllocationSigningBytes,
  type AdmissionInput,
  type ChallengeAllocationInput,
} from "../../src/substrate/sqlite/session-store.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

const directories: string[] = [];
const AUTHENTICATION_KEY = "service-session-integration-key";
const NOW_MS = Date.parse(BASIC_FIXTURE.producedAt);

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("service runtime with persistent session admission", () => {
  test("runs only the signed request after admission and survives restart idempotently", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-service-session-"));
    directories.push(directory);
    const path = join(directory, "state.sqlite");
    const firstDatabase = openDatabase(path);
    const firstSessions = sessionStore(firstDatabase);
    admit(firstSessions);
    firstDatabase.close();

    const secondDatabase = openDatabase(path);
    const secondSessions = sessionStore(secondDatabase);
    const runtime = new ServiceRuntime({
      artifactStore: new ArtifactStore(secondDatabase),
      contract: serviceContract,
      deploymentMode: "fixture",
      now: () => BASIC_FIXTURE.producedAt,
      sessionStore: secondSessions,
      signer: fixtureSigner(),
    });
    const first = await runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    secondDatabase.close();

    const thirdDatabase = openDatabase(path);
    const replay = await new ServiceRuntime({
      artifactStore: new ArtifactStore(thirdDatabase),
      contract: serviceContract,
      deploymentMode: "fixture",
      now: () => BASIC_FIXTURE.producedAt,
      sessionStore: sessionStore(thirdDatabase),
      signer: fixtureSigner(),
    }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(replay.outputArtifact.contentHash).toBe(first.outputArtifact.contentHash);
    expect(replay.receiptArtifact.contentHash).toBe(first.receiptArtifact.contentHash);
    expect(thirdDatabase.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()?.count).toBe(2n);
    thirdDatabase.close();
  });
});

function sessionStore(database: ReturnType<typeof openDatabase>): SessionStore {
  return new SessionStore(database, {
    audience: "https://service.example",
    authenticator: {
      verify: ({ proof, signedBytes }) => proof === sign(signedBytes),
    },
    deploymentMode: "fixture",
    instanceId: "reference-instance",
    jobAuthorizer: { authorize: () => true },
    now: () => NOW_MS,
    randomBytes: () => Buffer.alloc(16, 7),
  });
}

function admit(store: SessionStore): void {
  const unsignedChallenge: ChallengeAllocationInput = {
    instanceId: "reference-instance",
    audience: "https://service.example",
    principal: "key:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    jobId: BASIC_FIXTURE.jobId,
    evidenceMode: "fixture",
    clientNonce: "1".repeat(32),
    clientIdempotencyKey: "reference-request",
    requestedAtMs: NOW_MS,
    proof: "pending",
  };
  const allocation = store.allocateChallenge({
    ...unsignedChallenge,
    proof: sign(challengeAllocationSigningBytes(unsignedChallenge)),
  });
  if (allocation.disposition !== "created") throw new Error("Fixture challenge was not created");
  const unsignedAdmission: AdmissionInput = {
    instanceId: allocation.challenge.instanceId,
    audience: allocation.challenge.audience,
    principal: allocation.challenge.principal,
    jobId: allocation.challenge.jobId,
    evidenceMode: "fixture",
    nonce: allocation.challenge.nonce,
    idempotencyKey: "reference-request",
    requestHash: serviceRequestHash(serviceContract, BASIC_FIXTURE.input, BASIC_FIXTURE.seed),
    proof: "pending",
  };
  const admitted = store.admit({
    ...unsignedAdmission,
    proof: sign(admissionSigningBytes(unsignedAdmission)),
  });
  if (admitted.disposition !== "created") throw new Error("Fixture session was not admitted");
}

function sign(value: string): string {
  return createHmac("sha256", AUTHENTICATION_KEY).update(value).digest("hex");
}

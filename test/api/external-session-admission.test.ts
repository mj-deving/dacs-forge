import { afterEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HttpResourceGuards } from "../../src/http/resource-guards.ts";
import {
  SESSION_CHALLENGE_ROUTE,
  SESSION_CREATE_ROUTE,
  createSessionAdmissionHttpHandler,
} from "../../src/http/session-admission.ts";
import { validateTerminalBody } from "../../src/http/terminal-server.ts";
import { contentHash } from "../../src/protocol/hash.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  SessionStore,
  admissionSigningBytes,
  challengeAllocationSigningBytes,
  type AdmissionInput,
  type ChallengeAllocationInput,
} from "../../src/substrate/sqlite/session-store.ts";

const directories: string[] = [];
const NOW = Date.parse("2026-07-27T08:00:00.000Z");
const AUTH_KEY = "external-admission-test-key";
const JOB_ID = "01J00000000000000000000001";

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("external HTTP session admission", () => {
  test("keeps invalid principals indistinguishable and persists no challenge", async () => {
    const fixture = await httpFixture();
    const unknown = signedChallenge({ principal: "did:demos:unknown" });
    const badProof = { ...signedChallenge(), proof: "bad" };
    const [unknownResponse, badProofResponse] = await Promise.all([
      fixture.handler(jsonRequest("/v1/session-challenges", unknown)),
      fixture.handler(jsonRequest("/v1/session-challenges", badProof)),
    ]);
    expect(unknownResponse.status).toBe(401);
    expect(badProofResponse.status).toBe(401);
    expect(await unknownResponse.text()).toBe(await badProofResponse.text());
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(0n);
    fixture.database.close();
  });

  test("maps concurrent exact replay to one challenge and rejects binding mutation", async () => {
    const fixture = await httpFixture();
    const request = signedChallenge();
    const responses = await Promise.all(Array.from({ length: 8 }, () =>
      fixture.handler(jsonRequest("/v1/session-challenges", request))));
    const bodies = await Promise.all(responses.map(async (response) => {
      expect([200, 201]).toContain(response.status);
      const text = await response.text();
      expect(validateTerminalBody(text)).toMatchObject({
        valid: true,
        schema: "dacs-session-challenge/v1",
      });
      return JSON.parse(text) as { challenge: { nonce: string } };
    }));
    expect(new Set(bodies.map((body) => body.challenge.nonce)).size).toBe(1);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_challenges",
    ).get()?.count).toBe(1n);

    const mutation = signedChallenge({
      clientNonce: request.clientNonce,
      clientIdempotencyKey: request.clientIdempotencyKey,
      jobId: "01J00000000000000000000002",
    });
    expect((await fixture.handler(jsonRequest("/v1/session-challenges", mutation))).status)
      .toBe(409);
    fixture.database.close();
  });

  test("consumes admission and creates exactly one session across restart", async () => {
    const fixture = await httpFixture();
    const allocation = await fixture.handler(jsonRequest(
      "/v1/session-challenges",
      signedChallenge(),
    ));
    const challenge = (await allocation.json() as {
      challenge: { nonce: string };
    }).challenge;
    const admission = signedAdmission(challenge.nonce);
    const created = await fixture.handler(jsonRequest("/v1/sessions", {
      kind: "external",
      admission,
    }));
    expect(created.status).toBe(201);
    const body = await created.text();
    expect(validateTerminalBody(body)).toMatchObject({ valid: true, schema: "dacs-session/v1" });
    expect(fixture.store.count()).toBe(1n);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM admission_consumptions",
    ).get()?.count).toBe(1n);
    expect((await fixture.handler(jsonRequest("/v1/sessions", {
      kind: "external",
      admission,
    }))).status).toBe(401);
    fixture.database.close();

    const reopened = openDatabase(fixture.path);
    const restartedStore = sessionStore(reopened);
    expect(restartedStore.get(JOB_ID)).toMatchObject({
      jobId: JOB_ID,
      requestHash: admission.requestHash,
      status: "admitted",
    });
    expect(restartedStore.count()).toBe(1n);
    reopened.close();
  });
});

async function httpFixture(): Promise<{
  readonly database: ReturnType<typeof openDatabase>;
  readonly handler: (request: Request) => Promise<Response>;
  readonly path: string;
  readonly store: SessionStore;
}> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-external-admission-"));
  directories.push(directory);
  const path = join(directory, "state.sqlite");
  const database = openDatabase(path);
  const store = sessionStore(database);
  const limit = Object.freeze({
    bodyBytes: 16_384,
    concurrency: 16,
    rate: Object.freeze({ requests: 100, windowMs: 60_000 }),
  });
  const guards = new HttpResourceGuards(database, {
    global: limit,
    routes: {
      [SESSION_CHALLENGE_ROUTE]: limit,
      [SESSION_CREATE_ROUTE]: limit,
    },
    now: () => NOW,
  });
  return {
    database,
    path,
    store,
    handler: createSessionAdmissionHttpHandler({ guards, sessionStore: store }),
  };
}

function sessionStore(database: ReturnType<typeof openDatabase>): SessionStore {
  return new SessionStore(database, {
    audience: "https://service.example",
    authenticator: {
      verify: ({ proof, signedBytes }) => proof === sign(signedBytes),
    },
    deploymentMode: "fixture",
    instanceId: "instance-1",
    jobAuthorizer: {
      authorize: ({ principal }) => principal === "did:demos:buyer",
    },
    now: () => NOW,
  });
}

function signedChallenge(
  overrides: Partial<ChallengeAllocationInput> = {},
): ChallengeAllocationInput {
  const unsigned: ChallengeAllocationInput = {
    instanceId: "instance-1",
    audience: "https://service.example",
    principal: "did:demos:buyer",
    jobId: JOB_ID,
    evidenceMode: "fixture",
    clientNonce: "1".padStart(32, "0"),
    clientIdempotencyKey: "allocation-1",
    requestedAtMs: NOW,
    proof: "pending",
    ...overrides,
  };
  return { ...unsigned, proof: sign(challengeAllocationSigningBytes(unsigned)) };
}

function signedAdmission(nonce: string): AdmissionInput {
  const unsigned: AdmissionInput = {
    instanceId: "instance-1",
    audience: "https://service.example",
    principal: "did:demos:buyer",
    jobId: JOB_ID,
    evidenceMode: "fixture",
    nonce,
    idempotencyKey: "session-1",
    requestHash: contentHash({ input: "hello" }),
    proof: "pending",
  };
  return { ...unsigned, proof: sign(admissionSigningBytes(unsigned)) };
}

function sign(value: string): string {
  return createHmac("sha256", AUTH_KEY).update(value).digest("hex");
}

function jsonRequest(path: string, body: unknown): Request {
  return new Request(`http://127.0.0.1${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

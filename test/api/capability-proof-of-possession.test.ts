import { afterEach, describe, expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AdministratorCapabilityScope, PartyCapabilityScope } from "../../src/http/capability-authority.ts";
import {
  ADMINISTRATOR_ROTATE_ROUTE,
  ADMINISTRATOR_SESSIONS_ROUTE,
  CAPABILITY_REPLACEMENT_ROUTE,
  CAPABILITY_RENEW_ROUTE,
  CAPABILITY_REVOKE_ROUTE,
  PARTY_CHALLENGE_ROUTE,
  PARTY_EXCHANGE_ROUTE,
  createPartyAuthorityHttpHandler,
} from "../../src/http/party-authority.ts";
import { HttpResourceGuards } from "../../src/http/resource-guards.ts";
import {
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
  readAuthorityCapabilityOutput,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  PartyAuthorityLifecycle,
  partyCapabilityExchangeSigningBytes,
  partyChallengeAllocationSigningBytes,
  type PartyChallengeAllocationInput,
} from "../../src/substrate/sqlite/party-authority-lifecycle.ts";
import { MAX_PARTY_CAPABILITY_HISTORY } from "../../src/substrate/capability-limits.ts";

const NOW = 1_800_000_000_000;
const INSTANCE = "instance-1";
const AUDIENCE = "https://service.example";
const ADMIN_KEY = "key:administrator";
const RECOVERY_KEY = "key:recovery";
const PARTY_KEY = "key:buyer-admission";
const JOB = "01J00000000000000000000001";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("party capability proof of possession", () => {
  test("bootstraps digest-only custody and exchanges one replay-bounded challenge", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-party-authority-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite");
    const outputPath = join(root, "administrator.cap");
    const current = new Set([ADMIN_KEY, RECOVERY_KEY, PARTY_KEY]);
    const request = prepareAuthorityBootstrap({
      administratorKey: ADMIN_KEY,
      administratorOperations: ["session:inspect", "capability:revoke", "administrator:rotate"],
      administratorPrincipal: "did:demos:administrator",
      audience: AUDIENCE,
      expiresAtMs: NOW + 60_000,
      instanceId: INSTANCE,
      outputPath,
      recoveryKey: RECOVERY_KEY,
      requestedAtMs: NOW,
      storeBinding: authorityStoreBinding(databasePath),
    }, sequenceEntropy());
    const bootstrapBytes = authorityBootstrapSigningBytes(request);
    completeAuthorityBootstrap({
      request,
      administratorProof: sign(ADMIN_KEY, bootstrapBytes),
      recoveryProof: sign(RECOVERY_KEY, bootstrapBytes),
    }, offlineOptions(databasePath, current));

    const administratorToken = readAuthorityCapabilityOutput(outputPath);
    expect(administratorToken).toMatch(/^[0-9a-f]{64}$/);
    expect((await stat(outputPath)).mode & 0o777).toBe(0o600);
    const databaseBytes = await readFile(databasePath);
    expect(databaseBytes.includes(Buffer.from(administratorToken))).toBe(false);

    let database = openDatabase(databasePath);
    let lifecycle = authority(database, current);
    const administratorScope: AdministratorCapabilityScope = {
      kind: "administrator",
      instanceId: INSTANCE,
      audience: AUDIENCE,
      principal: "did:demos:administrator",
      operations: ["administrator:rotate", "capability:revoke", "session:inspect"],
      expiresAtMs: NOW + 60_000,
      configuredKey: ADMIN_KEY,
    };
    expect(lifecycle.authorize(administratorToken, administratorScope)).toBe(true);

    const allocation = signedAllocation();
    const created = lifecycle.allocatePartyChallenge(allocation);
    expect(created.disposition).toBe("created");
    const replayed = lifecycle.allocatePartyChallenge(allocation);
    expect(replayed.disposition).toBe("replayed");
    if (!("challenge" in created) || !("challenge" in replayed)) throw new Error("challenge missing");
    expect(replayed.challenge).toEqual(created.challenge);
    expect(lifecycle.allocatePartyChallenge(signedAllocation({
      clientNonce: allocation.clientNonce,
      jobId: "01J00000000000000000000002",
    })).disposition).toBe("rejected");
    expect(lifecycle.allocatePartyChallenge(signedAllocation({
      principal: "did:demos:unknown",
    })).disposition).toBe("rejected");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_challenges",
    ).get()?.count).toBe(1n);

    const scope: PartyCapabilityScope = {
      kind: "party",
      instanceId: INSTANCE,
      audience: AUDIENCE,
      principal: "did:demos:buyer",
      operations: ["artifact:read", "session:read"],
      expiresAtMs: NOW + 30_000,
      jobId: JOB,
      role: "buyer",
      authority: { kind: "admission", key: PARTY_KEY },
    };
    const partyToken = lifecycle.prepareCapabilityReplacement();
    lifecycle.close();
    database.close();
    database = openDatabase(databasePath);
    lifecycle = authority(database, current);
    const exchanged = lifecycle.exchangePartyChallenge({
      nonce: created.challenge.nonce,
      expiresAtMs: scope.expiresAtMs,
      replacementToken: partyToken,
      proof: sign(PARTY_KEY, partyCapabilityExchangeSigningBytes({
        nonce: created.challenge.nonce,
        replacementDigest: digest(partyToken),
        scope,
      })),
    });
    expect(exchanged.disposition).toBe("created");
    if (!("grant" in exchanged)) throw new Error("grant missing");
    expect(lifecycle.authorize(exchanged.grant.token, exchanged.grant.scope)).toBe(true);
    const insertHistorical = database.query<never, { digest: string }>(`
      INSERT INTO party_capabilities (
        capability_digest, instance_id, audience, kind, principal, operations_json,
        expires_at_ms, configured_key, job_id, role, authority_kind, authority_key,
        agreement_hash, state, issued_at_ms, revoked_at_ms, generation
      ) VALUES (
        $digest, '${INSTANCE}', '${AUDIENCE}', 'party', 'did:demos:buyer',
        '["artifact:read"]', ${NOW - 1}, NULL, '${JOB}', 'buyer', 'admission',
        '${PARTY_KEY}', NULL, 'revoked', ${NOW - 2}, ${NOW - 1}, 1
      )
    `);
    database.transaction(() => {
      for (let index = 1; index < MAX_PARTY_CAPABILITY_HISTORY; index += 1) {
        insertHistorical.run({ digest: digest(`historical-party-${index}`) });
      }
    }).immediate();
    expect(database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM party_capabilities WHERE kind = 'party'
    `).get()?.count).toBe(BigInt(MAX_PARTY_CAPABILITY_HISTORY));
    const boundedAllocation = lifecycle.allocatePartyChallenge(signedAllocation({
      clientIdempotencyKey: "bounded-history-allocation",
      clientNonce: "5".padStart(32, "0"),
    }));
    if (!("challenge" in boundedAllocation)) throw new Error("bounded challenge missing");
    const capRef = lifecycle.prepareCapabilityReplacement();
    const boundedScope = { ...scope, expiresAtMs: NOW + 20_000 };
    expect(lifecycle.exchangePartyChallenge({
      nonce: boundedAllocation.challenge.nonce,
      expiresAtMs: boundedScope.expiresAtMs,
      replacementToken: capRef,
      proof: sign(PARTY_KEY, partyCapabilityExchangeSigningBytes({
        nonce: boundedAllocation.challenge.nonce,
        replacementDigest: digest(capRef),
        scope: boundedScope,
      })),
    }).disposition).toBe("created");
    expect(database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM party_capabilities WHERE kind = 'party' AND state = 'revoked'
    `).get()?.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM party_capabilities WHERE kind = 'party'
    `).get()?.count).toBe(2n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_capability_preparations",
    ).get()?.count).toBe(0n);
    database.query(`
      UPDATE party_authority_challenges
      SET issued_at_ms = $issued, expires_at_ms = $expired, retain_until_ms = $retained
    `).run({ issued: NOW - 2, expired: NOW - 1, retained: NOW });
    expect(lifecycle.allocatePartyChallenge(signedAllocation({
      clientIdempotencyKey: "replacement-allocation",
      clientNonce: "3".padStart(32, "0"),
    })).disposition).toBe("created");
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_challenges",
    ).get()?.count).toBe(1n);
    const replayToken = lifecycle.prepareCapabilityReplacement();
    expect(lifecycle.exchangePartyChallenge({
      nonce: created.challenge.nonce,
      expiresAtMs: scope.expiresAtMs,
      replacementToken: replayToken,
      proof: sign(PARTY_KEY, "replay"),
    }).disposition).toBe("rejected");
    expect(database.query<{ raw: string | null }, []>(`
      SELECT max(CASE WHEN capability_digest = '${exchanged.grant.token}' THEN capability_digest END) AS raw
      FROM party_capabilities
    `).get()?.raw).toBeNull();

    const limit = Object.freeze({
      bodyBytes: 8_192,
      concurrency: 4,
      rate: Object.freeze({ requests: 20, windowMs: 60_000 }),
    });
    const handler = createPartyAuthorityHttpHandler({
      authority: lifecycle,
      guards: new HttpResourceGuards(database, {
        global: limit,
        routes: Object.fromEntries([
          PARTY_CHALLENGE_ROUTE,
          PARTY_EXCHANGE_ROUTE,
          CAPABILITY_REPLACEMENT_ROUTE,
          CAPABILITY_RENEW_ROUTE,
          CAPABILITY_REVOKE_ROUTE,
          ADMINISTRATOR_ROTATE_ROUTE,
          ADMINISTRATOR_SESSIONS_ROUTE,
        ].map((route) => [route, limit])),
        now: () => NOW,
      }),
    });
    expect((await handler(jsonRequest("/v1/administrators/rotate", {
      expiresAtMs: NOW + 120_000,
      newConfiguredKey: "key:replacement",
      newPrincipal: "did:demos:replacement",
      operations: ["administrator:rotate"],
      proof: "old-administrator-proof",
      replacementToken: "9".repeat(64),
      requestedAtMs: NOW,
    }, administratorToken))).status).toBe(401);
    const preparedResponse = await handler(jsonRequest("/v1/capability-replacements", {}));
    expect(preparedResponse.status).toBe(201);
    const testToken3 = (await preparedResponse.json() as { token: string }).token;
    expect(testToken3).toMatch(/^[0-9a-f]{64}$/);
    const httpAllocation = signedAllocation({
      clientIdempotencyKey: "http-party-allocation",
      clientNonce: "2".padStart(32, "0"),
    });
    const httpChallengeResponse = await handler(jsonRequest(
      "/v1/party-capability-challenges",
      httpAllocation,
    ));
    expect(httpChallengeResponse.status).toBe(201);
    const httpChallenge = (await httpChallengeResponse.json() as {
      challenge: { nonce: string };
    }).challenge;
    const httpScope = { ...scope, expiresAtMs: NOW + 40_000 };
    const httpExchangeResponse = await handler(jsonRequest("/v1/party-capabilities", {
      nonce: httpChallenge.nonce,
      expiresAtMs: httpScope.expiresAtMs,
      replacementToken: testToken3,
      proof: sign(PARTY_KEY, partyCapabilityExchangeSigningBytes({
        nonce: httpChallenge.nonce,
        replacementDigest: digest(testToken3),
        scope: httpScope,
      })),
    }));
    expect(httpExchangeResponse.status).toBe(201);
    expect((await httpExchangeResponse.json() as { grant: { token: string } }).grant.token)
      .toMatch(/^[0-9a-f]{64}$/);
    expect((await handler(jsonRequest("/v1/party-capability-challenges", {
      ...httpAllocation,
      unsignedExtra: true,
    }))).status).toBe(400);

    const oversizedOperations = ["a".repeat(4_096), "b".repeat(4_096), "c".repeat(4_096)];
    const oversizedAllocation = lifecycle.allocatePartyChallenge(signedAllocation({
      clientIdempotencyKey: "oversized-response-allocation",
      clientNonce: "4".padStart(32, "0"),
      operations: oversizedOperations,
    }));
    expect(oversizedAllocation.disposition).toBe("created");
    if (!("challenge" in oversizedAllocation)) throw new Error("oversized challenge missing");
    const testToken4 = lifecycle.prepareCapabilityReplacement();
    const oversizedScope: PartyCapabilityScope = {
      ...scope,
      operations: oversizedOperations,
    };
    expect(lifecycle.exchangePartyChallenge({
      nonce: oversizedAllocation.challenge.nonce,
      expiresAtMs: oversizedScope.expiresAtMs,
      replacementToken: testToken4,
      proof: "rejected-before-proof",
    }).disposition).toBe("rejected");
    expect(database.query<{ consumedAtMs: bigint | null }, { nonce: string }>(`
      SELECT consumed_at_ms AS consumedAtMs FROM party_authority_challenges WHERE nonce = $nonce
    `).get({ nonce: oversizedAllocation.challenge.nonce })?.consumedAtMs).toBeNull();
    expect(database.query<{ found: bigint }, { digest: string }>(`
      SELECT count(*) AS found FROM party_capability_preparations WHERE capability_digest = $digest
    `).get({ digest: digest(testToken4) })?.found).toBe(1n);
    lifecycle.close();
    database.close();

    const reopened = openDatabase(databasePath);
    const restarted = authority(reopened, current);
    expect(restarted.authorize(exchanged.grant.token, exchanged.grant.scope)).toBe(true);
    current.delete(PARTY_KEY);
    expect(restarted.authorize(exchanged.grant.token, exchanged.grant.scope)).toBe(false);
    restarted.close();
    reopened.close();
  });
});

function authority(database: ReturnType<typeof openDatabase>, current: Set<string>) {
  return new PartyAuthorityLifecycle(database, {
    audience: AUDIENCE,
    instanceId: INSTANCE,
    keyCurrentness: currentness(current),
    now: () => NOW,
    partyAuthority: {
      resolve: ({ jobId, role }) => jobId === JOB && role === "buyer"
        ? {
            disposition: "current" as const,
            principal: "did:demos:buyer",
            authority: { kind: "admission" as const, key: PARTY_KEY },
          }
        : { disposition: "unavailable" as const },
    },
    proofVerifier: { verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes) },
    randomBytes: sequenceEntropy(),
  });
}

function signedAllocation(
  overrides: Partial<PartyChallengeAllocationInput> = {},
): PartyChallengeAllocationInput {
  const unsigned: PartyChallengeAllocationInput = {
    clientIdempotencyKey: "party-allocation-1",
    clientNonce: "1".padStart(32, "0"),
    jobId: JOB,
    operations: ["session:read", "artifact:read"],
    principal: "did:demos:buyer",
    proof: "pending",
    requestedAtMs: NOW,
    role: "buyer",
    ...overrides,
  };
  return { ...unsigned, proof: sign(PARTY_KEY, partyChallengeAllocationSigningBytes(unsigned)) };
}

function offlineOptions(databasePath: string, current: Set<string>) {
  return {
    databasePath,
    keyCurrentness: currentness(current),
    now: () => NOW,
    proofVerifier: { verify: ({ key, proof, signedBytes }: {
      key: string; proof: string; signedBytes: string;
    }) => proof === sign(key, signedBytes) },
    randomBytes: sequenceEntropy(),
  };
}

function currentness(current: Set<string>) {
  return {
    resolve: ({ keyClaim, checkedAt }: { keyClaim: string; checkedAt: number }) => current.has(keyClaim)
      ? { disposition: "current" as const, currentClaim: keyClaim, recipeVersion: 1, checkedAt }
      : { disposition: "revoked" as const, currentClaim: "key:replacement", recipeVersion: 1, checkedAt },
  };
}

function sign(key: string, bytes: string): string {
  return createHmac("sha256", key).update(bytes).digest("hex");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function jsonRequest(path: string, body: unknown, authorization?: string): Request {
  return new Request(`http://127.0.0.1${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(authorization === undefined ? {} : { authorization: `Bearer ${authorization}` }),
    },
    body: JSON.stringify(body),
  });
}

function sequenceEntropy(): (size: number) => Uint8Array {
  let sequence = 1n;
  return (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, sequence);
    sequence += 1n;
    return bytes;
  };
}

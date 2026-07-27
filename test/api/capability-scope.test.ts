import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CapabilityAuthority,
  type AdministratorCapabilityScope,
  type PartyCapabilityScope,
} from "../../src/http/capability-authority.ts";
import { HttpResourceGuards } from "../../src/http/resource-guards.ts";
import {
  SESSION_CHALLENGE_ROUTE,
  SESSION_CREATE_ROUTE,
  createSessionAdmissionHttpHandler,
} from "../../src/http/session-admission.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  SessionStore,
  type AdmissionResult,
} from "../../src/substrate/sqlite/session-store.ts";

const directories: string[] = [];
const NOW = 1_800_000_000_000;

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("capability scope", () => {
  test("aborts startup and issuance on throwing or short entropy", () => {
    expect(() => authority({ randomBytes: () => { throw new Error("rng failed"); } }))
      .toThrow("rng failed");
    expect(() => authority({ randomBytes: () => new Uint8Array(31) }))
      .toThrow(/startup.*exactly 32 bytes/);

    let calls = 0;
    const issuanceFailure = authority({
      randomBytes: () => {
        calls += 1;
        if (calls === 1) return new Uint8Array(32).fill(1);
        throw new Error("issuance rng failed");
      },
    });
    expect(() => issuanceFailure.issueAdministrator(administratorInput()))
      .toThrow("issuance rng failed");

    calls = 0;
    const issuanceShort = authority({
      randomBytes: () => {
        calls += 1;
        return new Uint8Array(calls === 1 ? 32 : 8);
      },
    });
    expect(() => issuanceShort.issueParty(partyInput()))
      .toThrow(/issuance.*exactly 32 bytes/);
  });

  test("binds administrator and party grants to every immutable scope field", () => {
    const capabilityAuthority = authority({ randomBytes: sequenceEntropy() });
    const administrator = capabilityAuthority.issueAdministrator(administratorInput());
    expect(administrator.token).toMatch(/^[0-9a-f]{64}$/);
    expect(capabilityAuthority.authorize(administrator.token, administrator.scope)).toBe(true);
    const adminMutations: AdministratorCapabilityScope[] = [
      { ...administrator.scope, instanceId: "instance-2" },
      { ...administrator.scope, audience: "https://other.example" },
      { ...administrator.scope, principal: "did:demos:other" },
      { ...administrator.scope, operations: ["read"] },
      { ...administrator.scope, expiresAtMs: administrator.scope.expiresAtMs + 1 },
      { ...administrator.scope, configuredKey: "key:other" },
    ];
    for (const mutation of adminMutations) {
      expect(capabilityAuthority.authorize(administrator.token, mutation)).toBe(false);
    }

    const party = capabilityAuthority.issueParty(partyInput());
    expect(capabilityAuthority.authorize(party.token, party.scope)).toBe(true);
    const partyMutations: PartyCapabilityScope[] = [
      { ...party.scope, jobId: "01J00000000000000000000002" },
      { ...party.scope, role: "seller" },
      { ...party.scope, operations: ["artifact:read"] },
      { ...party.scope, authority: { ...party.scope.authority, kind: "agreement" } },
      { ...party.scope, authority: { ...party.scope.authority, key: "key:other" } },
    ];
    for (const mutation of partyMutations) {
      expect(capabilityAuthority.authorize(party.token, mutation)).toBe(false);
    }
    expect(capabilityAuthority.authorize("0".repeat(64), party.scope)).toBe(false);
  });

  test("issues 100000 collision-free 256-bit capabilities", () => {
    const capabilityAuthority = authority({ randomBytes: sequenceEntropy() });
    const tokens = new Set<string>();
    for (let index = 0; index < 100_000; index += 1) {
      tokens.add(capabilityAuthority.issueAdministrator({
        ...administratorInput(),
        principal: `did:demos:admin-${index}`,
      }).token);
    }
    expect(tokens.size).toBe(100_000);
  });

  test("admits the fixture callback only under the exact administrator capability", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-fixture-capability-"));
    directories.push(directory);
    const database = openDatabase(join(directory, "state.sqlite"));
    const capabilityAuthority = authority({ randomBytes: sequenceEntropy() });
    const grant = capabilityAuthority.issueAdministrator(administratorInput());
    const limit = Object.freeze({
      bodyBytes: 4_096,
      concurrency: 4,
      rate: Object.freeze({ requests: 20, windowMs: 60_000 }),
    });
    const guards = new HttpResourceGuards(database, {
      global: limit,
      routes: { [SESSION_CHALLENGE_ROUTE]: limit, [SESSION_CREATE_ROUTE]: limit },
      now: () => NOW,
    });
    const store = new SessionStore(database, {
      audience: "https://service.example",
      authenticator: { verify: () => false },
      deploymentMode: "fixture",
      instanceId: "instance-1",
      jobAuthorizer: { authorize: () => false },
      now: () => NOW,
    });
    let fixtureAdmissions = 0;
    const created: AdmissionResult = {
      disposition: "created",
      session: {
        instanceId: "instance-1",
        audience: "https://service.example",
        jobId: "01J00000000000000000000001",
        evidenceMode: "fixture",
        requestHash: "1".repeat(64),
        admissionFingerprint: "2".repeat(64),
        status: "admitted",
        version: 0n,
        createdAt: "2027-01-15T08:00:00.000Z",
      },
    };
    const handler = createSessionAdmissionHttpHandler({
      guards,
      sessionStore: store,
      fixtureAdministratorAdmission: {
        admitAuthorized: ({ authorization }) => {
          if (!authorization.startsWith("Bearer ")
            || !capabilityAuthority.authorize(authorization.slice(7), grant.scope)) {
            return { disposition: "rejected", reason: "authentication-failed" };
          }
          fixtureAdmissions += 1;
          return created;
        },
      },
    });
    const request = (authorization?: string, kind = "fixture-admin"): Request => new Request(
      "http://127.0.0.1/v1/sessions",
      {
        method: "POST",
        headers: authorization === undefined ? {} : { authorization },
        body: JSON.stringify({ kind, admission: { jobId: "fixture-job" } }),
      },
    );
    expect((await handler(request())).status).toBe(401);
    expect((await handler(request(`Bearer ${"0".repeat(64)}`))).status).toBe(401);
    expect((await handler(request(`Bearer ${"0".repeat(128)}`))).status).toBe(401);
    expect(fixtureAdmissions).toBe(0);
    expect((await handler(request(`Bearer ${grant.token}`, "external"))).status).toBe(401);
    expect(fixtureAdmissions).toBe(0);
    expect((await handler(request(`Bearer ${grant.token}`))).status).toBe(201);
    expect(fixtureAdmissions).toBe(1);
    database.close();
  });
});

function authority(overrides: Partial<ConstructorParameters<typeof CapabilityAuthority>[0]> = {}) {
  return new CapabilityAuthority({
    instanceId: "instance-1",
    audience: "https://service.example",
    now: () => NOW,
    ...overrides,
  });
}

function administratorInput() {
  return {
    principal: "did:demos:administrator",
    operations: ["session:create", "readiness:read"],
    expiresAtMs: NOW + 60_000,
    configuredKey: "key:administrator",
  } as const;
}

function partyInput() {
  return {
    principal: "did:demos:buyer",
    operations: ["session:read", "artifact:read"],
    expiresAtMs: NOW + 60_000,
    jobId: "01J00000000000000000000001",
    role: "buyer" as const,
    authority: { kind: "admission" as const, key: "key:buyer" },
  } as const;
}

function sequenceEntropy(): (size: number) => Uint8Array {
  let sequence = 0n;
  return (size: number): Uint8Array => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, sequence);
    sequence += 1n;
    return bytes;
  };
}

import { afterEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import {
  PUBLIC_ARTIFACT_ROUTE,
  PUBLIC_DISCLOSURE_CONSENT_DOMAIN,
  PUBLIC_DELIVERY_POLICY_DOMAIN,
  PublicArtifactDisclosureAuthority,
  createPublicArtifactHttpHandler,
  publicDisclosureConsentSigningBytes,
  publicDeliveryPolicySigningBytes,
  type AgreementDisclosureAuthorityResolution,
  type PublicArtifactDisclosureGrant,
  type PublicDeliveryEvidenceResolution,
} from "../../src/http/public-artifact-disclosure.ts";
import { HttpResourceGuards } from "../../src/http/resource-guards.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";

const NOW = 1_800_000_000_000;
const INSTANCE = "instance-1";
const AUDIENCE = "https://service.example";
const JOB = "01J00000000000000000000001";
const OTHER_JOB = "01J00000000000000000000002";
const AGREEMENT = "a".repeat(64);
const BUYER = "key:buyer";
const ATTACKER = "key:attacker";
const SELLER = "key:seller";
const ARTIFACT_REF = `dacs4:deliverable:${JOB}`;
const ARTIFACT = canonicalize({ answer: 42 });
const ARTIFACT_HASH = new Bun.CryptoHasher("sha256").update(ARTIFACT).digest("hex");
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("agreement-bound anonymous artifact disclosure", () => {
  test("serves exact verified bytes only while the buyer authority remains current", async () => {
    const fixture = await disclosureFixture();
    const grant = fixture.grant();
    const handler = fixture.handler(() => ({
      disposition: "resolved",
      artifact: artifact(),
      grant,
    }));

    const response = await handler(request(ARTIFACT_HASH));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(ARTIFACT);
    expect(response.headers.get("content-length")).toBe(String(Buffer.byteLength(ARTIFACT)));

    fixture.currentBuyer = false;
    const revoked = await handler(request(ARTIFACT_HASH));
    expect(revoked.status).toBe(404);
    expect(await revoked.json()).toEqual({
      schema: "dacs-http-error/v1",
      status: 404,
      code: "not-found",
    });
    expect(() => fixture.grant()).toThrow();
    fixture.close();
  });

  test("refuses private delivery and every missing, conflicting, stale, or substituted binding", async () => {
    const fixture = await disclosureFixture();
    const valid = grantInput();
    const cases: readonly [string, unknown][] = [
      ["buyer-only", { ...valid, delivery: { ...valid.delivery, accessModel: "buyer-only" } }],
      ["encrypted", { ...valid, delivery: { ...valid.delivery, accessModel: "encrypt-to-buyer" } }],
      ["missing consent", { delivery: valid.delivery, policy: valid.policy }],
      ["wrong agreement", {
        ...valid,
        consent: signedConsent({ agreementHash: "b".repeat(64) }),
      }],
      ["cross-job", { ...valid, policy: signedPolicy({ jobId: OTHER_JOB }) }],
      ["expired", {
        ...valid,
        consent: signedConsent({ expiresAtMs: NOW }),
        policy: signedPolicy({ expiresAtMs: NOW }),
      }],
      ["bad policy proof", { ...valid, policy: { ...valid.policy, signature: "bad" } }],
      ["bad consent proof", { ...valid, consent: { ...valid.consent, signature: "bad" } }],
    ];
    for (const [name, input] of cases) {
      expect(() => fixture.authority.grant(input), name).toThrow();
    }

    const grant = fixture.grant();
    for (const [name, changed] of [
      ["hash substitution", { ...artifact(), contentHash: "b".repeat(64) }],
      ["ref substitution", { ...artifact(), artifactRef: `dacs4:deliverable:${OTHER_JOB}` }],
      ["byte substitution", { ...artifact(), canonicalJson: canonicalize({ answer: 41 }) }],
    ] as const) {
      const response = await fixture.handler(() => ({
        disposition: "resolved",
        artifact: changed,
        grant,
      }))(request(ARTIFACT_HASH));
      expect(response.status, name).toBe(404);
    }
    fixture.close();
  });

  test("exposes only the exact anonymous artifact route", async () => {
    const fixture = await disclosureFixture();
    let resolutions = 0;
    const handler = fixture.handler(() => {
      resolutions += 1;
      return { disposition: "resolved", artifact: artifact(), grant: fixture.grant() };
    });
    for (const url of [
      `http://service.test/v1/artifacts/${ARTIFACT_HASH}`,
      `http://service.test/v1/public-artifacts/${ARTIFACT_HASH}/extra`,
      `http://service.test/v1/public-artifacts/${ARTIFACT_HASH}?token=secret`,
    ]) {
      expect((await handler(new Request(url))).status).toBe(404);
    }
    expect(resolutions).toBe(0);

    const malformed = fixture.handler(() => ({ disposition: "resolved" } as never));
    expect((await malformed(request(ARTIFACT_HASH))).status).toBe(404);
    fixture.close();
  });

  test("serves the one normalized snapshot when a resolver record changes on reread", async () => {
    const fixture = await disclosureFixture();
    let canonicalReads = 0;
    const changing = {
      ...artifact(),
      get canonicalJson(): string {
        canonicalReads += 1;
        return canonicalReads === 1 ? ARTIFACT : canonicalize({ answer: 41 });
      },
    };
    const response = await fixture.handler(() => ({
      disposition: "resolved",
      artifact: changing,
      grant: fixture.grant(),
    }))(request(ARTIFACT_HASH));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(ARTIFACT);
    expect(canonicalReads).toBe(1);
    fixture.close();
  });

  test("verifies signatures against one normalized authority snapshot", async () => {
    let buyerReads = 0;
    const fixture = await disclosureFixture(() => ({
      disposition: "current",
      agreementHash: AGREEMENT,
      get buyerKey(): string {
        buyerReads += 1;
        return buyerReads === 1 ? BUYER : ATTACKER;
      },
      sellerKey: SELLER,
    }));
    const valid = grantInput();
    const forgedConsent = {
      ...valid.consent,
      signature: sign(ATTACKER, publicDisclosureConsentSigningBytes(valid.consent)),
    };
    expect(() => fixture.authority.grant({ ...valid, consent: forgedConsent })).toThrow();
    expect(buyerReads).toBe(1);
    fixture.close();
  });

  test("rejects a public marker when delivery authority resolves the artifact as private", async () => {
    const fixture = await disclosureFixture(undefined, () => ({
      ...grantInput().delivery,
      accessModel: "buyer-only",
    }));
    expect(() => fixture.grant()).toThrow();
    fixture.close();
  });
});

async function disclosureFixture(
  resolveAuthority?: () => AgreementDisclosureAuthorityResolution,
  resolveDelivery?: () => PublicDeliveryEvidenceResolution,
) {
  const root = await mkdtemp(join(tmpdir(), "dacs-public-artifact-"));
  roots.push(root);
  const database = openDatabase(join(root, "state.sqlite"));
  const guards = new HttpResourceGuards(database, {
    global: { bodyBytes: 64, concurrency: 2, rate: { requests: 100, windowMs: 60_000 } },
    routes: {
      [PUBLIC_ARTIFACT_ROUTE]: {
        bodyBytes: 0,
        concurrency: 1,
        rate: { requests: 100, windowMs: 60_000 },
      },
    },
    now: () => NOW,
  });
  const state = { currentBuyer: true };
  const authority = new PublicArtifactDisclosureAuthority({
    audience: AUDIENCE,
    instanceId: INSTANCE,
    now: () => NOW,
    agreementAuthority: {
      resolveDisclosureAuthority: ({ jobId }) => jobId === JOB && state.currentBuyer
        ? resolveAuthority?.() ?? {
          disposition: "current", agreementHash: AGREEMENT, buyerKey: BUYER, sellerKey: SELLER,
        }
        : { disposition: "unavailable" },
    },
    deliveryAuthority: {
      resolveVerifiedDelivery: ({ artifactHash }) => artifactHash === ARTIFACT_HASH
        ? resolveDelivery?.() ?? grantInput().delivery
        : { disposition: "unavailable" },
    },
    proofVerifier: {
      verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes),
    },
  });
  return {
    authority,
    get currentBuyer() { return state.currentBuyer; },
    set currentBuyer(value: boolean) { state.currentBuyer = value; },
    grant: (): PublicArtifactDisclosureGrant => authority.grant(grantInput()),
    handler: (resolve: Parameters<typeof createPublicArtifactHttpHandler>[0]["resolve"]) =>
      createPublicArtifactHttpHandler({ authority, guards, resolve, maxArtifactBytes: 1_024 }),
    close(): void { database.close(); },
  };
}

function grantInput() {
  return {
    delivery: {
      disposition: "verified" as const,
      accessModel: "public" as const,
      instanceId: INSTANCE,
      audience: AUDIENCE,
      jobId: JOB,
      agreementHash: AGREEMENT,
      artifactRef: ARTIFACT_REF,
      artifactHash: ARTIFACT_HASH,
    },
    policy: signedPolicy(),
    consent: signedConsent(),
  };
}

function signedPolicy(overrides: Record<string, unknown> = {}) {
  const unsigned = {
    policyVersion: "1",
    accessModel: "public",
    instanceId: INSTANCE,
    audience: AUDIENCE,
    jobId: JOB,
    agreementHash: AGREEMENT,
    artifactRef: ARTIFACT_REF,
    artifactHash: ARTIFACT_HASH,
    expiresAtMs: NOW + 60_000,
    sellerKey: SELLER,
    ...overrides,
  };
  return { ...unsigned, signature: sign(SELLER, publicDeliveryPolicySigningBytes(unsigned)) };
}

function signedConsent(overrides: Record<string, unknown> = {}) {
  const unsigned = {
    consentVersion: "1",
    instanceId: INSTANCE,
    audience: AUDIENCE,
    jobId: JOB,
    agreementHash: AGREEMENT,
    artifactRef: ARTIFACT_REF,
    artifactHash: ARTIFACT_HASH,
    expiresAtMs: NOW + 60_000,
    buyerKey: BUYER,
    ...overrides,
  };
  return { ...unsigned, signature: sign(BUYER, publicDisclosureConsentSigningBytes(unsigned)) };
}

function artifact() {
  return {
    artifactRef: ARTIFACT_REF,
    contentHash: ARTIFACT_HASH,
    canonicalJson: ARTIFACT,
    byteLength: Buffer.byteLength(ARTIFACT),
  };
}

function request(hash: string): Request {
  return new Request(`http://service.test/v1/public-artifacts/${hash}`);
}

function sign(key: string, bytes: string): string {
  expect(bytes.startsWith(PUBLIC_DELIVERY_POLICY_DOMAIN)
    || bytes.startsWith(PUBLIC_DISCLOSURE_CONSENT_DOMAIN)).toBe(true);
  return createHmac("sha256", key).update(bytes).digest("hex");
}

import { afterEach, describe, expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PartyCapabilityScope } from "../../src/http/capability-authority.ts";
import {
  authorityBootstrapSigningBytes,
  authorityStoreBinding,
  completeAuthorityBootstrap,
  prepareAuthorityBootstrap,
} from "../../src/substrate/authority-offline.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  PartyAuthorityLifecycle,
  partyCapabilityExchangeSigningBytes,
  partyChallengeAllocationSigningBytes,
  sessionAuthorityAmendmentSigningBytes,
  type PartyChallengeAllocationInput,
  type SessionAuthorityAmendment,
} from "../../src/substrate/sqlite/party-authority-lifecycle.ts";

const NOW = 1_800_000_000_000;
const INSTANCE = "instance-1";
const AUDIENCE = "https://service.example";
const JOB = "01J00000000000000000000001";
const AGREEMENT = "a".repeat(64);
const OLD_BUYER = "key:buyer-old";
const NEW_BUYER = "key:buyer-new";
const OTHER_BUYER = "key:buyer-other";
const SELLER = "key:seller";
const NEW_SELLER = "key:seller-new";
const ADMIN = "key:administrator";
const RECOVERY = "key:recovery";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("agreement-bound artifact authority", () => {
  test("fails closed on key revocation and restores only an anchored two-party amendment", async () => {
    const root = await mkdtemp(join(tmpdir(), "dacs-artifact-access-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite");
    bootstrap(databasePath, join(root, "admin.cap"));
    const current = new Set([ADMIN, RECOVERY, OLD_BUYER, SELLER]);
    const agreement = { hash: AGREEMENT, counterpartyKey: SELLER };
    const database = openDatabase(databasePath);
    const lifecycle = authority(database, current, agreement);
    const old = issueParty(lifecycle, OLD_BUYER, NOW + 60_000, "allocation-old");
    expect(lifecycle.authorize(old.token, old.scope)).toBe(true);
    expect(lifecycle.authorize(old.token, {
      ...old.scope,
      operations: ["session:read"],
    })).toBe(false);

    current.delete(OLD_BUYER);
    expect(lifecycle.authorize(old.token, old.scope)).toBe(false);
    current.add(NEW_BUYER);
    const unsigned: Omit<SessionAuthorityAmendment, "buyerProof" | "sellerProof"> = {
      agreementHash: AGREEMENT,
      anchor: "demos:amendment-anchor",
      counterpartyKey: SELLER,
      expiresAtMs: NOW + 3_600_000,
      jobId: JOB,
      newKey: NEW_BUYER,
      oldKey: OLD_BUYER,
      operations: ["artifact:read"],
      role: "buyer",
    };
    const amendmentBytes = sessionAuthorityAmendmentSigningBytes(unsigned);
    const amendment: SessionAuthorityAmendment = {
      ...unsigned,
      buyerProof: sign(NEW_BUYER, amendmentBytes),
      sellerProof: sign(SELLER, amendmentBytes),
    };
    const collapsedUnsigned = { ...unsigned, newKey: SELLER };
    const collapsedBytes = sessionAuthorityAmendmentSigningBytes(collapsedUnsigned);
    expect(() => lifecycle.applySessionAmendment({
      ...collapsedUnsigned,
      buyerProof: sign(SELLER, collapsedBytes),
      sellerProof: sign(SELLER, collapsedBytes),
    }, { verifyAnchor: () => true })).toThrow(/distinct party keys/);
    agreement.counterpartyKey = OLD_BUYER;
    const aliasedUnsigned = { ...unsigned, counterpartyKey: OLD_BUYER };
    const aliasedBytes = sessionAuthorityAmendmentSigningBytes(aliasedUnsigned);
    expect(() => lifecycle.applySessionAmendment({
      ...aliasedUnsigned,
      buyerProof: sign(NEW_BUYER, aliasedBytes),
      sellerProof: sign(OLD_BUYER, aliasedBytes),
    }, { verifyAnchor: () => true })).toThrow(/distinct party keys/);
    agreement.counterpartyKey = SELLER;
    expect(() => lifecycle.applySessionAmendment(
      { ...amendment, sellerProof: "unilateral" },
      { verifyAnchor: () => true },
    )).toThrow(/both party proofs/);
    expect(() => lifecycle.applySessionAmendment(
      amendment,
      { verifyAnchor: () => false },
    )).toThrow(/anchor is invalid/);
    lifecycle.applySessionAmendment(amendment, {
      verifyAnchor: ({ agreementHash, anchor, digest, jobId }) => agreementHash === AGREEMENT
        && anchor === unsigned.anchor && digest === createHash("sha256").update(amendmentBytes).digest("hex")
        && jobId === JOB,
    });
    current.add(OTHER_BUYER);
    const conflictingUnsigned = { ...unsigned, newKey: OTHER_BUYER };
    const conflictingBytes = sessionAuthorityAmendmentSigningBytes(conflictingUnsigned);
    expect(() => lifecycle.applySessionAmendment({
      ...conflictingUnsigned,
      buyerProof: sign(OTHER_BUYER, conflictingBytes),
      sellerProof: sign(SELLER, conflictingBytes),
    }, { verifyAnchor: () => true })).toThrow(/already fixed/);

    expect(lifecycle.allocatePartyChallenge(signedAllocation(
      NEW_BUYER,
      "allocation-overbroad",
      ["artifact:read", "session:read"],
    )).disposition).toBe("rejected");
    const replacement = issueParty(
      lifecycle,
      NEW_BUYER,
      NOW + 3_600_000,
      "allocation-new",
      ["artifact:read"],
    );
    expect(lifecycle.authorize(replacement.token, replacement.scope)).toBe(true);
    lifecycle.applySessionAmendment(amendment, { verifyAnchor: () => true });
    expect(lifecycle.authorize(replacement.token, replacement.scope)).toBe(true);
    agreement.hash = "b".repeat(64);
    expect(lifecycle.authorize(replacement.token, replacement.scope)).toBe(false);
    agreement.hash = AGREEMENT;
    expect(lifecycle.authorize(old.token, old.scope)).toBe(false);
    expect(issuePartyResult(
      lifecycle,
      NEW_BUYER,
      NOW + 3_600_001,
      "too-long",
      ["artifact:read"],
    ).disposition)
      .toBe("rejected");

    current.add(OLD_BUYER);
    current.add(NEW_SELLER);
    const staleCounterpartySeller = {
      agreementHash: AGREEMENT,
      anchor: "demos:seller-amendment-anchor",
      counterpartyKey: OLD_BUYER,
      expiresAtMs: NOW + 3_600_000,
      jobId: JOB,
      newKey: NEW_SELLER,
      oldKey: SELLER,
      operations: ["artifact:read"],
      role: "seller" as const,
    };
    const staleCounterpartyBytes = sessionAuthorityAmendmentSigningBytes(staleCounterpartySeller);
    expect(() => lifecycle.applySessionAmendment({
      ...staleCounterpartySeller,
      buyerProof: sign(OLD_BUYER, staleCounterpartyBytes),
      sellerProof: sign(NEW_SELLER, staleCounterpartyBytes),
    }, { verifyAnchor: () => true })).toThrow(/current counterparty authority/);
    const currentCounterpartySeller = {
      ...staleCounterpartySeller,
      counterpartyKey: NEW_BUYER,
    };
    const currentCounterpartyBytes = sessionAuthorityAmendmentSigningBytes(currentCounterpartySeller);
    lifecycle.applySessionAmendment({
      ...currentCounterpartySeller,
      buyerProof: sign(NEW_BUYER, currentCounterpartyBytes),
      sellerProof: sign(NEW_SELLER, currentCounterpartyBytes),
    }, { verifyAnchor: () => true });
    lifecycle.applySessionAmendment(amendment, { verifyAnchor: () => true });
    lifecycle.close();
    database.close();

    const reopened = openDatabase(databasePath);
    const restarted = authority(reopened, current, agreement);
    expect(restarted.authorize(replacement.token, replacement.scope)).toBe(true);
    reopened.query<never, { expiresAtMs: number; jobId: string }>(`
      UPDATE party_authority_amendments SET expires_at_ms = $expiresAtMs
      WHERE job_id = $jobId AND role = 'buyer'
    `).run({ expiresAtMs: NOW - 1, jobId: JOB });
    current.add(OLD_BUYER);
    expect(restarted.authorize(replacement.token, replacement.scope)).toBe(false);
    expect(restarted.allocatePartyChallenge(signedAllocation(
      OLD_BUYER,
      "allocation-after-amendment-expiry",
      ["artifact:read"],
    )).disposition).toBe("rejected");
    restarted.close();
    reopened.close();
  });
});

function issueParty(
  lifecycle: PartyAuthorityLifecycle,
  key: string,
  expiresAtMs: number,
  idempotency: string,
  operations: readonly string[] = ["artifact:read", "session:read"],
) {
  const result = issuePartyResult(lifecycle, key, expiresAtMs, idempotency, operations);
  if (!("grant" in result)) throw new Error(`party grant failed: ${result.disposition}`);
  return result.grant;
}

function issuePartyResult(
  lifecycle: PartyAuthorityLifecycle,
  key: string,
  expiresAtMs: number,
  idempotency: string,
  operations: readonly string[] = ["artifact:read", "session:read"],
) {
  const allocation = signedAllocation(key, idempotency, operations);
  const challenge = lifecycle.allocatePartyChallenge(allocation);
  if (!("challenge" in challenge)) throw new Error(`challenge failed: ${challenge.disposition}`);
  const scope: PartyCapabilityScope = {
    kind: "party",
    instanceId: INSTANCE,
    audience: AUDIENCE,
    principal: "did:demos:buyer",
    operations,
    expiresAtMs,
    jobId: JOB,
    role: "buyer",
    authority: { kind: "agreement", key },
  };
  const replacementToken = lifecycle.prepareCapabilityReplacement();
  return lifecycle.exchangePartyChallenge({
    nonce: challenge.challenge.nonce,
    expiresAtMs,
    replacementToken,
    proof: sign(key, partyCapabilityExchangeSigningBytes({
      nonce: challenge.challenge.nonce,
      replacementDigest: createHash("sha256").update(replacementToken).digest("hex"),
      scope,
    })),
  });
}

function signedAllocation(
  key: string,
  idempotency: string,
  operations: readonly string[] = ["artifact:read", "session:read"],
): PartyChallengeAllocationInput {
  const unsigned: PartyChallengeAllocationInput = {
    clientIdempotencyKey: idempotency,
    clientNonce: createHmac("sha256", "nonce").update(idempotency).digest("hex").slice(0, 32),
    jobId: JOB,
    operations,
    principal: "did:demos:buyer",
    proof: "pending",
    requestedAtMs: NOW,
    role: "buyer",
  };
  return { ...unsigned, proof: sign(key, partyChallengeAllocationSigningBytes(unsigned)) };
}

function authority(
  database: ReturnType<typeof openDatabase>,
  current: Set<string>,
  agreement: { hash: string; counterpartyKey: string },
) {
  return new PartyAuthorityLifecycle(database, {
    audience: AUDIENCE,
    instanceId: INSTANCE,
    keyCurrentness: {
      resolve: ({ keyClaim, checkedAt }) => current.has(keyClaim)
        ? { disposition: "current", currentClaim: keyClaim, recipeVersion: 1, checkedAt }
        : { disposition: "revoked", currentClaim: NEW_BUYER, recipeVersion: 1, checkedAt },
    },
    now: () => NOW,
    partyAuthority: {
      resolve: ({ jobId, role }) => {
        if (jobId !== JOB) return { disposition: "unavailable" as const };
        return role === "buyer"
          ? {
              disposition: "current" as const,
              principal: "did:demos:buyer",
              authority: {
                kind: "agreement" as const,
                key: OLD_BUYER,
                agreementHash: agreement.hash,
                counterpartyKey: agreement.counterpartyKey,
              },
            }
          : {
              disposition: "current" as const,
              principal: "did:demos:seller",
              authority: {
                kind: "agreement" as const,
                key: SELLER,
                agreementHash: agreement.hash,
                counterpartyKey: OLD_BUYER,
              },
            };
      },
    },
    proofVerifier: { verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(),
  });
}

function bootstrap(databasePath: string, outputPath: string): void {
  const request = prepareAuthorityBootstrap({
    administratorKey: ADMIN,
    administratorOperations: ["capability:revoke"],
    administratorPrincipal: "did:demos:administrator",
    audience: AUDIENCE,
    expiresAtMs: NOW + 60_000,
    instanceId: INSTANCE,
    outputPath,
    recoveryKey: RECOVERY,
    requestedAtMs: NOW,
    storeBinding: authorityStoreBinding(databasePath),
  }, entropy());
  const bytes = authorityBootstrapSigningBytes(request);
  completeAuthorityBootstrap({
    request,
    administratorProof: sign(ADMIN, bytes),
    recoveryProof: sign(RECOVERY, bytes),
  }, {
    databasePath,
    keyCurrentness: { resolve: ({ keyClaim, checkedAt }) => ({
      disposition: "current", currentClaim: keyClaim, recipeVersion: 1, checkedAt,
    }) },
    now: () => NOW,
    proofVerifier: { verify: ({ key, proof, signedBytes }) => proof === sign(key, signedBytes) },
    randomBytes: entropy(),
  });
}

function sign(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("hex");
}

function entropy(): (size: number) => Uint8Array {
  let value = 1n;
  return (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, value++);
    return bytes;
  };
}

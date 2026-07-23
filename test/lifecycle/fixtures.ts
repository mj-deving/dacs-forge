import { createHmac } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { UnsignedAgreementArtifact } from "../../src/producer/agreement.ts";
import type { UnsignedListing } from "../../src/producer/listing.ts";
import type { ArtifactSigner } from "../../src/producer/fixture-ed25519.ts";
import {
  FixtureLifecycleOrchestrator,
  fixtureLifecycleRequestHash,
  type FixtureLifecycleOrchestratorOptions,
} from "../../src/lifecycle/fixture-orchestrator.ts";
import {
  FixtureCommitmentStore,
  type AgreementCommitVerification,
  type TrustedHistoricalCommitment,
} from "../../src/substrate/sqlite/fixture-commitment.ts";
import { openDatabase, type DacsDatabase } from "../../src/substrate/sqlite/database.ts";
import {
  SessionStore,
  admissionSigningBytes,
  challengeAllocationSigningBytes,
  type AdmissionInput,
  type ChallengeAllocationInput,
} from "../../src/substrate/sqlite/session-store.ts";
import {
  FIXTURE_COMMITTED_AT,
  FIXTURE_JOB_ID,
  fixtureAgreementSigningOptions,
  fixtureBuyerIdentity,
  fixtureListingSellerIdentity,
  fixtureSignedPaidListing,
  fixtureUnsignedPayeeBoundAgreement,
  signFixtureAgreementForListing,
} from "../fixtures/reference-agreement.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

const AUTHENTICATION_KEY = "fixture-lifecycle-authentication-key";
export const LIFECYCLE_INSTANCE_ID = "reference-lifecycle-instance";
export const LIFECYCLE_AUDIENCE = "https://lifecycle.service.example";
export const LIFECYCLE_NOW = new Date(FIXTURE_COMMITTED_AT).toISOString();

export interface AgreementFixture {
  readonly agreementCanonicalJson: string;
  readonly input: UnsignedAgreementArtifact;
  readonly verification: AgreementCommitVerification;
}

export async function lifecycleDatabasePath(): Promise<string> {
  return join(await mkdtemp(join(tmpdir(), "dacs-lifecycle-")), "state.sqlite");
}

export function agreementFixture(
  mutate?: (input: UnsignedAgreementArtifact) => UnsignedAgreementArtifact,
  listingOverrides: Partial<UnsignedListing> = {},
): AgreementFixture {
  const listing = fixtureSignedPaidListing(listingOverrides);
  const base = fixtureUnsignedPayeeBoundAgreement(listing);
  const input = mutate?.(base) ?? base;
  const signed = signFixtureAgreementForListing(input, listing);
  const options = fixtureAgreementSigningOptions(input, listing);
  return Object.freeze({
    agreementCanonicalJson: signed.canonicalJson,
    input,
    verification: Object.freeze({
      expectedCommitPhase: options.expectedCommitPhase,
      listingCanonicalJson: options.listingCanonicalJson,
      listingVerification: options.listingVerification,
      listingAuthority: {
        railRegistryVersion: 1,
        recipeRegistryVersion: 1,
        revocationCheck: () => "absent",
        paymentRailCheck: ({ railId }: { readonly railId: string }) => railId === "x402:default"
          ? { status: "resolved" as const, phaseHandler: "pay-x402" }
          : railId === "demos-native:DEM"
            ? { status: "resolved" as const, phaseHandler: "pay-dem" }
            : { status: "unresolved" as const },
      },
      partyIdentityCanonicalJsons: [
        fixtureBuyerIdentity().canonicalJson,
        fixtureListingSellerIdentity(listing).canonicalJson,
      ],
      vettedPartyCheck: options.vettedPartyCheck,
      ...(options.sealedEnvelopeResult === undefined
        ? {} : { sealedEnvelopeResult: options.sealedEnvelopeResult }),
    }),
  });
}

export interface LifecycleDeploymentFixture {
  readonly audience?: string;
  readonly entropyByte?: number;
  readonly instanceId?: string;
  readonly jobId?: string;
}

export function lifecycleSessionStore(
  database: DacsDatabase,
  deployment: LifecycleDeploymentFixture = {},
): SessionStore {
  const instanceId = deployment.instanceId ?? LIFECYCLE_INSTANCE_ID;
  const audience = deployment.audience ?? LIFECYCLE_AUDIENCE;
  const jobId = deployment.jobId ?? FIXTURE_JOB_ID;
  return new SessionStore(database, {
    audience,
    authenticator: { verify: ({ proof, signedBytes }) => proof === sign(signedBytes) },
    deploymentMode: "fixture",
    instanceId,
    jobAuthorizer: { authorize: ({ jobId: candidate }) => candidate === jobId },
    now: () => FIXTURE_COMMITTED_AT - 1_000,
    randomBytes: () => Buffer.alloc(16, deployment.entropyByte ?? 9),
  });
}

export function admitLifecycleSession(
  store: SessionStore,
  agreementCanonicalJson: string,
  deployment: LifecycleDeploymentFixture = {},
  requestHash = fixtureLifecycleRequestHash(agreementCanonicalJson),
): void {
  const instanceId = deployment.instanceId ?? LIFECYCLE_INSTANCE_ID;
  const audience = deployment.audience ?? LIFECYCLE_AUDIENCE;
  const jobId = deployment.jobId ?? FIXTURE_JOB_ID;
  const suffix = deployment.entropyByte ?? 9;
  const unsignedChallenge: ChallengeAllocationInput = {
    instanceId,
    audience,
    principal: "did:demos:fixture-lifecycle-buyer",
    jobId,
    evidenceMode: "fixture",
    clientNonce: suffix.toString(16).padStart(32, "0"),
    clientIdempotencyKey: `fixture-lifecycle-request-${suffix}`,
    requestedAtMs: FIXTURE_COMMITTED_AT - 1_000,
    proof: "pending",
  };
  const challenge = store.allocateChallenge({
    ...unsignedChallenge,
    proof: sign(challengeAllocationSigningBytes(unsignedChallenge)),
  });
  if (challenge.disposition !== "created") throw new Error("Lifecycle challenge was not created");
  const unsignedAdmission: AdmissionInput = {
    instanceId: challenge.challenge.instanceId,
    audience: challenge.challenge.audience,
    principal: challenge.challenge.principal,
    jobId: challenge.challenge.jobId,
    evidenceMode: "fixture",
    nonce: challenge.challenge.nonce,
    idempotencyKey: `fixture-lifecycle-request-${suffix}`,
    requestHash,
    proof: "pending",
  };
  const admitted = store.admit({
    ...unsignedAdmission,
    proof: sign(admissionSigningBytes(unsignedAdmission)),
  });
  if (admitted.disposition !== "created") throw new Error("Lifecycle session was not admitted");
}

export function lifecycleCommitmentStore(
  database: DacsDatabase,
  anchorTimeMs = FIXTURE_COMMITTED_AT,
  signer: ArtifactSigner = fixtureSigner(),
  trustedHistoricalCommitments: readonly TrustedHistoricalCommitment[] = [],
): FixtureCommitmentStore {
  return new FixtureCommitmentStore(database, {
    anchorTimeMs: () => anchorTimeMs,
    deploymentMode: "fixture",
    now: () => LIFECYCLE_NOW,
    preAnchorTimeMs: () => FIXTURE_COMMITTED_AT - 1,
    signer,
    trustedHistoricalCommitments,
  });
}

export function lifecycleOrchestrator(
  database: DacsDatabase,
  sessionStore: SessionStore,
  commitmentStore: FixtureCommitmentStore,
  handlers: Pick<FixtureLifecycleOrchestratorOptions, "payment" | "settlement" | "delivery">
    & Partial<Pick<FixtureLifecycleOrchestratorOptions, "now" | "substratePauseMs">>,
): FixtureLifecycleOrchestrator {
  return new FixtureLifecycleOrchestrator(database, {
    commitmentStore,
    sessionStore,
    ...handlers,
    now: handlers.now ?? (() => LIFECYCLE_NOW),
  });
}

export function openLifecycleDatabase(path: string): DacsDatabase {
  return openDatabase(path);
}

function sign(value: string): string {
  return createHmac("sha256", AUTHENTICATION_KEY).update(value).digest("hex");
}

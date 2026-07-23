import { canonicalize } from "../../protocol/canonical-json.ts";
import { sha256Hex } from "../../protocol/hash.ts";
import { listingLogicalAddress } from "../../protocol/logical-address.ts";
import {
  RECIPE_AVAILABILITIES,
  compositeVerificationLogicalAddress,
  verifyResultLogicalAddress,
  type RecipeAvailability,
  type VetBundleRequirement,
  type VetDecision,
} from "../../protocol/vet.ts";
import { verifyCanonicalCompositeVerificationRecordJson } from "../../consumer/composite-verification-record-verifier.ts";
import { verifyBuyerVetRequirementJson } from "../../consumer/buyer-vet-requirement-verifier.ts";
import { verifyFixtureKeyPossessionJson } from "../../consumer/fixture-key-possession-verifier.ts";
import { verifyCanonicalListingJson } from "../../consumer/listing-verifier.ts";
import { verifyCanonicalVerifyResultJson } from "../../consumer/verify-result-verifier.ts";
import { signCompositeVerificationRecord } from "../../producer/composite-verification-record.ts";
import {
  signFixtureKeyPossession,
} from "../../producer/fixture-key-possession.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
} from "../../producer/fixture-ed25519.ts";
import { signVerifyResult } from "../../producer/verify-result.ts";
import { assertFixtureAuthority } from "../../core/evidence-mode.ts";
import { ArtifactIntegrityError, ArtifactStore, type ArtifactRecord } from "./artifact-store.ts";
import type { DacsDatabase } from "./database.ts";
import { readPersistedSession, type SessionRecord } from "./session-store.ts";

const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
export const FIXTURE_RECIPE_REGISTRY_VERSION = 1;
export const FIXTURE_KEY_DEFAULT_MAX_AGE_SEC = 300;
const FIXTURE_KEY_AVAILABILITY_BY_VERSION = Object.freeze({
  1: "live",
  2: "mocked",
  3: "disabled",
  4: "failed",
} as const);

export class FixtureVetConflictError extends Error {
  override readonly name = "FixtureVetConflictError";
}

export class FixtureVetIntegrityError extends Error {
  override readonly name = "FixtureVetIntegrityError";
}

export class FixtureVetPresentationError extends Error {
  override readonly name = "FixtureVetPresentationError";
}

export interface FixtureVetInput {
  readonly session: SessionRecord;
  readonly evaluatedRole: "buyer" | "seller";
  readonly evaluatedBundleHash: string;
  readonly requirementAuthority: FixtureVetRequirementAuthority;
  readonly evaluatedSigner: ArtifactSigner;
  readonly verifierSigner: ArtifactSigner;
  readonly generatedAt: number;
  readonly createdAt: string;
}

export type FixtureVetSessionScope = Readonly<Pick<SessionRecord, "instanceId" | "audience" | "jobId">>;

export interface FixtureRecipeRegistryAuthority {
  readonly version: number;
  readonly keyAvailability: RecipeAvailability;
  readonly keyDefaultMaxAgeSec: number;
}

const DEFAULT_FIXTURE_RECIPE_REGISTRY = Object.freeze({
  version: FIXTURE_RECIPE_REGISTRY_VERSION,
  keyAvailability: "live" as const,
  keyDefaultMaxAgeSec: FIXTURE_KEY_DEFAULT_MAX_AGE_SEC,
});

export type FixtureVetRequirementAuthority =
  | { readonly kind: "seller-listing"; readonly canonicalJson: string }
  | { readonly kind: "buyer-signed"; readonly canonicalJson: string };

export interface FixtureVetRecord {
  readonly instanceId: string;
  readonly audience: string;
  readonly jobId: string;
  readonly evaluatedRole: "buyer" | "seller";
  readonly evaluatedParty: string;
  readonly verifierParty: string;
  readonly bundleHash: string;
  readonly requirementHash: string;
  readonly requirementCanonicalJson: string;
  readonly requirementSourceKind: "seller-listing" | "buyer-signed";
  readonly requirementSourceAddress: string;
  readonly requirementSourceContentHash: string;
  readonly requirementSourceArtifactHash: string;
  readonly recipeRegistryVersion: number;
  readonly recipeAvailability: RecipeAvailability;
  readonly assertionAddress: string;
  readonly assertionArtifactHash: string;
  readonly verifyResultAddress: string;
  readonly verifyResultArtifactHash: string;
  readonly compositeAddress: string;
  readonly compositeArtifactHash: string;
  readonly overallDecision: VetDecision;
  readonly generatedAt: number;
  readonly createdAt: string;
  readonly compositeReference: Readonly<Record<string, unknown>>;
}

export type FixtureAgreementVetAuthority =
  | { readonly mode: "legacy-fixture" }
  | {
      readonly mode: "dacs2";
      readonly buyer: FixtureVetRecord;
      readonly seller: FixtureVetRecord;
    };

interface FixtureVetRow extends Omit<FixtureVetRecord, "recipeRegistryVersion" | "generatedAt" | "compositeReference"> {
  readonly recipeRegistryVersion: bigint;
  readonly generatedAt: bigint;
}

interface PreparedVet {
  readonly input: FixtureVetInput;
  readonly evaluatedParty: string;
  readonly verifierParty: string;
  readonly requirementCanonicalJson: string;
  readonly requirementHash: string;
  readonly requirement: VetBundleRequirement;
  readonly requirementSourceKind: "seller-listing" | "buyer-signed";
  readonly requirementSourceAddress: string;
  readonly requirementSourceContentHash: string;
  readonly requirementSourceValue: Readonly<Record<string, unknown>>;
  readonly recipeRegistry: FixtureRecipeRegistryAuthority;
  readonly assertion: ReturnType<typeof signFixtureKeyPossession>;
  readonly verifyResult: ReturnType<typeof signVerifyResult>;
  readonly verifyResultAddress: string;
  readonly composite: ReturnType<typeof signCompositeVerificationRecord>;
  readonly compositeAddress: string;
}

export class FixtureVetStore {
  readonly #artifacts: ArtifactStore;
  readonly #database: DacsDatabase;
  readonly #persist: (prepared: PreparedVet) => void;
  readonly #recipeRegistry: FixtureRecipeRegistryAuthority;

  constructor(
    database: DacsDatabase,
    deploymentMode: "fixture" | "local-chain" | "live",
    recipeRegistry: FixtureRecipeRegistryAuthority = DEFAULT_FIXTURE_RECIPE_REGISTRY,
  ) {
    assertFixtureAuthority(deploymentMode, "fixture");
    if (recipeRegistry === null || typeof recipeRegistry !== "object"
      || !Number.isSafeInteger(recipeRegistry.version)
      || FIXTURE_KEY_AVAILABILITY_BY_VERSION[
        recipeRegistry.version as keyof typeof FIXTURE_KEY_AVAILABILITY_BY_VERSION
      ] !== recipeRegistry.keyAvailability
      || !RECIPE_AVAILABILITIES.includes(recipeRegistry.keyAvailability)
      || recipeRegistry.keyDefaultMaxAgeSec !== FIXTURE_KEY_DEFAULT_MAX_AGE_SEC) {
      throw new TypeError("Fixture recipe registry authority is unsupported");
    }
    this.#database = database;
    this.#recipeRegistry = Object.freeze({ ...recipeRegistry });
    this.#artifacts = new ArtifactStore(database);
    const transaction = database.transaction((prepared: PreparedVet) => this.#persistWithinTransaction(prepared));
    this.#persist = (prepared) => { transaction.immediate(prepared); };
  }

  run(input: FixtureVetInput): FixtureVetRecord {
    const persistedSession = readPersistedSession(
      this.#database,
      input.session.instanceId,
      input.session.audience,
      input.session.jobId,
    );
    if (persistedSession === null || !sameSession(persistedSession, input.session)) {
      throw new FixtureVetIntegrityError("Fixture Vet session differs from persisted admission authority");
    }
    const prepared = this.#prepare(Object.freeze({ ...input, session: persistedSession }));
    this.#persist(prepared);
    const stored = this.get(input.session, input.evaluatedRole);
    if (stored === null) throw new FixtureVetIntegrityError("Fixture Vet record was not visible after persistence");
    return stored;
  }

  get(scope: FixtureVetSessionScope, evaluatedRole: "buyer" | "seller"): FixtureVetRecord | null {
    if (scope === null || typeof scope !== "object"
      || typeof scope.instanceId !== "string" || scope.instanceId.length === 0
      || typeof scope.audience !== "string" || scope.audience.length === 0
      || !ULID.test(scope.jobId)
      || (evaluatedRole !== "buyer" && evaluatedRole !== "seller")) {
      throw new TypeError("Fixture Vet lookup binding is invalid");
    }
    const row = this.#readRow(scope, evaluatedRole);
    if (row === null) return null;
    const record = rowToRecord(row);
    const persistedSession = readPersistedSession(
      this.#database,
      scope.instanceId,
      scope.audience,
      scope.jobId,
    );
    const admittedAt = persistedSession === null ? Number.NaN : Date.parse(persistedSession.createdAt);
    if (persistedSession === null || !exactTimestamp(admittedAt, persistedSession.createdAt)
      || record.generatedAt < admittedAt
      || !exactTimestamp(record.generatedAt, record.createdAt)) {
      throw new FixtureVetIntegrityError("Persisted Vet chronology differs from admission authority");
    }
    if (record.recipeRegistryVersion !== this.#recipeRegistry.version
      || record.recipeAvailability !== this.#recipeRegistry.keyAvailability) {
      throw new FixtureVetIntegrityError("Persisted Vet recipe authority differs from the configured registry");
    }
    const requirementSource = requiredArtifact(
      this.#artifacts,
      record.requirementSourceArtifactHash,
      record.requirementSourceKind === "seller-listing" ? "dacs-1-listing" : "dacs-x-buyer-vet-requirement",
    );
    const assertion = requiredArtifact(this.#artifacts, record.assertionArtifactHash, "dacs-x-fixture-key-possession");
    const verifyResult = requiredArtifact(this.#artifacts, record.verifyResultArtifactHash, "dacs-2-verify-result");
    const composite = requiredArtifact(this.#artifacts, record.compositeArtifactHash, "dacs-2-composite");
    assertAnchorBinding(
      this.#database,
      requirementSource,
      record.requirementSourceAddress,
      record.requirementSourceKind === "seller-listing" ? "dacs-1-listing" : "dacs-x-buyer-vet-requirement",
      record.requirementSourceContentHash,
    );
    assertAnchor(this.#database, assertion, record.assertionAddress, "dacs-x-fixture-key-possession");
    assertAnchor(this.#database, verifyResult, record.verifyResultAddress, "dacs-2-verify-result");
    assertAnchor(this.#database, composite, record.compositeAddress, "dacs-2-composite");

    const assertionVerification = verifyFixtureKeyPossessionJson(assertion.canonicalJson, {
      jobId: record.jobId,
      evaluatedParty: record.evaluatedParty,
      bundleHash: record.bundleHash,
    });
    if (assertionVerification.disposition !== "verified"
      || assertionVerification.logicalAddress !== record.assertionAddress
      || assertionVerification.observedAt !== record.generatedAt) {
      throw new FixtureVetIntegrityError("Persisted fixture key-possession evidence is invalid");
    }
    const verifiedResult = verifyCanonicalVerifyResultJson(verifyResult.canonicalJson, {
      availability: record.recipeAvailability,
      expectedScheme: "key",
      expectedIdentifier: record.evaluatedParty.slice("key:".length),
      expectedRecipeVersion: record.recipeRegistryVersion,
      expectedMethod: "self-signed",
      expectedVerifier: record.verifierParty,
      jobId: record.jobId,
      resolveAttestation: (reference) => {
        const anchor = reference["anchor"] as Record<string, unknown>;
        return anchor?.["kind"] === "storage-program" && anchor["locator"] === record.assertionAddress
          && reference["contentHash"] === assertion.contentHash
          && reference["signer"] === record.evaluatedParty
          ? {
              status: "resolved" as const,
              canonicalJson: assertion.canonicalJson,
              signer: record.evaluatedParty,
              signatureVerified: true,
            }
          : { status: "rejected" as const, reason: "VerifyResult attestation authority does not match persisted Vet evidence" };
      },
    });
    if (verifiedResult.disposition !== "verified"
      || verifiedResult.logicalAddress !== record.verifyResultAddress
      || verifiedResult.contentHash !== record.verifyResultArtifactHash
      || verifiedResult.fetchedAt !== record.generatedAt
      || verifiedResult.verifiedAt !== record.generatedAt) {
      throw new FixtureVetIntegrityError("Persisted VerifyResult is invalid or misbound");
    }
    const requirement = verifyPersistedRequirementAuthority(record, requirementSource.canonicalJson, admittedAt);
    const verifiedComposite = verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: record.jobId,
      evaluatedParty: record.evaluatedParty,
      evaluatedClaims: [record.evaluatedParty],
      bundleHash: record.bundleHash,
      requirementHash: record.requirementHash,
      requirement,
      expectedVerifier: record.verifierParty,
      resolveRecipeAuthority: (scheme, version) => scheme === "key" && version === this.#recipeRegistry.version
        ? {
            status: "resolved",
            availability: this.#recipeRegistry.keyAvailability,
            defaultMaxAgeSec: this.#recipeRegistry.keyDefaultMaxAgeSec,
          }
        : { status: "rejected", reason: "Recipe is absent from the configured fixture registry" },
      resolveAttestation: () => ({
        status: "resolved",
        canonicalJson: assertion.canonicalJson,
        signer: record.evaluatedParty,
        signatureVerified: true,
      }),
      resolveVerifyResult: (reference) => {
        const anchor = reference["anchor"] as Record<string, unknown>;
        return anchor?.["kind"] === "storage-program" && anchor["locator"] === record.verifyResultAddress
          && reference["contentHash"] === verifyResult.contentHash
          ? {
              status: "resolved" as const,
              availability: record.recipeAvailability,
              canonicalJson: verifyResult.canonicalJson,
            }
          : { status: "rejected" as const, reason: "Composite VerifyResult authority does not match persisted Vet evidence" };
      },
    });
    if (verifiedComposite.disposition !== "verified"
      || verifiedComposite.logicalAddress !== record.compositeAddress
      || verifiedComposite.contentHash !== record.compositeArtifactHash
      || verifiedComposite.generatedAt !== record.generatedAt
      || verifiedComposite.overallDecision !== record.overallDecision) {
      throw new FixtureVetIntegrityError("Persisted CompositeVerificationRecord is invalid or misbound");
    }
    return record;
  }

  assertAgreementAuthority(
    agreement: Readonly<Record<string, unknown>>,
    scope: FixtureVetSessionScope,
    notAfter: number,
  ): FixtureAgreementVetAuthority {
    const jobId = agreement["jobId"];
    const parties = agreement["parties"];
    const listingRef = object(agreement["listingRef"]);
    if (scope === null || typeof scope !== "object"
      || typeof scope.instanceId !== "string" || scope.instanceId.length === 0
      || typeof scope.audience !== "string" || scope.audience.length === 0
      || typeof scope.jobId !== "string" || !ULID.test(scope.jobId)
      || typeof jobId !== "string" || !ULID.test(jobId) || jobId !== scope.jobId
      || !Number.isSafeInteger(notAfter) || notAfter < 0
      || !Array.isArray(parties) || listingRef === null) {
      throw new FixtureVetIntegrityError("Agreement Vet authority shape is invalid");
    }
    const buyerParty = parties.find((party) => object(party)?.["role"] === "buyer") as Record<string, unknown> | undefined;
    const sellerParty = parties.find((party) => object(party)?.["role"] === "seller") as Record<string, unknown> | undefined;
    const buyerRef = object(buyerParty?.["vetRecordRef"]);
    const sellerRef = object(sellerParty?.["vetRecordRef"]);
    if (buyerParty === undefined || sellerParty === undefined || buyerRef === null || sellerRef === null) {
      throw new FixtureVetIntegrityError("Agreement lacks exact buyer and seller Vet authority");
    }
    if (isLegacyFixtureVetReference(buyerRef, "buyer")
      && isLegacyFixtureVetReference(sellerRef, "seller")) {
      return Object.freeze({ mode: "legacy-fixture" });
    }
    if (!isCompositeVetReference(buyerRef) || !isCompositeVetReference(sellerRef)) {
      throw new FixtureVetIntegrityError("Agreement carries unsupported or mixed Vet references");
    }
    const buyer = this.get(scope, "buyer");
    const seller = this.get(scope, "seller");
    const expectedBuyerRequirementSource = typeof sellerParty["primaryClaim"] === "string"
      && typeof listingRef["listingId"] === "string"
      && Number.isSafeInteger(listingRef["version"])
      && typeof listingRef["contentHash"] === "string"
      ? {
          address: listingLogicalAddress(
            sellerParty["primaryClaim"],
            listingRef["listingId"],
            listingRef["version"] as number,
          ),
          contentHash: listingRef["contentHash"],
        }
      : null;
    if (buyer === null || seller === null
      || buyer.overallDecision !== "pass" || seller.overallDecision !== "pass"
      || buyer.evaluatedParty !== buyerParty["primaryClaim"]
      || buyer.bundleHash !== buyerParty["bundleHash"]
      || seller.evaluatedParty !== sellerParty["primaryClaim"]
      || seller.bundleHash !== sellerParty["bundleHash"]
      || buyer.verifierParty !== seller.evaluatedParty
      || seller.verifierParty !== buyer.evaluatedParty
      || canonicalize([buyerRef, sellerRef]) !== canonicalize([
        buyer.compositeReference,
        seller.compositeReference,
      ])) {
      throw new FixtureVetIntegrityError("Agreement Vet references do not resolve to two exact passing reciprocal records");
    }
    if (expectedBuyerRequirementSource === null
      || buyer.requirementSourceKind !== "seller-listing"
      || buyer.requirementSourceAddress !== expectedBuyerRequirementSource.address
      || buyer.requirementSourceContentHash !== expectedBuyerRequirementSource.contentHash) {
      throw new FixtureVetIntegrityError("Buyer Vet requirement source does not match the Agreement Listing");
    }
    if (buyer.generatedAt > notAfter || seller.generatedAt > notAfter) {
      throw new FixtureVetIntegrityError("Agreement Vet evidence does not precede its DACS-3 authority time");
    }
    return Object.freeze({ mode: "dacs2", buyer, seller });
  }

  #prepare(input: FixtureVetInput): PreparedVet {
    validateInput(input);
    assertFixtureSigningAuthority(input.evaluatedSigner, {
      deploymentMode: input.session.evidenceMode,
      requestMode: input.session.evidenceMode,
    });
    assertFixtureSigningAuthority(input.verifierSigner, {
      deploymentMode: input.session.evidenceMode,
      requestMode: input.session.evidenceMode,
    });
    const evaluatedParty = input.evaluatedSigner.signer;
    const verifierParty = input.verifierSigner.signer;
    if (evaluatedParty === verifierParty) throw new TypeError("Fixture Vet requires distinct evaluated and verifier parties");
    let requirementAuthority: ReturnType<typeof prepareRequirementAuthority>;
    try {
      requirementAuthority = prepareRequirementAuthority(input, evaluatedParty, verifierParty);
    } catch (error) {
      if (error instanceof FixtureVetIntegrityError || error instanceof TypeError) {
        throw new FixtureVetPresentationError(error.message);
      }
      throw error;
    }
    const requirementCanonicalJson = canonicalize(requirementAuthority.requirement);
    const requirementHash = sha256Hex(requirementCanonicalJson);
    const recipeRegistry = this.#recipeRegistry;
    const context = { deploymentMode: "fixture" as const, requestMode: "fixture" as const };
    const assertion = signFixtureKeyPossession({
      jobId: input.session.jobId,
      evaluatedParty,
      bundleHash: input.evaluatedBundleHash,
      observedAt: input.generatedAt,
    }, input.evaluatedSigner, context);
    const assertionVerification = verifyFixtureKeyPossessionJson(assertion.canonicalJson, {
      jobId: input.session.jobId,
      evaluatedParty,
      bundleHash: input.evaluatedBundleHash,
    });
    if (assertionVerification.disposition !== "verified") {
      throw new FixtureVetIntegrityError("Produced key-possession assertion failed independent verification");
    }
    const verifyResult = signVerifyResult({
      resultVersion: "1",
      scheme: "key",
      identifier: evaluatedParty.slice("key:".length),
      recipeVersion: recipeRegistry.version,
      method: "self-signed",
      decision: "pass",
      reason: "fixture key possession verified",
      attestation: {
        anchor: { kind: "storage-program", locator: assertion.logicalAddress },
        contentHash: assertion.contentHash,
        signer: evaluatedParty,
      },
      data: { possessionVerified: true },
      fetchedAt: input.generatedAt,
      verifiedAt: input.generatedAt,
    }, recipeRegistry.keyAvailability, input.verifierSigner, context);
    const verifyResultAddress = verifyResultLogicalAddress(
      input.session.jobId, "key", evaluatedParty.slice("key:".length), recipeRegistry.version,
    );
    const verifyResultVerification = verifyCanonicalVerifyResultJson(verifyResult.canonicalJson, {
      availability: recipeRegistry.keyAvailability,
      expectedScheme: "key",
      expectedIdentifier: evaluatedParty.slice("key:".length),
      expectedRecipeVersion: recipeRegistry.version,
      expectedMethod: "self-signed",
      expectedVerifier: verifierParty,
      jobId: input.session.jobId,
      resolveAttestation: (reference) => reference["contentHash"] === assertion.contentHash
        && reference["signer"] === evaluatedParty
        ? {
            status: "resolved",
            canonicalJson: assertion.canonicalJson,
            signer: evaluatedParty,
            signatureVerified: true,
          }
        : { status: "rejected", reason: "Produced VerifyResult does not reference its exact assertion" },
    });
    if (verifyResultVerification.disposition !== "verified"
      || verifyResultVerification.logicalAddress !== verifyResultAddress) {
      throw new FixtureVetIntegrityError("Produced VerifyResult failed independent verification before persistence");
    }
    const reference = {
      anchor: { kind: "storage-program" as const, locator: verifyResultAddress },
      contentHash: verifyResult.contentHash,
      recipeVersion: recipeRegistry.version,
    };
    const composite = signCompositeVerificationRecord({
      jobId: input.session.jobId,
      evaluatedParty,
      bundleHash: input.evaluatedBundleHash,
      requirementHash,
      requirement: requirementAuthority.requirement,
      freshness: [],
      dealSpecific: [{
        reference,
        scheme: "key",
        decision: verifyResult.decision,
        availability: verifyResult.availability,
        recipeVersion: recipeRegistry.version,
        verifiedAt: input.generatedAt,
        verificationPerformed: true,
        data: { possessionVerified: true },
      }],
      generatedAt: input.generatedAt,
    }, input.verifierSigner, context);
    const compositeAddress = compositeVerificationLogicalAddress(input.session.jobId, evaluatedParty);
    const compositeVerification = verifyCanonicalCompositeVerificationRecordJson(composite.canonicalJson, {
      jobId: input.session.jobId,
      evaluatedParty,
      evaluatedClaims: [evaluatedParty],
      bundleHash: input.evaluatedBundleHash,
      requirementHash,
      requirement: requirementAuthority.requirement,
      expectedVerifier: verifierParty,
      resolveRecipeAuthority: (scheme, version) => scheme === "key" && version === recipeRegistry.version
        ? {
            status: "resolved",
            availability: recipeRegistry.keyAvailability,
            defaultMaxAgeSec: recipeRegistry.keyDefaultMaxAgeSec,
          }
        : { status: "rejected", reason: "Recipe is absent from the configured fixture registry" },
      resolveAttestation: () => ({
        status: "resolved",
        canonicalJson: assertion.canonicalJson,
        signer: evaluatedParty,
        signatureVerified: true,
      }),
      resolveVerifyResult: (candidate) => candidate["contentHash"] === verifyResult.contentHash
        ? { status: "resolved", availability: recipeRegistry.keyAvailability, canonicalJson: verifyResult.canonicalJson }
        : { status: "rejected", reason: "Produced Composite does not reference its exact VerifyResult" },
    });
    if (compositeVerification.disposition !== "verified"
      || compositeVerification.logicalAddress !== compositeAddress) {
      throw new FixtureVetIntegrityError("Produced Composite failed independent verification before persistence");
    }
    return Object.freeze({
      input, evaluatedParty, verifierParty, requirementCanonicalJson, requirementHash,
      requirement: requirementAuthority.requirement,
      requirementSourceKind: requirementAuthority.kind,
      requirementSourceAddress: requirementAuthority.logicalAddress,
      requirementSourceContentHash: requirementAuthority.contentHash,
      requirementSourceValue: requirementAuthority.value, recipeRegistry,
      assertion, verifyResult, verifyResultAddress, composite, compositeAddress,
    });
  }

  #persistWithinTransaction(prepared: PreparedVet): void {
    const existing = this.#readRow(prepared.input.session, prepared.input.evaluatedRole);
    if (existing !== null) {
      assertReplay(rowToRecord(existing), prepared);
      return;
    }
    const requirementSourceKind = prepared.requirementSourceKind === "seller-listing"
      ? "dacs-1-listing" : "dacs-x-buyer-vet-requirement";
    const requirementSourceArtifact = this.#artifacts.putWithinTransaction(
      requirementSourceKind, prepared.requirementSourceValue, prepared.input.createdAt,
    );
    const assertionArtifact = this.#artifacts.putWithinTransaction(
      "dacs-x-fixture-key-possession", prepared.assertion.assertion, prepared.input.createdAt,
    );
    const verifyResultArtifact = this.#artifacts.putWithinTransaction(
      "dacs-2-verify-result", prepared.verifyResult.verifyResult, prepared.input.createdAt,
    );
    const compositeArtifact = this.#artifacts.putWithinTransaction(
      "dacs-2-composite", prepared.composite.record, prepared.input.createdAt,
    );
    putAnchorWithContentHash(
      this.#database,
      prepared.requirementSourceAddress,
      requirementSourceKind,
      prepared.requirementSourceContentHash,
      requirementSourceArtifact,
      prepared.input.createdAt,
    );
    putAnchor(this.#database, prepared.assertion.logicalAddress, "dacs-x-fixture-key-possession", assertionArtifact, prepared.input.createdAt);
    putAnchor(this.#database, prepared.verifyResultAddress, "dacs-2-verify-result", verifyResultArtifact, prepared.input.createdAt);
    putAnchor(this.#database, prepared.compositeAddress, "dacs-2-composite", compositeArtifact, prepared.input.createdAt);
    this.#database.query<never, Record<string, string | number>>(`
      /* atomic-write: vet.put-record */
      INSERT INTO fixture_vet_records (
        instance_id, audience, job_id, evaluated_role, evaluated_party, verifier_party,
        bundle_hash, requirement_hash, requirement_json, recipe_registry_version,
        requirement_source_kind, requirement_source_address,
        requirement_source_content_hash, requirement_source_artifact_hash,
        recipe_availability, assertion_address, assertion_artifact_hash,
        verify_result_address, verify_result_artifact_hash, composite_address,
        composite_artifact_hash, overall_decision, generated_at, created_at
      ) VALUES (
        $instanceId, $audience, $jobId, $evaluatedRole, $evaluatedParty, $verifierParty,
        $bundleHash, $requirementHash, $requirementJson, $recipeRegistryVersion,
        $requirementSourceKind, $requirementSourceAddress,
        $requirementSourceContentHash, $requirementSourceArtifactHash,
        $recipeAvailability, $assertionAddress, $assertionArtifactHash,
        $verifyResultAddress, $verifyResultArtifactHash, $compositeAddress,
        $compositeArtifactHash, $overallDecision, $generatedAt, $createdAt
      )
    `).run({
      instanceId: prepared.input.session.instanceId,
      audience: prepared.input.session.audience,
      jobId: prepared.input.session.jobId,
      evaluatedRole: prepared.input.evaluatedRole,
      evaluatedParty: prepared.evaluatedParty,
      verifierParty: prepared.verifierParty,
      bundleHash: prepared.input.evaluatedBundleHash,
      requirementHash: prepared.requirementHash,
      requirementJson: prepared.requirementCanonicalJson,
      requirementSourceKind: prepared.requirementSourceKind,
      requirementSourceAddress: prepared.requirementSourceAddress,
      requirementSourceContentHash: prepared.requirementSourceContentHash,
      requirementSourceArtifactHash: requirementSourceArtifact.contentHash,
      recipeRegistryVersion: prepared.recipeRegistry.version,
      recipeAvailability: prepared.recipeRegistry.keyAvailability,
      assertionAddress: prepared.assertion.logicalAddress,
      assertionArtifactHash: assertionArtifact.contentHash,
      verifyResultAddress: prepared.verifyResultAddress,
      verifyResultArtifactHash: verifyResultArtifact.contentHash,
      compositeAddress: prepared.compositeAddress,
      compositeArtifactHash: compositeArtifact.contentHash,
      overallDecision: prepared.composite.overallDecision,
      generatedAt: prepared.input.generatedAt,
      createdAt: prepared.input.createdAt,
    });
  }

  #readRow(scope: FixtureVetSessionScope, evaluatedRole: "buyer" | "seller"): FixtureVetRow | null {
    return this.#database.query<FixtureVetRow, {
      instanceId: string; audience: string; jobId: string; evaluatedRole: string;
    }>(`
      SELECT instance_id AS instanceId, audience, job_id AS jobId,
        evaluated_role AS evaluatedRole, evaluated_party AS evaluatedParty,
        verifier_party AS verifierParty, bundle_hash AS bundleHash,
        requirement_hash AS requirementHash, requirement_json AS requirementCanonicalJson,
        requirement_source_kind AS requirementSourceKind,
        requirement_source_address AS requirementSourceAddress,
        requirement_source_content_hash AS requirementSourceContentHash,
        requirement_source_artifact_hash AS requirementSourceArtifactHash,
        recipe_registry_version AS recipeRegistryVersion,
        recipe_availability AS recipeAvailability, assertion_address AS assertionAddress,
        assertion_artifact_hash AS assertionArtifactHash,
        verify_result_address AS verifyResultAddress,
        verify_result_artifact_hash AS verifyResultArtifactHash,
        composite_address AS compositeAddress,
        composite_artifact_hash AS compositeArtifactHash,
        overall_decision AS overallDecision, generated_at AS generatedAt, created_at AS createdAt
      FROM fixture_vet_records
      WHERE instance_id = $instanceId AND audience = $audience
        AND job_id = $jobId AND evaluated_role = $evaluatedRole
    `).get({
      instanceId: scope.instanceId,
      audience: scope.audience,
      jobId: scope.jobId,
      evaluatedRole,
    });
  }
}

function validateInput(input: FixtureVetInput): void {
  const session = input.session;
  const admittedAt = typeof session?.createdAt === "string" ? Date.parse(session.createdAt) : Number.NaN;
  if (session === null || typeof session !== "object" || !ULID.test(session.jobId)
    || session.status !== "admitted" || session.evidenceMode !== "fixture"
    || typeof session.instanceId !== "string" || session.instanceId.length === 0
    || typeof session.audience !== "string" || session.audience.length === 0
    || !HASH.test(session.requestHash) || !HASH.test(session.admissionFingerprint)
    || !exactTimestamp(admittedAt, session.createdAt)
    || (input.evaluatedRole !== "buyer" && input.evaluatedRole !== "seller")
    || !HASH.test(input.evaluatedBundleHash)
    || !Number.isSafeInteger(input.generatedAt) || input.generatedAt < admittedAt
    || !exactTimestamp(input.generatedAt, input.createdAt)) {
    throw new TypeError("Fixture Vet input is invalid or not fixture-authorized");
  }
}

function prepareRequirementAuthority(
  input: FixtureVetInput,
  evaluatedParty: string,
  verifierParty: string,
): {
  readonly kind: "seller-listing" | "buyer-signed";
  readonly value: Readonly<Record<string, unknown>>;
  readonly requirement: VetBundleRequirement;
  readonly logicalAddress: string;
  readonly contentHash: string;
} {
  const value = parseCanonicalObject(input.requirementAuthority.canonicalJson, "Vet requirement authority");
  if (input.requirementAuthority.kind === "seller-listing") {
    if (input.evaluatedRole !== "buyer") {
      throw new TypeError("Only buyer Vet may derive requirements from the seller Listing");
    }
    const verified = verifyFixtureListingRequirement(
      input.requirementAuthority.canonicalJson,
      input.generatedAt,
      evaluatedParty,
      verifierParty,
    );
    const seller = value["seller"] as Record<string, unknown>;
    const identity = seller["identity"] as Record<string, unknown>;
    return Object.freeze({
      kind: "seller-listing",
      value,
      requirement: value["buyerRequirement"] as VetBundleRequirement,
      logicalAddress: listingLogicalAddress(
        identity["presentedBy"] as string,
        verified.listingId,
        verified.listingVersion,
      ),
      contentHash: verified.contentHash,
    });
  }
  if (input.evaluatedRole !== "seller") {
    throw new TypeError("Only seller Vet may use a buyer-signed counterparty requirement");
  }
  const verified = verifyBuyerVetRequirementJson(input.requirementAuthority.canonicalJson, {
    jobId: input.session.jobId,
    buyer: verifierParty,
    seller: evaluatedParty,
  });
  if (verified.disposition !== "verified") {
    throw new FixtureVetIntegrityError(`Buyer Vet requirement is invalid: ${verified.reason}`);
  }
  const admittedAt = Date.parse(input.session.createdAt);
  if (verified.generatedAt < admittedAt || verified.generatedAt > input.generatedAt) {
    throw new FixtureVetIntegrityError("Buyer Vet requirement is outside the admitted Vet evaluation interval");
  }
  return Object.freeze({
    kind: "buyer-signed",
    value,
    requirement: verified.requirement,
    logicalAddress: verified.logicalAddress,
    contentHash: verified.contentHash,
  });
}

function verifyPersistedRequirementAuthority(
  record: FixtureVetRecord,
  canonicalJson: string,
  admittedAt: number,
): VetBundleRequirement {
  if (record.requirementSourceKind === "seller-listing") {
    const verified = verifyFixtureListingRequirement(
      canonicalJson,
      record.generatedAt,
      record.evaluatedParty,
      record.verifierParty,
    );
    const value = parseCanonicalObject(canonicalJson, "Persisted seller Listing");
    const seller = value["seller"] as Record<string, unknown>;
    const identity = seller["identity"] as Record<string, unknown>;
    if (verified.contentHash !== record.requirementSourceContentHash
      || listingLogicalAddress(
        identity["presentedBy"] as string,
        verified.listingId,
        verified.listingVersion,
      ) !== record.requirementSourceAddress) {
      throw new FixtureVetIntegrityError("Persisted seller Listing source binding is inconsistent");
    }
    const requirement = value["buyerRequirement"] as VetBundleRequirement;
    assertRequirementRecordBinding(record, requirement);
    return requirement;
  }
  const verified = verifyBuyerVetRequirementJson(canonicalJson, {
    jobId: record.jobId,
    buyer: record.verifierParty,
    seller: record.evaluatedParty,
  });
  if (verified.disposition !== "verified"
    || verified.contentHash !== record.requirementSourceContentHash
    || verified.logicalAddress !== record.requirementSourceAddress
    || verified.generatedAt < admittedAt
    || verified.generatedAt > record.generatedAt) {
    throw new FixtureVetIntegrityError("Persisted buyer-signed requirement source is invalid");
  }
  assertRequirementRecordBinding(record, verified.requirement);
  return verified.requirement;
}

function sameSession(left: SessionRecord, right: SessionRecord): boolean {
  return left.instanceId === right.instanceId
    && left.audience === right.audience
    && left.jobId === right.jobId
    && left.evidenceMode === right.evidenceMode
    && left.requestHash === right.requestHash
    && left.admissionFingerprint === right.admissionFingerprint
    && left.status === right.status
    && left.version === right.version
    && left.createdAt === right.createdAt;
}

function exactTimestamp(timestamp: number, iso: unknown): iso is string {
  if (!Number.isSafeInteger(timestamp) || typeof iso !== "string" || Date.parse(iso) !== timestamp) return false;
  try {
    return new Date(timestamp).toISOString() === iso;
  } catch {
    return false;
  }
}

function verifyFixtureListingRequirement(
  canonicalJson: string,
  nowMs: number,
  expectedBuyer: string,
  expectedSeller: string,
) {
  const value = parseCanonicalObject(canonicalJson, "Seller Listing");
  const verification = verifyCanonicalListingJson(canonicalJson, {
    nowMs,
    revocationCheck: () => "absent",
    paymentRailCheck: ({ railId, referencedByPhaseKinds }) => {
      const pipeline = value["pipeline"];
      if (!Array.isArray(pipeline)) return { status: "unresolved" as const };
      const phase = pipeline.find((candidate) => {
        if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) return false;
        const item = candidate as Record<string, unknown>;
        const parameters = item["parameters"] as Record<string, unknown> | undefined;
        return typeof item["kind"] === "string" && referencedByPhaseKinds.includes(item["kind"])
          && parameters?.["rail"] === railId;
      }) as Record<string, unknown> | undefined;
      return phase === undefined
        ? { status: "unresolved" as const }
        : { status: "resolved" as const, phaseHandler: phase["kind"] as string };
    },
  });
  if (verification.disposition !== "accepted") {
    throw new FixtureVetIntegrityError(`Seller Listing requirement authority is invalid: ${verification.stage}: ${verification.reason}`);
  }
  const seller = value["seller"] as Record<string, unknown>;
  const identity = seller["identity"] as Record<string, unknown>;
  const requirement = value["buyerRequirement"];
  if (identity?.["presentedBy"] !== expectedSeller || object(requirement) === null
    || !Array.isArray((requirement as Record<string, unknown>)["required"])
    || expectedBuyer === expectedSeller) {
    throw new FixtureVetIntegrityError("Seller Listing does not bind the expected Vet parties or buyer requirement");
  }
  return verification;
}

function assertRequirementRecordBinding(record: FixtureVetRecord, requirement: VetBundleRequirement): void {
  const canonicalJson = canonicalize(requirement);
  if (canonicalJson !== record.requirementCanonicalJson || sha256Hex(canonicalJson) !== record.requirementHash) {
    throw new FixtureVetIntegrityError("Persisted Vet requirement differs from its signed source");
  }
}

function parseCanonicalObject(canonicalJson: string, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (canonicalize(parsed) !== canonicalJson || parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new TypeError();
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new FixtureVetIntegrityError(`${label} is not canonical JSON`);
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function isCompositeVetReference(value: Readonly<Record<string, unknown>>): boolean {
  const anchor = object(value["anchor"]);
  return anchor?.["kind"] === "storage-program"
    && typeof anchor["locator"] === "string"
    && anchor["locator"].startsWith("dacs2:composite:");
}

function isLegacyFixtureVetReference(
  value: Readonly<Record<string, unknown>>,
  role: "buyer" | "seller",
): boolean {
  return canonicalize(value) === canonicalize({
    anchor: { kind: "https", locator: `https://fixture.example/vet/${role}` },
    contentHash: sha256Hex(`${role}-vet-record`),
  });
}

function requiredArtifact(artifacts: ArtifactStore, hash: string, kind: string): ArtifactRecord {
  const artifact = artifacts.get(hash);
  if (artifact === null || !artifact.kinds.includes(kind) || artifact.contentHash !== sha256Hex(artifact.canonicalJson)) {
    throw new ArtifactIntegrityError(`Fixture Vet cannot resolve ${kind}`);
  }
  return artifact;
}

function putAnchor(
  database: DacsDatabase,
  logicalAddress: string,
  artifactKind: string,
  artifact: ArtifactRecord,
  createdAt: string,
): void {
  const existing = database.query<{
    artifactKind: string; contentHash: string; artifactContentHash: string | null;
  }, { logicalAddress: string }>(`
    SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
      artifact_content_hash AS artifactContentHash
    FROM fixture_anchors WHERE logical_address = $logicalAddress
  `).get({ logicalAddress });
  if (existing !== null) {
    if (existing.artifactKind !== artifactKind || existing.contentHash !== artifact.contentHash
      || existing.artifactContentHash !== artifact.contentHash) {
      throw new FixtureVetConflictError("Fixture Vet anchor already contains different content");
    }
    return;
  }
  database.query<never, Record<string, string>>(`
    /* atomic-write: vet.put-artifact-anchor */
    INSERT INTO fixture_anchors (
      logical_address, artifact_kind, content_hash, artifact_content_hash, created_at
    ) VALUES ($logicalAddress, $artifactKind, $contentHash, $artifactContentHash, $createdAt)
  `).run({
    logicalAddress,
    artifactKind,
    contentHash: artifact.contentHash,
    artifactContentHash: artifact.contentHash,
    createdAt,
  });
}

function putAnchorWithContentHash(
  database: DacsDatabase,
  logicalAddress: string,
  artifactKind: string,
  contentHash: string,
  artifact: ArtifactRecord,
  createdAt: string,
): void {
  const existing = database.query<{
    artifactKind: string; contentHash: string; artifactContentHash: string | null;
  }, { logicalAddress: string }>(`
    SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
      artifact_content_hash AS artifactContentHash
    FROM fixture_anchors WHERE logical_address = $logicalAddress
  `).get({ logicalAddress });
  if (existing !== null) {
    if (existing.artifactKind !== artifactKind || existing.contentHash !== contentHash
      || existing.artifactContentHash !== artifact.contentHash) {
      throw new FixtureVetConflictError("Fixture Vet requirement-source anchor contains different content");
    }
    return;
  }
  database.query<never, Record<string, string>>(`
    /* atomic-write: vet.put-requirement-anchor */
    INSERT INTO fixture_anchors (
      logical_address, artifact_kind, content_hash, artifact_content_hash, created_at
    ) VALUES ($logicalAddress, $artifactKind, $contentHash, $artifactContentHash, $createdAt)
  `).run({ logicalAddress, artifactKind, contentHash, artifactContentHash: artifact.contentHash, createdAt });
}

function assertAnchorBinding(
  database: DacsDatabase,
  artifact: ArtifactRecord,
  logicalAddress: string,
  artifactKind: string,
  contentHash: string,
): void {
  const row = database.query<{
    artifactKind: string; contentHash: string; artifactContentHash: string | null;
  }, { logicalAddress: string }>(`
    SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
      artifact_content_hash AS artifactContentHash
    FROM fixture_anchors WHERE logical_address = $logicalAddress
  `).get({ logicalAddress });
  if (row === null || row.artifactKind !== artifactKind || row.contentHash !== contentHash
    || row.artifactContentHash !== artifact.contentHash) {
    throw new FixtureVetIntegrityError("Fixture Vet requirement-source anchor is missing or inconsistent");
  }
}

function assertAnchor(
  database: DacsDatabase,
  artifact: ArtifactRecord,
  logicalAddress: string,
  artifactKind: string,
): void {
  const row = database.query<{
    artifactKind: string; contentHash: string; artifactContentHash: string | null;
  }, { logicalAddress: string }>(`
    SELECT artifact_kind AS artifactKind, content_hash AS contentHash,
      artifact_content_hash AS artifactContentHash
    FROM fixture_anchors WHERE logical_address = $logicalAddress
  `).get({ logicalAddress });
  if (row === null || row.artifactKind !== artifactKind || row.contentHash !== artifact.contentHash
    || row.artifactContentHash !== artifact.contentHash) {
    throw new FixtureVetIntegrityError("Fixture Vet anchor is missing or inconsistent");
  }
}

function rowToRecord(row: FixtureVetRow): FixtureVetRecord {
  const generatedAt = Number(row.generatedAt);
  const recipeRegistryVersion = Number(row.recipeRegistryVersion);
  if (!Number.isSafeInteger(generatedAt) || !Number.isSafeInteger(recipeRegistryVersion)) {
    throw new FixtureVetIntegrityError("Fixture Vet integer authority exceeds the safe range");
  }
  return Object.freeze({
    ...row,
    generatedAt,
    recipeRegistryVersion,
    compositeReference: Object.freeze({
      anchor: Object.freeze({ kind: "storage-program", locator: row.compositeAddress }),
      contentHash: row.compositeArtifactHash,
      signer: row.verifierParty,
    }),
  });
}

function assertReplay(record: FixtureVetRecord, prepared: PreparedVet): void {
  if (record.instanceId !== prepared.input.session.instanceId
    || record.audience !== prepared.input.session.audience
    || record.evaluatedParty !== prepared.evaluatedParty
    || record.verifierParty !== prepared.verifierParty
    || record.bundleHash !== prepared.input.evaluatedBundleHash
    || record.requirementHash !== prepared.requirementHash
    || record.requirementCanonicalJson !== prepared.requirementCanonicalJson
    || record.requirementSourceKind !== prepared.requirementSourceKind
    || record.requirementSourceAddress !== prepared.requirementSourceAddress
    || record.requirementSourceContentHash !== prepared.requirementSourceContentHash
    || record.requirementSourceArtifactHash !== sha256Hex(canonicalize(prepared.requirementSourceValue))
    || record.recipeRegistryVersion !== prepared.recipeRegistry.version
    || record.recipeAvailability !== prepared.recipeRegistry.keyAvailability
    || record.assertionAddress !== prepared.assertion.logicalAddress
    || record.assertionArtifactHash !== prepared.assertion.contentHash
    || record.verifyResultAddress !== prepared.verifyResultAddress
    || record.verifyResultArtifactHash !== prepared.verifyResult.contentHash
    || record.compositeAddress !== prepared.compositeAddress
    || record.compositeArtifactHash !== prepared.composite.contentHash
    || record.overallDecision !== prepared.composite.overallDecision
    || record.generatedAt !== prepared.input.generatedAt) {
    throw new FixtureVetConflictError("Fixture Vet role already anchors different immutable authority");
  }
}

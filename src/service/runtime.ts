import Ajv2020, {
  type ErrorObject,
  type ValidateFunction,
} from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { randomBytes as operatingSystemRandomBytes } from "node:crypto";
import { verifyWorkProductReceiptJson } from "../consumer/work-product-receipt-verifier.ts";
import { assertArtifactSizeLimit } from "../core/artifact-size.ts";
import { assertFixtureAuthority, type EvidenceMode } from "../core/evidence-mode.ts";
import type { ArtifactSigner } from "../producer/fixture-ed25519.ts";
import {
  signWorkProductReceipt,
  type WorkProductReceipt,
} from "../producer/work-product-receipt.ts";
import { canonicalize, deepFreezeJson } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  ArtifactIntegrityError,
  type ArtifactRecord,
  type ArtifactStore,
  type CompletedServiceRun,
  type ServiceRunBinding,
} from "../substrate/sqlite/artifact-store.ts";
import type { SessionRecord } from "../substrate/sqlite/session-store.ts";
import { defineServiceContract, type ServiceContract } from "./contract.ts";

const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const MAX_INPUT_BYTES = 262_144;
const MAX_OUTPUT_BYTES = 262_144;
const MAX_RECEIPT_BYTES = 16_384;

export interface AdmittedSessionLookup {
  get(jobId: string): SessionRecord | null;
}

export interface ServiceRuntimeOptions<TInput, TOutput> {
  readonly artifactStore: ArtifactStore;
  readonly contract: ServiceContract<TInput, TOutput>;
  readonly deploymentMode: EvidenceMode;
  readonly now: () => string;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly sessionStore: AdmittedSessionLookup;
  readonly signer: ArtifactSigner;
}

export interface ServiceRunInput<TInput> {
  readonly input: TInput;
  readonly jobId: string;
  readonly seed: string;
}

export function serviceContractHash<TInput, TOutput>(
  contract: ServiceContract<TInput, TOutput>,
): string {
  const normalized = defineServiceContract(contract);
  return sha256Hex(canonicalize(contractScope(normalized)));
}

export function serviceRequestHash<TInput, TOutput>(
  contract: ServiceContract<TInput, TOutput>,
  input: unknown,
  seed: string,
): string {
  validateSeed(seed);
  return sha256Hex(canonicalize({
    contract: contractScope(defineServiceContract(contract)),
    input,
    seed,
  }));
}

export interface ServiceRunResult<TInput, TOutput> {
  readonly input: Readonly<TInput>;
  readonly output: Readonly<TOutput>;
  readonly receipt: WorkProductReceipt;
  readonly outputArtifact: ArtifactRecord;
  readonly receiptArtifact: ArtifactRecord;
}

export interface ValidationIssue {
  readonly instancePath: string;
  readonly keyword: string;
  readonly message: string;
  readonly schemaPath: string;
}

export class ServiceValidationError extends Error {
  override readonly name = "ServiceValidationError";
  readonly stage: "input" | "output";
  readonly issues: readonly ValidationIssue[];

  constructor(stage: "input" | "output", issues: readonly ValidationIssue[]) {
    super(`Service ${stage} failed JSON Schema validation`);
    this.stage = stage;
    this.issues = Object.freeze([...issues]);
  }
}

export class ServiceRequestBindingError extends Error {
  override readonly name = "ServiceRequestBindingError";
}

export class ServiceRunInProgressError extends Error {
  override readonly name = "ServiceRunInProgressError";

  constructor(
    message: string,
    readonly claimFingerprint: string,
    readonly claimedAt: string,
  ) {
    super(message);
  }
}

export class ServiceRuntime<TInput, TOutput> {
  readonly #artifactStore: ArtifactStore;
  readonly #contract: ServiceContract<TInput, TOutput>;
  readonly #contractHash: string;
  readonly #deploymentMode: EvidenceMode;
  readonly #inputValidator: ValidateFunction;
  readonly #now: () => string;
  readonly #outputValidator: ValidateFunction;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #sessionStore: AdmittedSessionLookup;
  readonly #signer: ArtifactSigner;

  constructor(options: ServiceRuntimeOptions<TInput, TOutput>) {
    assertFixtureAuthority(options.deploymentMode, options.deploymentMode);
    this.#artifactStore = options.artifactStore;
    this.#contract = defineServiceContract(options.contract);
    this.#contractHash = serviceContractHash(this.#contract);
    this.#deploymentMode = options.deploymentMode;
    this.#now = options.now;
    this.#randomBytes = options.randomBytes ?? operatingSystemRandomBytes;
    this.#sessionStore = options.sessionStore;
    this.#signer = options.signer;
    const ajv = new Ajv2020({
      allErrors: true,
      coerceTypes: false,
      removeAdditional: false,
      strict: true,
      useDefaults: false,
      validateFormats: true,
    });
    addFormats(ajv);
    this.#inputValidator = ajv.compile(this.#contract.input.schema);
    this.#outputValidator = ajv.compile(this.#contract.output.schema);
  }

  async run(request: ServiceRunInput<TInput>): Promise<ServiceRunResult<TInput, TOutput>> {
    validateRunEnvelope(request);
    const session = this.#sessionStore.get(request.jobId);
    if (session === null || session.status !== "admitted") {
      throw new Error("Service run requires an admitted session");
    }
    if (session.evidenceMode !== this.#deploymentMode) {
      throw new Error("Service run evidence mode does not match its admitted session");
    }

    const input = snapshotJson<TInput>(request.input, "input");
    assertValid("input", this.#inputValidator, input);
    assertArtifactSizeLimit("Service input", canonicalize(input), MAX_INPUT_BYTES);
    if (serviceRequestHash(this.#contract, input, request.seed) !== session.requestHash) {
      throw new ServiceRequestBindingError(
        "Service contract, input, or seed does not match session admission",
      );
    }
    const binding: ServiceRunBinding = Object.freeze({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      contractHash: this.#contractHash,
    });
    const claim = this.#artifactStore.claimServiceRun(
      binding,
      this.#signer.signer,
      () => {
        const createdAt = this.#now();
        validateCanonicalTimestamp(createdAt);
        return Object.freeze({ claimToken: this.#claimToken(), createdAt });
      },
    );
    if (claim.disposition === "in-progress") {
      throw new ServiceRunInProgressError(
        "Service run is already in progress",
        claim.run.claimFingerprint,
        claim.run.createdAt,
      );
    }
    if (claim.disposition === "replayed") {
      return this.#storedResult(input, claim.run);
    }
    const { claimToken, createdAt: claimedAt } = claim;

    let completed: CompletedServiceRun;
    try {
      completed = await this.#executeClaimed(
        input,
        request,
        session,
        binding,
        claimToken,
        claimedAt,
      );
    } catch (error) {
      if (!this.#artifactStore.releaseServiceRun(binding, claimToken)) {
        throw new AggregateError(
          [error, new Error("Failed to release an incomplete service run claim")],
          "Service run failed and its claim could not be released",
        );
      }
      throw error;
    }
    return this.#storedResult(input, completed);
  }

  async #executeClaimed(
    input: Readonly<TInput>,
    request: ServiceRunInput<TInput>,
    session: SessionRecord,
    binding: ServiceRunBinding,
    claimToken: string,
    producedAt: string,
  ): Promise<CompletedServiceRun> {
    const context = Object.freeze({
      evidenceMode: this.#deploymentMode,
      jobId: request.jobId,
      seed: request.seed,
    });
    const handled = await this.#contract.handler(input, context);
    const output = snapshotJson<TOutput>(handled, "output");
    assertValid("output", this.#outputValidator, output);

    const inputCanonicalJson = canonicalize(input);
    const outputCanonicalJson = canonicalize(output);
    assertArtifactSizeLimit("Service output", outputCanonicalJson, MAX_OUTPUT_BYTES);
    const inputSchemaHash = sha256Hex(canonicalize(this.#contract.input.schema));
    const outputSchemaHash = sha256Hex(canonicalize(this.#contract.output.schema));
    const signedReceipt = signWorkProductReceipt({
      receiptVersion: "2",
      jobId: request.jobId,
      requestHash: session.requestHash,
      service: {
        id: this.#contract.service.id,
        version: this.#contract.service.version,
      },
      evidenceMode: this.#deploymentMode,
      input: {
        contentHash: sha256Hex(inputCanonicalJson),
        schema: {
          id: this.#contract.input.id,
          version: this.#contract.input.version,
          contentHash: inputSchemaHash,
        },
      },
      output: {
        kind: this.#contract.service.deliverableKind,
        contentHash: sha256Hex(outputCanonicalJson),
        schema: {
          id: this.#contract.output.id,
          version: this.#contract.output.version,
          contentHash: outputSchemaHash,
        },
      },
      producedAt,
      seller: this.#signer.signer,
    }, this.#signer, {
      deploymentMode: this.#deploymentMode,
      requestMode: session.evidenceMode,
    });
    assertArtifactSizeLimit("Work-product receipt", signedReceipt.canonicalJson, MAX_RECEIPT_BYTES);
    const completed = this.#artifactStore.completeServiceRun(
      binding,
      claimToken,
      { kind: `work-product:${this.#contract.service.id}`, value: output },
      { kind: "work-product-receipt", value: signedReceipt.receipt },
      producedAt,
    );
    return completed;
  }

  #storedResult(
    input: Readonly<TInput>,
    run: CompletedServiceRun,
  ): ServiceRunResult<TInput, TOutput> {
    const outputArtifact = this.#artifactStore.get(run.outputContentHash);
    const receiptArtifact = this.#artifactStore.get(run.receiptContentHash);
    if (
      outputArtifact === null
      || receiptArtifact === null
      || !outputArtifact.kinds.includes(`work-product:${this.#contract.service.id}`)
      || !receiptArtifact.kinds.includes("work-product-receipt")
    ) throw new ArtifactIntegrityError("Completed service run artifacts are missing or mistyped");
    const verification = verifyWorkProductReceiptJson(
      receiptArtifact.canonicalJson,
      canonicalize(input),
      outputArtifact.canonicalJson,
      {
        inputSchemaJson: canonicalize(this.#contract.input.schema),
        inputSchemaVersion: this.#contract.input.version,
        jobId: run.jobId,
        outputKind: this.#contract.service.deliverableKind,
        outputSchemaJson: canonicalize(this.#contract.output.schema),
        outputSchemaVersion: this.#contract.output.version,
        requestHash: run.requestHash,
        seller: run.seller,
        serviceId: this.#contract.service.id,
        serviceVersion: this.#contract.service.version,
      },
    );
    if (verification.disposition !== "verified") {
      throw new ArtifactIntegrityError(
        `Stored work-product receipt failed ${verification.stage}: ${verification.reason}`,
      );
    }
    const output = deepFreezeJson(JSON.parse(outputArtifact.canonicalJson) as TOutput);
    assertValid("output", this.#outputValidator, output);
    const receipt = deepFreezeJson(
      JSON.parse(receiptArtifact.canonicalJson) as WorkProductReceipt,
    );
    return Object.freeze({ input, output, receipt, outputArtifact, receiptArtifact });
  }

  #claimToken(): string {
    const bytes = this.#randomBytes(32);
    if (bytes.byteLength !== 32) {
      throw new Error("Service run claim entropy provider must return exactly 32 bytes");
    }
    return Buffer.from(bytes).toString("hex");
  }
}

function contractScope<TInput, TOutput>(
  contract: ServiceContract<TInput, TOutput>,
): Record<string, unknown> {
  return {
    service: {
      id: contract.service.id,
      version: contract.service.version,
      deliverableKind: contract.service.deliverableKind,
    },
    inputSchema: {
      id: contract.input.id,
      version: contract.input.version,
      contentHash: sha256Hex(canonicalize(contract.input.schema)),
    },
    outputSchema: {
      id: contract.output.id,
      version: contract.output.version,
      contentHash: sha256Hex(canonicalize(contract.output.schema)),
    },
  };
}

function snapshotJson<T>(value: T, stage: "input" | "output"): Readonly<T> {
  try {
    return deepFreezeJson(JSON.parse(canonicalize(value)) as T);
  } catch {
    throw new ServiceValidationError(stage, [Object.freeze({
      instancePath: "",
      keyword: "canonical-json",
      message: "must be finite canonical JSON",
      schemaPath: "",
    })]);
  }
}

function assertValid(
  stage: "input" | "output",
  validator: ValidateFunction,
  value: unknown,
): void {
  if (validator(value)) return;
  throw new ServiceValidationError(stage, issuesFrom(validator.errors));
}

function issuesFrom(errors: ErrorObject[] | null | undefined): readonly ValidationIssue[] {
  return Object.freeze((errors ?? []).map((error) => Object.freeze({
    instancePath: error.instancePath,
    keyword: error.keyword,
    message: error.message ?? "schema validation failed",
    schemaPath: error.schemaPath,
  })));
}

function validateRunEnvelope<TInput>(request: ServiceRunInput<TInput>): void {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("Service run request must be an object");
  }
  const keys = Object.keys(request).sort();
  if (keys.join(",") !== "input,jobId,seed") {
    throw new TypeError("Service run request must contain exactly input, jobId, and seed");
  }
  if (!ULID.test(request.jobId)) throw new TypeError("Service run jobId must be a canonical ULID");
  validateSeed(request.seed);
}

function validateSeed(seed: unknown): asserts seed is string {
  if (
    typeof seed !== "string"
    || seed.length === 0
    || seed.length > 4_096
    || seed !== seed.normalize("NFC")
  ) throw new TypeError("Service run seed must be a bounded NFC string");
}

function validateCanonicalTimestamp(value: string): void {
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    throw new TypeError("Service clock must return a canonical ISO timestamp");
  }
}

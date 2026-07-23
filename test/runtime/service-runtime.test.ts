import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serviceContract } from "../../service/service.config.ts";
import {
  handler,
  type ReferenceTransformInput,
  type ReferenceTransformOutput,
} from "../../service/handler.ts";
import { BASIC_FIXTURE } from "../../service/fixtures/basic.ts";
import { verifyWorkProductReceiptJson } from "../../src/consumer/work-product-receipt-verifier.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { defineServiceContract } from "../../src/service/contract.ts";
import {
  ServiceRuntime,
  ServiceRequestBindingError,
  ServiceRunInProgressError,
  ServiceValidationError,
  serviceContractHash,
  serviceRequestHash,
  type AdmittedSessionLookup,
} from "../../src/service/runtime.ts";
import { ArtifactSizeLimitError } from "../../src/core/artifact-size.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { openDatabase, type DacsDatabase } from "../../src/substrate/sqlite/database.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("builder-owned service runtime", () => {
  test("rejects invalid input before invoking the handler or persisting artifacts", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        invocations += 1;
        return handler(input, context);
      },
    });
    const runtime = serviceRuntime(database, { contract });
    const invalidInputs = [
      { document: { alpha: "one" } },
      { document: { alpha: "one" }, select: [], extra: true },
      { document: { alpha: 1 }, select: ["alpha"] },
      { document: { alpha: Number.NaN }, select: ["alpha"] },
    ];

    for (const input of invalidInputs) {
      const error = await capture(runtime.run({
        input: input as unknown as ReferenceTransformInput,
        jobId: BASIC_FIXTURE.jobId,
        seed: BASIC_FIXTURE.seed,
      }));
      expect(error).toBeInstanceOf(ServiceValidationError);
      expect((error as ServiceValidationError).stage).toBe("input");
    }
    expect(invocations).toBe(0);
    expect(artifactCount(database)).toBe(0n);
    database.close();
  });

  test("passes only the frozen documented request and context to builder code", async () => {
    const database = await openTestDatabase();
    let observedContext: readonly string[] = [];
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        expect(Object.isFrozen(input)).toBe(true);
        expect(Object.isFrozen(input.document)).toBe(true);
        expect(Object.isFrozen(input.select)).toBe(true);
        expect(Object.isFrozen(context)).toBe(true);
        observedContext = Object.keys(context).sort();
        return handler(input, context);
      },
    });
    const result = await serviceRuntime(database, { contract }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(observedContext).toEqual(["evidenceMode", "jobId", "seed"]);
    expect(result.output).toEqual(BASIC_FIXTURE.output);
    expect(Object.isFrozen(result.output)).toBe(true);
    expect(Object.isFrozen(result.receipt)).toBe(true);
    database.close();
  });

  test("produces byte-identical output and receipt across clean stores", async () => {
    const firstDatabase = await openTestDatabase();
    const secondDatabase = await openTestDatabase();
    const first = await serviceRuntime(firstDatabase).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    const second = await serviceRuntime(secondDatabase).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(canonicalize(first.output)).toBe(canonicalize(second.output));
    expect(canonicalize(first.receipt)).toBe(canonicalize(second.receipt));
    expect(first.outputArtifact.contentHash).toBe(second.outputArtifact.contentHash);
    expect(first.receiptArtifact.contentHash).toBe(second.receiptArtifact.contentHash);
    expect(first.outputArtifact.canonicalJson).toBe(canonicalize(BASIC_FIXTURE.output));
    expect(first.receipt.output.contentHash).toBe(first.outputArtifact.contentHash);
    expect(firstDatabase.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()?.count).toBe(2n);
    firstDatabase.close();
    secondDatabase.close();
  });

  test("independently verifies receipt hashes, seller binding, and signature", async () => {
    const database = await openTestDatabase();
    const result = await serviceRuntime(database).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    const receiptJson = canonicalize(result.receipt);
    const inputJson = canonicalize(result.input);
    const outputJson = canonicalize(result.output);

    expect(verifyWorkProductReceiptJson(receiptJson, inputJson, outputJson, {
      inputSchemaJson: canonicalize(serviceContract.input.schema),
      inputSchemaVersion: serviceContract.input.version,
      jobId: BASIC_FIXTURE.jobId,
      outputKind: serviceContract.service.deliverableKind,
      outputSchemaJson: canonicalize(serviceContract.output.schema),
      outputSchemaVersion: serviceContract.output.version,
      requestHash: serviceRequestHash(serviceContract, BASIC_FIXTURE.input, BASIC_FIXTURE.seed),
      seller: fixtureSigner().signer,
      serviceId: serviceContract.service.id,
      serviceVersion: serviceContract.service.version,
    })).toEqual({
      disposition: "verified",
      receiptContentHash: result.receiptArtifact.contentHash,
      outputContentHash: result.outputArtifact.contentHash,
      seller: fixtureSigner().signer,
    });

    const changedOutput = canonicalize({ ...result.output, selected: { alpha: "changed" } });
    expect(verifyWorkProductReceiptJson(receiptJson, inputJson, changedOutput).disposition)
      .toBe("rejected");
    const badSignature = structuredClone(result.receipt) as unknown as {
      signature: { value: string };
    };
    badSignature.signature.value = `${badSignature.signature.value.slice(0, -2)}AA`;
    expect(verifyWorkProductReceiptJson(
      canonicalize(badSignature), inputJson, outputJson,
    )).toMatchObject({ disposition: "rejected", stage: "signature" });
    const wrongSeller = structuredClone(result.receipt) as unknown as { seller: string };
    wrongSeller.seller = `key:${"0".repeat(64)}`;
    expect(verifyWorkProductReceiptJson(
      canonicalize(wrongSeller), inputJson, outputJson,
    )).toMatchObject({ disposition: "rejected", stage: "binding" });
    expect(verifyWorkProductReceiptJson(
      ` ${receiptJson}`, inputJson, outputJson,
    )).toMatchObject({ disposition: "rejected", stage: "canonical-form" });
    expect(verifyWorkProductReceiptJson(
      " ".repeat(16_385), inputJson, outputJson,
    )).toMatchObject({ disposition: "rejected", stage: "canonical-form" });
    const wrongSchemaIdentity = structuredClone(result.receipt) as unknown as {
      input: { schema: { id: string } };
    };
    wrongSchemaIdentity.input.schema.id = "urn:attacker:schema";
    expect(verifyWorkProductReceiptJson(
      canonicalize(wrongSchemaIdentity), inputJson, outputJson, {
        inputSchemaJson: canonicalize(serviceContract.input.schema),
        inputSchemaVersion: serviceContract.input.version,
      },
    )).toMatchObject({ disposition: "rejected", stage: "binding" });
    database.close();
  });

  test("rejects invalid handler output without persisting a partial work product", async () => {
    const database = await openTestDatabase();
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: () => ({ selected: {} }) as unknown as ReferenceTransformOutput,
    });
    const error = await capture(serviceRuntime(database, { contract }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    }));

    expect(error).toBeInstanceOf(ServiceValidationError);
    expect((error as ServiceValidationError).stage).toBe("output");
    expect(artifactCount(database)).toBe(0n);
    expect(serviceRunCount(database)).toBe(0n);
    database.close();
  });

  test("requires an admitted, mode-matching session before handler execution", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        invocations += 1;
        return handler(input, context);
      },
    });
    const missingSessionRuntime = serviceRuntime(database, {
      contract,
      sessionStore: { get: () => null },
    });
    await expect(missingSessionRuntime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    })).rejects.toThrow(/admitted session/);
    const wrongModeRuntime = serviceRuntime(database, {
      contract,
      sessionStore: sessionLookup("live"),
    });
    await expect(wrongModeRuntime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    })).rejects.toThrow(/evidence mode/);
    expect(invocations).toBe(0);
    expect(artifactCount(database)).toBe(0n);
    database.close();
  });

  test("binds handler execution to the exact input hash signed at admission", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        invocations += 1;
        return handler(input, context);
      },
    });
    const changedInput = {
      document: { alpha: "changed", beta: "two" },
      select: BASIC_FIXTURE.input.select,
    };
    const error = await capture(serviceRuntime(database, { contract }).run({
      input: changedInput,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    }));

    expect(error).toBeInstanceOf(ServiceRequestBindingError);
    expect(invocations).toBe(0);
    expect(artifactCount(database)).toBe(0n);
    database.close();
  });

  test("binds output-affecting fixture seed to the admitted request hash", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        invocations += 1;
        return handler(input, context);
      },
    });
    const error = await capture(serviceRuntime(database, { contract }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: "attacker-selected-seed",
    }));

    expect(error).toBeInstanceOf(ServiceRequestBindingError);
    expect(invocations).toBe(0);
    expect(artifactCount(database)).toBe(0n);
    database.close();
  });

  test("treats prototype-named selections as missing unless explicitly owned", async () => {
    const database = await openTestDatabase();
    const input: ReferenceTransformInput = {
      document: {},
      select: ["toString", "__proto__"],
    };
    const runtime = serviceRuntime(database, {
      sessionStore: sessionLookup(
        "fixture",
        serviceRequestHash(serviceContract, input, BASIC_FIXTURE.seed),
      ),
    });
    const result = await runtime.run({
      input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(result.output.selected).toEqual({});
    expect(result.output.missing).toEqual(["__proto__", "toString"]);
    database.close();
  });

  test("replays the original receipt without re-running the handler or clock", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    let clockCalls = 0;
    let entropyCalls = 0;
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        invocations += 1;
        return handler(input, context);
      },
    });
    const runtime = serviceRuntime(database, {
      contract,
      now: () => {
        clockCalls += 1;
        if (clockCalls > 1) throw new Error("replay clock must not be called");
        return BASIC_FIXTURE.producedAt;
      },
      randomBytes: (size) => {
        entropyCalls += 1;
        if (entropyCalls > 1) throw new Error("replay entropy must not be called");
        return Buffer.alloc(size, 7);
      },
    });
    const first = await runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    const replay = await runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(invocations).toBe(1);
    expect(clockCalls).toBe(1);
    expect(entropyCalls).toBe(1);
    expect(replay.receiptArtifact.contentHash).toBe(first.receiptArtifact.contentHash);
    expect(replay.receipt.producedAt).toBe(BASIC_FIXTURE.producedAt);
    expect(artifactCount(database)).toBe(2n);
    expect(serviceRunCount(database)).toBe(1n);
    database.close();
  });

  test("replays a persisted v1 receipt through its explicit legacy signature path", async () => {
    const database = await openTestDatabase();
    const first = await serviceRuntime(database).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    const signer = fixtureSigner();
    const { signature: _currentSignature, ...currentBody } = first.receipt;
    const legacyBody = { ...currentBody, receiptVersion: "1" as const };
    const legacyScope = {
      ...legacyBody,
      signature: { algorithm: signer.algorithm, signer: signer.signer },
    };
    const legacyValue = signer.sign(
      Buffer.from(
        `dacs-template:work-product-receipt:v1:${sha256Hex(canonicalize(legacyScope))}`,
        "utf8",
      ),
      { deploymentMode: "fixture", requestMode: "fixture" },
    );
    const legacyReceipt = {
      ...legacyBody,
      signature: { algorithm: signer.algorithm, signer: signer.signer, value: legacyValue },
    };
    expect(legacyValue).toMatch(/=$/);
    const legacyArtifact = new ArtifactStore(database).put(
      "work-product-receipt",
      legacyReceipt,
      BASIC_FIXTURE.producedAt,
    );
    database.query<never, { receiptContentHash: string }>(`
      UPDATE service_runs
      SET receipt_content_hash = $receiptContentHash
      WHERE job_id = '${BASIC_FIXTURE.jobId}' AND status = 'completed'
    `).run({ receiptContentHash: legacyArtifact.contentHash });

    const replay = await serviceRuntime(database, {
      contract: defineServiceContract({
        ...serviceContract,
        handler: () => { throw new Error("legacy replay must not execute the handler"); },
      }),
    }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(replay.receipt.receiptVersion).toBe("1");
    expect(replay.receiptArtifact.contentHash).toBe(legacyArtifact.contentHash);
    expect(replay.outputArtifact.contentHash).toBe(first.outputArtifact.contentHash);
    database.close();
  });

  test("blocks concurrent duplicate execution before a second handler invocation", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    let clockCalls = 0;
    let releaseHandler = (): void => {};
    let reportEntered = (): void => {};
    const gate = new Promise<void>((resolve) => { releaseHandler = resolve; });
    const entered = new Promise<void>((resolve) => { reportEntered = resolve; });
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: async (input, context) => {
        invocations += 1;
        reportEntered();
        await gate;
        return handler(input, context);
      },
    });
    const runtime = serviceRuntime(database, {
      contract,
      now: () => {
        clockCalls += 1;
        return BASIC_FIXTURE.producedAt;
      },
    });
    const first = runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    await entered;
    const duplicateError = await capture(runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    }));
    expect(duplicateError).toBeInstanceOf(ServiceRunInProgressError);
    expect((duplicateError as ServiceRunInProgressError).claimFingerprint)
      .toMatch(/^[0-9a-f]{64}$/);
    expect((duplicateError as ServiceRunInProgressError).claimedAt)
      .toBe(BASIC_FIXTURE.producedAt);
    expect(invocations).toBe(1);
    expect(clockCalls).toBe(1);
    releaseHandler();
    await first;
    database.close();
  });

  test("releases an ordinary failed handler claim for an explicit retry", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    const contract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      handler: (input, context) => {
        invocations += 1;
        if (invocations === 1) throw new Error("fixture handler failure");
        return handler(input, context);
      },
    });
    const runtime = serviceRuntime(database, { contract });
    await expect(runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    })).rejects.toThrow("fixture handler failure");
    expect(serviceRunCount(database)).toBe(0n);
    const retried = await runtime.run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    expect(retried.output).toEqual(BASIC_FIXTURE.output);
    expect(invocations).toBe(2);
    database.close();
  });

  test("rejects an admitted request after service contract version drift", async () => {
    const database = await openTestDatabase();
    let invocations = 0;
    const changedContract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      service: { ...serviceContract.service, version: "1.0.1" },
      handler: (input, context) => {
        invocations += 1;
        return handler(input, context);
      },
    });
    const error = await capture(serviceRuntime(database, { contract: changedContract }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    }));
    expect(error).toBeInstanceOf(ServiceRequestBindingError);
    expect(invocations).toBe(0);
    database.close();
  });

  test("rejects impossible receipt configuration at contract definition", () => {
    expect(() => defineServiceContract({
      ...serviceContract,
      service: { ...serviceContract.service, deliverableKind: "x".repeat(257) },
    })).toThrow(/deliverableKind/);
  });

  test("verifies a completed replay after fixture signer rotation", async () => {
    const database = await openTestDatabase();
    const first = await serviceRuntime(database).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });
    const rotatedSigner = createFixtureEd25519Signer(Buffer.alloc(32, 9), {
      deploymentMode: "fixture",
      authorityMode: "fixture",
    });
    const replay = await serviceRuntime(database, { signer: rotatedSigner }).run({
      input: BASIC_FIXTURE.input,
      jobId: BASIC_FIXTURE.jobId,
      seed: BASIC_FIXTURE.seed,
    });

    expect(replay.receipt.seller).toBe(first.receipt.seller);
    expect(replay.receipt.seller).not.toBe(rotatedSigner.signer);
    expect(replay.receiptArtifact.contentHash).toBe(first.receiptArtifact.contentHash);
    database.close();
  });

  test("registers standard JSON Schema formats and rejects unknown ones at startup", async () => {
    const database = await openTestDatabase();
    const outputSchema = structuredClone(serviceContract.output.schema) as Record<string, unknown>;
    const outputProperties = outputSchema["properties"] as Record<string, Record<string, unknown>>;
    outputProperties["seed"] = { ...outputProperties["seed"], format: "date-time" };
    const formattedContract = defineServiceContract<ReferenceTransformInput, ReferenceTransformOutput>({
      ...serviceContract,
      output: { ...serviceContract.output, schema: outputSchema },
    });
    expect(() => serviceRuntime(database, { contract: formattedContract })).not.toThrow();

    outputProperties["seed"] = { ...outputProperties["seed"], format: "unknown-format" };
    const unknownFormatContract = defineServiceContract<
      ReferenceTransformInput,
      ReferenceTransformOutput
    >({ ...serviceContract, output: { ...serviceContract.output, schema: outputSchema } });
    expect(() => serviceRuntime(database, { contract: unknownFormatContract }))
      .toThrow(/unknown format/);
    database.close();
  });

  test("rejects aggregate receipt metadata overflow during contract definition", () => {
    const longId = `https://example.com/${"é".repeat(2_000)}`;
    expect(() => defineServiceContract({
      ...serviceContract,
      input: {
        ...serviceContract.input,
        id: `${longId}/input`,
        schema: { ...serviceContract.input.schema, $id: `${longId}/input` },
      },
      output: {
        ...serviceContract.output,
        id: `${longId}/output`,
        schema: { ...serviceContract.output.schema, $id: `${longId}/output` },
      },
    })).toThrow(/metadata.*byte budget/);
  });

  test("reports artifact byte limits independently from JSON Schema failures", () => {
    const error = new ArtifactSizeLimitError("Work-product receipt", 16_385, 16_384);

    expect(error.name).toBe("ArtifactSizeLimitError");
    expect(error.artifact).toBe("Work-product receipt");
    expect(error.actualBytes).toBe(16_385);
    expect(error.limitBytes).toBe(16_384);
    expect(error.message).toBe("Work-product receipt exceeds 16384 canonical UTF-8 bytes");
  });

  test("recovers only an exact stale claim under confirmed executor isolation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "dacs-service-recovery-"));
    directories.push(directory);
    const path = join(directory, "state.sqlite");
    let database = openDatabase(path);
    serviceRuntime(database);
    let store = new ArtifactStore(database);
    const binding = {
      instanceId: "reference-instance",
      audience: "https://service.example",
      jobId: BASIC_FIXTURE.jobId,
      requestHash: serviceRequestHash(serviceContract, BASIC_FIXTURE.input, BASIC_FIXTURE.seed),
      contractHash: serviceContractHash(serviceContract),
    } as const;
    const firstToken = "1".repeat(64);
    expect(() => store.claimServiceRun(
      binding,
      fixtureSigner().signer,
      () => ({ claimToken: firstToken, createdAt: "now" }),
    )).toThrow(/createdAt.*canonical ISO timestamp/);
    expect(serviceRunCount(database)).toBe(0n);
    expect(store.claimServiceRun(
      binding,
      fixtureSigner().signer,
      () => ({ claimToken: firstToken, createdAt: BASIC_FIXTURE.producedAt }),
    )).toEqual({
      disposition: "claimed",
      claimToken: firstToken,
      createdAt: BASIC_FIXTURE.producedAt,
    });
    database.close();

    database = openDatabase(path);
    store = new ArtifactStore(database);
    const observed = store.claimServiceRun(
      binding,
      fixtureSigner().signer,
      () => {
        throw new Error("existing claim must not request new claim material");
      },
    );
    expect(observed.disposition).toBe("in-progress");
    if (observed.disposition !== "in-progress") throw new Error("Expected stale running claim");
    expect(observed.run.createdAt).toBe(BASIC_FIXTURE.producedAt);
    expect(observed.run.claimFingerprint).not.toBe(firstToken);

    const recovery = {
      expectedClaimFingerprint: observed.run.claimFingerprint,
      expectedCreatedAt: observed.run.createdAt,
      observedAt: "2026-07-17T08:10:00.000Z",
      minimumAgeMs: 300_000,
      executorIsolationConfirmed: true,
    } as const;
    expect(store.recoverStaleServiceRun(binding, {
      ...recovery,
      observedAt: "2026-07-17T08:01:00.000Z",
    })).toBe(false);
    expect(() => store.recoverStaleServiceRun(binding, {
      ...recovery,
      executorIsolationConfirmed: false,
    } as unknown as typeof recovery)).toThrow(/executor isolation/);
    expect(store.recoverStaleServiceRun(binding, recovery)).toBe(true);
    expect(serviceRunCount(database)).toBe(0n);

    expect(store.claimServiceRun(
      binding,
      fixtureSigner().signer,
      () => ({ claimToken: "3".repeat(64), createdAt: BASIC_FIXTURE.producedAt }),
    )).toEqual({
      disposition: "claimed",
      claimToken: "3".repeat(64),
      createdAt: BASIC_FIXTURE.producedAt,
    });
    expect(store.recoverStaleServiceRun(binding, recovery)).toBe(false);
    expect(store.releaseServiceRun(binding, "3".repeat(64))).toBe(true);
    database.close();
  });
});

async function openTestDatabase(): Promise<DacsDatabase> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-service-runtime-"));
  directories.push(directory);
  return openDatabase(join(directory, "state.sqlite"));
}

function serviceRuntime(
  database: DacsDatabase,
  overrides: Partial<ConstructorParameters<typeof ServiceRuntime<
    ReferenceTransformInput,
    ReferenceTransformOutput
  >>[0]> = {},
): ServiceRuntime<ReferenceTransformInput, ReferenceTransformOutput> {
  database.query<never, Record<string, string>>(`
    INSERT INTO sessions (
      instance_id, audience, job_id, evidence_mode, admission_fingerprint,
      status, created_at
    ) VALUES (
      $instanceId, $audience, $jobId, 'fixture', $admissionFingerprint,
      'admitted', $createdAt
    ) ON CONFLICT(instance_id, audience, job_id) DO NOTHING
  `).run({
    instanceId: "reference-instance",
    audience: "https://service.example",
    jobId: BASIC_FIXTURE.jobId,
    admissionFingerprint: "0".repeat(64),
    createdAt: BASIC_FIXTURE.producedAt,
  });
  return new ServiceRuntime({
    artifactStore: new ArtifactStore(database),
    contract: serviceContract,
    deploymentMode: "fixture",
    now: () => BASIC_FIXTURE.producedAt,
    sessionStore: sessionLookup("fixture"),
    signer: fixtureSigner(),
    ...overrides,
  });
}

function sessionLookup(
  evidenceMode: "fixture" | "local-chain" | "live",
  requestHash = serviceRequestHash(serviceContract, BASIC_FIXTURE.input, BASIC_FIXTURE.seed),
): AdmittedSessionLookup {
  return {
    get: (jobId) => jobId === BASIC_FIXTURE.jobId ? {
      instanceId: "reference-instance",
      audience: "https://service.example",
      jobId,
      evidenceMode,
      requestHash,
      admissionFingerprint: "0".repeat(64),
      status: "admitted",
      version: 0n,
      createdAt: BASIC_FIXTURE.producedAt,
    } : null,
  };
}

function artifactCount(database: DacsDatabase): bigint {
  return database.query<{ count: bigint }, []>(
    "SELECT count(*) AS count FROM artifacts",
  ).get()?.count ?? 0n;
}

function serviceRunCount(database: DacsDatabase): bigint {
  return database.query<{ count: bigint }, []>(
    "SELECT count(*) AS count FROM service_runs",
  ).get()?.count ?? 0n;
}

async function capture(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    throw new Error("Expected operation to fail");
  } catch (error) {
    return error;
  }
}

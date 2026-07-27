import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  linkSync,
  openSync,
  readFileSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { createHash, randomBytes as operatingSystemRandomBytes, timingSafeEqual } from "node:crypto";
import { canonicalize } from "../protocol/canonical-json.ts";
import { openDatabase, type DacsDatabase } from "./sqlite/database.ts";
import type { Dacs2KeyCurrentnessResolver } from "./keys/production-key-lifecycle.ts";
import type { AuthorityProofVerifier } from "./sqlite/party-authority-lifecycle.ts";
import {
  MAX_ADMINISTRATOR_CAPABILITY_HISTORY,
  MAX_ADMINISTRATOR_CAPABILITY_MS,
  MAX_CAPABILITY_SCOPE_BYTES,
} from "./capability-limits.ts";

const BOOTSTRAP_DOMAIN = "dacs-forge:administrator-bootstrap:v1:";
const RECOVERY_DOMAIN = "dacs-forge:administrator-recovery:v1:";
const CLONE_DOMAIN = "dacs-forge:clone-rotation:v1:";
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const MAX_FIELD_LENGTH = 4_096;
const REQUEST_PAST_MS = 900_000;
const REQUEST_FUTURE_MS = 30_000;

export type AuthorityFileStage =
  | "after-create"
  | "after-write"
  | "after-file-fsync"
  | "after-directory-fsync"
  | "before-database-commit"
  | "after-database-commit";

export interface AuthorityBootstrapRequest {
  readonly administratorKey: string;
  readonly administratorOperations: readonly string[];
  readonly administratorPrincipal: string;
  readonly audience: string;
  readonly expiresAtMs: number;
  readonly instanceId: string;
  readonly nonce: string;
  readonly outputPath: string;
  readonly recoveryKey: string;
  readonly requestedAtMs: number;
  readonly storeBinding: string;
}

export interface AuthorityBootstrapCompletion {
  readonly administratorProof: string;
  readonly recoveryProof: string;
  readonly request: AuthorityBootstrapRequest;
}

export interface AuthorityRecoveryRequest {
  readonly administratorKey: string;
  readonly administratorOperations: readonly string[];
  readonly administratorPrincipal: string;
  readonly audience: string;
  readonly expiresAtMs: number;
  readonly expectedGeneration: number;
  readonly instanceId: string;
  readonly nonce: string;
  readonly outputPath: string;
  readonly requestedAtMs: number;
  readonly storeBinding: string;
}

export interface AuthorityRecoveryCompletion {
  readonly administratorProof: string;
  readonly proof: string;
  readonly request: AuthorityRecoveryRequest;
}

export interface CloneRotationRequest {
  readonly administratorProof: string;
  readonly administratorCapability: string;
  readonly audience: string;
  readonly expiresAtMs: number;
  readonly newAdministratorKey: string;
  readonly newAdministratorOperations: readonly string[];
  readonly newAdministratorPrincipal: string;
  readonly newAdministratorProof: string;
  readonly newInstanceId: string;
  readonly newRecoveryKey: string;
  readonly newRecoveryProof: string;
  readonly nonce: string;
  readonly oldInstanceId: string;
  readonly outputPath: string;
  readonly requestedAtMs: number;
  readonly storeBinding: string;
}

export interface OfflineAuthorityOptions {
  readonly databasePath: string;
  readonly fault?: (stage: AuthorityFileStage) => void;
  readonly keyCurrentness: Dacs2KeyCurrentnessResolver;
  readonly now?: () => number;
  readonly proofVerifier: AuthorityProofVerifier;
  readonly randomBytes?: (size: number) => Uint8Array;
}

export interface AuthorityServiceLease {
  assertActive(): void;
  close(): void;
}

interface AuthorityLeaseIdentity {
  readonly canonicalPath: string | null;
  readonly device: bigint | null;
  readonly inode: bigint | null;
  readonly socket: string;
}

interface AuthorityCapabilityOutput {
  readonly capability: string;
  readonly operationDigest: string;
  readonly schema: "dacs-authority-capability/v1";
}

interface InstanceRow {
  readonly audience: string;
  readonly generation: bigint;
  readonly instanceId: string;
  readonly recoveryKey: string;
}

interface AdminRow {
  readonly capabilityDigest: string;
  readonly configuredKey: string;
  readonly expiresAtMs: bigint;
  readonly operationsJson: string;
  readonly principal: string;
}

export function prepareAuthorityBootstrap(
  input: Omit<AuthorityBootstrapRequest, "nonce">,
  randomBytes: (size: number) => Uint8Array = operatingSystemRandomBytes,
): AuthorityBootstrapRequest {
  const nonce = Buffer.from(exactEntropy(randomBytes, 32, "bootstrap nonce")).toString("hex");
  return normalizeBootstrap({ ...input, nonce });
}

export function authorityStoreBinding(databasePath: string): string {
  return hashHex(`dacs-forge:authority-store:v1:${canonicalAuthorityDatabasePath(databasePath)}`);
}

export function authorityBootstrapSigningBytes(request: AuthorityBootstrapRequest): string {
  return `${BOOTSTRAP_DOMAIN}${canonicalize(normalizeBootstrap(request))}`;
}

export function completeAuthorityBootstrap(
  completion: AuthorityBootstrapCompletion,
  options: OfflineAuthorityOptions,
): Readonly<{ readonly instanceId: string; readonly generation: number; readonly outputPath: string }> {
  const request = normalizeBootstrap(completion.request);
  assertStoreBinding(request.storeBinding, options.databasePath);
  assertBoundedAdministratorScope(request);
  const now = safeNow(options.now);
  if (!requestIsCurrent(request.requestedAtMs, now) || request.expiresAtMs <= now
    || request.expiresAtMs > now + MAX_ADMINISTRATOR_CAPABILITY_MS) {
    throw new Error("Bootstrap request is not current");
  }
  assertCurrent(options.keyCurrentness, request.administratorKey, now);
  assertCurrent(options.keyCurrentness, request.recoveryKey, now);
  const signedBytes = authorityBootstrapSigningBytes(request);
  if (!options.proofVerifier.verify({
    key: request.administratorKey,
    proof: completion.administratorProof,
    signedBytes,
  }) || !options.proofVerifier.verify({
    key: request.recoveryKey,
    proof: completion.recoveryProof,
    signedBytes,
  })) throw new Error("Bootstrap requires administrator and recovery proof");

  return withOfflineStore(options.databasePath, (store) => store.bootstrap(request, now, options));
}

export function authorityRecoverySigningBytes(request: AuthorityRecoveryRequest): string {
  return `${RECOVERY_DOMAIN}${canonicalize(normalizeRecovery(request))}`;
}

export function recoverAdministrator(
  completion: AuthorityRecoveryCompletion,
  options: OfflineAuthorityOptions,
): Readonly<{ readonly instanceId: string; readonly generation: number; readonly outputPath: string }> {
  const request = normalizeRecovery(completion.request);
  assertStoreBinding(request.storeBinding, options.databasePath);
  assertBoundedAdministratorScope(request);
  const now = safeNow(options.now);
  if (!requestIsCurrent(request.requestedAtMs, now) || request.expiresAtMs <= now
    || request.expiresAtMs > now + MAX_ADMINISTRATOR_CAPABILITY_MS) {
    throw new Error("Recovery request is not current");
  }
  assertCurrent(options.keyCurrentness, request.administratorKey, now);
  const signedBytes = authorityRecoverySigningBytes(request);
  if (!options.proofVerifier.verify({
    key: request.administratorKey,
    proof: field("administratorProof", completion.administratorProof),
    signedBytes,
  })) throw new Error("Recovery administrator proof is invalid");
  return withOfflineStore(options.databasePath, (store) =>
    store.recover(request, field("proof", completion.proof), now, options));
}

export function cloneRotationSigningBytes(request: CloneRotationRequest): string {
  const normalized = normalizeClone(request);
  return `${CLONE_DOMAIN}${canonicalize({
    administratorDigest: hashHex(normalized.administratorCapability),
    audience: normalized.audience,
    expiresAtMs: normalized.expiresAtMs,
    newAdministratorKey: normalized.newAdministratorKey,
    newAdministratorOperations: normalized.newAdministratorOperations,
    newAdministratorPrincipal: normalized.newAdministratorPrincipal,
    newInstanceId: normalized.newInstanceId,
    newRecoveryKey: normalized.newRecoveryKey,
    nonce: normalized.nonce,
    oldInstanceId: normalized.oldInstanceId,
    outputPath: normalized.outputPath,
    requestedAtMs: normalized.requestedAtMs,
    storeBinding: normalized.storeBinding,
  })}`;
}

export function rotateCloneAuthority(
  input: CloneRotationRequest,
  options: OfflineAuthorityOptions,
): Readonly<{ readonly instanceId: string; readonly generation: number; readonly outputPath: string }> {
  const request = normalizeClone(input);
  assertStoreBinding(request.storeBinding, options.databasePath);
  assertBoundedAdministratorScope({
    administratorKey: request.newAdministratorKey,
    administratorOperations: request.newAdministratorOperations,
    administratorPrincipal: request.newAdministratorPrincipal,
    audience: request.audience,
    expiresAtMs: request.expiresAtMs,
    instanceId: request.newInstanceId,
  });
  const now = safeNow(options.now);
  if (!requestIsCurrent(request.requestedAtMs, now) || request.expiresAtMs <= now
    || request.expiresAtMs > now + MAX_ADMINISTRATOR_CAPABILITY_MS
    || request.newInstanceId === request.oldInstanceId) throw new Error("Clone rotation request is invalid");
  assertCurrent(options.keyCurrentness, request.newAdministratorKey, now);
  assertCurrent(options.keyCurrentness, request.newRecoveryKey, now);
  return withOfflineStore(options.databasePath, (store) => store.rotateClone(request, now, options));
}

export function acquireAuthorityServiceLease(databasePath: string): AuthorityServiceLease {
  const identity = authorityLeaseIdentity(databasePath);
  let listener: Bun.UnixSocketListener<undefined>;
  try {
    listener = Bun.listen({ unix: identity.socket, socket: { data() {} } });
  } catch (error) {
    if (isNodeError(error) && error.code === "EADDRINUSE") {
      throw new Error("Authority service is running");
    }
    throw error;
  }
  let closed = false;
  return Object.freeze({
    assertActive(): void {
      if (closed) throw new Error("Authority service lease is closed");
      assertAuthorityDatabaseIdentity(identity);
    },
    close(): void {
      if (closed) return;
      closed = true;
      listener.stop(true);
    },
  });
}

export function readAuthorityCapabilityOutput(path: string): string {
  return readAuthorityOutputDocument(resolve(path)).capability;
}

function withOfflineStore<T>(databasePath: string, action: (store: OfflineAuthorityStore) => T): T {
  const resolved = resolve(databasePath);
  const lease = acquireAuthorityServiceLease(resolved);
  let store: OfflineAuthorityStore | undefined;
  try {
    store = new OfflineAuthorityStore(resolved);
    return action(store);
  } finally {
    store?.close();
    lease.close();
  }
}

class OfflineAuthorityStore {
  readonly #database: DacsDatabase;

  constructor(path: string) {
    this.#database = openDatabase(path);
  }

  close(): void {
    this.#database.close();
  }

  bootstrap(
    request: AuthorityBootstrapRequest,
    now: number,
    options: OfflineAuthorityOptions,
  ): Readonly<{ readonly instanceId: string; readonly generation: number; readonly outputPath: string }> {
    const count = this.#database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM party_authority_instances",
    ).get()?.count ?? 0n;
    if (count !== 0n) throw new Error("Party authority is already initialized");
    const token = this.#uniqueCapability(options.randomBytes);
    const digest = hashHex(token);
    writeAuthorityOutput(
      request.outputPath,
      token,
      hashHex(authorityBootstrapSigningBytes(request)),
      options.fault,
      () => {
      this.#database.transaction(() => {
        this.#database.query<never, Record<string, string | number>>(`
          /* atomic-write: party-authority.bootstrap-instance */
          INSERT INTO party_authority_instances (
            instance_id, audience, recovery_key, generation, initialized_at_ms
          ) VALUES ($instanceId, $audience, $recoveryKey, 1, $initializedAtMs)
        `).run({
          instanceId: request.instanceId,
          audience: request.audience,
          recoveryKey: request.recoveryKey,
          initializedAtMs: now,
        });
        this.#insertAdministrator({
          digest,
          instanceId: request.instanceId,
          audience: request.audience,
          principal: request.administratorPrincipal,
          operations: request.administratorOperations,
          expiresAtMs: request.expiresAtMs,
          configuredKey: request.administratorKey,
          issuedAtMs: now,
          generation: 1,
        }, MAX_ADMINISTRATOR_CAPABILITY_HISTORY);
      }).exclusive();
      },
    );
    return Object.freeze({ instanceId: request.instanceId, generation: 1, outputPath: request.outputPath });
  }

  recover(
    request: AuthorityRecoveryRequest,
    proof: string,
    now: number,
    options: OfflineAuthorityOptions,
  ): Readonly<{ readonly instanceId: string; readonly generation: number; readonly outputPath: string }> {
    const instance = this.#instance(request.instanceId, request.audience);
    if (instance === null || Number(instance.generation) !== request.expectedGeneration) {
      throw new Error("Recovery authority generation does not match");
    }
    assertCurrent(options.keyCurrentness, instance.recoveryKey, now);
    const signedBytes = authorityRecoverySigningBytes(request);
    if (!options.proofVerifier.verify({
      key: instance.recoveryKey,
      proof,
      signedBytes,
    })) throw new Error("Recovery proof is invalid");
    const proofDigest = hashHex(canonicalize({
      domain: RECOVERY_DOMAIN,
      instanceId: request.instanceId,
      expectedGeneration: request.expectedGeneration,
      nonce: request.nonce,
      recoveryKey: instance.recoveryKey,
    }));
    const replay = this.#database.query<{ count: bigint }, { proofDigest: string }>(
      "SELECT count(*) AS count FROM party_authority_recovery_replays WHERE proof_digest = $proofDigest",
    ).get({ proofDigest })?.count ?? 0n;
    if (replay !== 0n) throw new Error("Recovery proof was already consumed");
    const token = this.#uniqueCapability(options.randomBytes);
    const digest = hashHex(token);
    const generation = request.expectedGeneration + 1;
    writeAuthorityOutput(request.outputPath, token, hashHex(signedBytes), options.fault, () => {
      this.#database.transaction(() => {
        this.#database.query<never, { instanceId: string }>(`
          /* atomic-write: party-authority.recovery-delete-admins */
          DELETE FROM party_capabilities
          WHERE instance_id = $instanceId AND kind = 'administrator'
        `).run({ instanceId: request.instanceId });
        const advanced = this.#database.query<never, {
          instanceId: string; expectedGeneration: number;
        }>(`
          /* atomic-write: party-authority.recovery-generation */
          UPDATE party_authority_instances SET generation = generation + 1
          WHERE instance_id = $instanceId AND generation = $expectedGeneration
        `).run({ instanceId: request.instanceId, expectedGeneration: request.expectedGeneration });
        if (advanced.changes !== 1) throw new Error("Recovery authority changed during replacement");
        this.#insertAdministrator({
          digest,
          instanceId: request.instanceId,
          audience: request.audience,
          principal: request.administratorPrincipal,
          operations: request.administratorOperations,
          expiresAtMs: request.expiresAtMs,
          configuredKey: request.administratorKey,
          issuedAtMs: now,
          generation,
        }, MAX_ADMINISTRATOR_CAPABILITY_HISTORY);
        this.#database.query<never, Record<string, string | number>>(`
          /* atomic-write: party-authority.consume-recovery */
          INSERT INTO party_authority_recovery_replays (
            proof_digest, instance_id, generation, consumed_at_ms
          ) VALUES ($proofDigest, $instanceId, $generation, $consumedAtMs)
        `).run({
          proofDigest,
          instanceId: request.instanceId,
          generation,
          consumedAtMs: now,
        });
      }).exclusive();
    });
    return Object.freeze({ instanceId: request.instanceId, generation, outputPath: request.outputPath });
  }

  rotateClone(
    request: CloneRotationRequest,
    now: number,
    options: OfflineAuthorityOptions,
  ): Readonly<{ readonly instanceId: string; readonly generation: number; readonly outputPath: string }> {
    const instance = this.#instance(request.oldInstanceId, request.audience);
    if (instance === null) throw new Error("Clone source authority does not exist");
    const hasSessions = this.#database.query<{ found: bigint }, {
      instanceId: string; audience: string;
    }>(`
      SELECT count(*) AS found FROM sessions
      WHERE instance_id = $instanceId AND audience = $audience LIMIT 1
    `).get({ instanceId: request.oldInstanceId, audience: request.audience })?.found !== 0n;
    if (hasSessions) throw new Error("Clone rotation requires an unused source instance");
    const actor = this.#matchingAdministrator(request.administratorCapability, request.oldInstanceId, now);
    if (actor === null || !operations(actor.operationsJson).includes("clone:rotate")) {
      throw new Error("Clone rotation requires current administrator authority");
    }
    assertCurrent(options.keyCurrentness, actor.configuredKey, now);
    const signedBytes = cloneRotationSigningBytes(request);
    if (!options.proofVerifier.verify({
      key: actor.configuredKey,
      proof: request.administratorProof,
      signedBytes,
    }) || !options.proofVerifier.verify({
      key: request.newAdministratorKey,
      proof: request.newAdministratorProof,
      signedBytes,
    }) || !options.proofVerifier.verify({
      key: request.newRecoveryKey,
      proof: request.newRecoveryProof,
      signedBytes,
    })) throw new Error("Clone rotation proofs are invalid");
    const token = this.#uniqueCapability(options.randomBytes);
    const digest = hashHex(token);
    const generation = Number(instance.generation) + 1;
    const retiredAudience = `dacs-forge:retired:${hashHex(canonicalize({
      nonce: request.nonce,
      oldInstanceId: request.oldInstanceId,
    }))}`;
    writeAuthorityOutput(request.outputPath, token, hashHex(signedBytes), options.fault, () => {
      this.#database.transaction(() => {
        this.#database.query(`/* atomic-write: party-authority.clone-delete-amendments */
          DELETE FROM party_authority_amendments`)
          .run();
        this.#database.query(`/* atomic-write: party-authority.clone-delete-challenges */
          DELETE FROM party_authority_challenges WHERE instance_id = $instanceId`)
          .run({ instanceId: request.oldInstanceId });
        this.#database.query(`/* atomic-write: party-authority.clone-delete-admission-challenges */
          DELETE FROM admission_challenges WHERE instance_id = $instanceId AND audience = $audience`)
          .run({ instanceId: request.oldInstanceId, audience: request.audience });
        this.#database.query(`/* atomic-write: party-authority.clone-delete-preparations */
          DELETE FROM party_capability_preparations WHERE instance_id = $instanceId`)
          .run({ instanceId: request.oldInstanceId });
        const vacated = this.#database.query<never, {
          oldInstanceId: string; audience: string; retiredAudience: string;
        }>(`/* atomic-write: party-authority.clone-vacate-source */
          UPDATE party_authority_instances SET audience = $retiredAudience
          WHERE instance_id = $oldInstanceId AND audience = $audience`)
          .run({
            oldInstanceId: request.oldInstanceId,
            audience: request.audience,
            retiredAudience,
          });
        if (vacated.changes !== 1) throw new Error("Clone authority changed during rotation");
        this.#database.query<never, Record<string, string | number>>(`
          /* atomic-write: party-authority.clone-create-instance */
          INSERT INTO party_authority_instances (
            instance_id, audience, recovery_key, generation, initialized_at_ms
          ) VALUES ($newInstanceId, $audience, $newRecoveryKey, $generation, $initializedAtMs)
        `).run({
          newInstanceId: request.newInstanceId,
          audience: request.audience,
          newRecoveryKey: request.newRecoveryKey,
          generation,
          initializedAtMs: now,
        });
        this.#database.query(`/* atomic-write: party-authority.clone-revoke-capabilities */
          UPDATE party_capabilities
          SET instance_id = $newInstanceId, state = 'revoked',
            revoked_at_ms = CASE WHEN state = 'active' THEN $now ELSE revoked_at_ms END
          WHERE instance_id = $oldInstanceId`)
          .run({
            newInstanceId: request.newInstanceId,
            oldInstanceId: request.oldInstanceId,
            now,
          });
        this.#database.query(`/* atomic-write: party-authority.clone-delete-source */
          DELETE FROM party_authority_instances WHERE instance_id = $oldInstanceId`)
          .run({ oldInstanceId: request.oldInstanceId });
        this.#insertAdministrator({
          digest,
          instanceId: request.newInstanceId,
          audience: request.audience,
          principal: request.newAdministratorPrincipal,
          operations: request.newAdministratorOperations,
          expiresAtMs: request.expiresAtMs,
          configuredKey: request.newAdministratorKey,
          issuedAtMs: now,
          generation,
        }, MAX_ADMINISTRATOR_CAPABILITY_HISTORY);
      }).exclusive();
    });
    return Object.freeze({ instanceId: request.newInstanceId, generation, outputPath: request.outputPath });
  }

  #insertAdministrator(input: Readonly<{
    readonly audience: string;
    readonly configuredKey: string;
    readonly digest: string;
    readonly expiresAtMs: number;
    readonly generation: number;
    readonly instanceId: string;
    readonly issuedAtMs: number;
    readonly operations: readonly string[];
    readonly principal: string;
  }>, historyLimit: number): void {
    const history = this.#database.query<{ count: bigint }, { instanceId: string }>(`
      SELECT count(*) AS count FROM party_capabilities
      WHERE instance_id = $instanceId AND kind = 'administrator'
    `).get({ instanceId: input.instanceId })?.count ?? 0n;
    if (history >= BigInt(historyLimit)) {
      throw new Error("Administrator capability history capacity is exhausted");
    }
    this.#database.query<never, Record<string, string | number | null>>(`
      /* atomic-write: party-authority.insert-offline-administrator */
      INSERT INTO party_capabilities (
        capability_digest, instance_id, audience, kind, principal, operations_json,
        expires_at_ms, configured_key, job_id, role, authority_kind, authority_key,
        agreement_hash, state, issued_at_ms, revoked_at_ms, generation
      ) VALUES (
        $digest, $instanceId, $audience, 'administrator', $principal, $operationsJson,
        $expiresAtMs, $configuredKey, NULL, NULL, NULL, NULL,
        NULL, 'active', $issuedAtMs, NULL, $generation
      )
    `).run({
      digest: input.digest,
      instanceId: input.instanceId,
      audience: input.audience,
      principal: input.principal,
      operationsJson: canonicalize(normalizeOperations(input.operations)),
      expiresAtMs: input.expiresAtMs,
      configuredKey: input.configuredKey,
      issuedAtMs: input.issuedAtMs,
      generation: input.generation,
    });
  }

  #matchingAdministrator(token: string, instanceId: string, now: number): AdminRow | null {
    if (!LOWER_HEX_64.test(token)) return null;
    const digest = hashHex(token);
    const rows = this.#database.query<AdminRow, { instanceId: string; now: number }>(`
      SELECT capability_digest AS capabilityDigest, configured_key AS configuredKey,
        expires_at_ms AS expiresAtMs, operations_json AS operationsJson, principal
      FROM party_capabilities
      WHERE instance_id = $instanceId AND kind = 'administrator'
        AND state = 'active' AND expires_at_ms > $now
    `).all({ instanceId, now });
    for (const row of rows) {
      if (constantDigestEqual(digest, row.capabilityDigest)) return row;
    }
    return null;
  }

  #instance(instanceId: string, audience: string): InstanceRow | null {
    return this.#database.query<InstanceRow, { instanceId: string; audience: string }>(`
      SELECT instance_id AS instanceId, audience, recovery_key AS recoveryKey, generation
      FROM party_authority_instances WHERE instance_id = $instanceId AND audience = $audience
    `).get({ instanceId, audience });
  }

  #uniqueCapability(randomBytes: OfflineAuthorityOptions["randomBytes"]): string {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const token = Buffer.from(exactEntropy(
        randomBytes ?? operatingSystemRandomBytes,
        32,
        "capability",
      )).toString("hex");
      const digest = hashHex(token);
      const count = this.#database.query<{ count: bigint }, { digest: string }>(
        "SELECT count(*) AS count FROM party_capabilities WHERE capability_digest = $digest",
      ).get({ digest })?.count ?? 0n;
      if (count === 0n) return token;
    }
    throw new Error("Capability entropy provider produced repeated collisions");
  }
}

function writeAuthorityOutput(
  path: string,
  token: string,
  operationDigest: string,
  fault: OfflineAuthorityOptions["fault"],
  commit: () => void,
): void {
  const output = resolve(path);
  const directory = dirname(output);
  const staging = join(
    directory,
    `.dacs-authority-${hashHex(output).slice(0, 16)}-${operationDigest.slice(0, 16)}.pending`,
  );
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.geteuid?.()
    || (stat.mode & 0o077) !== 0) {
    throw new Error("Authority output directory must be process-owned and owner-only");
  }
  if (existsSync(output)) {
    let existing: AuthorityCapabilityOutput;
    try {
      existing = readAuthorityOutputDocument(output);
    } catch {
      throw new Error("Authority output path already exists and is not a recoverable orphan");
    }
    if (existing.operationDigest !== operationDigest) {
      throw new Error("Authority output path belongs to a different operation");
    }
    unlinkSync(output);
    fsyncDirectory(directory);
  }
  if (existsSync(staging)) {
    unlinkSync(staging);
    fsyncDirectory(directory);
  }
  let fd: number | undefined;
  let committed = false;
  let published = false;
  try {
    fd = openSync(staging, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    fault?.("after-create");
    const document = `${canonicalize({
      capability: token,
      operationDigest,
      schema: "dacs-authority-capability/v1",
    })}\n`;
    writeAll(fd, Buffer.from(document));
    fault?.("after-write");
    fsyncSync(fd);
    fault?.("after-file-fsync");
    const staged = readAuthorityOutputDocument(staging);
    if (staged.capability !== token || staged.operationDigest !== operationDigest) {
      throw new Error("Authority capability staging validation failed");
    }
    closeSync(fd);
    fd = undefined;
    linkSync(staging, output);
    published = true;
    fsyncDirectory(directory);
    unlinkSync(staging);
    fsyncDirectory(directory);
    fault?.("after-directory-fsync");
    fault?.("before-database-commit");
    commit();
    committed = true;
    fault?.("after-database-commit");
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (!committed) {
      for (const candidate of published ? [output, staging] : [staging]) {
        try {
          unlinkSync(candidate);
        } catch (error) {
          if (!isNodeError(error) || error.code !== "ENOENT") throw error;
        }
      }
      fsyncDirectory(directory);
    }
  }
}

function readAuthorityOutputDocument(path: string): AuthorityCapabilityOutput {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== process.geteuid?.()
    || (metadata.mode & 0o777) !== 0o600 || metadata.size > 8_192) {
    throw new Error("Authority capability output is not a process-owned 0600 regular file");
  }
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Authority capability output is invalid");
  }
  const value = parsed as Record<string, unknown>;
  if (Object.keys(value).sort().join(",") !== "capability,operationDigest,schema"
    || value["schema"] !== "dacs-authority-capability/v1"
    || typeof value["capability"] !== "string" || !LOWER_HEX_64.test(value["capability"])
    || typeof value["operationDigest"] !== "string"
    || !LOWER_HEX_64.test(value["operationDigest"])) {
    throw new Error("Authority capability output is invalid");
  }
  return Object.freeze({
    capability: value["capability"],
    operationDigest: value["operationDigest"],
    schema: "dacs-authority-capability/v1",
  });
}

function fsyncDirectory(path: string): void {
  const directoryFd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(directoryFd);
  } finally {
    closeSync(directoryFd);
  }
}

function writeAll(fd: number, bytes: Uint8Array): void {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const written = writeSync(fd, bytes, offset, bytes.byteLength - offset);
    if (written < 1) throw new Error("Authority file write made no progress");
    offset += written;
  }
}


function normalizeBootstrap(input: AuthorityBootstrapRequest): AuthorityBootstrapRequest {
  return Object.freeze({
    administratorKey: field("administratorKey", input.administratorKey),
    administratorOperations: normalizeOperations(input.administratorOperations),
    administratorPrincipal: field("administratorPrincipal", input.administratorPrincipal),
    audience: field("audience", input.audience),
    expiresAtMs: timestamp(input.expiresAtMs, "expiresAtMs"),
    instanceId: field("instanceId", input.instanceId),
    nonce: hash(input.nonce, "nonce"),
    outputPath: absolutePath(input.outputPath),
    recoveryKey: field("recoveryKey", input.recoveryKey),
    requestedAtMs: timestamp(input.requestedAtMs, "requestedAtMs"),
    storeBinding: hash(input.storeBinding, "storeBinding"),
  });
}

function normalizeRecovery(input: AuthorityRecoveryRequest): AuthorityRecoveryRequest {
  return Object.freeze({
    administratorKey: field("administratorKey", input.administratorKey),
    administratorOperations: normalizeOperations(input.administratorOperations),
    administratorPrincipal: field("administratorPrincipal", input.administratorPrincipal),
    audience: field("audience", input.audience),
    expiresAtMs: timestamp(input.expiresAtMs, "expiresAtMs"),
    expectedGeneration: positiveInteger(input.expectedGeneration, "expectedGeneration"),
    instanceId: field("instanceId", input.instanceId),
    nonce: hash(input.nonce, "nonce"),
    outputPath: absolutePath(input.outputPath),
    requestedAtMs: timestamp(input.requestedAtMs, "requestedAtMs"),
    storeBinding: hash(input.storeBinding, "storeBinding"),
  });
}

function normalizeClone(input: CloneRotationRequest): CloneRotationRequest {
  return Object.freeze({
    administratorProof: field("administratorProof", input.administratorProof),
    administratorCapability: hash(input.administratorCapability, "administratorCapability"),
    audience: field("audience", input.audience),
    expiresAtMs: timestamp(input.expiresAtMs, "expiresAtMs"),
    newAdministratorKey: field("newAdministratorKey", input.newAdministratorKey),
    newAdministratorOperations: normalizeOperations(input.newAdministratorOperations),
    newAdministratorPrincipal: field("newAdministratorPrincipal", input.newAdministratorPrincipal),
    newAdministratorProof: field("newAdministratorProof", input.newAdministratorProof),
    newInstanceId: field("newInstanceId", input.newInstanceId),
    newRecoveryKey: field("newRecoveryKey", input.newRecoveryKey),
    newRecoveryProof: field("newRecoveryProof", input.newRecoveryProof),
    nonce: hash(input.nonce, "nonce"),
    oldInstanceId: field("oldInstanceId", input.oldInstanceId),
    outputPath: absolutePath(input.outputPath),
    requestedAtMs: timestamp(input.requestedAtMs, "requestedAtMs"),
    storeBinding: hash(input.storeBinding, "storeBinding"),
  });
}

function absolutePath(value: string): string {
  if (typeof value !== "string" || resolve(value) !== value) {
    throw new TypeError("Authority output path must be absolute");
  }
  return value;
}

function normalizeOperations(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new TypeError("Authority operations must contain 1 through 64 entries");
  }
  const result = value.map((item) => field("operation", item)).sort();
  if (new Set(result).size !== result.length) throw new TypeError("Authority operations must be unique");
  return Object.freeze(result);
}

function operations(value: string): readonly string[] {
  return normalizeOperations(JSON.parse(value) as readonly string[]);
}

function assertCurrent(resolver: Dacs2KeyCurrentnessResolver, keyClaim: string, checkedAt: number): void {
  const result = resolver.resolve({ keyClaim, checkedAt });
  if (result.disposition !== "current" || result.currentClaim !== keyClaim
    || result.checkedAt !== checkedAt) throw new Error("Authority key is not current");
}

function exactEntropy(
  randomBytes: (size: number) => Uint8Array,
  size: number,
  stage: string,
): Uint8Array {
  const bytes = randomBytes(size);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== size) {
    throw new Error(`${stage} entropy must return exactly ${size} bytes`);
  }
  return Uint8Array.from(bytes);
}

function safeNow(now: (() => number) | undefined): number {
  const value = (now ?? Date.now)();
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Authority clock is invalid");
  return value;
}

function requestIsCurrent(requestedAtMs: number, now: number): boolean {
  return requestedAtMs >= now - REQUEST_PAST_MS && requestedAtMs <= now + REQUEST_FUTURE_MS;
}

function field(name: string, value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_LENGTH
    || value !== value.normalize("NFC")) throw new TypeError(`${name} is invalid`);
  return value;
}

function hash(value: string, name: string): string {
  if (typeof value !== "string" || !LOWER_HEX_64.test(value)) {
    throw new TypeError(`${name} must be 32-byte lowercase hex`);
  }
  return value;
}

function timestamp(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} is invalid`);
  return value;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} is invalid`);
  return value;
}

function hashHex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function constantDigestEqual(left: string, right: string): boolean {
  return LOWER_HEX_64.test(left) && LOWER_HEX_64.test(right)
    && timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function authorityLeaseIdentity(databasePath: string): AuthorityLeaseIdentity {
  const canonicalPath = canonicalAuthorityDatabasePath(databasePath);
  try {
    const snapshot = statSync(canonicalPath, { bigint: true });
    if (!snapshot.isFile()) throw new Error("Authority database must be a regular file");
    if (snapshot.nlink !== 1n) throw new Error("Authority database must not have hard-link aliases");
    return Object.freeze({
      canonicalPath,
      device: snapshot.dev,
      inode: snapshot.ino,
      socket: `\0dacs-forge-authority-${hashHex(`path:${canonicalPath}`)}`,
    });
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    return Object.freeze({
      canonicalPath: null,
      device: null,
      inode: null,
      socket: `\0dacs-forge-authority-${hashHex(`path:${canonicalPath}`)}`,
    });
  }
}

function canonicalAuthorityDatabasePath(databasePath: string): string {
  const absolute = resolve(databasePath);
  try {
    return realpathSync(absolute);
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    return join(realpathSync(dirname(absolute)), basename(absolute));
  }
}

function assertStoreBinding(binding: string, databasePath: string): void {
  if (!constantDigestEqual(binding, authorityStoreBinding(databasePath))) {
    throw new Error("Offline authority request targets a different store");
  }
}

function assertBoundedAdministratorScope(input: Readonly<{
  readonly administratorKey: string;
  readonly administratorOperations: readonly string[];
  readonly administratorPrincipal: string;
  readonly audience: string;
  readonly expiresAtMs: number;
  readonly instanceId: string;
}>): void {
  const scope = {
    kind: "administrator",
    instanceId: input.instanceId,
    audience: input.audience,
    principal: input.administratorPrincipal,
    operations: input.administratorOperations,
    expiresAtMs: input.expiresAtMs,
    configuredKey: input.administratorKey,
  } as const;
  if (Buffer.byteLength(canonicalize(scope), "utf8") > MAX_CAPABILITY_SCOPE_BYTES) {
    throw new TypeError("Administrator capability scope exceeds its aggregate byte bound");
  }
}

function assertAuthorityDatabaseIdentity(identity: AuthorityLeaseIdentity): void {
  if (identity.canonicalPath === null || identity.device === null || identity.inode === null) return;
  const current = statSync(identity.canonicalPath, { bigint: true });
  if (!current.isFile() || current.dev !== identity.device || current.ino !== identity.inode) {
    throw new Error("Authority database identity changed while leased");
  }
  if (current.nlink !== 1n) throw new Error("Authority database gained a hard-link alias while leased");
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

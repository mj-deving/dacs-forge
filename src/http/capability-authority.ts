import { createHash, randomBytes as operatingSystemRandomBytes } from "node:crypto";
import { canonicalize } from "../protocol/canonical-json.ts";

const CAPABILITY_BYTES = 32;
const MAX_COLLISION_ATTEMPTS = 8;
const MAX_FIELD_LENGTH = 4_096;

export type CapabilityOperation = string;

interface CapabilityScopeBase {
  readonly instanceId: string;
  readonly audience: string;
  readonly principal: string;
  readonly operations: readonly CapabilityOperation[];
  readonly expiresAtMs: number;
}

export interface AdministratorCapabilityScope extends CapabilityScopeBase {
  readonly kind: "administrator";
  readonly configuredKey: string;
}

export interface PartyCapabilityScope extends CapabilityScopeBase {
  readonly kind: "party";
  readonly jobId: string;
  readonly role: "buyer" | "seller";
  readonly authority: Readonly<{
    readonly kind: "admission" | "agreement";
    readonly key: string;
  }>;
}

export type CapabilityScope = AdministratorCapabilityScope | PartyCapabilityScope;

export interface CapabilityGrant<TScope extends CapabilityScope = CapabilityScope> {
  readonly token: string;
  readonly scope: TScope;
}

export interface CapabilityAuthorityOptions {
  readonly audience: string;
  readonly instanceId: string;
  readonly now?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
}

/**
 * Minimal in-process capability primitive for the prototype HTTP boundary.
 *
 * Lifecycle persistence, revocation, recovery and digest-only storage belong to the successor
 * PartyAuthorityLifecycle feature. This class owns only the load-bearing seam needed here:
 * 256-bit OS entropy and exact immutable deployment/audience/authority scopes.
 */
export class CapabilityAuthority {
  readonly #audience: string;
  readonly #instanceId: string;
  readonly #issued = new Map<string, string>();
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly issuerId: string;

  constructor(options: CapabilityAuthorityOptions) {
    validateField("instanceId", options?.instanceId);
    validateField("audience", options?.audience);
    this.#instanceId = options.instanceId;
    this.#audience = options.audience;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? operatingSystemRandomBytes;
    this.issuerId = digestHex(this.#entropy("startup"));
    this.#safeNow();
  }

  issueAdministrator(
    input: Readonly<{
      readonly principal: string;
      readonly operations: readonly CapabilityOperation[];
      readonly expiresAtMs: number;
      readonly configuredKey: string;
    }>,
  ): CapabilityGrant<AdministratorCapabilityScope> {
    const scope = Object.freeze({
      kind: "administrator" as const,
      instanceId: this.#instanceId,
      audience: this.#audience,
      principal: validatedField("principal", input?.principal),
      operations: normalizeOperations(input?.operations),
      expiresAtMs: this.#validateExpiry(input?.expiresAtMs),
      configuredKey: validatedField("configuredKey", input?.configuredKey),
    });
    return this.#issue(scope);
  }

  issueParty(
    input: Readonly<{
      readonly principal: string;
      readonly operations: readonly CapabilityOperation[];
      readonly expiresAtMs: number;
      readonly jobId: string;
      readonly role: "buyer" | "seller";
      readonly authority: Readonly<{
        readonly kind: "admission" | "agreement";
        readonly key: string;
      }>;
    }>,
  ): CapabilityGrant<PartyCapabilityScope> {
    if (input?.role !== "buyer" && input?.role !== "seller") {
      throw new TypeError("Party capability role must be buyer or seller");
    }
    if (input.authority?.kind !== "admission" && input.authority?.kind !== "agreement") {
      throw new TypeError("Party capability authority must be admission or agreement");
    }
    const scope = Object.freeze({
      kind: "party" as const,
      instanceId: this.#instanceId,
      audience: this.#audience,
      principal: validatedField("principal", input.principal),
      operations: normalizeOperations(input.operations),
      expiresAtMs: this.#validateExpiry(input.expiresAtMs),
      jobId: validatedField("jobId", input.jobId),
      role: input.role,
      authority: Object.freeze({
        kind: input.authority.kind,
        key: validatedField("authority.key", input.authority.key),
      }),
    });
    return this.#issue(scope);
  }

  authorize(token: string, expectedScope: CapabilityScope): boolean {
    if (!/^[0-9a-f]{64}$/.test(token)) return false;
    let expected: string;
    try {
      expected = canonicalize(normalizeExpectedScope(expectedScope));
    } catch {
      return false;
    }
    const stored = this.#issued.get(digestHex(token));
    return stored !== undefined && stored === expected
      && expectedScope.instanceId === this.#instanceId
      && expectedScope.audience === this.#audience
      && expectedScope.expiresAtMs > this.#safeNow();
  }

  #issue<TScope extends CapabilityScope>(scope: TScope): CapabilityGrant<TScope> {
    const canonicalScope = canonicalize(scope);
    for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
      const token = Buffer.from(this.#entropy("issuance")).toString("hex");
      const digest = digestHex(token);
      if (this.#issued.has(digest)) continue;
      this.#issued.set(digest, canonicalScope);
      return Object.freeze({ token, scope });
    }
    throw new Error("Capability entropy provider produced repeated collisions");
  }

  #entropy(stage: "startup" | "issuance"): Uint8Array {
    const bytes = this.#randomBytes(CAPABILITY_BYTES);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== CAPABILITY_BYTES) {
      throw new Error(`Capability ${stage} entropy provider must return exactly 32 bytes`);
    }
    return bytes;
  }

  #safeNow(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("Clock returned an invalid time");
    return now;
  }

  #validateExpiry(expiresAtMs: number): number {
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= this.#safeNow()) {
      throw new TypeError("Capability expiry must be a future safe-integer timestamp");
    }
    return expiresAtMs;
  }
}

function normalizeExpectedScope(scope: CapabilityScope): CapabilityScope {
  if (scope?.kind === "administrator") {
    return Object.freeze({
      kind: "administrator",
      instanceId: validatedField("instanceId", scope.instanceId),
      audience: validatedField("audience", scope.audience),
      principal: validatedField("principal", scope.principal),
      operations: normalizeOperations(scope.operations),
      expiresAtMs: validatedTimestamp(scope.expiresAtMs),
      configuredKey: validatedField("configuredKey", scope.configuredKey),
    });
  }
  if (scope?.kind === "party" && (scope.role === "buyer" || scope.role === "seller")
    && (scope.authority?.kind === "admission" || scope.authority?.kind === "agreement")) {
    return Object.freeze({
      kind: "party",
      instanceId: validatedField("instanceId", scope.instanceId),
      audience: validatedField("audience", scope.audience),
      principal: validatedField("principal", scope.principal),
      operations: normalizeOperations(scope.operations),
      expiresAtMs: validatedTimestamp(scope.expiresAtMs),
      jobId: validatedField("jobId", scope.jobId),
      role: scope.role,
      authority: Object.freeze({
        kind: scope.authority.kind,
        key: validatedField("authority.key", scope.authority.key),
      }),
    });
  }
  throw new TypeError("Capability scope is invalid");
}

function normalizeOperations(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new TypeError("Capability operations must contain 1 through 64 entries");
  }
  const operations = value.map((operation) => validatedField("operation", operation));
  if (new Set(operations).size !== operations.length) {
    throw new TypeError("Capability operations must be unique");
  }
  return Object.freeze([...operations].sort());
}

function validatedTimestamp(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("Capability timestamp must be a non-negative safe integer");
  }
  return value;
}

function validatedField(name: string, value: string): string {
  validateField(name, value);
  return value;
}

function validateField(name: string, value: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_LENGTH
    || value !== value.normalize("NFC")) {
    throw new TypeError(`Capability ${name} is invalid`);
  }
}

function digestHex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

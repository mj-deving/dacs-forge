import { createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalize } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import type { DacsDatabase } from "../substrate/sqlite/database.ts";
import type { AdmittedExecutionProfile } from "./profile.ts";

const ACTIVITY_TYPE = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2" as const;
const ENCODING = "PAYLOAD_ENCODING_HEXADECIMAL" as const;
const HASH_FUNCTION = "HASH_FUNCTION_NOT_APPLICABLE" as const;
const SIGNING_ROLE = "demos-storage-anchor" as const;

export type TurnkeySigningIntentState =
  | "prepared"
  | "submitting"
  | "activity-observed"
  | "signed"
  | "failed";

export interface TurnkeySignRawPayloadRequest extends Record<string, unknown> {
  readonly type: typeof ACTIVITY_TYPE;
  readonly timestampMs: string;
  readonly organizationId: string;
  readonly parameters: Readonly<{
    readonly signWith: string;
    readonly payload: string;
    readonly encoding: typeof ENCODING;
    readonly hashFunction: typeof HASH_FUNCTION;
  }>;
}

export interface TurnkeySignature extends Record<string, unknown> {
  readonly r: string;
  readonly s: string;
  readonly v: string;
}

export interface TurnkeyActivity extends Record<string, unknown> {
  readonly id: string;
  readonly organizationId: string;
  readonly status: string;
  readonly type: string;
  readonly intent: Readonly<{
    readonly signRawPayloadIntentV2?: Readonly<Record<string, unknown>>;
  }>;
  readonly result?: Readonly<{
    readonly signRawPayloadResult?: Readonly<Record<string, unknown>>;
  }>;
  readonly failure?: Readonly<Record<string, unknown>>;
}

export interface TurnkeyActivityClient {
  readonly submitSignRawPayload: (request: TurnkeySignRawPayloadRequest) => Promise<TurnkeyActivity>;
  readonly getActivity: (input: Readonly<{
    readonly organizationId: string;
    readonly activityId: string;
  }>) => Promise<TurnkeyActivity>;
}

export interface TurnkeySellerAnchorConfig {
  readonly organizationId: string;
  readonly privateKeyId: string;
  readonly publicKeyHex: string;
  readonly sellerClaim: string;
  readonly chain: "demos-testnet";
  readonly signingDomain: string;
  readonly maxFeeAtomic: string;
}

export interface TurnkeySigningIntentRecord {
  readonly effectKey: string;
  readonly providerRequestId: string;
  readonly signingRole: typeof SIGNING_ROLE;
  readonly sellerClaim: string;
  readonly organizationId: string;
  readonly privateKeyId: string;
  readonly publicKeyHex: string;
  readonly chain: "demos-testnet";
  readonly signingDomain: string;
  readonly amountAtomic: "0";
  readonly feeAtomic: string;
  readonly feeCapAtomic: string;
  readonly payloadHash: string;
  readonly requestBodyHash: string;
  readonly requestBodyJson: string;
  readonly state: TurnkeySigningIntentState;
  readonly activityId?: string;
  readonly activityStatus?: string;
  readonly activityJson?: string;
  readonly signatureJson?: string;
  readonly signatureDigest?: string;
}

interface TurnkeySigningIntentRow {
  readonly effectKey: string;
  readonly providerRequestId: string;
  readonly signingRole: typeof SIGNING_ROLE;
  readonly sellerClaim: string;
  readonly organizationId: string;
  readonly privateKeyId: string;
  readonly publicKeyHex: string;
  readonly chain: "demos-testnet";
  readonly signingDomain: string;
  readonly amountAtomic: "0";
  readonly feeAtomic: string;
  readonly feeCapAtomic: string;
  readonly payloadHash: string;
  readonly requestBodyHash: string;
  readonly requestBodyJson: string;
  readonly state: TurnkeySigningIntentState;
  readonly activityId: string | null;
  readonly activityStatus: string | null;
  readonly activityJson: string | null;
  readonly signatureJson: string | null;
  readonly signatureDigest: string | null;
}

export class TurnkeySigningIntentStore {
  constructor(
    private readonly database: DacsDatabase,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  prepare(input: Readonly<{
    readonly effectKey: string;
    readonly config: TurnkeySellerAnchorConfig;
    readonly feeAtomic: string;
    readonly payloadHex: string;
    readonly request: TurnkeySignRawPayloadRequest;
  }>): TurnkeySigningIntentRecord {
    validateEffectKey(input.effectKey);
    const requestBodyJson = canonicalize(input.request);
    const requestBodyHash = sha256Hex(requestBodyJson);
    const payloadHash = sha256Hex(Buffer.from(input.payloadHex, "hex"));
    const now = this.timestamp();
    this.database.query<never, {
      effectKey: string;
      providerRequestId: string;
      signingRole: typeof SIGNING_ROLE;
      sellerClaim: string;
      organizationId: string;
      privateKeyId: string;
      publicKeyHex: string;
      signingDomain: string;
      feeAtomic: string;
      feeCapAtomic: string;
      payloadHash: string;
      requestBodyHash: string;
      requestBodyJson: string;
      now: string;
    }>(`
      /* atomic-write: turnkey-signing.prepare */
      INSERT INTO turnkey_signing_intents (
        effect_key, provider_request_id, signing_role, seller_claim, organization_id,
        private_key_id, public_key_hex, chain, signing_domain, amount_atomic, fee_atomic, fee_cap_atomic,
        payload_hash, request_body_hash, request_body_json, state, created_at, updated_at
      ) VALUES (
        $effectKey, $providerRequestId, $signingRole, $sellerClaim, $organizationId,
        $privateKeyId, $publicKeyHex, 'demos-testnet', $signingDomain, '0', $feeAtomic, $feeCapAtomic,
        $payloadHash, $requestBodyHash, $requestBodyJson, 'prepared', $now, $now
      ) ON CONFLICT(effect_key) DO NOTHING
    `).run({
      effectKey: input.effectKey,
      providerRequestId: requestBodyHash,
      signingRole: SIGNING_ROLE,
      sellerClaim: input.config.sellerClaim,
      organizationId: input.config.organizationId,
      privateKeyId: input.config.privateKeyId,
      publicKeyHex: input.config.publicKeyHex,
      signingDomain: input.config.signingDomain,
      feeAtomic: input.feeAtomic,
      feeCapAtomic: input.config.maxFeeAtomic,
      payloadHash,
      requestBodyHash,
      requestBodyJson,
      now,
    });
    const record = this.get(input.effectKey);
    if (record === null || record.requestBodyJson !== requestBodyJson
      || record.requestBodyHash !== requestBodyHash || record.providerRequestId !== requestBodyHash
      || record.payloadHash !== payloadHash || record.signingRole !== SIGNING_ROLE
      || record.sellerClaim !== input.config.sellerClaim
      || record.organizationId !== input.config.organizationId
      || record.privateKeyId !== input.config.privateKeyId
      || record.publicKeyHex !== input.config.publicKeyHex
      || record.chain !== input.config.chain
      || record.signingDomain !== input.config.signingDomain
      || record.amountAtomic !== "0" || record.feeAtomic !== input.feeAtomic
      || record.feeCapAtomic !== input.config.maxFeeAtomic) {
      throw new Error("Effect key is already bound to a different immutable intent");
    }
    return record;
  }

  markSubmitting(effectKey: string): TurnkeySigningIntentRecord {
    this.database.query<never, { effectKey: string; now: string }>(`
      /* atomic-write: turnkey-signing.mark-submitting */
      UPDATE turnkey_signing_intents SET state = 'submitting', updated_at = $now
      WHERE effect_key = $effectKey AND state = 'prepared'
    `).run({ effectKey, now: this.timestamp() });
    const record = this.getRequired(effectKey);
    if (record.state === "prepared") throw new Error("Signing intent cannot enter submission state");
    return record;
  }

  observeActivity(effectKey: string, activity: TurnkeyActivity): TurnkeySigningIntentRecord {
    const record = this.getRequired(effectKey);
    validateActivityIdentity(record, activity);
    const activityJson = canonicalize(activity);
    const state = isFailedStatus(activity.status) ? "failed" : "activity-observed";
    this.database.query<never, {
      effectKey: string;
      activityId: string;
      activityStatus: string;
      activityJson: string;
      state: "activity-observed" | "failed";
      now: string;
    }>(`
      /* atomic-write: turnkey-signing.observe-activity */
      UPDATE turnkey_signing_intents SET
        state = $state, activity_id = $activityId, activity_status = $activityStatus,
        activity_json = $activityJson, updated_at = $now
      WHERE effect_key = $effectKey AND state IN ('prepared', 'submitting', 'activity-observed')
        AND (activity_id IS NULL OR activity_id = $activityId)
        AND signature_json IS NULL AND signature_digest IS NULL
    `).run({
      effectKey,
      activityId: activity.id,
      activityStatus: activity.status,
      activityJson,
      state,
      now: this.timestamp(),
    });
    const observed = this.getRequired(effectKey);
    if (observed.state === "signed") {
      if (activity.status === "ACTIVITY_STATUS_COMPLETED") {
        validateStoredSignature(observed, activity);
      } else if (isFailedStatus(activity.status)) {
        throw new Error("Terminal Turnkey Activity conflicts with durable signed state");
      }
      return observed;
    }
    if (observed.activityId !== activity.id || observed.activityJson !== activityJson
      || observed.activityStatus !== activity.status || observed.state !== state) {
      throw new Error("Turnkey Activity conflicts with durable signing state");
    }
    return observed;
  }

  persistSignature(effectKey: string, activity: TurnkeyActivity): TurnkeySigningIntentRecord {
    const record = this.getRequired(effectKey);
    validateActivityIdentity(record, activity);
    const signature = readVerifiedCompletedSignature(record, activity);
    const signatureJson = canonicalize(signature);
    const signatureDigest = sha256Hex(signatureJson);
    const activityJson = canonicalize(activity);
    this.database.query<never, {
      effectKey: string;
      activityId: string;
      activityJson: string;
      signatureJson: string;
      signatureDigest: string;
      now: string;
    }>(`
      /* atomic-write: turnkey-signing.persist-signature */
      UPDATE turnkey_signing_intents SET
        state = 'signed', activity_status = 'ACTIVITY_STATUS_COMPLETED',
        activity_json = $activityJson, signature_json = $signatureJson,
        signature_digest = $signatureDigest, updated_at = $now
      WHERE effect_key = $effectKey AND state = 'activity-observed'
        AND activity_id = $activityId AND signature_json IS NULL AND signature_digest IS NULL
    `).run({
      effectKey,
      activityId: activity.id,
      activityJson,
      signatureJson,
      signatureDigest,
      now: this.timestamp(),
    });
    const signed = this.getRequired(effectKey);
    if (signed.state !== "signed" || signed.activityId !== activity.id
      || signed.signatureJson !== signatureJson || signed.signatureDigest !== signatureDigest) {
      throw new Error("Turnkey signature conflicts with durable signing state");
    }
    return signed;
  }

  get(effectKey: string): TurnkeySigningIntentRecord | null {
    validateEffectKey(effectKey);
    const row = this.database.query<TurnkeySigningIntentRow, { effectKey: string }>(`
      SELECT effect_key AS effectKey, provider_request_id AS providerRequestId,
        signing_role AS signingRole, seller_claim AS sellerClaim,
        organization_id AS organizationId, private_key_id AS privateKeyId,
        public_key_hex AS publicKeyHex,
        chain, signing_domain AS signingDomain, amount_atomic AS amountAtomic,
        fee_atomic AS feeAtomic, fee_cap_atomic AS feeCapAtomic,
        payload_hash AS payloadHash, request_body_hash AS requestBodyHash,
        request_body_json AS requestBodyJson, state, activity_id AS activityId,
        activity_status AS activityStatus, activity_json AS activityJson,
        signature_json AS signatureJson, signature_digest AS signatureDigest
      FROM turnkey_signing_intents WHERE effect_key = $effectKey
    `).get({ effectKey });
    if (row === null) return null;
    const record = Object.freeze({
      effectKey: row.effectKey,
      providerRequestId: row.providerRequestId,
      signingRole: row.signingRole,
      sellerClaim: row.sellerClaim,
      organizationId: row.organizationId,
      privateKeyId: row.privateKeyId,
      publicKeyHex: row.publicKeyHex,
      chain: row.chain,
      signingDomain: row.signingDomain,
      amountAtomic: row.amountAtomic,
      feeAtomic: row.feeAtomic,
      feeCapAtomic: row.feeCapAtomic,
      payloadHash: row.payloadHash,
      requestBodyHash: row.requestBodyHash,
      requestBodyJson: row.requestBodyJson,
      state: row.state,
      ...(row.activityId === null ? {} : { activityId: row.activityId }),
      ...(row.activityStatus === null ? {} : { activityStatus: row.activityStatus }),
      ...(row.activityJson === null ? {} : { activityJson: row.activityJson }),
      ...(row.signatureJson === null ? {} : { signatureJson: row.signatureJson }),
      ...(row.signatureDigest === null ? {} : { signatureDigest: row.signatureDigest }),
    });
    validatePersistentRecord(record);
    return record;
  }

  private getRequired(effectKey: string): TurnkeySigningIntentRecord {
    const record = this.get(effectKey);
    if (record === null) throw new Error("Turnkey signing intent does not exist");
    return record;
  }

  private timestamp(): string {
    const value = this.now();
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
      throw new TypeError("Turnkey signing store clock returned an invalid timestamp");
    }
    return value;
  }
}

export type TurnkeySigningCrashBoundary =
  | "after-prepare"
  | "after-submit"
  | "after-activity-observed"
  | "after-signed-persist";

export async function runTurnkeySellerAnchorSigning(input: Readonly<{
  readonly store: TurnkeySigningIntentStore;
  readonly profile: AdmittedExecutionProfile;
  readonly client: TurnkeyActivityClient;
  readonly config: TurnkeySellerAnchorConfig;
  readonly effectKey: string;
  readonly payloadHex: string;
  readonly timestampMs: string;
  readonly feeAtomic: string;
  readonly crash?: (boundary: TurnkeySigningCrashBoundary) => void;
}>): Promise<Readonly<{
  readonly activityId: string;
  readonly providerRequestId: string;
  readonly signature: TurnkeySignature;
  readonly signatureDigest: string;
}>> {
  validateAdmission(input.profile, input.config, input.feeAtomic);
  const request = createRequest(input.config, input.payloadHex, input.timestampMs);
  let record = input.store.prepare({
    effectKey: input.effectKey,
    config: input.config,
    feeAtomic: input.feeAtomic,
    payloadHex: input.payloadHex,
    request,
  });
  input.crash?.("after-prepare");
  if (record.state === "signed") return signedResult(record);
  if (record.state === "failed") throw new Error("Turnkey signing Activity failed");

  let activity: TurnkeyActivity;
  if (record.activityId === undefined) {
    if (record.state === "prepared") record = input.store.markSubmitting(input.effectKey);
    if (record.state === "signed") return signedResult(record);
    if (record.state === "failed") throw new Error("Turnkey signing Activity failed");
  }
  if (record.activityId === undefined) {
    // Turnkey defines the complete POST body as the Activity idempotency identity. The persisted
    // canonical body includes timestampMs, so crash recovery must resend it byte-for-byte.
    activity = await input.client.submitSignRawPayload(parseRequest(record.requestBodyJson));
    input.crash?.("after-submit");
  } else {
    activity = await input.client.getActivity({
      organizationId: record.organizationId,
      activityId: record.activityId,
    });
  }
  record = input.store.observeActivity(input.effectKey, activity);
  input.crash?.("after-activity-observed");
  if (record.state === "signed") return signedResult(record);
  if (record.state === "failed") throw new Error("Turnkey signing Activity failed");
  if (activity.status !== "ACTIVITY_STATUS_COMPLETED") {
    throw new Error(`Turnkey signing Activity is pending: ${activity.status}`);
  }
  record = input.store.persistSignature(input.effectKey, activity);
  input.crash?.("after-signed-persist");
  return signedResult(record);
}

function createRequest(
  config: TurnkeySellerAnchorConfig,
  payloadHex: string,
  timestampMs: string,
): TurnkeySignRawPayloadRequest {
  if (!bounded(config.organizationId) || !bounded(config.privateKeyId)
    || !/^[0-9a-f]{64}$/.test(config.publicKeyHex)
    || !/^did:demos:agent:[0-9a-f]{64}$/.test(config.sellerClaim)
    || config.chain !== "demos-testnet" || !bounded(config.signingDomain)) {
    throw new TypeError("Turnkey seller-anchor configuration is invalid");
  }
  if (!/^(0|[1-9][0-9]{0,18})$/.test(timestampMs)) {
    throw new TypeError("Turnkey timestampMs must be a bounded canonical integer string");
  }
  if (!/^(?:[0-9a-f]{2}){1,32768}$/.test(payloadHex)) {
    throw new TypeError("Turnkey payload must be bounded lower-case hexadecimal bytes");
  }
  return Object.freeze({
    type: ACTIVITY_TYPE,
    timestampMs,
    organizationId: config.organizationId,
    parameters: Object.freeze({
      signWith: config.privateKeyId,
      payload: payloadHex,
      encoding: ENCODING,
      hashFunction: HASH_FUNCTION,
    }),
  });
}

function validateAdmission(
  profile: AdmittedExecutionProfile,
  config: TurnkeySellerAnchorConfig,
  feeAtomic: string,
): void {
  if (profile.mode !== "live-testnet" || !profile.networkEffects
    || !profile.allowedEffects.includes("anchor")
    || profile.config?.signer.expectedClaim !== config.sellerClaim
    || profile.config.signer.keyReference !== `turnkey:private-key:${config.privateKeyId}`
    || profile.config.signer.publicKeyHex !== config.publicKeyHex
    || profile.config.anchor.chain !== config.chain) {
    throw new Error("Execution profile does not admit the exact Turnkey seller-anchor role");
  }
  if (!canonicalAtomic(feeAtomic) || !canonicalAtomic(config.maxFeeAtomic)
    || BigInt(feeAtomic) > BigInt(config.maxFeeAtomic)) {
    throw new Error("Turnkey seller-anchor fee exceeds the admitted fee cap");
  }
}

function validateActivityIdentity(record: TurnkeySigningIntentRecord, activity: TurnkeyActivity): void {
  if (!bounded(activity.id) || activity.organizationId !== record.organizationId
    || activity.type !== ACTIVITY_TYPE || !bounded(activity.status)) {
    throw new Error("Turnkey Activity does not match the durable signing intent");
  }
  const request = parseRequest(record.requestBodyJson);
  const intent = activity.intent?.signRawPayloadIntentV2;
  if (intent === undefined || canonicalize(intent) !== canonicalize(request.parameters)) {
    throw new Error("Turnkey Activity intent does not match the durable signing intent");
  }
  if (activity.status === "ACTIVITY_STATUS_COMPLETED") {
    readVerifiedCompletedSignature(record, activity);
  }
  else if (activity.status !== "ACTIVITY_STATUS_PENDING"
    && activity.status !== "ACTIVITY_STATUS_CREATED"
    && activity.status !== "ACTIVITY_STATUS_CONSENSUS_NEEDED"
    && activity.status !== "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED"
    && !isFailedStatus(activity.status)) {
    throw new Error(`Turnkey Activity has unsupported status: ${activity.status}`);
  }
}

function isFailedStatus(status: string): boolean {
  return status === "ACTIVITY_STATUS_FAILED" || status === "ACTIVITY_STATUS_REJECTED";
}

function readCompletedSignature(activity: TurnkeyActivity): TurnkeySignature {
  if (activity.status !== "ACTIVITY_STATUS_COMPLETED") {
    throw new Error("Turnkey Activity has no completed signature");
  }
  const result = activity.result?.signRawPayloadResult;
  const r = result?.["r"];
  const s = result?.["s"];
  const v = result?.["v"];
  if (typeof r !== "string" || !/^[0-9a-fA-F]{64}$/.test(r)
    || typeof s !== "string" || !/^[0-9a-fA-F]{64}$/.test(s)
    || v !== "") {
    throw new Error("Turnkey Activity returned an invalid signature envelope");
  }
  return Object.freeze({ r: r.toLowerCase(), s: s.toLowerCase(), v });
}

function readVerifiedCompletedSignature(
  record: TurnkeySigningIntentRecord,
  activity: TurnkeyActivity,
): TurnkeySignature {
  const signature = readCompletedSignature(activity);
  const request = parseRequest(record.requestBodyJson);
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(record.publicKeyHex, "hex"),
    ]),
    format: "der",
    type: "spki",
  });
  const signatureBytes = Buffer.from(`${signature.r}${signature.s}`, "hex");
  if (!verifySignature(
    null,
    Buffer.from(request.parameters.payload, "hex"),
    publicKey,
    signatureBytes,
  )) {
    throw new Error("Turnkey Activity returned a signature that does not verify the durable payload");
  }
  return signature;
}

function validateStoredSignature(record: TurnkeySigningIntentRecord, activity: TurnkeyActivity): void {
  const signature = readVerifiedCompletedSignature(record, activity);
  const signatureJson = canonicalize(signature);
  if (record.signatureJson !== signatureJson || record.signatureDigest !== sha256Hex(signatureJson)) {
    throw new Error("Turnkey signature conflicts with durable signing state");
  }
}

function signedResult(record: TurnkeySigningIntentRecord): Readonly<{
  readonly activityId: string;
  readonly providerRequestId: string;
  readonly signature: TurnkeySignature;
  readonly signatureDigest: string;
}> {
  if (record.state !== "signed" || record.activityId === undefined
    || record.signatureJson === undefined || record.signatureDigest === undefined) {
    throw new Error("Turnkey signature is not durably persisted");
  }
  const parsed = JSON.parse(record.signatureJson) as TurnkeySignature;
  return Object.freeze({
    activityId: record.activityId,
    providerRequestId: record.providerRequestId,
    signature: Object.freeze(parsed),
    signatureDigest: record.signatureDigest,
  });
}

function parseRequest(value: string): TurnkeySignRawPayloadRequest {
  const parsed: unknown = JSON.parse(value);
  if (!plainRecord(parsed) || exactKeys(parsed, ["organizationId", "parameters", "timestampMs", "type"]) === false
    || parsed["type"] !== ACTIVITY_TYPE || !bounded(parsed["organizationId"])
    || typeof parsed["timestampMs"] !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(parsed["timestampMs"])
    || !plainRecord(parsed["parameters"])
    || exactKeys(parsed["parameters"], ["encoding", "hashFunction", "payload", "signWith"]) === false
    || !bounded(parsed["parameters"]["signWith"])
    || typeof parsed["parameters"]["payload"] !== "string"
    || !/^(?:[0-9a-f]{2}){1,32768}$/.test(parsed["parameters"]["payload"])
    || parsed["parameters"]["encoding"] !== ENCODING
    || parsed["parameters"]["hashFunction"] !== HASH_FUNCTION
    || canonicalize(parsed) !== value) {
    throw new Error("Durable Turnkey request body is invalid");
  }
  return Object.freeze(parsed as unknown as TurnkeySignRawPayloadRequest);
}

function validatePersistentRecord(record: TurnkeySigningIntentRecord): void {
  const request = parseRequest(record.requestBodyJson);
  if (sha256Hex(record.requestBodyJson) !== record.requestBodyHash
    || record.providerRequestId !== record.requestBodyHash
    || request.organizationId !== record.organizationId
    || request.parameters.signWith !== record.privateKeyId
    || !/^[0-9a-f]{64}$/.test(record.publicKeyHex)
    || sha256Hex(Buffer.from(request.parameters.payload, "hex")) !== record.payloadHash
    || record.signingRole !== SIGNING_ROLE
    || !/^did:demos:agent:[0-9a-f]{64}$/.test(record.sellerClaim)
    || record.chain !== "demos-testnet" || !bounded(record.signingDomain)
    || record.amountAtomic !== "0" || !canonicalAtomic(record.feeAtomic)
    || !canonicalAtomic(record.feeCapAtomic)
    || BigInt(record.feeAtomic) > BigInt(record.feeCapAtomic)) {
    throw new Error("Durable Turnkey signing intent failed integrity validation");
  }
  if (record.activityJson !== undefined) {
    const parsed: unknown = JSON.parse(record.activityJson);
    if (!plainRecord(parsed) || canonicalize(parsed) !== record.activityJson) {
      throw new Error("Durable Turnkey Activity is invalid");
    }
    const activity = parsed as unknown as TurnkeyActivity;
    validateActivityIdentity(record, activity);
    if (activity.id !== record.activityId || activity.status !== record.activityStatus) {
      throw new Error("Durable Turnkey Activity failed integrity validation");
    }
    if (record.state === "failed" && !isFailedStatus(activity.status)) {
      throw new Error("Durable Turnkey failure state is inconsistent");
    }
    if (record.state === "signed") validateStoredSignature(record, activity);
  }
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateEffectKey(value: string): void {
  if (!/^[A-Za-z0-9:._-]{1,512}$/.test(value)) throw new TypeError("Effect key is invalid");
}

function canonicalAtomic(value: string): boolean {
  return /^(0|[1-9][0-9]{0,38})$/.test(value);
}

function bounded(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096
    && value === value.normalize("NFC");
}

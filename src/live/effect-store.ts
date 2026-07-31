import { canonicalize } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import type { DacsDatabase } from "../substrate/sqlite/database.ts";
import type { LiveEffectKind } from "./profile.ts";

export type LiveEffectState = "prepared" | "submitting" | "observed" | "committed";

export interface LiveEffectRecord {
  readonly effectKey: string;
  readonly kind: LiveEffectKind;
  readonly payloadHash: string;
  readonly payloadJson: string;
  readonly state: LiveEffectState;
  readonly externalRef?: string;
  readonly resultJson?: string;
}

interface EffectRow {
  readonly effectKey: string;
  readonly kind: LiveEffectKind;
  readonly payloadHash: string;
  readonly payloadJson: string;
  readonly state: LiveEffectState;
  readonly externalRef: string | null;
  readonly resultJson: string | null;
}

export class LiveEffectStore {
  constructor(
    private readonly database: DacsDatabase,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  prepare(effectKey: string, kind: LiveEffectKind, payload: Readonly<Record<string, unknown>>): LiveEffectRecord {
    validateKey(effectKey);
    const payloadJson = canonicalize(payload);
    const payloadHash = sha256Hex(payloadJson);
    this.database.query<never, {
      effectKey: string; kind: string; payloadHash: string; payloadJson: string; now: string;
    }>(`
      /* atomic-write: live-effect.prepare */
      INSERT INTO live_effect_intents (
        effect_key, effect_kind, payload_hash, payload_json, state, created_at, updated_at
      ) VALUES ($effectKey, $kind, $payloadHash, $payloadJson, 'prepared', $now, $now)
      ON CONFLICT(effect_key) DO NOTHING
    `).run({ effectKey, kind, payloadHash, payloadJson, now: this.timestamp() });
    const record = this.get(effectKey);
    if (record === null || record.kind !== kind || record.payloadHash !== payloadHash
      || record.payloadJson !== payloadJson) {
      throw new Error("Effect key is already bound to a different immutable intent");
    }
    return record;
  }

  observe(effectKey: string, result: Readonly<Record<string, unknown>>): LiveEffectRecord {
    const externalRef = result["externalRef"];
    if (typeof externalRef !== "string" || externalRef.length === 0 || externalRef.length > 4_096) {
      throw new TypeError("Observed effect requires a bounded externalRef");
    }
    const resultJson = canonicalize(result);
    this.database.query<never, { effectKey: string; externalRef: string; resultJson: string; now: string }>(`
      /* atomic-write: live-effect.observe */
      UPDATE live_effect_intents SET
        state = 'observed', external_ref = $externalRef, result_json = $resultJson, updated_at = $now
      WHERE effect_key = $effectKey AND state IN ('prepared', 'submitting', 'observed')
        AND (external_ref IS NULL OR external_ref = $externalRef)
        AND (result_json IS NULL OR result_json = $resultJson)
    `).run({ effectKey, externalRef, resultJson, now: this.timestamp() });
    const record = this.get(effectKey);
    if (record === null || record.externalRef !== externalRef || record.resultJson !== resultJson) {
      throw new Error("Observed effect conflicts with durable intent state");
    }
    return record;
  }

  markSubmitting(effectKey: string): LiveEffectRecord {
    const transition = this.database.query<never, { effectKey: string; now: string }>(`
      /* atomic-write: live-effect.mark-submitting */
      UPDATE live_effect_intents SET state = 'submitting', updated_at = $now
      WHERE effect_key = $effectKey AND state = 'prepared'
        AND external_ref IS NULL AND result_json IS NULL
    `).run({ effectKey, now: this.timestamp() });
    if (transition.changes !== 1) throw new Error("Effect submission attempt already has a winner");
    const record = this.get(effectKey);
    if (record?.state !== "submitting") throw new Error("Effect submission attempt cannot be recorded");
    return record;
  }

  commit(effectKey: string): LiveEffectRecord {
    this.database.query<never, { effectKey: string; now: string }>(`
      /* atomic-write: live-effect.commit */
      UPDATE live_effect_intents SET state = 'committed', updated_at = $now
      WHERE effect_key = $effectKey AND state = 'observed'
        AND external_ref IS NOT NULL AND result_json IS NOT NULL
    `).run({ effectKey, now: this.timestamp() });
    const record = this.get(effectKey);
    if (record?.state !== "committed") throw new Error("Effect cannot commit before an observation");
    return record;
  }

  get(effectKey: string): LiveEffectRecord | null {
    validateKey(effectKey);
    const row = this.database.query<EffectRow, { effectKey: string }>(`
      SELECT effect_key AS effectKey, effect_kind AS kind, payload_hash AS payloadHash,
        payload_json AS payloadJson, state, external_ref AS externalRef, result_json AS resultJson
      FROM live_effect_intents WHERE effect_key = $effectKey
    `).get({ effectKey });
    if (row === null) return null;
    return Object.freeze({
      effectKey: row.effectKey,
      kind: row.kind,
      payloadHash: row.payloadHash,
      payloadJson: row.payloadJson,
      state: row.state,
      ...(row.externalRef === null ? {} : { externalRef: row.externalRef }),
      ...(row.resultJson === null ? {} : { resultJson: row.resultJson }),
    });
  }

  private timestamp(): string {
    const value = this.now();
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
      throw new TypeError("Effect store clock returned an invalid timestamp");
    }
    return value;
  }
}

function validateKey(value: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 512
    || !/^[A-Za-z0-9:._-]+$/.test(value)) throw new TypeError("Effect key is invalid");
}

import { Database } from "bun:sqlite";
import {
  chmodSync,
  closeSync,
  constants,
  lstatSync,
  openSync,
  statSync,
} from "node:fs";
import { dirname, join, parse, resolve } from "node:path";

export type DacsDatabase = Database;

const SCHEMA_VERSION = 26;
const WAL_RETRY_ATTEMPTS = 20;
const WAL_RETRY_DELAY_MS = 25;
const retrySignal = new Int32Array(new SharedArrayBuffer(4));

const PRODUCTION_SIGNING_KEYS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS production_signing_keys (
    key_claim TEXT PRIMARY KEY NOT NULL CHECK (
      length(key_claim) = 68 AND key_claim GLOB 'key:*'
    ),
    provider_id TEXT NOT NULL,
    key_handle TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('current', 'revoked')),
    activated_at INTEGER NOT NULL CHECK (activated_at >= 0),
    revoked_at INTEGER CHECK (revoked_at >= activated_at),
    UNIQUE (provider_id, key_handle),
    CHECK ((state = 'current' AND revoked_at IS NULL)
      OR (state = 'revoked' AND revoked_at IS NOT NULL))
  ) STRICT
`;

const PRODUCTION_SIGNING_KEYS_CURRENT_INDEX = `
  CREATE UNIQUE INDEX IF NOT EXISTS production_signing_keys_one_current
    ON production_signing_keys(state) WHERE state = 'current'
`;

const PRODUCTION_KEY_LISTING_VERSIONS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS production_key_listing_versions (
    key_claim TEXT NOT NULL REFERENCES production_signing_keys(key_claim) ON DELETE RESTRICT,
    listing_id TEXT NOT NULL,
    listing_version INTEGER NOT NULL CHECK (listing_version > 0),
    listing_content_hash TEXT NOT NULL CHECK (
      length(listing_content_hash) = 64
      AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (key_claim, listing_id, listing_version)
  ) STRICT
`;

const PRODUCTION_KEY_REVOCATIONS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS production_key_revocations (
    key_claim TEXT NOT NULL REFERENCES production_signing_keys(key_claim) ON DELETE RESTRICT,
    listing_id TEXT NOT NULL,
    listing_version INTEGER NOT NULL CHECK (listing_version > 0),
    listing_content_hash TEXT NOT NULL CHECK (
      length(listing_content_hash) = 64
      AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    replacement_key_claim TEXT NOT NULL
      REFERENCES production_signing_keys(key_claim) ON DELETE RESTRICT,
    revoked_at INTEGER NOT NULL CHECK (revoked_at >= 0),
    revocation_content_hash TEXT NOT NULL UNIQUE CHECK (
      length(revocation_content_hash) = 64
      AND revocation_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_json TEXT NOT NULL,
    PRIMARY KEY (key_claim, listing_id, listing_version),
    FOREIGN KEY (key_claim, listing_id, listing_version)
      REFERENCES production_key_listing_versions(key_claim, listing_id, listing_version)
      ON DELETE RESTRICT
  ) STRICT
`;

const PRODUCTION_SESSION_KEY_PINS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS production_session_key_pins (
    job_id TEXT PRIMARY KEY NOT NULL,
    agreement_hash TEXT NOT NULL CHECK (
      length(agreement_hash) = 64 AND agreement_hash NOT GLOB '*[^0-9a-f]*'
    ),
    key_claim TEXT NOT NULL REFERENCES production_signing_keys(key_claim) ON DELETE RESTRICT,
    committed_at INTEGER NOT NULL CHECK (committed_at >= 0)
  ) STRICT
`;

const HTTP_RATE_BUCKETS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS http_rate_buckets (
    scope TEXT NOT NULL,
    window_ms INTEGER NOT NULL CHECK (window_ms > 0),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
    request_count INTEGER NOT NULL CHECK (request_count > 0),
    PRIMARY KEY (scope, window_ms, window_start_ms)
  ) STRICT
`;

const PARTY_AUTHORITY_INSTANCES_SCHEMA = `
  CREATE TABLE IF NOT EXISTS party_authority_instances (
    instance_id TEXT PRIMARY KEY NOT NULL,
    audience TEXT NOT NULL,
    recovery_key TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    initialized_at_ms INTEGER NOT NULL CHECK (initialized_at_ms >= 0),
    UNIQUE (audience)
  ) STRICT
`;

const PARTY_CAPABILITIES_SCHEMA = `
  CREATE TABLE IF NOT EXISTS party_capabilities (
    capability_digest TEXT PRIMARY KEY NOT NULL CHECK (
      length(capability_digest) = 64 AND capability_digest NOT GLOB '*[^0-9a-f]*'
    ),
    instance_id TEXT NOT NULL REFERENCES party_authority_instances(instance_id) ON DELETE RESTRICT,
    audience TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('administrator', 'party')),
    principal TEXT NOT NULL,
    operations_json TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > 0),
    configured_key TEXT,
    job_id TEXT,
    role TEXT CHECK (role IN ('buyer', 'seller')),
    authority_kind TEXT CHECK (authority_kind IN ('admission', 'agreement')),
    authority_key TEXT,
    agreement_hash TEXT CHECK (
      agreement_hash IS NULL OR (
        length(agreement_hash) = 64 AND agreement_hash NOT GLOB '*[^0-9a-f]*'
      )
    ),
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
    revoked_at_ms INTEGER CHECK (revoked_at_ms >= issued_at_ms),
    generation INTEGER NOT NULL CHECK (generation > 0),
    CHECK (
      (kind = 'administrator' AND configured_key IS NOT NULL AND job_id IS NULL
        AND role IS NULL AND authority_kind IS NULL AND authority_key IS NULL
        AND agreement_hash IS NULL)
      OR
      (kind = 'party' AND configured_key IS NULL AND job_id IS NOT NULL
        AND role IS NOT NULL AND authority_kind IS NOT NULL AND authority_key IS NOT NULL
        AND ((authority_kind = 'admission' AND agreement_hash IS NULL)
          OR (authority_kind = 'agreement' AND agreement_hash IS NOT NULL)))
    ),
    CHECK ((state = 'active' AND revoked_at_ms IS NULL)
      OR (state = 'revoked' AND revoked_at_ms IS NOT NULL))
  ) STRICT
`;

const PARTY_AUTHORITY_CHALLENGES_SCHEMA = `
  CREATE TABLE IF NOT EXISTS party_authority_challenges (
    nonce TEXT PRIMARY KEY NOT NULL CHECK (
      length(nonce) = 32 AND nonce NOT GLOB '*[^0-9a-f]*'
    ),
    instance_id TEXT NOT NULL REFERENCES party_authority_instances(instance_id) ON DELETE RESTRICT,
    audience TEXT NOT NULL,
    principal TEXT NOT NULL,
    job_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('buyer', 'seller')),
    operations_json TEXT NOT NULL,
    authority_kind TEXT NOT NULL CHECK (authority_kind IN ('admission', 'agreement')),
    authority_key TEXT NOT NULL,
    agreement_hash TEXT,
    client_nonce TEXT NOT NULL CHECK (
      length(client_nonce) = 32 AND client_nonce NOT GLOB '*[^0-9a-f]*'
    ),
    client_idempotency_key TEXT NOT NULL,
    allocation_fingerprint TEXT NOT NULL CHECK (
      length(allocation_fingerprint) = 64 AND allocation_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    requested_at_ms INTEGER NOT NULL CHECK (requested_at_ms >= 0),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > issued_at_ms),
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms >= expires_at_ms),
    consumed_at_ms INTEGER CHECK (consumed_at_ms >= issued_at_ms),
    generation INTEGER NOT NULL CHECK (generation > 0),
    UNIQUE (instance_id, audience, principal, client_nonce),
    UNIQUE (instance_id, audience, principal, client_idempotency_key)
  ) STRICT
`;

const PARTY_AUTHORITY_RECOVERY_REPLAYS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS party_authority_recovery_replays (
    proof_digest TEXT PRIMARY KEY NOT NULL CHECK (
      length(proof_digest) = 64 AND proof_digest NOT GLOB '*[^0-9a-f]*'
    ),
    instance_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    consumed_at_ms INTEGER NOT NULL CHECK (consumed_at_ms >= 0)
  ) STRICT
`;

const PARTY_AUTHORITY_AMENDMENTS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS party_authority_amendments (
    job_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('buyer', 'seller')),
    agreement_hash TEXT NOT NULL CHECK (
      length(agreement_hash) = 64 AND agreement_hash NOT GLOB '*[^0-9a-f]*'
    ),
    old_key TEXT NOT NULL,
    new_key TEXT NOT NULL,
    operations_json TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > 0),
    anchor TEXT NOT NULL,
    amendment_digest TEXT NOT NULL UNIQUE CHECK (
      length(amendment_digest) = 64 AND amendment_digest NOT GLOB '*[^0-9a-f]*'
    ),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0),
    PRIMARY KEY (job_id, role)
  ) STRICT
`;

const PARTY_CAPABILITY_PREPARATIONS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS party_capability_preparations (
    capability_digest TEXT PRIMARY KEY NOT NULL CHECK (
      length(capability_digest) = 64 AND capability_digest NOT GLOB '*[^0-9a-f]*'
    ),
    instance_id TEXT NOT NULL REFERENCES party_authority_instances(instance_id) ON DELETE RESTRICT,
    audience TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms)
  ) STRICT
`;

const LIVE_EFFECT_INTENTS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS live_effect_intents (
    effect_key TEXT PRIMARY KEY NOT NULL,
    effect_kind TEXT NOT NULL CHECK (effect_kind IN ('anchor', 'directory-register', 'payment')),
    payload_hash TEXT NOT NULL CHECK (
      length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'submitting', 'observed', 'committed')),
    external_ref TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
      (state IN ('prepared', 'submitting') AND external_ref IS NULL AND result_json IS NULL)
      OR (state IN ('observed', 'committed') AND external_ref IS NOT NULL AND result_json IS NOT NULL)
    )
  ) STRICT
`;

const TURNKEY_SIGNING_INTENTS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS turnkey_signing_intents (
    effect_key TEXT PRIMARY KEY NOT NULL,
    provider_request_id TEXT NOT NULL UNIQUE CHECK (
      length(provider_request_id) = 64 AND provider_request_id NOT GLOB '*[^0-9a-f]*'
    ),
    signing_role TEXT NOT NULL CHECK (signing_role = 'demos-storage-anchor'),
    seller_claim TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    private_key_id TEXT NOT NULL,
    public_key_hex TEXT NOT NULL CHECK (
      length(public_key_hex) = 64 AND public_key_hex NOT GLOB '*[^0-9a-f]*'
    ),
    chain TEXT NOT NULL CHECK (chain = 'demos-testnet'),
    signing_domain TEXT NOT NULL,
    amount_atomic TEXT NOT NULL CHECK (amount_atomic = '0'),
    fee_atomic TEXT NOT NULL,
    fee_cap_atomic TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK (
      length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    request_body_hash TEXT NOT NULL UNIQUE CHECK (
      length(request_body_hash) = 64 AND request_body_hash NOT GLOB '*[^0-9a-f]*'
    ),
    request_body_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
      state IN ('prepared', 'submitting', 'activity-observed', 'signed', 'failed')
    ),
    activity_id TEXT UNIQUE,
    activity_status TEXT,
    activity_json TEXT,
    signature_json TEXT,
    signature_digest TEXT CHECK (
      signature_digest IS NULL OR (
        length(signature_digest) = 64 AND signature_digest NOT GLOB '*[^0-9a-f]*'
      )
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
      (state IN ('prepared', 'submitting')
        AND activity_id IS NULL AND activity_status IS NULL AND activity_json IS NULL
        AND signature_json IS NULL AND signature_digest IS NULL)
      OR (state = 'activity-observed'
        AND activity_id IS NOT NULL AND activity_status IS NOT NULL AND activity_json IS NOT NULL
        AND signature_json IS NULL AND signature_digest IS NULL)
      OR (state = 'signed'
        AND activity_id IS NOT NULL AND activity_status = 'ACTIVITY_STATUS_COMPLETED'
        AND activity_json IS NOT NULL AND signature_json IS NOT NULL
        AND signature_digest IS NOT NULL)
      OR (state = 'failed'
        AND activity_id IS NOT NULL
        AND activity_status IN ('ACTIVITY_STATUS_FAILED', 'ACTIVITY_STATUS_REJECTED')
        AND activity_json IS NOT NULL AND signature_json IS NULL AND signature_digest IS NULL)
    )
  ) STRICT
`;

const FIXTURE_LIFECYCLE_SCHEMA = `
  CREATE TABLE fixture_lifecycle_runs (
    instance_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    job_id TEXT NOT NULL,
    request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
    agreement_artifact_hash TEXT NOT NULL CHECK (length(agreement_artifact_hash) = 64),
    required_payment_phases_json TEXT NOT NULL,
    delivery_phase_index INTEGER NOT NULL CHECK (delivery_phase_index >= 0),
    delivery_phase_kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
      'commit-pending', 'commit-completed', 'commit-failed',
      'settle-pending', 'settle-completed', 'settle-failed', 'settle-unsupported',
      'substrate-failure-paused', 'failed-substrate', 'aborted', 'finalised'
    )),
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    commitment_artifact_hash TEXT REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    payment_invocations INTEGER NOT NULL DEFAULT 0 CHECK (payment_invocations >= 0),
    settlement_invocations INTEGER NOT NULL DEFAULT 0 CHECK (settlement_invocations >= 0),
    delivery_invocations INTEGER NOT NULL DEFAULT 0 CHECK (delivery_invocations IN (0, 1)),
    payment_result_json TEXT,
    settlement_result_json TEXT,
    delivery_result_json TEXT,
    terminal_result_json TEXT,
    terminal_state TEXT CHECK (terminal_state IN (
      'settle-failed', 'settle-unsupported', 'failed-substrate', 'aborted'
    )),
    abort_actor_role TEXT CHECK (abort_actor_role IN ('buyer', 'seller')),
    abort_reason TEXT,
    failure_stage TEXT CHECK (failure_stage IN ('commit', 'payment', 'settlement', 'delivery')),
    error_class TEXT CHECK (error_class IN (
      'permanent', 'counterparty', 'transient', 'substrate', 'settlement-atomicity'
    )),
    failure_reason TEXT,
    paused_at TEXT,
    pause_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT,
    PRIMARY KEY (instance_id, audience, job_id),
    FOREIGN KEY (instance_id, audience, job_id)
      REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT,
    CHECK (
      (state IN ('commit-failed', 'settle-failed')
        AND failure_stage IS NOT NULL
        AND error_class IN ('permanent', 'counterparty', 'transient')
        AND failure_reason IS NOT NULL AND ended_at IS NOT NULL
        AND paused_at IS NULL AND pause_expires_at IS NULL)
      OR
      (state = 'substrate-failure-paused'
        AND failure_stage IN ('payment', 'settlement', 'delivery')
        AND error_class = 'substrate' AND failure_reason IS NOT NULL
        AND paused_at IS NOT NULL AND pause_expires_at IS NOT NULL
        AND ended_at IS NULL)
      OR
      (state = 'failed-substrate'
        AND failure_stage IN ('payment', 'settlement', 'delivery')
        AND error_class = 'substrate' AND failure_reason IS NOT NULL
        AND paused_at IS NOT NULL AND pause_expires_at IS NOT NULL
        AND ended_at IS NOT NULL)
      OR
      (state = 'settle-unsupported'
        AND failure_stage IN ('payment', 'settlement', 'delivery')
        AND error_class = 'settlement-atomicity' AND failure_reason IS NOT NULL
        AND paused_at IS NULL AND pause_expires_at IS NULL
        AND ended_at IS NOT NULL)
      OR
      (state = 'finalised'
        AND ended_at IS NOT NULL
        AND (
          (terminal_state IS NULL AND terminal_result_json IS NULL
            AND abort_actor_role IS NULL AND abort_reason IS NULL
            AND failure_stage IS NULL AND error_class IS NULL
            AND failure_reason IS NULL AND paused_at IS NULL AND pause_expires_at IS NULL)
          OR
          (terminal_state = 'settle-failed'
            AND failure_stage IN ('payment', 'settlement', 'delivery')
            AND error_class IN ('permanent', 'counterparty', 'transient')
            AND failure_reason IS NOT NULL AND terminal_result_json IS NOT NULL
            AND abort_actor_role IS NULL AND abort_reason IS NULL
            AND paused_at IS NULL AND pause_expires_at IS NULL)
          OR
          (terminal_state = 'settle-unsupported'
            AND failure_stage IN ('payment', 'settlement', 'delivery')
            AND error_class = 'settlement-atomicity'
            AND failure_reason IS NOT NULL AND terminal_result_json IS NOT NULL
            AND abort_actor_role IS NULL AND abort_reason IS NULL
            AND paused_at IS NULL AND pause_expires_at IS NULL)
          OR
          (terminal_state = 'failed-substrate'
            AND failure_stage IN ('payment', 'settlement', 'delivery')
            AND error_class = 'substrate' AND failure_reason IS NOT NULL
            AND terminal_result_json IS NOT NULL
            AND abort_actor_role IS NULL AND abort_reason IS NULL
            AND paused_at IS NOT NULL AND pause_expires_at IS NOT NULL)
          OR
          (terminal_state = 'aborted'
            AND failure_stage IS NULL AND error_class IS NULL AND failure_reason IS NULL
            AND terminal_result_json IS NULL
            AND abort_actor_role IS NOT NULL AND abort_reason IS NOT NULL
            AND paused_at IS NULL AND pause_expires_at IS NULL)
        ))
      OR
      (state = 'aborted'
        AND terminal_state IS NULL AND terminal_result_json IS NULL
        AND failure_stage IS NULL AND error_class IS NULL AND failure_reason IS NULL
        AND abort_actor_role IS NOT NULL AND abort_reason IS NOT NULL
        AND paused_at IS NULL AND pause_expires_at IS NULL AND ended_at IS NOT NULL)
      OR
      (state NOT IN (
          'commit-failed', 'settle-failed', 'settle-unsupported',
          'substrate-failure-paused', 'failed-substrate', 'aborted', 'finalised'
        )
        AND terminal_state IS NULL AND terminal_result_json IS NULL
        AND abort_actor_role IS NULL AND abort_reason IS NULL
        AND failure_stage IS NULL AND error_class IS NULL
        AND failure_reason IS NULL AND paused_at IS NULL
        AND pause_expires_at IS NULL AND ended_at IS NULL)
    )
  ) STRICT;
`;

const FIXTURE_DELIVERY_SCHEMA = `
  CREATE TABLE fixture_deliveries (
    instance_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    job_id TEXT NOT NULL,
    phase_index INTEGER NOT NULL CHECK (phase_index >= 0),
    agreement_hash TEXT NOT NULL CHECK (
      length(agreement_hash) = 64 AND agreement_hash NOT GLOB '*[^0-9a-f]*'
    ),
    session_binding_hash TEXT NOT NULL CHECK (
      length(session_binding_hash) = 64 AND session_binding_hash NOT GLOB '*[^0-9a-f]*'
    ),
    orchestrator_claim TEXT NOT NULL,
    payment_amount_json TEXT NOT NULL,
    payload_format TEXT NOT NULL,
    payload_content_hash TEXT NOT NULL CHECK (
      length(payload_content_hash) = 64 AND payload_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    assertion_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    verify_result_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    delivery_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    evidence_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    evidence_hash TEXT NOT NULL CHECK (
      length(evidence_hash) = 64 AND evidence_hash NOT GLOB '*[^0-9a-f]*'
    ),
    assertion_address TEXT NOT NULL UNIQUE,
    verify_result_address TEXT NOT NULL UNIQUE,
    delivery_address TEXT NOT NULL UNIQUE,
    evidence_address TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (instance_id, audience, job_id),
    FOREIGN KEY (instance_id, audience, job_id)
      REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT
  ) STRICT;
`;

const FIXTURE_BUNDLE_SCHEMA = `
  CREATE TABLE fixture_bundles (
    instance_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    job_id TEXT NOT NULL,
    anchored_by_role TEXT NOT NULL CHECK (anchored_by_role IN ('buyer', 'seller', 'orchestrator')),
    logical_address TEXT NOT NULL UNIQUE,
    bundle_hash TEXT NOT NULL CHECK (
      length(bundle_hash) = 64 AND bundle_hash NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_content_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    finalised_at INTEGER NOT NULL CHECK (finalised_at >= 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (instance_id, audience, job_id, anchored_by_role),
    FOREIGN KEY (instance_id, audience, job_id)
      REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT
  ) STRICT;
`;

const FIXTURE_FAILURE_EVIDENCE_SCHEMA = `
  CREATE TABLE fixture_failure_evidence (
    evidence_hash TEXT PRIMARY KEY NOT NULL CHECK (
      length(evidence_hash) = 64 AND evidence_hash NOT GLOB '*[^0-9a-f]*'
    ),
    job_id TEXT NOT NULL REFERENCES sessions(job_id) ON DELETE RESTRICT,
    phase_index INTEGER NOT NULL CHECK (phase_index >= 0),
    phase_kind TEXT NOT NULL,
    orchestrator_claim TEXT NOT NULL,
    expectation_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (job_id, phase_index)
  ) STRICT;
`;

const FIXTURE_VET_SCHEMA = `
  CREATE TABLE fixture_vet_records (
    instance_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    job_id TEXT NOT NULL,
    evaluated_role TEXT NOT NULL CHECK (evaluated_role IN ('buyer', 'seller')),
    evaluated_party TEXT NOT NULL,
    verifier_party TEXT NOT NULL,
    bundle_hash TEXT NOT NULL CHECK (
      length(bundle_hash) = 64 AND bundle_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirement_hash TEXT NOT NULL CHECK (
      length(requirement_hash) = 64 AND requirement_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirement_json TEXT NOT NULL,
    requirement_source_kind TEXT NOT NULL CHECK (
      requirement_source_kind IN ('seller-listing', 'buyer-signed')
    ),
    requirement_source_address TEXT NOT NULL,
    requirement_source_content_hash TEXT NOT NULL CHECK (
      length(requirement_source_content_hash) = 64
        AND requirement_source_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirement_source_artifact_hash TEXT NOT NULL
      REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    recipe_registry_version INTEGER NOT NULL CHECK (recipe_registry_version > 0),
    recipe_availability TEXT NOT NULL CHECK (recipe_availability IN (
      'live', 'operator_gated', 'closed_data', 'bilateral', 'mocked', 'disabled', 'failed'
    )),
    assertion_address TEXT NOT NULL UNIQUE,
    assertion_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    verify_result_address TEXT NOT NULL UNIQUE,
    verify_result_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    composite_address TEXT NOT NULL UNIQUE,
    composite_artifact_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
    overall_decision TEXT NOT NULL CHECK (
      overall_decision IN ('pass', 'fail', 'indeterminate', 'error')
    ),
    generated_at INTEGER NOT NULL CHECK (generated_at >= 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (instance_id, audience, job_id, evaluated_role),
    FOREIGN KEY (instance_id, audience, job_id)
      REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT,
    CHECK (evaluated_party <> verifier_party)
  ) STRICT;
`;

const FIXTURE_LISTING_ANCHOR_REGISTRY_SCHEMA = `
  CREATE TABLE IF NOT EXISTS fixture_listing_anchor_registry (
    native_address TEXT PRIMARY KEY NOT NULL,
    logical_address TEXT NOT NULL UNIQUE,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('listing', 'revocation')),
    content_hash TEXT NOT NULL CHECK (
      length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'
    )
  ) STRICT
`;

const FIXTURE_LISTING_LIFECYCLE_VERSIONS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS fixture_listing_lifecycle_versions (
    seller_primary_claim TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    listing_version INTEGER NOT NULL CHECK (listing_version > 0),
    listing_content_hash TEXT NOT NULL UNIQUE CHECK (
      length(listing_content_hash) = 64 AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_json TEXT NOT NULL,
    logical_address TEXT NOT NULL UNIQUE,
    native_address TEXT NOT NULL UNIQUE,
    anchor_tx TEXT NOT NULL,
    anchor_verified_at INTEGER NOT NULL CHECK (anchor_verified_at >= 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (seller_primary_claim, listing_id, listing_version)
  ) STRICT
`;

const FIXTURE_LISTING_DISCOVERY_SCHEMA = `
  CREATE TABLE IF NOT EXISTS fixture_listing_discovery (
    seller_primary_claim TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    listing_version INTEGER NOT NULL CHECK (listing_version > 0),
    listing_content_hash TEXT NOT NULL CHECK (
      length(listing_content_hash) = 64 AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    native_address TEXT NOT NULL,
    published_at TEXT NOT NULL,
    PRIMARY KEY (seller_primary_claim, listing_id),
    FOREIGN KEY (seller_primary_claim, listing_id, listing_version)
      REFERENCES fixture_listing_lifecycle_versions(
        seller_primary_claim, listing_id, listing_version
      )
      ON DELETE RESTRICT
  ) STRICT
`;

const FIXTURE_LISTING_REVOCATIONS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS fixture_listing_revocations (
    seller_primary_claim TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    listing_version INTEGER NOT NULL CHECK (listing_version > 0),
    listing_content_hash TEXT NOT NULL CHECK (
      length(listing_content_hash) = 64 AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    revocation_content_hash TEXT NOT NULL UNIQUE CHECK (
      length(revocation_content_hash) = 64
        AND revocation_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_json TEXT NOT NULL,
    logical_address TEXT NOT NULL UNIQUE,
    native_address TEXT NOT NULL UNIQUE,
    anchor_tx TEXT NOT NULL,
    anchor_verified_at INTEGER NOT NULL CHECK (anchor_verified_at >= 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (seller_primary_claim, listing_id, listing_version),
    FOREIGN KEY (seller_primary_claim, listing_id, listing_version)
      REFERENCES fixture_listing_lifecycle_versions(
        seller_primary_claim, listing_id, listing_version
      )
      ON DELETE RESTRICT
  ) STRICT
`;

const FIXTURE_SESSION_LISTING_PINS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS fixture_session_listing_pins (
    job_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(job_id) ON DELETE RESTRICT,
    seller_primary_claim TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    listing_version INTEGER NOT NULL CHECK (listing_version > 0),
    listing_content_hash TEXT NOT NULL CHECK (
      length(listing_content_hash) = 64 AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    pinned_at TEXT NOT NULL,
    FOREIGN KEY (seller_primary_claim, listing_id, listing_version)
      REFERENCES fixture_listing_lifecycle_versions(
        seller_primary_claim, listing_id, listing_version
      )
      ON DELETE RESTRICT
  ) STRICT
`;

export function openDatabase(path: string): DacsDatabase {
  const securePath = prepareDatabasePath(path);
  const database = new Database(securePath, {
    create: true,
    safeIntegers: true,
    strict: true,
  });

  try {
    database.run("PRAGMA busy_timeout = 5000");
    database.run("PRAGMA foreign_keys = ON");
    migrate(database);
    const journalMode = enableWal(database);
    if (journalMode?.toLowerCase() !== "wal") {
      throw new Error(`Persistent database requires WAL journal mode; got ${journalMode ?? "unknown"}`);
    }
    database.run("PRAGMA synchronous = FULL");
    secureDatabaseFiles(securePath);
    return database;
  } catch (error) {
    database.close();
    throw error;
  }
}

function prepareDatabasePath(path: string): string {
  if (path === ":memory:") {
    throw new Error("Persistent database requires a filesystem path");
  }
  const securePath = resolve(path);
  const directory = dirname(securePath);
  validateSecureDirectoryChain(directory);

  try {
    const file = openSync(
      securePath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    closeSync(file);
  } catch (error) {
    if (!isNodeError(error) || error.code !== "EEXIST") throw error;
    assertOwnedRegularFile(securePath);
    chmodSync(securePath, 0o600);
  }
  assertOwnerOnlyFile(securePath);
  return securePath;
}

function secureDatabaseFiles(path: string): void {
  validateSecureDirectoryChain(dirname(path));
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      assertOwnedRegularFile(candidate);
      chmodSync(candidate, 0o600);
      assertOwnerOnlyFile(candidate);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") continue;
      throw error;
    }
  }
}

function assertOwnerOnlyFile(path: string): void {
  const fileStat = lstatSync(path);
  if (
    !fileStat.isFile()
    || fileStat.isSymbolicLink()
    || fileStat.uid !== effectiveUserId()
    || (fileStat.mode & 0o177) !== 0
  ) {
    throw new Error(`Database file must be owner-only and regular: ${path}`);
  }
}

function assertOwnedRegularFile(path: string): void {
  const fileStat = lstatSync(path);
  if (!fileStat.isFile() || fileStat.isSymbolicLink() || fileStat.uid !== effectiveUserId()) {
    throw new Error(`Database path must be a process-owned regular file: ${path}`);
  }
}

function validateSecureDirectoryChain(directory: string): void {
  const resolved = resolve(directory);
  const { root } = parse(resolved);
  const parts = resolved.slice(root.length).split("/").filter(Boolean);
  let current = root;
  const effectiveUid = effectiveUserId();

  for (const part of parts) {
    current = join(current, part);
    const directoryStat = lstatSync(current);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      throw new Error(`Database directory chain must not contain symbolic links: ${current}`);
    }
    if (directoryStat.uid !== 0 && directoryStat.uid !== effectiveUid) {
      throw new Error(`Database directory chain contains a foreign-owned component: ${current}`);
    }
    const groupOrWorldWritable = (directoryStat.mode & 0o022) !== 0;
    const stickyRoot = (directoryStat.mode & 0o1000) !== 0 && directoryStat.uid === 0;
    if (groupOrWorldWritable && !stickyRoot) {
      throw new Error(`Database directory chain contains an unsafe writable component: ${current}`);
    }
  }

  const leafStat = statSync(resolved);
  if (leafStat.uid !== effectiveUid || (leafStat.mode & 0o077) !== 0) {
    throw new Error("Database directory must be process-owned and owner-only (mode 0700 or stricter)");
  }
}

function effectiveUserId(): number {
  const uid = process.geteuid?.();
  if (uid === undefined) throw new Error("Database ownership checks require a POSIX effective user id");
  return uid;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function enableWal(database: Database): string | undefined {
  for (let attempt = 0; attempt < WAL_RETRY_ATTEMPTS; attempt += 1) {
    try {
      return database.query<{ journal_mode: string }, []>(
        "PRAGMA journal_mode = WAL",
      ).get()?.journal_mode;
    } catch (error) {
      if (!isSqliteBusy(error) || attempt === WAL_RETRY_ATTEMPTS - 1) throw error;
      Atomics.wait(retrySignal, 0, 0, WAL_RETRY_DELAY_MS);
    }
  }
  throw new Error("WAL initialization retry bound was exhausted");
}

function isSqliteBusy(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && (error as { code?: unknown }).code === "SQLITE_BUSY";
}

function migrate(database: Database): void {
  const apply = database.transaction(() => {
    const versionRow = database.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get();
    const version = Number(versionRow?.user_version ?? 0n);
    if (version > SCHEMA_VERSION) {
      throw new Error(`Database schema ${version} is newer than supported ${SCHEMA_VERSION}`);
    }
    if (version === SCHEMA_VERSION) return;

    rejectUnrecoverableFixtureMigration(database, version);

    if (version === 0) {
      database.run(`
      CREATE TABLE sessions (
        instance_id TEXT NOT NULL,
        audience TEXT NOT NULL,
        job_id TEXT NOT NULL,
        evidence_mode TEXT NOT NULL CHECK (evidence_mode IN ('fixture', 'local-chain', 'live')),
        admission_fingerprint TEXT NOT NULL CHECK (length(admission_fingerprint) = 64),
        status TEXT NOT NULL CHECK (status IN ('admitted', 'failed')),
        version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
        created_at TEXT NOT NULL,
        PRIMARY KEY (instance_id, audience, job_id)
      ) STRICT;
      `);
      database.run(`
      CREATE TABLE admission_challenges (
        nonce TEXT PRIMARY KEY NOT NULL CHECK (
          length(nonce) = 32 AND nonce NOT GLOB '*[^0-9a-f]*'
        ),
        job_id TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        audience TEXT NOT NULL,
        principal_ref TEXT NOT NULL,
        principal_scheme TEXT NOT NULL,
        principal_identifier TEXT NOT NULL,
        evidence_mode TEXT NOT NULL CHECK (evidence_mode IN ('fixture', 'local-chain', 'live')),
        client_nonce TEXT NOT NULL CHECK (
          length(client_nonce) = 32 AND client_nonce NOT GLOB '*[^0-9a-f]*'
        ),
        client_idempotency_key TEXT NOT NULL,
        allocation_fingerprint TEXT NOT NULL CHECK (length(allocation_fingerprint) = 64),
        requested_at_ms INTEGER NOT NULL CHECK (requested_at_ms >= 0),
        issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
        expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > issued_at_ms),
        retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms >= expires_at_ms),
        consumed_at_ms INTEGER CHECK (consumed_at_ms >= issued_at_ms),
        UNIQUE (
          instance_id, audience, principal_scheme, principal_identifier, client_nonce
        ),
        UNIQUE (
          instance_id, audience, principal_scheme, principal_identifier, client_idempotency_key
        )
      ) STRICT;
      `);
      database.run(`
      CREATE TABLE admission_consumptions (
        nonce TEXT PRIMARY KEY NOT NULL REFERENCES admission_challenges(nonce) ON DELETE RESTRICT,
        instance_id TEXT NOT NULL,
        audience TEXT NOT NULL,
        principal_ref TEXT NOT NULL,
        principal_scheme TEXT NOT NULL,
        principal_identifier TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
        admission_fingerprint TEXT NOT NULL CHECK (length(admission_fingerprint) = 64),
        session_id TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        FOREIGN KEY (instance_id, audience, session_id)
          REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT,
        UNIQUE (
          instance_id, audience, principal_scheme, principal_identifier, idempotency_key
        )
      ) STRICT;
      `);
      database.run(`
      CREATE TABLE artifacts (
        content_hash TEXT PRIMARY KEY NOT NULL CHECK (length(content_hash) = 64),
        canonical_json TEXT NOT NULL,
        byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
        created_at TEXT NOT NULL
      ) STRICT;
      `);
      database.run(`
      CREATE TABLE artifact_kinds (
        content_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        kind TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (content_hash, kind)
      ) STRICT;
      `);
    }
    if (version < 2) database.run(`
      CREATE TABLE service_runs (
        instance_id TEXT NOT NULL,
        audience TEXT NOT NULL,
        job_id TEXT NOT NULL,
        request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
        contract_hash TEXT NOT NULL CHECK (length(contract_hash) = 64),
        seller_claim TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('running', 'completed')),
        claim_token TEXT NOT NULL CHECK (
          length(claim_token) = 64 AND claim_token NOT GLOB '*[^0-9a-f]*'
        ),
        output_content_hash TEXT REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        receipt_content_hash TEXT REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        created_at TEXT NOT NULL,
        completed_at TEXT,
        PRIMARY KEY (instance_id, audience, job_id),
        FOREIGN KEY (instance_id, audience, job_id)
          REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT,
        CHECK (
          (status = 'running' AND output_content_hash IS NULL
            AND receipt_content_hash IS NULL AND completed_at IS NULL)
          OR
          (status = 'completed' AND output_content_hash IS NOT NULL
            AND receipt_content_hash IS NOT NULL AND completed_at IS NOT NULL)
        )
      ) STRICT;
    `);
    if (version < 3) {
      database.run(`
      CREATE TABLE fixture_settlements (
        tx_hash TEXT PRIMARY KEY NOT NULL CHECK (
          length(tx_hash) = 64 AND tx_hash NOT GLOB '*[^0-9a-f]*'
        ),
        job_id TEXT NOT NULL,
        phase_index INTEGER NOT NULL CHECK (phase_index >= 0),
        agreement_hash TEXT NOT NULL CHECK (
          length(agreement_hash) = 64 AND agreement_hash NOT GLOB '*[^0-9a-f]*'
        ),
        payer_claim TEXT NOT NULL,
        payee_claim TEXT NOT NULL,
        payment_amount_json TEXT NOT NULL,
        block_number INTEGER NOT NULL CHECK (block_number >= 0),
        finality_observed_at INTEGER NOT NULL CHECK (finality_observed_at >= 0),
        created_at TEXT NOT NULL,
        UNIQUE (job_id, phase_index)
      ) STRICT;
      `);
      database.run(`
      CREATE TABLE fixture_anchors (
        logical_address TEXT PRIMARY KEY NOT NULL,
        artifact_kind TEXT NOT NULL,
        content_hash TEXT NOT NULL CHECK (
          length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL
      ) STRICT;
      `);
    }
    if (version < 4) database.run(`
      ALTER TABLE fixture_settlements ADD COLUMN payee_address TEXT NOT NULL DEFAULT '';
    `);
    if (version < 5) database.run(`
      ALTER TABLE fixture_anchors ADD COLUMN artifact_content_hash TEXT
        REFERENCES artifacts(content_hash) ON DELETE RESTRICT;
    `);
    if (version < 6) database.run(`
      CREATE TABLE fixture_settlement_consumptions (
        settlement_tx_id TEXT PRIMARY KEY NOT NULL,
        tx_hash TEXT NOT NULL REFERENCES fixture_settlements(tx_hash) ON DELETE RESTRICT,
        settlement_tx_ids_json TEXT NOT NULL,
        evidence_hash TEXT NOT NULL CHECK (
          length(evidence_hash) = 64 AND evidence_hash NOT GLOB '*[^0-9a-f]*'
        ),
        job_id TEXT NOT NULL,
        phase_index INTEGER NOT NULL CHECK (phase_index >= 0),
        observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
        UNIQUE (tx_hash)
      ) STRICT;
    `);
    if (version < 7) database.run(`
      ALTER TABLE fixture_settlements ADD COLUMN orchestrator_claim TEXT NOT NULL DEFAULT '';
    `);
    if (version < 8) database.run(`
      CREATE TABLE fixture_commitments (
        instance_id TEXT NOT NULL,
        audience TEXT NOT NULL,
        job_id TEXT NOT NULL,
        logical_address TEXT PRIMARY KEY NOT NULL,
        agreement_hash TEXT NOT NULL CHECK (
          length(agreement_hash) = 64 AND agreement_hash NOT GLOB '*[^0-9a-f]*'
        ),
        commitment_hash TEXT NOT NULL CHECK (
          length(commitment_hash) = 64 AND commitment_hash NOT GLOB '*[^0-9a-f]*'
        ),
        orchestrator_claim TEXT NOT NULL,
        agreement_artifact_hash TEXT NOT NULL
          REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        commitment_artifact_hash TEXT NOT NULL
          REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        anchor_tx_hash TEXT NOT NULL CHECK (
          length(anchor_tx_hash) = 64 AND anchor_tx_hash NOT GLOB '*[^0-9a-f]*'
        ),
        committed_at INTEGER NOT NULL CHECK (committed_at >= 0),
        created_at TEXT NOT NULL,
        UNIQUE (instance_id, audience, job_id),
        FOREIGN KEY (instance_id, audience, job_id)
          REFERENCES sessions(instance_id, audience, job_id) ON DELETE RESTRICT
      ) STRICT;
    `);
    if (version < 9) {
      if (version === 8) database.run("DROP TABLE fixture_lifecycle_runs");
      database.run(FIXTURE_LIFECYCLE_SCHEMA);
    } else if (version === 9) {
      migrateLifecycleV9(database);
    }
    if (version < 11) {
      database.run("CREATE UNIQUE INDEX IF NOT EXISTS sessions_job_id_unique ON sessions(job_id)");
      if (!columnExists(database, "fixture_settlements", "session_binding_hash")) {
        database.run(`
          ALTER TABLE fixture_settlements ADD COLUMN session_binding_hash TEXT NOT NULL
            DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
            CHECK (length(session_binding_hash) = 64
              AND session_binding_hash NOT GLOB '*[^0-9a-f]*');
        `);
      }
      if (!tableExists(database, "fixture_deliveries")) database.run(FIXTURE_DELIVERY_SCHEMA);
    }
    if (version > 0 && version < 12) migrateLifecycleV12(database);
    if (version < 12 && !tableExists(database, "fixture_bundles")) database.run(FIXTURE_BUNDLE_SCHEMA);
    if (version < 13 && !columnExists(database, "fixture_commitments", "orchestrator_claim")) {
      database.run("ALTER TABLE fixture_commitments ADD COLUMN orchestrator_claim TEXT NOT NULL DEFAULT ''");
    }
    if (version < 14) {
      database.run(`
      CREATE TABLE IF NOT EXISTS fixture_listing_authorities (
        listing_id TEXT NOT NULL,
        listing_version INTEGER NOT NULL CHECK (listing_version > 0),
        listing_content_hash TEXT NOT NULL UNIQUE CHECK (
          length(listing_content_hash) = 64 AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
        ),
        artifact_content_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (listing_id, listing_version)
      ) STRICT;
      `);
      database.run(`
      CREATE TABLE IF NOT EXISTS fixture_identity_authorities (
        bundle_hash TEXT PRIMARY KEY NOT NULL CHECK (
          length(bundle_hash) = 64 AND bundle_hash NOT GLOB '*[^0-9a-f]*'
        ),
        primary_claim TEXT NOT NULL,
        artifact_content_hash TEXT NOT NULL REFERENCES artifacts(content_hash) ON DELETE RESTRICT,
        created_at TEXT NOT NULL
      ) STRICT;
      `);
    }
    if (version < 15) database.run(`
      CREATE TABLE IF NOT EXISTS fixture_listing_verification_authorities (
        job_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(job_id) ON DELETE RESTRICT,
        listing_id TEXT NOT NULL,
        listing_version INTEGER NOT NULL CHECK (listing_version > 0),
        listing_content_hash TEXT NOT NULL CHECK (
          length(listing_content_hash) = 64 AND listing_content_hash NOT GLOB '*[^0-9a-f]*'
        ),
        verified_at INTEGER NOT NULL CHECK (verified_at >= 0),
        revocation_status TEXT NOT NULL CHECK (revocation_status IN ('absent', 'revoked', 'indeterminate')),
        revocation_check_json TEXT NOT NULL,
        rail_resolutions_json TEXT NOT NULL,
        recipe_registry_version INTEGER NOT NULL CHECK (recipe_registry_version > 0),
        rail_registry_version INTEGER NOT NULL CHECK (rail_registry_version > 0),
        created_at TEXT NOT NULL
      ) STRICT;
    `);
    if (version > 0 && version < 16) migrateLifecycleV16(database);
    if (version < 16 && !tableExists(database, "fixture_failure_evidence")) {
      database.run(FIXTURE_FAILURE_EVIDENCE_SCHEMA);
    }
    if (version < 18 && tableExists(database, "fixture_vet_records")) {
      database.run("DROP TABLE fixture_vet_records");
    }
    if (version < 18 && !tableExists(database, "fixture_vet_records")) {
      database.run(FIXTURE_VET_SCHEMA);
    }
    if (version === 18) {
      if (tableExists(database, "fixture_vet_records")) {
        migrateFixtureVetV19(database);
      } else {
        database.run(FIXTURE_VET_SCHEMA);
      }
    }
    if (version < 20) {
      database.run(FIXTURE_LISTING_ANCHOR_REGISTRY_SCHEMA);
      database.run(FIXTURE_LISTING_LIFECYCLE_VERSIONS_SCHEMA);
      database.run(FIXTURE_LISTING_DISCOVERY_SCHEMA);
      database.run(FIXTURE_LISTING_REVOCATIONS_SCHEMA);
      database.run(FIXTURE_SESSION_LISTING_PINS_SCHEMA);
    }
    if (version < 21) {
      database.run(PRODUCTION_SIGNING_KEYS_SCHEMA);
      database.run(PRODUCTION_SIGNING_KEYS_CURRENT_INDEX);
      database.run(PRODUCTION_KEY_LISTING_VERSIONS_SCHEMA);
      database.run(PRODUCTION_KEY_REVOCATIONS_SCHEMA);
      database.run(PRODUCTION_SESSION_KEY_PINS_SCHEMA);
    }
    if (version < 22) database.run(HTTP_RATE_BUCKETS_SCHEMA);
    if (version < 23) {
      database.run(PARTY_AUTHORITY_INSTANCES_SCHEMA);
      database.run(PARTY_CAPABILITIES_SCHEMA);
      database.run(PARTY_AUTHORITY_CHALLENGES_SCHEMA);
      database.run(PARTY_AUTHORITY_RECOVERY_REPLAYS_SCHEMA);
      database.run(PARTY_AUTHORITY_AMENDMENTS_SCHEMA);
    }
    if (version < 24) database.run(PARTY_CAPABILITY_PREPARATIONS_SCHEMA);
    if (version < 25) database.run(LIVE_EFFECT_INTENTS_SCHEMA);
    if (version < 26) database.run(TURNKEY_SIGNING_INTENTS_SCHEMA);
    database.run(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  });
  apply.exclusive();
}

function migrateFixtureVetV19(database: Database): void {
  database.run("ALTER TABLE fixture_vet_records RENAME TO fixture_vet_records_v18");
  database.run(FIXTURE_VET_SCHEMA);
  database.run(`
    INSERT INTO fixture_vet_records (
      instance_id, audience, job_id, evaluated_role, evaluated_party, verifier_party,
      bundle_hash, requirement_hash, requirement_json, requirement_source_kind,
      requirement_source_address, requirement_source_content_hash,
      requirement_source_artifact_hash, recipe_registry_version, recipe_availability,
      assertion_address, assertion_artifact_hash, verify_result_address,
      verify_result_artifact_hash, composite_address, composite_artifact_hash,
      overall_decision, generated_at, created_at
    ) SELECT
      instance_id, audience, job_id, evaluated_role, evaluated_party, verifier_party,
      bundle_hash, requirement_hash, requirement_json, requirement_source_kind,
      requirement_source_address, requirement_source_content_hash,
      requirement_source_artifact_hash, recipe_registry_version, recipe_availability,
      assertion_address, assertion_artifact_hash, verify_result_address,
      verify_result_artifact_hash, composite_address, composite_artifact_hash,
      overall_decision, generated_at, created_at
    FROM fixture_vet_records_v18
  `);
  database.run("DROP TABLE fixture_vet_records_v18");
}

function migrateLifecycleV16(database: Database): void {
  database.run("ALTER TABLE fixture_lifecycle_runs RENAME TO fixture_lifecycle_runs_v15");
  database.run(FIXTURE_LIFECYCLE_SCHEMA);
  database.run(`
    INSERT INTO fixture_lifecycle_runs (
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      state, version, commitment_artifact_hash, payment_invocations,
      settlement_invocations, delivery_invocations, payment_result_json,
      settlement_result_json, delivery_result_json, terminal_result_json,
      terminal_state, abort_actor_role, abort_reason, failure_stage, error_class,
      failure_reason, paused_at, pause_expires_at, created_at, updated_at, ended_at
    ) SELECT
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      state, version, commitment_artifact_hash, payment_invocations,
      settlement_invocations, delivery_invocations, payment_result_json,
      settlement_result_json, delivery_result_json, NULL,
      NULL, NULL, NULL, failure_stage, error_class,
      failure_reason, paused_at, pause_expires_at, created_at, updated_at, ended_at
    FROM fixture_lifecycle_runs_v15
  `);
  database.run("DROP TABLE fixture_lifecycle_runs_v15");
}

function migrateLifecycleV12(database: Database): void {
  database.run("ALTER TABLE fixture_lifecycle_runs RENAME TO fixture_lifecycle_runs_v11");
  database.run(FIXTURE_LIFECYCLE_SCHEMA);
  database.run(`
    INSERT INTO fixture_lifecycle_runs (
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      state, version, commitment_artifact_hash, payment_invocations,
      settlement_invocations, delivery_invocations, payment_result_json,
      settlement_result_json, delivery_result_json, failure_stage, error_class,
      failure_reason, paused_at, pause_expires_at, created_at, updated_at, ended_at
    ) SELECT
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      state, version, commitment_artifact_hash, payment_invocations,
      settlement_invocations, delivery_invocations, payment_result_json,
      settlement_result_json, delivery_result_json, failure_stage, error_class,
      failure_reason, paused_at, pause_expires_at, created_at, updated_at, ended_at
    FROM fixture_lifecycle_runs_v11
  `);
  database.run("DROP TABLE fixture_lifecycle_runs_v11");
}

function migrateLifecycleV9(database: Database): void {
  database.run("ALTER TABLE fixture_lifecycle_runs RENAME TO fixture_lifecycle_runs_v9");
  database.run(FIXTURE_LIFECYCLE_SCHEMA);
  database.run(`
    INSERT INTO fixture_lifecycle_runs (
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      state, version, commitment_artifact_hash, payment_invocations,
      settlement_invocations, delivery_invocations, payment_result_json,
      settlement_result_json, delivery_result_json, failure_stage, error_class,
      failure_reason, paused_at, pause_expires_at, created_at, updated_at, ended_at
    )
    SELECT
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      CASE state
        WHEN 'substrate-failure-expired' THEN 'failed-substrate'
        ELSE state
      END,
      version, commitment_artifact_hash, payment_invocations,
      settlement_invocations, delivery_invocations, payment_result_json,
      settlement_result_json, delivery_result_json, failure_stage, error_class,
      failure_reason, paused_at, pause_expires_at, created_at, updated_at, ended_at
    FROM fixture_lifecycle_runs_v9
  `);
  database.run("DROP TABLE fixture_lifecycle_runs_v9");
}

function rejectUnrecoverableFixtureMigration(database: Database, version: number): void {
  if (version > 0 && version < 11 && tableExists(database, "sessions")) {
    const duplicateJob = database.query<{ jobId: string }, []>(`
      SELECT job_id AS jobId
      FROM sessions
      GROUP BY job_id
      HAVING count(*) > 1
      LIMIT 1
    `).get();
    if (duplicateJob !== null) {
      throw new Error(
        `Cannot migrate schema before v11 with a cross-namespace duplicate jobId: ${duplicateJob.jobId}`,
      );
    }
  }
  if (version === 8 && tableCount(database, "fixture_lifecycle_runs") > 0n) {
    throw new Error(
      "Cannot migrate populated schema v8 lifecycle state: substrate pause deadlines are unavailable",
    );
  }
  if (version >= 3 && version < 4 && tableCount(database, "fixture_settlements") > 0n) {
    throw new Error("Cannot migrate populated fixture settlements from schema v3: payee address is unavailable");
  }
  if (version >= 4 && version < SCHEMA_VERSION) {
    const missingPayeeAddress = database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM fixture_settlements WHERE payee_address = ''
    `).get()?.count ?? 0n;
    if (missingPayeeAddress > 0n) {
      throw new Error("Cannot migrate fixture settlements with an unavailable payee address");
    }
  }
  if (version >= 4 && version < 7 && tableCount(database, "fixture_settlements") > 0n) {
    throw new Error("Cannot migrate populated fixture settlements before schema v7: orchestrator claim is unavailable");
  }
  if (version >= 3 && version < 5 && tableCount(database, "fixture_anchors") > 0n) {
    throw new Error("Cannot migrate populated fixture anchors before schema v5: artifact binding is unavailable");
  }
  if (version >= 5 && version < SCHEMA_VERSION) {
    const missingArtifactBinding = database.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM fixture_anchors WHERE artifact_content_hash IS NULL
    `).get()?.count ?? 0n;
    if (missingArtifactBinding > 0n) {
      throw new Error("Cannot migrate fixture anchors with an unavailable artifact binding");
    }
  }
  if (version >= 7 && version < 11 && tableCount(database, "fixture_settlements") > 0n
    && !columnExists(database, "fixture_settlements", "session_binding_hash")) {
    throw new Error(
      "Cannot migrate populated fixture settlements before schema v11: session binding is unavailable",
    );
  }
  if (version < 13 && tableExists(database, "fixture_commitments")
    && tableCount(database, "fixture_commitments") > 0n) {
    throw new Error(
      "Cannot migrate populated fixture commitments before schema v13: persisted orchestrator authority is unavailable",
    );
  }
  if (version === 13 && ((tableExists(database, "fixture_commitments")
    && tableCount(database, "fixture_commitments") > 0n)
    || (tableExists(database, "fixture_bundles") && tableCount(database, "fixture_bundles") > 0n))) {
    throw new Error(
      "Cannot migrate populated schema v13: signed Listing and IdentityBundle authority provenance is unavailable",
    );
  }
  if (version === 14 && ((tableExists(database, "fixture_commitments")
    && tableCount(database, "fixture_commitments") > 0n)
    || (tableExists(database, "fixture_bundles") && tableCount(database, "fixture_bundles") > 0n))) {
    throw new Error(
      "Cannot migrate populated schema v14: per-commitment Listing verification authority is unavailable",
    );
  }
  if (version === 17 && tableExists(database, "fixture_vet_records")
    && tableCount(database, "fixture_vet_records") > 0n) {
    throw new Error(
      "Cannot migrate populated schema v17 Vet state: signed requirement-source provenance is unavailable",
    );
  }
  if (version < 17 && tableExists(database, "fixture_vet_records")
    && tableCount(database, "fixture_vet_records") > 0n) {
    throw new Error(
      "Cannot migrate populated pre-v17 Vet state: schema provenance is inconsistent",
    );
  }
  if (version === 18 && tableExists(database, "fixture_vet_records")
    && tableCount(database, "fixture_vet_records") > 0n) {
    throw new Error(
      "Cannot migrate populated schema v18 Vet state: signed chronology provenance was not enforced",
    );
  }
  if (version === 0 && (database.query<{ count: bigint }, []>(`
    SELECT count(*) AS count FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
  `).get()?.count ?? 0n) > 0n) {
    throw new Error("Cannot migrate an existing unversioned database safely");
  }
}

function tableExists(database: Database, table: string): boolean {
  return (database.query<{ count: bigint }, { table: string }>(`
    SELECT count(*) AS count FROM sqlite_master WHERE type = 'table' AND name = $table
  `).get({ table })?.count ?? 0n) === 1n;
}

function columnExists(database: Database, table: string, column: string): boolean {
  return (database.query<{ count: bigint }, { table: string; column: string }>(`
    SELECT count(*) AS count FROM pragma_table_info($table) WHERE name = $column
  `).get({ table, column })?.count ?? 0n) === 1n;
}

function tableCount(
  database: Database,
  table: "fixture_settlements" | "fixture_anchors" | "fixture_lifecycle_runs"
    | "fixture_commitments" | "fixture_bundles" | "fixture_vet_records",
): bigint {
  if (table === "fixture_settlements") {
    return database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_settlements").get()?.count ?? 0n;
  }
  if (table === "fixture_anchors") {
    return database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_anchors").get()?.count ?? 0n;
  }
  if (table === "fixture_lifecycle_runs") {
    return database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_lifecycle_runs").get()?.count ?? 0n;
  }
  if (table === "fixture_commitments") {
    return database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_commitments").get()?.count ?? 0n;
  }
  if (table === "fixture_bundles") {
    return database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_bundles").get()?.count ?? 0n;
  }
  return database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_vet_records").get()?.count ?? 0n;
}

# Live testnet profile

Status: v0.2 foundation candidate. Local and fixture-qualified only. No live
anchor, Directory registration, payment, deployment, or reachable service is
claimed by this source state.

The supported v0.1.1 release remains the immutable no-spend baseline. The v0.2
foundation adds a second, explicit `live-testnet` admission contract without
changing the default fixture profile or the five-path service-extension boundary.

## Admission

A live profile is admitted only when it binds all of the following:

- an injected signer reference and expected Demos seller claim;
- Demos testnet RPC and the exact official dacs-sdk commit
  `e2070e0085414c67d139e1e62924ca9ef8b316c7`;
- HTTPS Community Directory endpoint, manifest URL, and schema digest;
- one bounded Demos-testnet or Base-Sepolia rail;
- an explicit testnet-only effect allow-list with one submission attempt.

Missing, floating, mainnet, production, or unbounded configuration fails
admission. Configuration alone performs no network operation.

## SDK boundary

Forge Core, the producer-independent consumer, and the public package entry point
do not import `dacs-sdk`. The optional Demos storage adapter consumes a narrowly
typed injected SDK object and rejects any composition that does not declare the
exact official commit above. This preserves Forge as an independent implementation
and keeps the public frozen install working while the official SDK repository is
not publicly installable.

The adapter uses the merged SDK storage behavior from PRs #70 and #78: immutable
write-once anchoring, owner-bound logical-to-native resolution, and exact native
readback. The published binding remains discovery, not trust. Forge verifies the
canonical Listing bytes, signed scope, expected seller, content hash, current
revocation disposition, and supported rail before Directory submission.

The anchor-only operation stops after independent native readback and returns the
verified Listing hash and native address without accepting or invoking a Directory
adapter. The composed publication operation calls the same anchor path before its
separately admitted Directory effect.

## Intent and recovery

Every live anchor, Directory registration, or payment uses an immutable effect
key and canonical payload. SQLite schema v25 records the intent before adapter
submission. On restart Forge reconciles the external system before any retry:

```text
prepared intent -> adapter reconcile -> durable submission-attempt marker
                -> submit at most once -> reconcile observation
                -> durable observation -> committed result
```

An indeterminate reconciliation fails closed. Reusing an effect key with changed
payload bytes is rejected. Once a submission attempt is durable, an absent result
fails closed instead of resubmitting; an operator or successor-specific recovery
contract must resolve whether the effect occurred. Adapters should additionally be
idempotent under the effect key: Demos storage uses `anchorWriteOnce`, while each
rail must supply its own session-bound idempotency and reconciliation contract
before live use. The admitted profile allow-list is enforced before intent
persistence.

The interruption tests cover crashes before submission, after submission, after
external observation, and before the local commit. They reopen the same database
and require exactly one externally observable fixture effect.

## Chain authority and Directory projection

The local qualification flow is ordered:

1. verify the signed Listing;
2. persist anchor intent and invoke the injected Demos adapter;
3. resolve and read the native record independently;
4. verify exact canonical bytes, signature, seller, hash, rail, and revocation;
5. derive a Directory `ListingSummary` from that verified record;
6. persist registration intent and submit only the authoritative chain pointer;
7. treat catalog absence, lag, or conflict as discovery state, never authority.

The Community adapter matches the current `POST /api/dacs/register` pointer
contract and reads `GET /api/dacs/listings` for the resulting projection. Directory
inclusion does not prove reachability, service quality, reputation, production
readiness, certification, or endorsement.

## Still open

Live Demos anchoring and consumer readback, actual Community registration,
reachable-service proof, buyer identity, pay-dem, x402, cross-rail comparison,
and supported v0.2 publication remain separately evidenced successor work.

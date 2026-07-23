# Listing Trust Boundary

Normative pin: DACS-Standard `ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4`.

## Publisher

`signPerClaimIdentityBundle` and `signListing` are fixture-mode producer paths.
They currently support direct `key:<32-byte-ed25519-public-key>` claims only.
Every signing call must provide the current trusted deployment mode and the
signed request mode; both must be `fixture`. Creation-time authorization is not
reused as request authority. A module-private capability registry rejects copied
or structurally forged `ArtifactSigner` objects. The fixture private seed is
copied into a non-exporting Node `KeyObject` closure and is not returned by any API.

Before emitting a Listing, the publisher:

- canonicalizes every signed byte and every ClaimReference;
- verifies the embedded per-claim IdentityBundle presentation again;
- validates current DACS Listing, deliverable, pricing, pipeline, and rail-reference shapes;
- enforces PS-1..PS-3, monotonic `vet -> negotiate -> commit -> settle -> rate`
  ordering, CA-1 settlement gating, and pay-phase-to-accepted-rail binding;
- requires the SE-1 60-second sealed-envelope lead time and HTTPS external rule references;
- signs `dacs-listing:v1:` plus the lowercase SHA-256 content hash;
- rejects a final canonical signed Listing larger than 16,384 bytes;
- returns a recursively frozen JSON object plus its exact canonical bytes.

Unknown inert fields remain in the canonical signed scope. Unknown phase kinds
are not emitted by this publisher.

## Reader

`verifyCanonicalListingJson` independently implements canonical JSON and
Ed25519 verification. It does not call the producer canonicalizer or signer.
The reader follows the DACS-1 validation order and stops at the first failure:

1. Listing schema and current wire shapes
2. DACS major version
3. inclusive validity window
4. canonical bytes, final size cap, content hash, signature
5. revocation disposition
6. IdentityBundle presentation
7. phase support and pipeline semantics
8. accepted payment-rail binding and resolution
9. Listing signer membership in publisher claims

A correctly signed unknown phase produces `refused-unsupported` only after the
signature verifies because phase support is validation step 7. Unknown deliverable,
pricing, and verification-method kinds are structurally `refused-unsupported` at
schema step 1, before signature verification, per the DACS-1 validation order.
Their bytes are still preserved unchanged whenever the document is forwarded.
Known-but-unimplemented signature algorithms, indirect signer resolution, and
non-key IdentityBundle presentations also produce `refused-unsupported`; they
are not mislabeled as invalid cryptography.
Unknown supporting ClaimReferences remain in signed scope, count as unverified,
and are returned byte-for-byte in the accepted result's immutable `unknownClaims`
field so the caller can surface them. An unknown primary claim never throws or
silently establishes control.

## Required Adapters

`revocationCheck` is mandatory. It receives an immutable tuple containing the
publisher primary claim, verified Listing signer, Listing id, version, and content hash. It must complete
the DACS-1 RB-4..RB-6 binding-resolution procedure and synchronously return one
of `absent`, `revoked`, or `indeterminate`. Exceptions propagate as infrastructure
failures; Promises and unknown dispositions are rejected as adapter-contract bugs.
The resolved marker signer must equal the supplied Listing signer.

For any pay phase, `paymentRailCheck` is mandatory. It receives only immutable
primitive fields, all referencing pay-phase kinds, and canonical PaymentRailRef JSON. A
resolved result must return the authoritative rail definition's `phaseHandler`;
it must exactly match every referencing pay-phase kind. Unresolved and indeterminate results,
phase mismatch, missing adapters, Promises, and malformed results never produce
an accepted Listing.

The repository does not yet provide either live adapter. Tests use explicit
fixture adapters; these are not production substitutes.

## Explicitly Unsupported

- live keys, HSM/KMS integration, ECDSA, SR-1 aggregate signatures
- SIWD, session-key, or SR-1 IdentityBundle presentation verification
- indirect ClaimReference-to-key resolution through DACS-2
- live Demos logical-to-native anchor and revocation-binding resolution
- payment-rail registry reads
- external selection-rule fetching and network egress policy enforcement
- registration, funded settlement, live settlement, live delivery, external DACS-5 qualification, or reputation writes

Delivery-shape verification keeps two addresses distinct: the delivered artifact
address and an explicit `AttestationRef`-derived evidence-anchor address. The
current pin does not define a canonical delivery-evidence address formula, so an
absent or colliding evidence address is `refused-unsupported`, never derived by a
template-local convention.

No readiness command may report these gates as passed until the corresponding
adapter and live evidence exist.

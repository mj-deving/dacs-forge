# Public review-capsule export correction

Artifact maturity: bounded v0.2 fixture-qualified foundation increment; public main snapshot, not a v0.2 release or live-commerce qualification.

Protected claim: the public-export verifier permits only the named `evidence/reviews/live-demos-profile/` capsule while continuing to reject every other evidence path, private control path, forbidden nested segment, and forbidden content across the tracked tree and reachable release history.

Trusted actors and inputs: reviewed first-party Forge source, tests, and committed review-capsule bytes.

Untrusted inputs: tracked path names, nested path segments, file content, and changed paths or blobs in reachable history.

In scope: accidental allow-list widening, prefix confusion, forbidden nested paths, current-tree/history inconsistency, and provenance drift. Out of scope: malicious source author, hostile Git/runtime/toolchain, third-party certification, and any live network or value effect.

Review only the staged public-export verifier, regression test, and provenance-manifest correction. Stop when no accepted P0/P1 or protected-claim-bypassing P2 remains. Do not request broader product hardening.

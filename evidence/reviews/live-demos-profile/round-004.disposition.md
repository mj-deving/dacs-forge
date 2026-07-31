# Round 004 disposition

- Accepted P2: the initial public-capsule branch ignored every segment named `evidence`, including a nested suffix segment.
- Correction: identify the exact allowed root prefix, validate only its non-empty suffix, and apply the complete forbidden-segment set to every suffix segment.
- Regression: `evidence/reviews/live-demos-profile/evidence/private.json` is explicitly rejected.
- Recheck: required after focused export, provenance, release-manifest, typecheck, and regression gates pass.

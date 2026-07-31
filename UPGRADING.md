# Upgrading DACS Forge

## Supported direct path

`v0.1.1` is a metadata- and evidence-only patch over the immutable supported
`v0.1.0` commit `81507c792c158a5782ea67e6c43c873d49356903`.
It changes no runtime, persisted-artifact shape, DACS pin, or declared service
extension path. Existing v0.1.0 forks can fast-forward or merge v0.1.1 and rerun
the unchanged complete rig.

The original first-Product-Seal path remains historical authority:

The v0.1.0 Product Seal has exactly one direct predecessor:
`v0.1.0-preview.2` at commit
`0c6e92cc707c62db0ca3c9627d59bb95ba9970e9`. That Preview is immutable and
unsupported. Every other predecessor is unsupported for a direct upgrade.

The supported update shape is a Git fork or clone retaining shared history. A
service fork keeps its owned changes inside these extension paths:

- `service/service.config.ts`
- `service/input.schema.json`
- `service/output.schema.json`
- `service/handler.ts`
- `service/fixtures/**`

## Procedure

1. Record the current fork commit, persisted database, signed artifact bytes,
   evidence bundle digests, and DACS pin.
2. Fetch the Product Seal tag from the Forge upstream without rewriting history.
3. Merge or rebase through shared Git history. Resolve conflicts only inside the
   declared extension paths. A conflict outside that boundary makes the result a
   substrate fork and ends the extension-only claim.
4. Confirm that the DACS pin remains the immutable `v0.4` commit
   `4bb9e48a1095ab32c06c25b7c0b52018d3ce4091`.
5. Run `bun install --frozen-lockfile`, `bun run verify:provenance`, `bun run
   typecheck`, `bun test --timeout 10000`, `bun run build`, `bun run
   mutation:calibrate`, and `bun run verify:container` without changing the rig.
6. Reopen the preserved database and independently resolve the previously signed
   artifact graph. Compare artifact and evidence digests with the recorded values.

Automatic conflict-free merging is not promised. Keep the recorded pre-upgrade
commit as the rollback point until every probe is green. Failed, skipped,
indeterminate, or substituted checks do not establish compatibility.

This path does not enable live registration, payment, deployment, certification,
steward endorsement, Community listing, or adoption claims.

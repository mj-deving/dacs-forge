# Building a DACS service agent

The product contract is simple: customize the service, not the protocol core.

This guide starts from a clean clone and proves a local fixture service. It does
not publish a Listing, register with a Directory, transfer value, or qualify a
release.

## 1. Install and record the fork base

Use Bun `1.3.9` on Linux:

```sh
bun install --frozen-lockfile
fork_base=$(git rev-parse HEAD)
```

## 2. Define the service

Change only:

- `service/service.config.ts`
- `service/input.schema.json`
- `service/output.schema.json`
- `service/handler.ts`
- `service/fixtures/`

Update the service id and version, schema ids and versions, TypeScript input/output
types, handler result, and fixtures as one coherent contract. A behavior or schema
change requires a service-version bump.

Keep the service handler deterministic and side-effect-free. It receives validated,
deep-frozen input plus inert execution metadata; it receives no signer, database,
wallet, payment capability, network client, or raw key through its API. It is
trusted code in the service process, not a sandbox, and can still import ambient
Bun or Node APIs.

## 3. Prove the service path and protocol path

A service fork is not locally proven merely because it compiles. Run both focused
tests because the runtime test isolates handler behavior while the full handshake
proves its integration with the protocol lifecycle:

```sh
bun test --timeout 10000 test/runtime/service-runtime.test.ts
bun test --timeout 10000 test/e2e/full-handshake.test.ts
```

The runtime test executes the configured handler and checks validated output, the
signed work-product receipt, atomic artifact persistence, duplicate refusal, and
replay after reopening SQLite. Its `ServiceRunResult` exposes `output`, `receipt`,
`outputArtifact`, and `receiptArtifact`; the test independently verifies their
canonical bytes and hashes. The test database is temporary, so this is currently
the supported artifact-inspection surface rather than a command that leaves a
production database behind.

The full-handshake test admits one authority over the Agreement and service request,
executes the service handler, uses its canonical output bytes as the attested Delivery
payload, and resolves those bytes through the buyer/seller/orchestrator DACS-5 bundle
copies. It also proves restart replay without another handler, settlement, or Delivery
effect. The isolated runtime test remains required for the narrower service contract.

## 4. Run repository gates

```sh
bun run check
bun run build
```

`bun run check` runs provenance verification, TypeScript validation, and the full
test suite. `bun run build` bundles the exported library surface.

Mutation calibration is optional during ordinary iteration and is not part of
`bun run check`:

```sh
bun run mutation:calibrate
```

That command proves the configured mutation runner kills its fixed calibration
catalog. The slower `bun run mutation:check` is the full repository mutation run;
neither command by itself qualifies a service or release.

## 5. Inspect the extension-only diff

```sh
git diff --name-only "$fork_base" --
```

Every changed path in an ordinary service fork must be one of the four exact files
or below the fixture prefix:

```text
service/service.config.ts
service/input.schema.json
service/output.schema.json
service/handler.ts
service/fixtures/**
```

For the reference exemplar, keep a clean checkout at the exact trusted base and
run its verifier and scanner against the separate committed exemplar checkout:

```sh
bun run verify:exemplar-diff -- --repository "$exemplar_checkout" --base "$fork_base" --tip "$exemplar_tip"
bun run scan:critical -- --repository "$exemplar_checkout" --base "$fork_base" --tip "$exemplar_tip"
```

Both commands refuse to run unless their own checkout is clean and exactly at
`$fork_base`. Verifier, scanner, policy, and regression bytes are therefore
outside the exemplar delta and cannot qualify themselves as extension changes.

The provenance gate intentionally allows those extension bytes to differ without
editing `docs/SOURCE-PROVENANCE.json`. It still fails closed on substrate drift,
undeclared tracked paths, missing required extension files, unsafe paths, duplicate
declarations, symlinks, and non-regular files.

## What this proves

Passing the steps above shows that the fork-owned handler and schemas work inside
the current fixture substrate and that the unchanged repository gates remain green.
It does not complete the still-open extension-only reference-fork and full
release-rig qualification. Publication, container/readiness qualification,
external-rig acceptance, live Directory registration, anchoring, payment, and
reputation remain separate gates.

## What not to change

Changing producer/consumer verification, canonicalization, signature handling,
persistence, lifecycle ordering, or conformance tests creates a substrate fork,
not an ordinary service-agent implementation. Such changes require independent
review and cannot qualify by weakening the rig that judges them.

For the underlying component and artifact flow, read the [architecture](ARCHITECTURE.md)
and [service contract](SERVICE-CONTRACT.md).

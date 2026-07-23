# Building a DACS service agent

The product contract is simple: customize the service, not the protocol core.

## Declared extension points

Change only:

- `service/service.config.ts`
- `service/input.schema.json`
- `service/output.schema.json`
- `service/handler.ts`
- `service/fixtures/`

Keep the service handler deterministic and side-effect-free. It receives validated,
deep-frozen input plus inert execution metadata; it receives no signer, database,
wallet, payment capability, network client, or raw key.

## Qualification

A DACS service agent is not qualified merely because it compiles. Its fork must have distinct
service logic plus its own schema or fixtures and must pass:

```sh
bun install --frozen-lockfile
bun test test/e2e/full-handshake.test.ts
bun run check
bun run build
```

The complete release path will additionally require the published container,
readiness, external-rig, and provenance gates. Those surfaces remain open in the
prototype and must not be represented as complete.

## What not to change

Changing producer/consumer verification, canonicalization, signature handling,
persistence, lifecycle ordering, or conformance tests creates a substrate fork,
not an ordinary service-agent implementation. Such changes require independent review
and cannot qualify by weakening the rig that judges them.

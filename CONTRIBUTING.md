# Contributing

DACS Forge welcomes focused protocol, test, documentation, and service-extension
contributions.

## Development

Use Bun `1.3.9` on Linux:

```sh
bun install --frozen-lockfile
bun run check
bun run build
```

Keep the lockfile immutable unless the change intentionally updates dependencies.
Use TypeScript for implementation and tests.

## Service contributions

Service-agent-specific behavior belongs in `service/`. A service-agent fork
should change only its metadata, input/output schemas, handler, pricing/rail
configuration, and fixtures. Changes to `src/` alter the shared protocol
substrate and require a separate protocol/security justification.

Every behavior change needs a deterministic positive probe and a fail-closed
negative probe where applicable. Report fixture evidence only as fixture evidence.

## Protocol findings

DACS specification ambiguities or defects belong in
[DACS-Standard](https://github.com/DACS-Agent-commerce/DACS-Standard/issues) with
the exact section, artifact, observed behavior, and proposed correction.

## Pull requests

Keep changes narrow and explain:

- the behavior or contract changed;
- the DACS surface affected;
- the checks executed;
- any remaining unsupported or indeterminate state.

Never commit API keys, private endpoints, mnemonics, signing seeds, generated
databases, or live transaction material.

Public-contract changes must follow [versioning and release policy](docs/VERSIONING.md).
Breaking changes require migration guidance; protocol and security boundaries may
not be weakened for compatibility.

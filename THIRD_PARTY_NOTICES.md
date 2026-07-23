# Third-party notices

This repository contains copied or projected test vectors and fixtures from the
following MIT-licensed repositories. These materials remain non-normative test
evidence; the named upstream commits are their source provenance.

## DACS-Standard

Source: <https://github.com/DACS-Agent-commerce/DACS-Standard>

Included paths and exact source commits:

- `vectors/dacs-standard-canonicalize-db9f9c0.json` — projection of the seven `area: canonicalize` entries in `conformance/MANIFEST.json` at `db9f9c0075a63d69d4464bac62cbfb2362a3f223`.
- `vectors/dacs-standard-listing-preserve-unknown-c4ace08.json` — copy of `conformance/vectors/security/listing-preserve-unknown-v0.1.json` at `c4ace086a6f7117784d65f527b93e632039db6de`.
- `vectors/dacs-standard-signature-value-encoding-c4ace08.json` — projection of `conformance/vectors/security/signature-value-encoding-v0.1.json` at `c4ace086a6f7117784d65f527b93e632039db6de`.
- `vectors/dacs-standard-bundle-convergence-ad48d16.json` — projection of `spec/DACS-5-VERIFY.md`, `conformance/fixtures/session-bundles-presence.json`, `conformance/fixtures/session-bundle-one-sided.json`, and `conformance/fixtures/attestation-bundle-0004.json` at `ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4`.
- `vectors/dacs-standard-settlement-finalization-ad48d16.json` — projection of `conformance/vectors/security/settlement-finalization-propagation-v0.3.json` at `ad48d16c25a810a6420b4d4cc9b9d8d6d38908c4`.
- `vectors/dacs-standard-storage-program-fcbf804.json` — projection of `spec/DACS-4-SETTLE.md` and `conformance/vectors/security/private-deliverables-v0.1.json` at `fcbf804dcc53184726eed4385d794a0fdbbe00cc`; the file separately records baseline `main` commit `2ff69b7f1fa13440a64cc865bd3f7e5fce6d34d2`.

## Community

Source: <https://github.com/DACS-Agent-commerce/Community>

Included paths and exact source commit:

- `vectors/community-directory/reviewbot-legacy-listing-634caef.json` — copy of `reference-implementations/dacs-directory/test/fixtures/reviewbot-listing-anchor.json` at `634caef4b952838281c8c602402e657d41074703`.
- `vectors/community-directory/provenance.json` — provenance record for `reference-implementations/dacs-directory/test/fixtures/reviewbot-listing-anchor.json`, `reference-implementations/dacs-directory/src/catalog/contracts.ts`, and `reference-implementations/dacs-directory/app/schemas/listing-summary.schema.json/route.ts` at `634caef4b952838281c8c602402e657d41074703`.
- `src/protocol/directory-summary-schema.ts` — local schema projection of `reference-implementations/dacs-directory/src/catalog/contracts.ts` and `reference-implementations/dacs-directory/app/schemas/listing-summary.schema.json/route.ts` at `634caef4b952838281c8c602402e657d41074703`.

## Retained MIT notice

MIT License

Copyright (c) 2026 KyneSys Labs and the DACS authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

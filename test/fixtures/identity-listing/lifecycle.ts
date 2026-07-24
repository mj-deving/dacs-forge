import { canonicalize } from "../../../src/protocol/canonical-json.ts";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256Hex } from "../../../src/protocol/hash.ts";
import {
  fixtureBindingSigningBytes,
  type FixtureBindingAuthority,
  type FixtureBindingProof,
  type FixtureBindingScope,
} from "../../../src/consumer/binding-verifier.ts";
import { signListing } from "../../../src/producer/listing.ts";
import type { ArtifactSigner } from "../../../src/producer/fixture-ed25519.ts";
import { ListingLifecycle } from "../../../src/directory/listing-lifecycle.ts";
import { listingLogicalAddress } from "../../../src/directory/listing-lifecycle.ts";
import { openDatabase } from "../../../src/substrate/sqlite/database.ts";
import { ListingStore } from "../../../src/substrate/sqlite/listing-store.ts";
import {
  FIXTURE_NOW_MS,
  FIXTURE_SIGNING_CONTEXT,
  fixtureSigner,
  fixtureUnsignedListing,
} from "../reference-listing.ts";

export function signedListingVersion(version: number) {
  const unsigned = fixtureUnsignedListing();
  return signListing({ ...unsigned, listingVersion: version }, fixtureSigner(), FIXTURE_SIGNING_CONTEXT);
}

export function fixtureBinding(
  canonicalJson: string,
  logicalAddress: string,
  suffix: string,
  options: {
    readonly signer?: ArtifactSigner;
    readonly nativeAddress?: string;
  } = {},
): { readonly proof: FixtureBindingProof; readonly authority: FixtureBindingAuthority } {
  const signer = options.signer ?? fixtureSigner();
  const scope: FixtureBindingScope = {
    logicalAddress,
    nativeAddress: options.nativeAddress ?? `stor-${sha256Hex(`native:${suffix}`).slice(0, 40)}`,
    contentHash: sha256Hex(canonicalJson),
    createdByTx: sha256Hex(`tx:${suffix}`),
  };
  const proof: FixtureBindingProof = {
    ...scope,
    signer: signer.signer,
    signature: signer.sign(
      new TextEncoder().encode(fixtureBindingSigningBytes(scope)),
      FIXTURE_SIGNING_CONTEXT,
    ),
  };
  const authority: FixtureBindingAuthority = {
    dereference: (nativeAddress) => nativeAddress === proof.nativeAddress
      ? { canonicalJson, createdByTx: proof.createdByTx }
      : null,
    verifyNativeWrite: (input) => canonicalize(input) === canonicalize({
      ...scope,
      signer: signer.signer,
    }),
  };
  return Object.freeze({ proof: Object.freeze(proof), authority });
}

export const CREATED_AT = new Date(FIXTURE_NOW_MS).toISOString();

export async function withListingLifecycle<T>(
  run: (input: {
    readonly database: ReturnType<typeof openDatabase>;
    readonly lifecycle: ListingLifecycle;
    readonly store: ListingStore;
  }) => T | Promise<T>,
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-listing-lifecycle-"));
  const database = openDatabase(join(directory, "state.sqlite"));
  const store = new ListingStore(database);
  try {
    return await run({ database, lifecycle: new ListingLifecycle(store), store });
  } finally {
    database.close();
    await rm(directory, { recursive: true, force: true });
  }
}

export function publishFixtureVersion(lifecycle: ListingLifecycle, version: number) {
  const signed = signedListingVersion(version);
  const logicalAddress = listingLogicalAddress(
    fixtureSigner().signer,
    "reference-json-transform",
    version,
  );
  const binding = fixtureBinding(signed.canonicalJson, logicalAddress, `listing-v${version}`);
  return lifecycle.publish({
    canonicalJson: signed.canonicalJson,
    bindingProof: binding.proof,
    bindingAuthority: binding.authority,
    verifiedAt: FIXTURE_NOW_MS,
    createdAt: CREATED_AT,
  });
}

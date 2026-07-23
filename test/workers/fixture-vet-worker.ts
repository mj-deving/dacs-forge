import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { readPersistedSessionByJobId } from "../../src/substrate/sqlite/session-store.ts";
import { FixtureVetStore } from "../../src/substrate/sqlite/fixture-vet.ts";
import {
  FIXTURE_COMMITTED_AT,
  buyerFixtureSigner,
  fixtureBuyerIdentity,
  fixtureSignedPaidListing,
} from "../fixtures/reference-agreement.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

declare const self: Worker;

self.onmessage = (event: MessageEvent<{ readonly kind: "initialize"; readonly path: string } | { readonly kind: "start" }>) => {
  if (event.data.kind === "initialize") {
    state.path = event.data.path;
    self.postMessage({ kind: "ready" });
    return;
  }
  let database: ReturnType<typeof openDatabase> | undefined;
  try {
    database = openDatabase(state.path);
    const listing = fixtureSignedPaidListing();
    const session = readPersistedSessionByJobId(database, "01J00000000000000000000000");
    if (session === null) throw new Error("Worker session is unavailable");
    const generatedAt = FIXTURE_COMMITTED_AT - 500;
    const record = new FixtureVetStore(database, "fixture").run({
      session,
      evaluatedRole: "buyer",
      evaluatedBundleHash: fixtureBuyerIdentity().bundleHash,
      requirementAuthority: { kind: "seller-listing", canonicalJson: listing.canonicalJson },
      evaluatedSigner: buyerFixtureSigner(),
      verifierSigner: fixtureSigner(),
      generatedAt,
      createdAt: new Date(generatedAt).toISOString(),
    });
    self.postMessage({ kind: "result", record });
  } catch (error) {
    self.postMessage({ kind: "error", message: error instanceof Error ? error.message : String(error) });
  } finally {
    database?.close();
  }
};

const state = { path: "" };

import { FixtureBundleStore, type FixtureBundleFinaliseInput } from "../../src/substrate/sqlite/fixture-bundle.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";
import { readPersistedSessionByJobId } from "../../src/substrate/sqlite/session-store.ts";
import { buyerFixtureSigner } from "../fixtures/reference-agreement.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import { orchestratorFixtureSigner } from "../fixtures/reference-bundle.ts";
import { lifecycleCommitmentStore } from "../lifecycle/fixtures.ts";

declare const self: {
  onmessage: ((event: MessageEvent<InitializeMessage | { readonly kind: "go" }>) => void) | null;
};

interface InitializeMessage {
  readonly kind: "initialize";
  readonly path: string;
  readonly input: Omit<FixtureBundleFinaliseInput, "partySigners" | "session">;
}

let initialized: InitializeMessage | null = null;

self.onmessage = (event: MessageEvent<InitializeMessage | { readonly kind: "go" }>) => {
  if (event.data.kind === "initialize") {
    initialized = event.data;
    postMessage({ kind: "ready" });
    return;
  }
  if (initialized === null) throw new Error("Negative bundle worker was not initialized");
  const database = openDatabase(initialized.path);
  try {
    const session = readPersistedSessionByJobId(database, initialized.input.bundle.jobId);
    if (session === null) throw new Error("Negative bundle worker session is unavailable");
    const signers = {
      buyer: buyerFixtureSigner,
      seller: fixtureSigner,
      orchestrator: orchestratorFixtureSigner,
    } as const;
    const result = new FixtureBundleStore(database, {
      commitments: lifecycleCommitmentStore(database),
      deploymentMode: "fixture",
    }).finalise({
      ...initialized.input,
      partySigners: initialized.input.anchorRoles.map((role) => ({ role, signer: signers[role]() })),
      session,
    });
    postMessage({ kind: "result", result });
  } catch (error) {
    postMessage({ kind: "error", message: error instanceof Error ? error.message : String(error) });
  } finally {
    database.close();
  }
};

import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { FixtureDeliveryStore } from "../../src/substrate/sqlite/fixture-delivery.ts";
import { attackerFixtureSigner } from "../fixtures/reference-agreement.ts";
import { deliveryInput, openDeliveryFixture } from "../delivery/fixtures.ts";

const paths: string[] = [];

afterEach(async () => {
  await Promise.all(paths.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("attested delivery restart verification", () => {
  test("re-resolves payload, DACS-2 chain, delivery anchor, and evidence after restart", async () => {
    let fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const first = fixture.store.deliver(deliveryInput(fixture.session));
    const path = fixture.path;
    fixture.database.close();

    fixture = await openDeliveryFixture(path);
    const restarted = fixture.store.get(fixture.session);
    expect(restarted).not.toBeNull();
    expect(restarted?.payloadCanonicalJson).toBe(first.payloadCanonicalJson);
    expect(restarted?.attestationRef).toEqual(first.attestationRef);
    expect(restarted?.attestationRef.contentHash).not.toBe(restarted?.verifyResultArtifactHash);
    expect(restarted?.evidenceCanonicalJson).toBe(first.evidenceCanonicalJson);
    expect(restarted?.sessionBindingHash).toBe(first.sessionBindingHash);
    const attackerStore = new FixtureDeliveryStore(fixture.database, {
      deploymentMode: "fixture",
      signer: attackerFixtureSigner(),
    });
    expect(() => attackerStore.get(fixture.session)).toThrow(/row binding is corrupt/);
    expect(() => new FixtureDeliveryStore(fixture.database, {
      deploymentMode: "fixture",
      signer: {
        algorithm: "ed25519",
        signer: first.orchestrator,
        sign: () => "not-a-signature",
      },
    })).toThrow(/not a fixture-authority capability/);
    fixture.database.close();
  });
});

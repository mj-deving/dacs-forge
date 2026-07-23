import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  FixtureDeliveryConflictError,
  FixtureDeliveryIntegrityError,
  FixtureDeliverySubstrateError,
} from "../../src/substrate/sqlite/fixture-delivery.ts";
import {
  deliveryInput,
  openDeliveryFixture,
} from "../delivery/fixtures.ts";

const paths: string[] = [];

afterEach(async () => {
  await Promise.all(paths.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("atomic attested delivery content", () => {
  test("binds delivery signing to the committed agreement, lifecycle phase, and price", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const valid = deliveryInput(fixture.session);
    expect(() => fixture.store.deliver({ ...valid, agreementHash: "f".repeat(64) }))
      .toThrow(FixtureDeliveryIntegrityError);
    expect(() => fixture.store.deliver({ ...valid, phaseIndex: valid.phaseIndex - 1 }))
      .toThrow(FixtureDeliveryIntegrityError);
    expect(() => fixture.store.deliver({ ...valid, payloadFormat: "application/cbor" }))
      .toThrow(FixtureDeliveryIntegrityError);
    expect(() => fixture.store.deliver({
      ...valid,
      paymentAmount: { ...valid.paymentAmount, amount: "2" },
    })).toThrow(FixtureDeliveryIntegrityError);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(0n);
    const delivered = fixture.store.deliver(valid);
    fixture.database.run("UPDATE fixture_lifecycle_runs SET delivery_phase_index = 2");
    expect(() => fixture.store.get(fixture.session)).toThrow(FixtureDeliveryIntegrityError);
    expect(delivered.agreementHash).toBe(valid.agreementHash);
    fixture.database.close();
  });

  test("canonicalizes cleartext before hashing and replays equivalent JSON", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const first = fixture.store.deliver(deliveryInput(fixture.session));
    const replay = fixture.store.deliver(deliveryInput(
      fixture.session,
      '{"nested":{"ok":true},"answer":42}',
    ));
    expect(first.deliverableContentHash).toBe(sha256Hex('{"answer":42,"nested":{"ok":true}}'));
    expect(replay.evidenceArtifactHash).toBe(first.evidenceArtifactHash);
    expect(replay.payloadCanonicalJson).toBe('{"answer":42,"nested":{"ok":true}}');
    const delivery = JSON.parse(first.deliveryCanonicalJson) as Record<string, unknown>;
    expect(delivery["payload"]).toEqual({ answer: 42, nested: { ok: true } });
    expect(delivery["attestationRef"]).toEqual(first.attestationRef);
    fixture.database.close();
  });

  test("rolls back payload, attestation, evidence, and anchors as one unit", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const artifactsBefore = fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()!.count;
    fixture.database.run(`
      CREATE TRIGGER fixture_delivery_failure
      BEFORE INSERT ON fixture_deliveries
      BEGIN SELECT RAISE(ABORT, 'forced fixture delivery failure'); END;
    `);
    let failure: unknown;
    try {
      fixture.store.deliver(deliveryInput(fixture.session));
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(FixtureDeliverySubstrateError);
    expect((failure as Error).message).toBe("Fixture delivery transaction failed");
    expect((failure as Error).cause).toBeInstanceOf(Error);
    expect(((failure as Error).cause as Error).message).toContain("forced fixture delivery failure");
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(0n);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(0n);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM artifacts",
    ).get()!.count).toBe(artifactsBefore);
    fixture.database.close();
  });

  test("rejects semantic re-delivery and oversized cleartext before persistence", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    fixture.store.deliver(deliveryInput(fixture.session));
    expect(() => fixture.store.deliver(deliveryInput(
      fixture.session,
      '{"answer":43,"nested":{"ok":true}}',
    ))).toThrow(/different immutable content/);
    expect(() => fixture.store.deliver(deliveryInput(
      fixture.session,
      `"${"x".repeat(131_073)}"`,
    ))).toThrow(/exceeds 131072 bytes/);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(1n);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(4n);
    fixture.database.close();
  });

  test("detects persisted artifact corruption and missing attestation anchors", async () => {
    const corrupt = await openDeliveryFixture();
    paths.push(corrupt.path.slice(0, corrupt.path.lastIndexOf("/")));
    const first = corrupt.store.deliver(deliveryInput(corrupt.session));
    corrupt.database.query<never, { hash: string }>(
      "UPDATE artifacts SET canonical_json = '{}' WHERE content_hash = $hash",
    ).run({ hash: first.deliveryArtifactHash });
    expect(() => corrupt.store.get(corrupt.session)).toThrow(/hash or length verification/);
    corrupt.database.close();

    const missing = await openDeliveryFixture();
    paths.push(missing.path.slice(0, missing.path.lastIndexOf("/")));
    const second = missing.store.deliver(deliveryInput(missing.session));
    missing.database.query<never, { address: string }>(
      "DELETE FROM fixture_anchors WHERE logical_address = $address",
    ).run({ address: second.verifyResultAddress });
    expect(() => missing.store.get(missing.session)).toThrow(/anchor binding is corrupt or absent/);
    missing.database.close();

    const missingDelivery = await openDeliveryFixture();
    paths.push(missingDelivery.path.slice(0, missingDelivery.path.lastIndexOf("/")));
    const third = missingDelivery.store.deliver(deliveryInput(missingDelivery.session));
    missingDelivery.database.query<never, { address: string }>(
      "DELETE FROM fixture_anchors WHERE logical_address = $address",
    ).run({ address: third.deliveryAddress });
    expect(() => missingDelivery.store.get(missingDelivery.session)).toThrow(/anchor binding is corrupt or absent/);
    missingDelivery.database.close();

    const wrongAddress = await openDeliveryFixture();
    paths.push(wrongAddress.path.slice(0, wrongAddress.path.lastIndexOf("/")));
    wrongAddress.store.deliver(deliveryInput(wrongAddress.session));
    wrongAddress.database.query<never, { jobId: string }>(
      "UPDATE fixture_deliveries SET assertion_address = 'dacs2:delivery-assertion:substituted:3' WHERE job_id = $jobId",
    ).run({ jobId: wrongAddress.session.jobId });
    expect(() => wrongAddress.store.get(wrongAddress.session)).toThrow(/anchor binding is corrupt or absent/);
    wrongAddress.database.close();

    const wrongDeclaredHash = await openDeliveryFixture();
    paths.push(wrongDeclaredHash.path.slice(0, wrongDeclaredHash.path.lastIndexOf("/")));
    const fourth = wrongDeclaredHash.store.deliver(deliveryInput(wrongDeclaredHash.session));
    wrongDeclaredHash.database.query<never, { address: string; hash: string }>(
      "UPDATE fixture_anchors SET content_hash = $hash WHERE logical_address = $address",
    ).run({ address: fourth.assertionAddress, hash: "c".repeat(64) });
    expect(() => wrongDeclaredHash.store.get(wrongDeclaredHash.session))
      .toThrow(/anchor binding is corrupt or absent/);
    wrongDeclaredHash.database.close();
  });

  test("preserves immutable anchor conflicts as permanent delivery failures", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const first = fixture.store.deliver(deliveryInput(fixture.session));
    fixture.database.query<never, { jobId: string }>(
      "DELETE FROM fixture_deliveries WHERE job_id = $jobId",
    ).run({ jobId: fixture.session.jobId });
    fixture.database.query<never, { address: string; hash: string }>(
      "UPDATE fixture_anchors SET content_hash = $hash WHERE logical_address = $address",
    ).run({ address: first.deliveryAddress, hash: "b".repeat(64) });
    expect(() => fixture.store.deliver(deliveryInput(fixture.session)))
      .toThrow(FixtureDeliveryConflictError);
    fixture.database.close();
  });
});

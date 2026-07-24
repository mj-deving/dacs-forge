import { describe, expect, test } from "bun:test";
import {
  CREATED_AT,
  fixtureBinding,
  publishFixtureVersion,
  withListingLifecycle,
} from "../fixtures/identity-listing/lifecycle.ts";
import {
  createSignedListingRevocation,
  listingRevocationLogicalAddress,
} from "../../src/directory/listing-lifecycle.ts";
import { fixtureSigner, FIXTURE_NOW_MS, FIXTURE_SIGNING_CONTEXT } from "../fixtures/reference-listing.ts";

const JOB_ID = "01J00000000000000000000000";
const SECOND_JOB_ID = "01J00000000000000000000001";

function admitSession(database: Parameters<Parameters<typeof withListingLifecycle>[0]>[0]["database"], jobId: string): void {
  database.query(`
    INSERT INTO sessions (
      instance_id, audience, job_id, evidence_mode, admission_fingerprint, status, created_at
    ) VALUES ('fixture-instance', 'fixture-audience', $jobId, 'fixture', $fingerprint, 'admitted', $createdAt)
  `).run({ jobId, fingerprint: jobId === JOB_ID ? "a".repeat(64) : "b".repeat(64), createdAt: CREATED_AT });
}

describe("Session Listing pin", () => {
  test("keeps the admitted tuple after discovery advances", async () => {
    await withListingLifecycle(({ database, lifecycle, store }) => {
      const first = publishFixtureVersion(lifecycle, 1);
      admitSession(database, JOB_ID);
      expect(store.pinSession(JOB_ID, first, CREATED_AT)).toEqual(first);
      publishFixtureVersion(lifecycle, 2);
      expect(store.sessionPin(JOB_ID)).toEqual(first);
      expect(() => store.pinSession(JOB_ID, {
        ...first,
        listingVersion: 2,
        contentHash: store.current(first.sellerPrimaryClaim, first.listingId)!.contentHash,
      }, CREATED_AT)).toThrow();
    });
  });

  test("keeps existing pins but atomically rejects new pins after revocation", async () => {
    await withListingLifecycle(({ database, lifecycle, store }) => {
      const listing = publishFixtureVersion(lifecycle, 1);
      admitSession(database, JOB_ID);
      admitSession(database, SECOND_JOB_ID);
      expect(store.pinSession(JOB_ID, listing, CREATED_AT)).toEqual(listing);

      const signer = fixtureSigner();
      const revocation = createSignedListingRevocation({
        listing,
        revokedAt: FIXTURE_NOW_MS + 1,
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
      });
      const logicalAddress = listingRevocationLogicalAddress(
        signer.signer,
        listing.listingId,
        listing.listingVersion,
      );
      const binding = fixtureBinding(revocation.canonicalJson, logicalAddress, "pin-revocation");
      lifecycle.withdraw({
        listing,
        revokedAt: FIXTURE_NOW_MS + 1,
        signer,
        signingContext: FIXTURE_SIGNING_CONTEXT,
        bindingProof: binding.proof,
        bindingAuthority: binding.authority,
        verifiedAt: FIXTURE_NOW_MS + 1,
        createdAt: CREATED_AT,
      });

      expect(store.pinSession(JOB_ID, listing, CREATED_AT)).toEqual(listing);
      expect(store.sessionPin(JOB_ID)).toEqual(listing);
      expect(() => store.pinSession(SECOND_JOB_ID, listing, CREATED_AT)).toThrow(/revoked/i);
      expect(store.sessionPin(SECOND_JOB_ID)).toBeNull();
    });
  });
});

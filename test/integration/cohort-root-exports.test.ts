import { describe, expect, test } from "bun:test";
import {
  DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
  DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
  STORAGE_PROGRAM_INLINE_LIMIT_BYTES,
  prepareDirectorySchemaDriftProbe,
  storageProgramDeliverableAddress,
  verifyListingSelectedDeliveryAttestation,
  verifyStorageProgramCompatibility,
} from "../../src/index.ts";

describe("compatibility cohort root exports", () => {
  test("exposes the joined Directory and Storage Program contracts", () => {
    expect(DIRECTORY_SCHEMA_DRIFT_CHECK_ID).toBe("directory.schema-drift");
    expect(DIRECTORY_LISTING_SUMMARY_SCHEMA_URL).toStartWith("https://");
    expect(STORAGE_PROGRAM_INLINE_LIMIT_BYTES).toBe(128 * 1024);
    expect(typeof prepareDirectorySchemaDriftProbe).toBe("function");
    expect(typeof verifyListingSelectedDeliveryAttestation).toBe("function");
    expect(typeof verifyStorageProgramCompatibility).toBe("function");
    expect(storageProgramDeliverableAddress("01J00000000000000000000000"))
      .toBe("dacs4:deliverable:01J00000000000000000000000");
  });
});

import { describe, expect, test } from "bun:test";
import { isPublicPathAllowed } from "../../scripts/verify-public-export";

describe("public export path policy", () => {
  test("allows only the named public review capsule under evidence", () => {
    expect(isPublicPathAllowed("evidence/reviews/live-demos-profile/index.json")).toBe(true);
    expect(isPublicPathAllowed("evidence/reviews/another-profile/index.json")).toBe(false);
    expect(isPublicPathAllowed("evidence/qualification/report.json")).toBe(false);
  });

  test("keeps private path segments forbidden inside the public capsule", () => {
    expect(isPublicPathAllowed("evidence/reviews/live-demos-profile/Plans/private.md")).toBe(false);
    expect(isPublicPathAllowed(["evidence/reviews/live-demos-profile/.", "beads/state.json"].join(""))).toBe(false);
    expect(isPublicPathAllowed("evidence/reviews/live-demos-profile/evidence/private.json")).toBe(false);
    expect(isPublicPathAllowed("AGENTS.md")).toBe(false);
  });
});

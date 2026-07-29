import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import packageMetadata from "../../package.json";
import profile from "../../release/preview-profile.json";
import provenance from "../../docs/SOURCE-PROVENANCE.json";
import { verifyPreviewProfile } from "../../scripts/verify-preview-profile.ts";
import { verifyPublicExport } from "../../scripts/verify-public-export.ts";

type MutableJsonObject = Record<string, unknown>;

function setNested(root: MutableJsonObject, path: readonly string[], value: unknown): void {
  let cursor = root;
  for (const key of path.slice(0, -1)) {
    const child = cursor[key];
    if (typeof child !== "object" || child === null || Array.isArray(child)) throw new Error(`invalid mutation path: ${path.join(".")}`);
    cursor = child as MutableJsonObject;
  }
  const leaf = path.at(-1);
  if (leaf === undefined) throw new Error("empty mutation path");
  cursor[leaf] = value;
}

function withTrackedFiles(files: Readonly<Record<string, string>>, run: (root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "dacs-forge-public-export-"));
  try {
    expect(spawnSync("git", ["init", "--quiet"], { cwd: root }).status).toBe(0);
    for (const [path, contents] of Object.entries(files)) {
      mkdirSync(resolve(root, path, ".."), { recursive: true });
      writeFileSync(resolve(root, path), contents);
    }
    expect(spawnSync("git", ["add", "."], { cwd: root }).status).toBe(0);
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("final Preview candidate profile", () => {
  test("binds version, tag, released DACS, Community, capability, and rig authority", () => {
    expect(verifyPreviewProfile(profile, packageMetadata, provenance)).toEqual({
      schema: "dacs-forge-preview-profile-verification/v1",
      version: "0.1.0-preview.1",
      tag: "v0.1.0-preview.1",
      dacsCommit: "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
      communityCommit: "634caef4b952838281c8c602402e657d41074703",
    });
  });

  test("rejects version, maturity, pin, capability, rig, and claim substitution", () => {
    for (const [path, value] of [
      [["version"], "0.1.0"],
      [["maturity"], "supported"],
      [["pins", "dacsStandard", "commit"], "0".repeat(40)],
      [["capabilities", "livePayment"], "implemented"],
      [["rig", "commands"], []],
      [["claims", "productSeal"], true],
    ] as const) {
      const changed = structuredClone(profile) as MutableJsonObject;
      setNested(changed, path, value);
      expect(() => verifyPreviewProfile(changed, packageMetadata, provenance)).toThrow();
    }
  });
});

describe("public export boundary", () => {
  test("accepts regular tracked public source files", () => {
    withTrackedFiles({ "README.md": "public source\n", "src/index.ts": "export const value = 1;\n" }, (root) => {
      expect(verifyPublicExport(root)).toMatchObject({
        schema: "dacs-forge-public-export-verification/v1",
        trackedFiles: 2,
      });
    });
  });

  test("rejects private control paths and local workspace references", () => {
    withTrackedFiles({ "AGENTS.md": "private control\n" }, (root) => {
      expect(() => verifyPublicExport(root)).toThrow("forbidden path");
    });
    const localPath = ["/", "home", "/", "mj", "/", "projects", "/", "private"].join("");
    withTrackedFiles({ "README.md": `${localPath}\n` }, (root) => {
      expect(() => verifyPublicExport(root)).toThrow("local-home-path");
    });
  });
});

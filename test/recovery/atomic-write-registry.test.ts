import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { API, SignatureKind, TypeFlags, type Checker, type Type } from "typescript/unstable/async";
import {
  NodeFlags,
  SyntaxKind,
  type CallExpression,
  type ElementAccessExpression,
  type Expression,
  type Identifier,
  type Node,
  type PropertyAccessExpression,
  type SourceFile,
  type TemplateExpression,
  type VariableDeclaration,
} from "typescript/unstable/ast";
import { createScanner } from "typescript/unstable/ast/scanner";
import { ATOMIC_WRITE_SITES } from "../../src/substrate/sqlite/atomic-write-registry.ts";
import { EXPECTED_ATOMIC_WRITE_SITES } from "../fixtures/atomic-write-expectations.ts";
import { ATOMIC_MIGRATION_SCENARIOS } from "../fixtures/atomic-migration-scenarios.ts";
import {
  classifySqliteMutations,
  containsSqliteTransactionControl,
  sqliteAtomicWriteMarkerIds,
} from "../fixtures/sqlite-mutation-classifier.ts";

const ROOT = join(import.meta.dir, "../..");
const MIGRATION_SOURCE = "src/substrate/sqlite/database.ts";
const MIGRATION_WORKER = join(ROOT, "test/workers/atomic-migration-worker.ts");
const CONNECTION_PRAGMAS = new Set([
  "PRAGMA busy_timeout = 5000",
  "PRAGMA foreign_keys = ON",
  "PRAGMA journal_mode = WAL",
  "PRAGMA synchronous = FULL",
]);

describe("atomic write registry", () => {
  test("covers every runtime SQL write exactly once and rejects stale registry entries", async () => {
    const sourceFiles = await sourceTypeScriptFiles(join(ROOT, "src"));
    const runtimeWrites: Array<{ id: string; operation: string; source: string; table: string }> = [];
    const unmarked: Array<{ source: string; statement: string }> = [];
    const migrationWrites: Array<{ source: string; statement: string }> = [];
    const migrationCallSites: MigrationCallSite[] = [];
    const scanFixture = join(ROOT, "test/fixtures/database-call-scan-fixture.ts");
    const widenedParameterFixture = join(ROOT, "test/fixtures/widened-parameter-destructuring-fixture.ts");
    const widenedAssignmentFixture = join(ROOT, "test/fixtures/widened-assignment-destructuring-fixture.ts");
    const widenedComputedFixture = join(ROOT, "test/fixtures/widened-computed-destructuring-fixture.ts");
    const widenedNestedFixture = join(ROOT, "test/fixtures/widened-nested-destructuring-fixture.ts");
    const widenedAnchorFreeFixture = join(ROOT, "test/fixtures/widened-anchor-free-fixture.ts");
    const widenedGenericFixture = join(ROOT, "test/fixtures/widened-generic-fixture.ts");
    const widenedUnresolvedFixture = join(ROOT, "test/fixtures/widened-unresolved-destructuring-fixture.ts");
    const widenedMixedFixture = join(ROOT, "test/fixtures/widened-mixed-destructuring-fixture.ts");
    const widenedRestFixture = join(ROOT, "test/fixtures/widened-rest-destructuring-fixture.ts");
    const widenedNonCallableFixture = join(ROOT, "test/fixtures/widened-non-callable-fixture.ts");
    const widenedPartialCallableFixture = join(ROOT, "test/fixtures/widened-partial-callability-fixture.ts");
    const exactDepletedRestFixture = join(ROOT, "test/fixtures/exact-depleted-rest-fixture.ts");
    const widenedDepletedRestFixture = join(ROOT, "test/fixtures/widened-depleted-rest-fixture.ts");
    const widenedAssignmentRestFixture = join(ROOT, "test/fixtures/widened-assignment-rest-fixture.ts");
    const parenthesizedCallFixture = join(ROOT, "test/fixtures/parenthesized-database-call-fixture.ts");
    const widenedOptionalCallableFixture = join(ROOT, "test/fixtures/widened-optional-callable-fixture.ts");
    const widenedNarrowedCallableFixture = join(ROOT, "test/fixtures/widened-narrowed-callable-fixture.ts");
    const widenedUnknownNarrowedFixture = join(ROOT, "test/fixtures/widened-unknown-narrowed-fixture.ts");
    const transparentAliasCallFixture = join(ROOT, "test/fixtures/transparent-exact-alias-call-fixture.ts");
    const transparentBoundCallFixture = join(ROOT, "test/fixtures/transparent-exact-bound-call-fixture.ts");
    const widenedUnknownDestructuredFixture = join(ROOT, "test/fixtures/widened-unknown-destructured-fixture.ts");
    const widenedComputedUnionNarrowedFixture = join(
      ROOT,
      "test/fixtures/widened-computed-union-narrowed-fixture.ts",
    );
    const widenedUnknownParameterFixture = join(
      ROOT,
      "test/fixtures/widened-unknown-parameter-fixture.ts",
    );
    const widenedUnknownAssignmentFixture = join(
      ROOT,
      "test/fixtures/widened-unknown-assignment-fixture.ts",
    );
    const widenedUnknownComputedAliasFixture = join(
      ROOT,
      "test/fixtures/widened-unknown-computed-alias-fixture.ts",
    );
    const widenedReceiverEscapeFixture = join(ROOT, "test/fixtures/widened-receiver-escape-fixture.ts");
    const zeroSurfaceWideningFixture = join(ROOT, "test/fixtures/zero-surface-database-widening-fixture.ts");
    const widenedIndirectAliasFixture = join(ROOT, "test/fixtures/widened-indirect-alias-fixture.ts");
    const widenedParameterPropertyFixture = join(ROOT, "test/fixtures/widened-parameter-property-fixture.ts");
    const widenedGenericComputedNarrowedFixture = join(
      ROOT,
      "test/fixtures/widened-generic-computed-narrowed-fixture.ts",
    );
    const widenedNonlocalAliasFixture = join(ROOT, "test/fixtures/widened-nonlocal-alias-fixture.ts");
    const widenedComputedIndirectFixture = join(ROOT, "test/fixtures/widened-computed-indirect-fixture.ts");
    const widenedLocalReceiverFixture = join(ROOT, "test/fixtures/widened-local-receiver-fixture.ts");
    const localReceiverAssignmentFixture = join(ROOT, "test/fixtures/local-receiver-assignment-fixture.ts");
    const exactMethodAliasFixture = join(ROOT, "test/fixtures/exact-method-alias-fixture.ts");
    const genericComputedDestructuredFixture = join(
      ROOT,
      "test/fixtures/generic-computed-destructured-fixture.ts",
    );
    const genericComputedIndirectFixture = join(ROOT, "test/fixtures/generic-computed-indirect-fixture.ts");
    const privateExactMethodAliasFixture = join(ROOT, "test/fixtures/private-exact-method-alias-fixture.ts");
    const separateExportDestructuredFixture = join(ROOT, "test/fixtures/separate-export-destructured-fixture.ts");
    const privateNarrowedMethodAliasFixture = join(ROOT, "test/fixtures/private-narrowed-method-alias-fixture.ts");
    const exactComputedDestructuredFixture = join(ROOT, "test/fixtures/exact-computed-destructured-fixture.ts");
    const exactGenericComputedMethodFixture = join(ROOT, "test/fixtures/exact-generic-computed-method-fixture.ts");
    const privateIdentifierNarrowedAliasFixture = join(ROOT, "test/fixtures/private-identifier-narrowed-alias-fixture.ts");
    const conditionalNarrowedAliasFixture = join(ROOT, "test/fixtures/conditional-narrowed-alias-fixture.ts");
    const destructuredDatabaseReceiverFixture = join(ROOT, "test/fixtures/destructured-database-receiver-fixture.ts");
    const migrationScanFixture = join(ROOT, "test/fixtures/migration-call-scan-fixture.ts");
    const setupAliasFixture = join(ROOT, "test/fixtures/setup-alias/src/substrate/sqlite/database.ts");
    const setupShadowFixture = join(ROOT, "test/fixtures/setup-shadow/src/substrate/sqlite/database.ts");
    const api = new API();
    const snapshot = await api.updateSnapshot({
      openFiles: [
        ...sourceFiles,
        scanFixture,
        widenedParameterFixture,
        widenedAssignmentFixture,
        widenedComputedFixture,
        widenedNestedFixture,
        widenedAnchorFreeFixture,
        widenedGenericFixture,
        widenedUnresolvedFixture,
        widenedMixedFixture,
        widenedRestFixture,
        widenedNonCallableFixture,
        widenedPartialCallableFixture,
        exactDepletedRestFixture,
        widenedDepletedRestFixture,
        widenedAssignmentRestFixture,
        parenthesizedCallFixture,
        widenedOptionalCallableFixture,
        widenedNarrowedCallableFixture,
        widenedUnknownNarrowedFixture,
        transparentAliasCallFixture,
        transparentBoundCallFixture,
        widenedUnknownDestructuredFixture,
        widenedComputedUnionNarrowedFixture,
        widenedUnknownParameterFixture,
        widenedUnknownAssignmentFixture,
        widenedUnknownComputedAliasFixture,
        widenedReceiverEscapeFixture,
        widenedIndirectAliasFixture,
        widenedParameterPropertyFixture,
        widenedGenericComputedNarrowedFixture,
        widenedNonlocalAliasFixture,
        widenedComputedIndirectFixture,
        widenedLocalReceiverFixture,
        localReceiverAssignmentFixture,
        exactMethodAliasFixture,
        genericComputedDestructuredFixture,
        genericComputedIndirectFixture,
        privateExactMethodAliasFixture,
        separateExportDestructuredFixture,
        privateNarrowedMethodAliasFixture,
        exactComputedDestructuredFixture,
        exactGenericComputedMethodFixture,
        privateIdentifierNarrowedAliasFixture,
        conditionalNarrowedAliasFixture,
        destructuredDatabaseReceiverFixture,
        migrationScanFixture,
        setupAliasFixture,
        setupShadowFixture,
      ],
    });
    try {
      const fixtureProject = await snapshot.getDefaultProjectForFile(scanFixture);
      if (fixtureProject === undefined) throw new Error("TypeScript project unavailable for database call fixture");
      const fixtureSourceFile = await fixtureProject.program.getSourceFile(scanFixture);
      if (fixtureSourceFile === undefined) throw new Error("TypeScript source unavailable for database call fixture");
      const canonicalDatabaseType = await requireDatabaseType(fixtureProject.checker, fixtureSourceFile);
      const scannedSources = await Promise.all(sourceFiles.map(async (absolutePath) => {
        const source = relative(ROOT, absolutePath);
        const text = await readFile(absolutePath, "utf8");
        const sourceFile = await fixtureProject.program.getSourceFile(absolutePath);
        if (sourceFile === undefined) throw new Error(`TypeScript source unavailable for ${source}`);
        const typedCalls = await findTypedDatabaseCalls(
          fixtureProject.checker,
          sourceFile,
          canonicalDatabaseType,
        );
        const discovered = discoverSqlWrites(source, text, typedCalls.calls);
        return { discovered, source, sourceFile, typedCalls };
      }));
      for (const { discovered, source, sourceFile, typedCalls } of scannedSources) {
        runtimeWrites.push(...discovered.runtimeWrites);
        unmarked.push(...discovered.unmarked);
        unmarked.push(...typedCalls.escapedMethods.map((method) => ({
          source,
          statement: `ESCAPED DATABASE METHOD ${method.toUpperCase()}`,
        })));
        migrationWrites.push(...discovered.migrationWrites);
        migrationCallSites.push(...discovered.migrationCallSites);
        for (const site of ATOMIC_WRITE_SITES.filter((candidate) => candidate.source === source)) {
          const expected = EXPECTED_ATOMIC_WRITE_SITES[site.id];
          if (expected === undefined) throw new Error(`Missing owner evidence for ${site.id}`);
          for (const ownerFrame of expected.ownerFrames) {
            expect(resolveOwnerScope(sourceFile, ownerFrame), site.id).toBe(expected.owner);
          }
        }
      }
      const fixtureCalls = await findTypedDatabaseCalls(
        fixtureProject.checker,
        fixtureSourceFile,
        canonicalDatabaseType,
      );
      expect(fixtureCalls.calls.map(({ computed, method }) => ({ computed, method }))).toEqual([
        { computed: false, method: "run" },
        { computed: true, method: "run" },
        { computed: true, method: "run" },
        { computed: false, method: "run" },
      ]);
      expect(Object.fromEntries([...new Set(fixtureCalls.escapedMethods)].sort().map((method) => [
        method,
        fixtureCalls.escapedMethods.filter((candidate) => candidate === method).length,
      ]))).toEqual({ exec: 30, prepare: 30, query: 32, run: 62 });
      const isolatedFixtureScans = new Map<string, ReturnType<typeof findTypedDatabaseCalls>>();
      const scanIsolatedFixture = (fixture: string, label: string) => {
        let scan = isolatedFixtureScans.get(fixture);
        if (scan === undefined) {
          scan = (async () => {
            const sourceFile = await fixtureProject.program.getSourceFile(fixture);
            if (sourceFile === undefined) throw new Error(`TypeScript source unavailable for ${label}`);
            return findTypedDatabaseCalls(
              fixtureProject.checker,
              sourceFile,
              canonicalDatabaseType,
            );
          })();
          isolatedFixtureScans.set(fixture, scan);
        }
        return scan;
      };
      await Promise.all([
        widenedParameterFixture,
        widenedAssignmentFixture,
        widenedComputedFixture,
        widenedNestedFixture,
        widenedAnchorFreeFixture,
        widenedGenericFixture,
        widenedUnresolvedFixture,
        widenedMixedFixture,
        widenedRestFixture,
        widenedNonCallableFixture,
        widenedPartialCallableFixture,
        exactDepletedRestFixture,
        widenedDepletedRestFixture,
        widenedAssignmentRestFixture,
        parenthesizedCallFixture,
        widenedOptionalCallableFixture,
        widenedNarrowedCallableFixture,
        widenedUnknownNarrowedFixture,
        transparentAliasCallFixture,
        transparentBoundCallFixture,
        widenedUnknownDestructuredFixture,
        widenedComputedUnionNarrowedFixture,
        widenedUnknownParameterFixture,
        widenedUnknownAssignmentFixture,
        widenedUnknownComputedAliasFixture,
        widenedReceiverEscapeFixture,
        widenedIndirectAliasFixture,
        widenedParameterPropertyFixture,
        widenedGenericComputedNarrowedFixture,
        widenedNonlocalAliasFixture,
        widenedComputedIndirectFixture,
        widenedLocalReceiverFixture,
        localReceiverAssignmentFixture,
        exactMethodAliasFixture,
        genericComputedDestructuredFixture,
        genericComputedIndirectFixture,
        privateExactMethodAliasFixture,
        separateExportDestructuredFixture,
        privateNarrowedMethodAliasFixture,
        exactComputedDestructuredFixture,
        exactGenericComputedMethodFixture,
        privateIdentifierNarrowedAliasFixture,
        conditionalNarrowedAliasFixture,
        destructuredDatabaseReceiverFixture,
      ].map((fixture) => scanIsolatedFixture(fixture, relative(ROOT, fixture))));
      for (const [fixture, label] of [
        [widenedParameterFixture, "widened parameter destructuring"],
        [widenedAssignmentFixture, "widened assignment destructuring"],
        [widenedComputedFixture, "widened computed destructuring"],
        [widenedNestedFixture, "widened nested destructuring"],
        [widenedAnchorFreeFixture, "anchor-free widened receiver"],
        [widenedGenericFixture, "generic widened receiver"],
        [widenedUnresolvedFixture, "widened unresolved destructuring"],
        [widenedMixedFixture, "widened mixed destructuring"],
        [widenedRestFixture, "widened rest destructuring"],
      ] as const) {
        const result = await scanIsolatedFixture(fixture, label);
        expect(result.calls, label).toEqual([]);
        expect(result.escapedMethods, label).toEqual(["run"]);
      }
      for (const [fixture, label] of [
        [widenedNonCallableFixture, "non-callable execution-shaped property"],
        [widenedPartialCallableFixture, "selected non-callable execution-shaped property"],
      ] as const) {
        const result = await scanIsolatedFixture(fixture, label);
        expect(result.calls, label).toEqual([]);
        expect(result.escapedMethods, label).toEqual([]);
      }
      const exactDepletedRest = await scanIsolatedFixture(exactDepletedRestFixture, "exact depleted rest");
      expect(exactDepletedRest.calls, "exact depleted rest").toEqual([]);
      expect([...exactDepletedRest.escapedMethods].sort(), "exact depleted rest").toEqual([
        "exec", "prepare", "query", "run",
      ]);
      for (const [fixture, label] of [
        [widenedDepletedRestFixture, "widened depleted rest"],
        [widenedAssignmentRestFixture, "widened assignment depleted rest"],
      ] as const) {
        const result = await scanIsolatedFixture(fixture, label);
        expect(result.calls, label).toEqual([]);
        expect(result.escapedMethods, label).toEqual(["run"]);
      }
      const parenthesizedCall = await scanIsolatedFixture(parenthesizedCallFixture, "parenthesized exact call");
      expect(parenthesizedCall.calls.map(({ computed, method }) => ({ computed, method }))).toEqual([
        { computed: false, method: "run" },
      ]);
      expect(parenthesizedCall.escapedMethods, "parenthesized exact call").toEqual([]);
      const optionalCallable = await scanIsolatedFixture(
        widenedOptionalCallableFixture,
        "optional widened execution method",
      );
      expect(optionalCallable.calls, "optional widened execution method").toEqual([]);
      expect(optionalCallable.escapedMethods, "optional widened execution method").toEqual(["run"]);
      const narrowedCallable = await scanIsolatedFixture(
        widenedNarrowedCallableFixture,
        "narrowed widened execution method",
      );
      expect(narrowedCallable.calls, "narrowed widened execution method").toEqual([]);
      expect(narrowedCallable.escapedMethods, "narrowed widened execution method").toEqual(["run", "run"]);
      const unknownNarrowed = await scanIsolatedFixture(
        widenedUnknownNarrowedFixture,
        "unknown narrowed execution method",
      );
      expect(unknownNarrowed.calls, "unknown narrowed execution method").toEqual([]);
      expect(unknownNarrowed.escapedMethods, "unknown narrowed execution method").toEqual(["run"]);
      const transparentAliasCall = await scanIsolatedFixture(
        transparentAliasCallFixture,
        "transparent exact alias calls",
      );
      expect(transparentAliasCall.calls.map(({ computed, method }) => ({ computed, method }))).toEqual([
        { computed: false, method: "run" },
      ]);
      expect(transparentAliasCall.escapedMethods, "transparent exact alias calls").toEqual([]);
      const transparentBoundCall = await scanIsolatedFixture(
        transparentBoundCallFixture,
        "transparent exact bound call",
      );
      expect(transparentBoundCall.calls.map(({ computed, method }) => ({ computed, method }))).toEqual([
        { computed: false, method: "run" },
      ]);
      expect(transparentBoundCall.escapedMethods, "transparent exact bound call").toEqual([]);
      const unknownDestructured = await scanIsolatedFixture(
        widenedUnknownDestructuredFixture,
        "unknown destructured narrowed call",
      );
      expect(unknownDestructured.calls, "unknown destructured narrowed call").toEqual([]);
      expect(unknownDestructured.escapedMethods, "unknown destructured narrowed call").toEqual(["run"]);
      const computedUnionNarrowed = await scanIsolatedFixture(
        widenedComputedUnionNarrowedFixture,
        "computed union narrowed call",
      );
      expect(computedUnionNarrowed.calls, "computed union narrowed call").toEqual([]);
      expect(computedUnionNarrowed.escapedMethods, "computed union narrowed call").toEqual(["exec", "run"]);
      for (const [fixture, label, expected] of [
        [widenedUnknownParameterFixture, "unknown parameter alias narrowed call", ["run"]],
        [widenedUnknownAssignmentFixture, "unknown assignment alias narrowed call", ["run"]],
        [widenedUnknownComputedAliasFixture, "unknown computed alias narrowed call", ["exec", "run"]],
        [widenedReceiverEscapeFixture, "widened receiver external escape", ["run"]],
        [zeroSurfaceWideningFixture, "zero-surface Database widening", ["exec", "prepare", "query", "run"]],
        [widenedIndirectAliasFixture, "widened indirect alias calls", ["run", "run", "run", "run"]],
        [widenedParameterPropertyFixture, "widened public parameter property", ["run"]],
        [widenedGenericComputedNarrowedFixture, "generic computed narrowed call", ["run"]],
        [widenedNonlocalAliasFixture, "non-local narrowed alias escape", ["run"]],
        [widenedComputedIndirectFixture, "computed indirect narrowed calls", ["run", "run", "run"]],
        [widenedLocalReceiverFixture, "proven-local widened receiver", []],
        [localReceiverAssignmentFixture, "local assignment and private field", []],
        [genericComputedDestructuredFixture, "generic computed destructured narrowed call", ["run"]],
        [genericComputedIndirectFixture, "generic computed indirect narrowed call", ["run"]],
        [privateExactMethodAliasFixture, "private exact method alias", []],
        [separateExportDestructuredFixture, "separately exported destructured method", ["run"]],
        [privateNarrowedMethodAliasFixture, "private narrowed method alias", []],
        [privateIdentifierNarrowedAliasFixture, "private-identifier narrowed alias", ["run"]],
        [conditionalNarrowedAliasFixture, "conditional narrowed alias", ["run"]],
        [destructuredDatabaseReceiverFixture, "destructured Database receiver transfer", ["exec", "prepare", "query", "run"]],
      ] as const) {
        const result = await scanIsolatedFixture(fixture, label);
        expect(result.calls, label).toEqual([]);
        expect(result.escapedMethods, label).toEqual([...expected]);
      }
      const exactMethodAliases = await scanIsolatedFixture(exactMethodAliasFixture, "exact method alias chains");
      expect(exactMethodAliases.calls.map(({ method }) => method), "exact method alias chains").toEqual([
        "run", "run",
      ]);
      expect(exactMethodAliases.escapedMethods, "exact method alias chains").toEqual([]);
      const exactComputedDestructured = await scanIsolatedFixture(
        exactComputedDestructuredFixture,
        "exact computed destructuring",
      );
      expect(exactComputedDestructured.calls.map(({ method }) => method), "exact computed destructuring").toEqual([
        "prepare", "prepare",
      ]);
      expect(exactComputedDestructured.escapedMethods, "exact computed destructuring").toEqual([]);
      const exactGenericComputedMethod = await scanIsolatedFixture(
        exactGenericComputedMethodFixture,
        "exact generic computed method",
      );
      expect(exactGenericComputedMethod.calls.map(({ method }) => method), "exact generic computed method").toEqual([
        "prepare",
      ]);
      expect(exactGenericComputedMethod.escapedMethods, "exact generic computed method").toEqual([]);

      const migrationFixtureSource = await fixtureProject.program.getSourceFile(migrationScanFixture);
      if (migrationFixtureSource === undefined) throw new Error("TypeScript source unavailable for migration fixture");
      const migrationFixtureText = await readFile(migrationScanFixture, "utf8");
      const migrationFixtureCalls = await findTypedDatabaseCalls(
        fixtureProject.checker,
        migrationFixtureSource,
        canonicalDatabaseType,
        true,
      );
      const migrationFixtureWrites = discoverSqlWrites(
        MIGRATION_SOURCE,
        migrationFixtureText,
        migrationFixtureCalls.calls,
      );
      expect(migrationFixtureWrites.migrationWrites).toEqual([
        { source: MIGRATION_SOURCE, statement: "CREATE <UNKNOWN>" },
      ]);
      expect(migrationFixtureWrites.unmarked).toEqual([
        { source: MIGRATION_SOURCE, statement: "MIGRATION WRITE OUTSIDE EXCLUSIVE CALLBACK" },
        { source: MIGRATION_SOURCE, statement: "MIGRATION WRITE OUTSIDE EXCLUSIVE CALLBACK" },
        { source: MIGRATION_SOURCE, statement: "MIGRATION WRITE OUTSIDE EXCLUSIVE CALLBACK" },
      ]);

      const setupAliasSource = await fixtureProject.program.getSourceFile(setupAliasFixture);
      if (setupAliasSource === undefined) throw new Error("TypeScript source unavailable for setup alias fixture");
      const setupAliasText = await readFile(setupAliasFixture, "utf8");
      const setupAliasCalls = await findTypedDatabaseCalls(fixtureProject.checker, setupAliasSource, undefined, false);
      expect(discoverSqlWrites(MIGRATION_SOURCE, setupAliasText, setupAliasCalls.calls).unmarked).toEqual([
        { source: MIGRATION_SOURCE, statement: "PRAGMA <UNKNOWN>" },
      ]);

      const setupShadowSource = await fixtureProject.program.getSourceFile(setupShadowFixture);
      if (setupShadowSource === undefined) throw new Error("TypeScript source unavailable for setup shadow fixture");
      const setupShadowText = await readFile(setupShadowFixture, "utf8");
      const setupShadowCalls = await findTypedDatabaseCalls(fixtureProject.checker, setupShadowSource, undefined, false);
      expect(discoverSqlWrites(MIGRATION_SOURCE, setupShadowText, setupShadowCalls.calls).unmarked).toEqual([
        { source: MIGRATION_SOURCE, statement: "PRAGMA <UNKNOWN>" },
      ]);
    } finally {
      await snapshot.dispose();
      await api.close();
    }

    expect(unmarked).toEqual([]);
    expect(migrationWrites.length).toBeGreaterThan(0);
    expect(new Set(migrationCallSites.map(({ api }) => api))).toEqual(new Set(["run"]));
    const observedMigrationSql = (await Promise.all(
      ATOMIC_MIGRATION_SCENARIOS.map(({ id }) => observeMigrationSql(id)),
    )).flat();
    expect(reconcileMigrationCallSites(migrationCallSites, observedMigrationSql)).toEqual({
      unmatchedExpected: [],
      unmatchedObserved: [],
    });
    expect(new Set(runtimeWrites.map(({ id }) => id)).size).toBe(runtimeWrites.length);
    expect(new Set(ATOMIC_WRITE_SITES.map(({ id }) => id)).size).toBe(ATOMIC_WRITE_SITES.length);
    expect(runtimeWrites.sort(byId)).toEqual(
      ATOMIC_WRITE_SITES.map(({ id, operation, source, table }) => ({ id, operation, source, table })).sort(byId),
    );
    const expectedMetadata = Object.fromEntries(Object.entries(EXPECTED_ATOMIC_WRITE_SITES)
      .map(([id, { boundary, owner, transactionMode }]) => [id, { boundary, owner, transactionMode }]));
    expect(Object.fromEntries(ATOMIC_WRITE_SITES.map(({ boundary, id, owner, transactionMode }) => [
      id, { boundary, owner, transactionMode },
    ]))).toEqual(expectedMetadata);
    expect(ATOMIC_WRITE_SITES.every(({ owner }) => /^[A-Z][A-Za-z0-9]*\.#?[A-Za-z][A-Za-z0-9]*$/.test(owner))).toBe(true);
  }, 60_000);

  test("classifies conflict, replacement, and CTE-led SQLite mutations", () => {
    const cases = [
      "INSERT OR REPLACE INTO alpha VALUES (1)",
      "REPLACE INTO beta VALUES (1)",
      "WITH source AS (SELECT 1) UPDATE gamma SET value = 1",
      "WITH source AS (SELECT 1) INSERT INTO delta SELECT * FROM source",
      "WITH source AS (SELECT 1) DELETE FROM epsilon WHERE value = 1",
    ];
    expect(cases.map((sql) => classifySqliteMutations(sql).at(-1)?.table)).toEqual([
      "alpha", "beta", "gamma", "delta", "epsilon",
    ]);
    expect(classifySqliteMutations("WITH source AS (SELECT 1) UPDATE gamma SET value = 1")).toEqual([
      { keyword: "UPDATE", operation: "update", table: "gamma" },
    ]);
    expect(classifySqliteMutations("ANALYZE; PRAGMA application_id = 1")).toEqual([
      { keyword: "ANALYZE", operation: "schema" },
      { keyword: "PRAGMA", operation: "schema" },
    ]);
    expect(classifySqliteMutations("PRAGMA main.optimize; PRAGMA temp.incremental_vacuum(1)")).toEqual([
      { keyword: "PRAGMA", operation: "schema" },
      { keyword: "PRAGMA", operation: "schema" },
    ]);
    expect(classifySqliteMutations("PRAGMA main.application_id = 1")).toEqual([
      { keyword: "PRAGMA", operation: "schema" },
    ]);
    expect(classifySqliteMutations("PRAGMA main.default_cache_size(2000)")).toEqual([
      { keyword: "PRAGMA", operation: "schema" },
    ]);
    expect(classifySqliteMutations("PRAGMA main.table_info(example)")).toEqual([]);
    expect(classifySqliteMutations("EXPLAIN UPDATE example SET value = 1")).toEqual([]);
    expect(classifySqliteMutations("EXPLAIN QUERY PLAN DELETE FROM example")).toEqual([]);
    for (const malformed of [
      "SELECT 'unterminated; SAVEPOINT hidden",
      "UPDATE [unterminated SET value = 1",
      "DELETE FROM `unterminated",
    ]) {
      expect(() => classifySqliteMutations(malformed)).toThrow("Unterminated SQLite quoted region");
      expect(() => containsSqliteTransactionControl(malformed)).toThrow("Unterminated SQLite quoted region");
    }
  });

  test("rejects every unresolved direct runtime SQL expression", () => {
    const snippets = [
      'database.run("INSERT INTO alpha VALUES (1)" + suffix);',
      "database.run(`INSERT INTO alpha VALUES (${value})`);",
      "database.run(sql);",
      'database.run("\\\\x55PDATE alpha SET value = 1");',
    ];
    for (const snippet of snippets) {
      expect(discoverSqlWrites(
        "src/runtime/unresolved.ts",
        snippet,
        findConventionDatabaseCalls(snippet),
      ).unmarked).toEqual([
        { source: "src/runtime/unresolved.ts", statement: "UNRESOLVED DATABASE SQL ARGUMENT" },
      ]);
    }
    expect(discoverSqlWrites(
      "src/runtime/multiple.ts",
      'database.exec("INSERT INTO alpha VALUES (1); UPDATE alpha SET value = 2");',
      findConventionDatabaseCalls('database.exec("INSERT INTO alpha VALUES (1); UPDATE alpha SET value = 2");'),
    ).unmarked).toEqual([
      { source: "src/runtime/multiple.ts", statement: "MULTI-MUTATION DATABASE SQL ARGUMENT" },
    ]);
    for (const sql of [
      "BEGIN IMMEDIATE",
      "SAVEPOINT nested",
      "ROLLBACK TO nested",
      "RELEASE nested",
      "COMMIT",
      "SELECT 1; /* hidden */ SAVEPOINT nested",
      "SELECT '('; SAVEPOINT hidden",
      "SELECT '; SAVEPOINT quoted'; SAVEPOINT hidden",
    ]) {
      const snippet = `database.exec(${JSON.stringify(sql)});`;
      expect(discoverSqlWrites(
        "src/runtime/transaction-control.ts",
        snippet,
        findConventionDatabaseCalls(snippet),
      ).unmarked).toEqual([
        { source: "src/runtime/transaction-control.ts", statement: "SQL TRANSACTION CONTROL" },
      ]);
    }
    const trigger = `CREATE TRIGGER fixture_trigger BEFORE UPDATE ON fixture BEGIN
      INSERT INTO fixture_log(value) VALUES ('CASE');
      UPDATE fixture_log SET value = 'END';
    END`;
    expect(classifySqliteMutations(trigger)).toEqual([
      { keyword: "CREATE", operation: "schema" },
    ]);
    expect(containsSqliteTransactionControl(trigger)).toBe(false);
    expect(containsSqliteTransactionControl(`${trigger}; SAVEPOINT hidden`)).toBe(true);
    expect(classifySqliteMutations("SELECT '('; UPDATE alpha SET value = 1")).toEqual([
      { keyword: "UPDATE", operation: "update", table: "alpha" },
    ]);
    expect(classifySqliteMutations("SELECT ')'; DELETE FROM alpha")).toEqual([
      { keyword: "DELETE", operation: "delete", table: "alpha" },
    ]);
    expect(classifySqliteMutations(`
      INSERT INTO main.alpha VALUES (1);
      UPDATE "main"."beta" SET value = 1;
      DELETE FROM temp.[gamma]
    `)).toEqual([
      { keyword: "INSERT", operation: "insert", table: "alpha" },
      { keyword: "UPDATE", operation: "update", table: "beta" },
      { keyword: "DELETE", operation: "delete", table: "gamma" },
    ]);
    expect(classifySqliteMutations(`
      UPDATE "order-items" SET value = 1;
      INSERT INTO [123 things] VALUES (1);
      DELETE FROM ` + "`punctuated.table`" + `
    `)).toEqual([
      { keyword: "UPDATE", operation: "update", table: "order-items" },
      { keyword: "INSERT", operation: "insert", table: "123 things" },
      { keyword: "DELETE", operation: "delete", table: "punctuated.table" },
    ]);
    const quotedMarkerSql = `/* atomic-write: real-site */
      UPDATE alpha
      SET value = '/* atomic-write: quoted-value */',
          "/* atomic-write: quoted-identifier */" = 1`;
    expect(sqliteAtomicWriteMarkerIds(quotedMarkerSql)).toEqual(["real-site"]);
    const unresolvedMigration = "function migrateDynamic(database: Database, sql: string) { database.run(sql); }";
    expect(discoverSqlWrites(
      MIGRATION_SOURCE,
      unresolvedMigration,
      findConventionDatabaseCalls(unresolvedMigration),
    ).unmarked).toEqual([
      { source: MIGRATION_SOURCE, statement: "UNRESOLVED DATABASE SQL ARGUMENT" },
    ]);
  });

  test("ignores convention-like calls in lexical non-code regions", () => {
    for (const snippet of [
      '// database.run("DELETE FROM records")',
      '/* database.exec("DROP TABLE records") */',
      'const note = "database.run(\\"DELETE FROM records\\")";',
      "const note = 'database.query(\\\"DELETE FROM records\\\")';",
      "const note = `database.prepare(\"DELETE FROM records\")`;",
      "const pattern = /database.run(\\\"DELETE FROM records\\\")/;",
      "throw /database.run(\\\"DELETE FROM records\\\")/;",
      "if (ok) /database.run(\\\"DELETE FROM records\\\")/.test(text);",
      "if (ok) {} /database.run(\\\"DELETE FROM records\\\")/.test(text);",
      "try {} finally {} /database.run(\\\"DELETE FROM records\\\")/.test(text);",
      "{} /database.run(\\\"DELETE FROM records\\\")/.test(text);",
      "function declared() {} /database.run(\\\"DELETE FROM records\\\")/.test(text);",
      "class Declared {} /database.run(\\\"DELETE FROM records\\\")/.test(text);",
    ]) expect(findConventionDatabaseCalls(snippet)).toEqual([]);
    expect(findConventionDatabaseCalls(
      'const value = {}; value / database.run("DELETE FROM records");',
    ).map(({ method }) => method)).toEqual(["run"]);
    const templateExpression = 'const note = `ignored database.run("DELETE") ${database.run(sql)} tail database.exec("DROP")`;';
    expect(findConventionDatabaseCalls(templateExpression).map(({ method }) => method)).toEqual(["run"]);
  });

  test("keeps schema writes inside the exclusive migration owner", async () => {
    expect(findFunctionBodies("function migrate(database: unknown) { const pattern = /function migrateFake(foo) \\}/; }", /^migrate$/))
      .toHaveLength(1);
    expect(findFunctionBodies("function declared() {} /function migrateFake(foo) \\}/; function migrate(database: unknown) {}", /^migrate$/))
      .toHaveLength(1);
    const text = await readFile(join(ROOT, MIGRATION_SOURCE), "utf8");
    expect(text).toContain("function migrate(database: Database): void");
    expect(text).toContain("const apply = database.transaction(() => {");
    expect(text).toContain("apply.exclusive();");
    expect(text).not.toContain("atomic-write:");
    for (const pragma of CONNECTION_PRAGMAS) {
      expect(text.split(pragma)).toHaveLength(2);
    }
    expect(text.indexOf("PRAGMA busy_timeout = 5000")).toBeLessThan(text.indexOf("migrate(database);"));
    expect(text.indexOf("PRAGMA foreign_keys = ON")).toBeLessThan(text.indexOf("migrate(database);"));
    expect(text.indexOf("migrate(database);")).toBeLessThan(text.indexOf("enableWal(database);"));
    expect(text.indexOf("enableWal(database);")).toBeLessThan(text.indexOf("PRAGMA synchronous = FULL"));
  });

  test("matches migration observations one-to-one", () => {
    const site = { api: "run" as const, startLine: 10, endLine: 12, sqlHash: "a" };
    const observation = { api: "run", callSiteLine: 11, index: 0, scenario: "fresh", sqlHash: "a" };
    expect(reconcileMigrationCallSites([site, site], [observation])).toEqual({
      unmatchedExpected: [site],
      unmatchedObserved: [],
    });
    expect(reconcileMigrationCallSites([site], [observation, observation])).toEqual({
      unmatchedExpected: [],
      unmatchedObserved: [observation],
    });
    const repeatedAtNextIndex = { ...observation, index: 1 };
    expect(reconcileMigrationCallSites([site], [observation, repeatedAtNextIndex])).toEqual({
      unmatchedExpected: [],
      unmatchedObserved: [repeatedAtNextIndex],
    });
    expect(reconcileMigrationCallSites([site], [
      observation,
      { ...observation, scenario: "v8-current" },
    ])).toEqual({
      unmatchedExpected: [],
      unmatchedObserved: [],
    });
    const unexpected = { api: "run", callSiteLine: 20, index: 1, scenario: "fresh", sqlHash: "b" };
    expect(reconcileMigrationCallSites([site], [observation, unexpected])).toEqual({
      unmatchedExpected: [],
      unmatchedObserved: [unexpected],
    });
    const wrongApi = { ...observation, api: "exec" };
    expect(reconcileMigrationCallSites([site], [wrongApi])).toEqual({
      unmatchedExpected: [site],
      unmatchedObserved: [wrongApi],
    });
    const wrongIndex = { ...observation, index: 1 };
    expect(reconcileMigrationCallSites([site], [wrongIndex])).toEqual({
      unmatchedExpected: [site],
      unmatchedObserved: [wrongIndex],
    });
  });

  test("bounds registry child termination after SIGKILL", async () => {
    let killed = false;
    const closed = () => new ReadableStream<Uint8Array>({ start(controller) { controller.close(); } });
    await expect(collectRegistryChild({
      exited: new Promise<number>(() => undefined),
      pid: 42,
      stderr: closed(),
      stdout: closed(),
      kill() { killed = true; },
    }, "stuck registry child", 1, 1)).rejects.toThrow("did not terminate within 1ms; leaked pid=42");
    expect(killed).toBe(true);
  });
});

interface DatabaseCall {
  readonly approvedConnectionSetup: boolean;
  readonly argumentStart: number;
  readonly computed: boolean;
  readonly end: number;
  readonly hasStaticArgument: boolean;
  readonly method: "exec" | "prepare" | "query" | "run";
  readonly migrationOwned: boolean;
  readonly staticSql: string | undefined;
  readonly start: number;
}

interface MigrationCallSite {
  readonly api: DatabaseCall["method"];
  readonly endLine: number;
  readonly sqlHash: string;
  readonly startLine: number;
}

interface MigrationObservation {
  readonly api: string;
  readonly callSiteLine: number;
  readonly index: number;
  readonly scenario: string;
  readonly sqlHash: string;
}

interface DatabaseMethodReference {
  readonly failClosed: boolean;
  readonly methods: readonly DatabaseCall["method"][];
}

function discoverSqlWrites(source: string, text: string, calls: readonly DatabaseCall[]): {
  readonly migrationCallSites: MigrationCallSite[];
  readonly migrationWrites: Array<{ source: string; statement: string }>;
  readonly runtimeWrites: Array<{ id: string; operation: string; source: string; table: string }>;
  readonly unmarked: Array<{ source: string; statement: string }>;
} {
  const migrationWrites: Array<{ source: string; statement: string }> = [];
  const migrationCallSites: MigrationCallSite[] = [];
  const runtimeWrites: Array<{ id: string; operation: string; source: string; table: string }> = [];
  const unmarked: Array<{ source: string; statement: string }> = [];
  const migrationRanges = source === MIGRATION_SOURCE ? findFunctionBodies(text, /^migrate(?:[A-Z][A-Za-z0-9]*)?$/) : [];
  for (const call of calls) {
    const inMigrationNamespace = migrationRanges.some((range) => call.start > range.start && call.start < range.end);
    if (!call.hasStaticArgument) {
      unmarked.push({ source, statement: "UNRESOLVED DATABASE SQL ARGUMENT" });
      continue;
    }
    const sql = call.staticSql ?? readStaticSqlArgument(text, call.argumentStart);
    if (sql === undefined) throw new Error(`Static SQL argument disappeared at byte ${call.argumentStart}`);
    if (containsSqliteTransactionControl(sql)) {
      unmarked.push({ source, statement: "SQL TRANSACTION CONTROL" });
      continue;
    }
    const markers = sqliteAtomicWriteMarkerIds(sql);
    const writes = classifySqliteMutations(sql);
    if (writes.length === 0) {
      continue;
    }
    if (writes.length > 1) {
      unmarked.push({ source, statement: "MULTI-MUTATION DATABASE SQL ARGUMENT" });
      continue;
    }
    if (call.approvedConnectionSetup && CONNECTION_PRAGMAS.has(sql.trim())) continue;
    for (const write of writes) {
      const statement = `${write.keyword} ${write.table ?? "<unknown>"}`.toUpperCase();
      if (call.migrationOwned) {
        migrationWrites.push({ source, statement });
        migrationCallSites.push({
          api: call.method,
          endLine: sourceLine(text, call.end),
          sqlHash: sqlHash(sql),
          startLine: sourceLine(text, call.start),
        });
      }
      else if (inMigrationNamespace) {
        unmarked.push({ source, statement: "MIGRATION WRITE OUTSIDE EXCLUSIVE CALLBACK" });
      }
      else if (markers.length !== 1 || writes.length !== 1 || write.table === undefined
        || write.operation === "schema") unmarked.push({ source, statement });
      else runtimeWrites.push({
        id: markers[0]!,
        operation: write.operation,
        source,
        table: write.table,
      });
    }
  }
  return { migrationCallSites, migrationWrites, runtimeWrites, unmarked };
}

async function observeMigrationSql(
  scenario: (typeof ATOMIC_MIGRATION_SCENARIOS)[number]["id"],
): Promise<MigrationObservation[]> {
  const root = await mkdtemp(join(tmpdir(), `dacs-registry-migration-${scenario}-`));
  try {
    const path = join(root, "state.sqlite");
    const child = Bun.spawn([process.execPath, "run", MIGRATION_WORKER, path], {
      cwd: ROOT,
      env: {
        ...process.env,
        DACS_MIGRATION_MODE: "observe",
        ...(scenario === "fresh" ? {} : { DACS_MIGRATION_SETUP_SCENARIO: scenario }),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const { exitCode, stdout, stderr } = await collectRegistryChild(
      child,
      `migration observer ${scenario}`,
      20_000,
    );
    if (exitCode !== 0) throw new Error(`Migration observer failed (${exitCode}): ${stderr}`);
    return stdout.trim().split("\n").flatMap((line) => {
      if (!line.startsWith('{"kind":"migration-observed"')) return [];
      const event = JSON.parse(line) as {
        readonly api: string;
        readonly callSiteLine: number;
        readonly index: number;
        readonly phase: string;
        readonly sqlHash: string;
      };
      return event.phase === "before"
        ? [{ api: event.api, callSiteLine: event.callSiteLine, index: event.index, scenario, sqlHash: event.sqlHash }]
        : [];
    });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

function reconcileMigrationCallSites(
  expected: readonly MigrationCallSite[],
  observed: readonly MigrationObservation[],
): {
  readonly unmatchedExpected: MigrationCallSite[];
  readonly unmatchedObserved: MigrationObservation[];
} {
  const unmatchedExpected: MigrationCallSite[] = [];
  const unmatchedObserved: MigrationObservation[] = [];
  const scenarioKeys = new Set<string>();
  const scenarioCoverageKeys = new Set<string>();
  const nextIndexByScenario = new Map<string, number>();
  const coverageKeys = new Set<string>();
  const coverage: MigrationObservation[] = [];
  for (const observation of observed) {
    const expectedIndex = nextIndexByScenario.get(observation.scenario) ?? 0;
    nextIndexByScenario.set(observation.scenario, expectedIndex + 1);
    if (observation.index !== expectedIndex) {
      unmatchedObserved.push(observation);
      continue;
    }
    const coverageKey = `${observation.api}:${observation.callSiteLine}:${observation.sqlHash}`;
    const scenarioKey = `${observation.scenario}:${observation.index}:${coverageKey}`;
    const scenarioCoverageKey = `${observation.scenario}:${coverageKey}`;
    if (scenarioCoverageKeys.has(scenarioCoverageKey)) {
      unmatchedObserved.push(observation);
      continue;
    }
    scenarioCoverageKeys.add(scenarioCoverageKey);
    if (scenarioKeys.has(scenarioKey)) {
      unmatchedObserved.push(observation);
      continue;
    }
    scenarioKeys.add(scenarioKey);
    if (!coverageKeys.has(coverageKey)) {
      coverageKeys.add(coverageKey);
      coverage.push(observation);
    }
  }
  for (const site of expected) {
    const match = coverage.findIndex(({ api, callSiteLine, sqlHash: observedHash }) =>
      api === site.api && observedHash === site.sqlHash
      && callSiteLine >= site.startLine && callSiteLine <= site.endLine);
    if (match === -1) unmatchedExpected.push(site);
    else coverage.splice(match, 1);
  }
  unmatchedObserved.push(...coverage);
  return { unmatchedExpected, unmatchedObserved };
}

interface RegistryChild {
  readonly exited: Promise<number>;
  readonly pid: number;
  readonly stderr: ReadableStream<Uint8Array>;
  readonly stdout: ReadableStream<Uint8Array>;
  kill(signal?: NodeJS.Signals | number): void;
}

async function collectRegistryChild(
  child: RegistryChild,
  label: string,
  timeoutMs: number,
  terminationTimeoutMs = 5_000,
): Promise<{ readonly exitCode: number; readonly stderr: string; readonly stdout: string }> {
  const stdoutReader = child.stdout.getReader();
  const stderrReader = child.stderr.getReader();
  const drain = async (reader: { read(): Promise<{ readonly done: boolean; readonly value?: Uint8Array }> }): Promise<string> => {
    const decoder = new TextDecoder();
    let output = "";
    while (true) {
      const next = await reader.read();
      if (next.done) return output + decoder.decode(new Uint8Array());
      output += decoder.decode(next.value!, { stream: true });
    }
  };
  const completion = Promise.all([
    child.exited,
    drain(stdoutReader as unknown as Parameters<typeof drain>[0]),
    drain(stderrReader as unknown as Parameters<typeof drain>[0]),
  ] as const);
  const absoluteDeadline = performance.now() + timeoutMs;
  const cleanupReserveMs = Math.min(terminationTimeoutMs, Math.min(250, Math.max(1, Math.floor(timeoutMs / 4))));
  const executionBudgetMs = Math.max(0, timeoutMs - cleanupReserveMs);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = Symbol("timed-out");
  const completed = await Promise.race([
    completion,
    new Promise<typeof timedOut>((resolve) => {
      timer = setTimeout(() => resolve(timedOut), executionBudgetMs);
    }),
  ]);
  if (timer !== undefined) clearTimeout(timer);
  if (completed === timedOut) {
    child.kill("SIGKILL");
    await Promise.allSettled([stdoutReader.cancel(), stderrReader.cancel()]);
    void completion.catch(() => {});
    let terminationTimer: ReturnType<typeof setTimeout> | undefined;
    const remainingMs = Math.max(1, Math.min(
      terminationTimeoutMs,
      Math.floor(absoluteDeadline - performance.now()),
    ));
    try {
      await Promise.race([
        child.exited,
        new Promise<never>((_, reject) => {
          terminationTimer = setTimeout(() => reject(new Error(
            `${label} did not terminate within ${remainingMs}ms; leaked pid=${child.pid}`,
          )), remainingMs);
        }),
      ]);
    } finally {
      if (terminationTimer !== undefined) clearTimeout(terminationTimer);
    }
  }
  if (completed === timedOut) throw new Error(`${label} timed out after ${timeoutMs}ms; terminated pid=${child.pid}`);
  const [exitCode, stdout, stderr] = completed;
  return { exitCode, stdout, stderr };
}

function normalizeSql(sql: string): string {
  return sql.replace(/\s+/g, " ").trim();
}

function sqlHash(sql: string): string {
  return createHash("sha256").update(normalizeSql(sql)).digest("hex");
}

function sourceLine(text: string, offset: number): number {
  return text.slice(0, offset).split("\n").length;
}

async function findTypedDatabaseCalls(
  checker: Checker,
  sourceFile: SourceFile,
  canonicalDatabaseType?: Type,
  enforceMigrationOwnership = sourceFile.fileName.endsWith(`/${MIGRATION_SOURCE}`),
): Promise<{
  readonly calls: DatabaseCall[];
  readonly escapedMethods: DatabaseCall["method"][];
}> {
  const candidates: CallExpression[] = [];
  const methodReferences: Expression[] = [];
  const identifiers: Identifier[] = [];
  const aliasIdentifiers: Node[] = [];
  const receiverExpressions: Expression[] = [];
  const objectBindingDeclarations: VariableDeclaration[] = [];
  const rejectedObjectBindingPatterns: Node[] = [];
  const destructuringAssignments: Node[] = [];
  const parameterProperties: Node[] = [];
  const visit = (node: Node): void => {
    if (node.kind === SyntaxKind.CallExpression) candidates.push(node as CallExpression);
    if ((node.kind === SyntaxKind.PropertyAccessExpression
      && ["exec", "prepare", "query", "run"].includes(
        (node as PropertyAccessExpression).name.getText(sourceFile),
      )) || node.kind === SyntaxKind.ElementAccessExpression) methodReferences.push(node as Expression);
    if (node.kind === SyntaxKind.Identifier) identifiers.push(node as Identifier);
    if (node.kind === SyntaxKind.Identifier || node.kind === SyntaxKind.PrivateIdentifier) aliasIdentifiers.push(node);
    if (node.kind === SyntaxKind.Identifier || node.kind === SyntaxKind.CallExpression
      || node.kind === SyntaxKind.NewExpression || node.kind === SyntaxKind.PropertyAccessExpression
      || node.kind === SyntaxKind.ElementAccessExpression || node.kind === SyntaxKind.AsExpression
      || node.kind === SyntaxKind.TypeAssertionExpression
      || node.kind === SyntaxKind.SatisfiesExpression) receiverExpressions.push(node as Expression);
    if (node.kind === SyntaxKind.VariableDeclaration
      && (node as VariableDeclaration).name.kind === SyntaxKind.ObjectBindingPattern) {
      objectBindingDeclarations.push(node as VariableDeclaration);
    }
    if (node.kind === SyntaxKind.ObjectBindingPattern
      && node.parent.kind !== SyntaxKind.VariableDeclaration) rejectedObjectBindingPatterns.push(node);
    if (node.kind === SyntaxKind.BinaryExpression) {
      const assignment = node as Node & {
        readonly left?: Node;
        readonly operatorToken?: Node;
      };
      if (assignment.left?.kind === SyntaxKind.ObjectLiteralExpression
        && assignment.operatorToken?.kind === SyntaxKind.EqualsToken) destructuringAssignments.push(node);
    }
    if (node.kind === SyntaxKind.Parameter) {
      const modifiers = (node as Node & { readonly modifiers?: readonly Node[] }).modifiers ?? [];
      if (modifiers.some((modifier) => modifier.kind === SyntaxKind.PublicKeyword
        || modifier.kind === SyntaxKind.ProtectedKeyword || modifier.kind === SyntaxKind.PrivateKeyword
        || modifier.kind === SyntaxKind.ReadonlyKeyword)) parameterProperties.push(node);
    }
    node.forEachChild(visit);
  };
  visit(sourceFile);
  const migrationOwnedStarts = enforceMigrationOwnership
    ? await findExclusiveMigrationOwnedCallStarts(checker, sourceFile, candidates, identifiers)
    : new Set<number>();
  const aliasedExportStarts = await exportedDeclarationStarts(checker, sourceFile);
  const calls: DatabaseCall[] = [];
  const escapedMethods: DatabaseCall["method"][] = [];
  const databaseType = canonicalDatabaseType ?? await findDatabaseType(checker, identifiers);
  for (const candidate of candidates) {
    const signature = await checker.getResolvedSignature(candidate);
    const declaration = await signature?.declaration?.resolve();
    const owner = declaration?.parent;
    if (declaration === undefined || owner?.kind !== SyntaxKind.ClassDeclaration
      || (owner as Node & { readonly name?: { getText(source: SourceFile): string } })
        .name?.getText(owner.getSourceFile()) !== "Database"
      || !declaration.getSourceFile().fileName.endsWith("/bun-types/sqlite.d.ts")) {
      continue;
    }
    const method = (declaration as Node & { readonly name?: { getText(source: SourceFile): string } })
      .name?.getText(declaration.getSourceFile());
    if (method !== "exec" && method !== "prepare" && method !== "query" && method !== "run") continue;
    const argumentStart = candidate.arguments[0]?.getStart(sourceFile) ?? candidate.expression.getEnd() + 1;
    const staticSql = candidate.arguments[0] === undefined
      ? undefined : await resolveStaticString(candidate.arguments[0], checker, new Set<number>());
    calls.push({
      approvedConnectionSetup: sourceFile.fileName.endsWith(`/${MIGRATION_SOURCE}`)
        && await isApprovedConnectionSetupCall(candidate, sourceFile, staticSql, checker, identifiers),
      argumentStart,
      computed: candidate.expression.kind === SyntaxKind.ElementAccessExpression,
      end: enclosingStatementEnd(candidate),
      hasStaticArgument: staticSql !== undefined,
      method,
      migrationOwned: migrationOwnedStarts.has(candidate.getStart(sourceFile)),
      staticSql,
      start: candidate.getStart(sourceFile),
    });
  }
  const directCallStarts = new Set(calls.map(({ start }) => start));
  escapedMethods.push(...await narrowedDestructuredDatabaseMethodCalls(
    objectBindingDeclarations,
    rejectedObjectBindingPatterns,
    destructuringAssignments,
    checker,
    databaseType,
    sourceFile,
    aliasIdentifiers,
    aliasedExportStarts,
  ));
  escapedMethods.push(...await databaseReceiverEscapeMethods(
    receiverExpressions,
    checker,
    databaseType,
    aliasedExportStarts,
  ));
  escapedMethods.push(...await rejectedDatabaseParameterProperties(parameterProperties, checker, databaseType));
  escapedMethods.push(...await rejectedDestructuredDatabaseMethods(
    rejectedObjectBindingPatterns,
    destructuringAssignments,
    checker,
    databaseType,
    sourceFile,
  ));
  for (const binding of await destructuredDatabaseMethodBindings(
    objectBindingDeclarations,
    checker,
    databaseType,
    sourceFile,
  )) {
    if (binding.failClosed) {
      escapedMethods.push(...binding.methods);
      continue;
    }
    if (binding.name === undefined) {
      escapedMethods.push(...binding.methods);
      continue;
    }
    if (isExportedVariableDeclaration(binding.declaration, aliasedExportStarts)) {
      escapedMethods.push(...binding.methods);
      continue;
    }
    const symbol = await checker.getSymbolAtLocation(binding.name);
    if (symbol === undefined) {
      escapedMethods.push(...binding.methods);
      continue;
    }
    if (!await hasOnlyProvenDirectCallUses(
      symbol.id,
      binding.name,
      identifiers,
      checker,
      sourceFile,
      directCallStarts,
      aliasedExportStarts,
      new Set<number>(),
    )) {
      escapedMethods.push(...binding.methods);
    }
  }
  for (const reference of methodReferences) {
    const { failClosed, methods } = await databaseMethodReferences(reference, checker, databaseType);
    if (methods.length === 0) continue;
    if (failClosed) {
      escapedMethods.push(...methods);
      continue;
    }
    const { parent, value } = transparentCallBoundary(reference as Expression);
    if (parent.kind === SyntaxKind.CallExpression
      && (parent as CallExpression).expression === value) {
      if (!directCallStarts.has(parent.getStart(sourceFile))) escapedMethods.push(...methods);
      continue;
    }
    if (parent.kind === SyntaxKind.VariableDeclaration
      && (parent as VariableDeclaration).initializer === value) {
      const declaration = parent as VariableDeclaration;
      if ((declaration.parent.flags & NodeFlags.Const) === 0
        || declaration.name.kind !== SyntaxKind.Identifier
        || isExportedVariableDeclaration(declaration, aliasedExportStarts)) {
        escapedMethods.push(...methods);
        continue;
      }
      const symbol = await checker.getSymbolAtLocation(declaration.name);
      if (symbol === undefined || !await hasOnlyProvenDirectCallUses(
        symbol.id,
        declaration.name,
        identifiers,
        checker,
        sourceFile,
        directCallStarts,
        aliasedExportStarts,
        new Set<number>(),
      )) escapedMethods.push(...methods);
      continue;
    }
    if (parent.kind !== SyntaxKind.PropertyAccessExpression
      || (parent as PropertyAccessExpression).expression !== value
      || (parent as PropertyAccessExpression).name.getText(sourceFile) !== "bind") {
      escapedMethods.push(...methods);
      continue;
    }
    const bind = parent.parent;
    if (bind.kind !== SyntaxKind.CallExpression || (bind as CallExpression).expression !== parent
      || bind.parent.kind !== SyntaxKind.VariableDeclaration) {
      escapedMethods.push(...methods);
      continue;
    }
    const declaration = bind.parent as VariableDeclaration;
    if ((declaration.parent.flags & NodeFlags.Const) === 0
      || declaration.name.kind !== SyntaxKind.Identifier
      || isExportedVariableDeclaration(declaration, aliasedExportStarts)) {
      escapedMethods.push(...methods);
      continue;
    }
    const symbol = await checker.getSymbolAtLocation(declaration.name);
    if (symbol === undefined) {
      escapedMethods.push(...methods);
      continue;
    }
    if (!await hasOnlyProvenDirectCallUses(
      symbol.id,
      declaration.name,
      identifiers,
      checker,
      sourceFile,
      directCallStarts,
      aliasedExportStarts,
      new Set<number>(),
    )) {
      escapedMethods.push(...methods);
    }
  }
  return { calls, escapedMethods };
}

async function destructuredDatabaseMethodBindings(
  declarations: readonly VariableDeclaration[],
  checker: Checker,
  databaseType: Type | undefined,
  sourceFile: SourceFile,
): Promise<Array<{
  readonly declaration: VariableDeclaration;
  readonly failClosed: boolean;
  readonly methods: readonly DatabaseCall["method"][];
  readonly name: Identifier | undefined;
}>> {
  const bindings: Array<{
    readonly declaration: VariableDeclaration;
    readonly failClosed: boolean;
    readonly methods: readonly DatabaseCall["method"][];
    readonly name: Identifier | undefined;
  }> = [];
  for (const declaration of declarations) {
    if (declaration.initializer === undefined) continue;
    const receiverType = await checker.getTypeAtLocation(declaration.initializer);
    if (receiverType === undefined) continue;
    const exactDatabase = await isDatabaseType(receiverType, checker);
    const widenedType = !exactDatabase && databaseType !== undefined
      ? await databaseCompatibleWidenedType(databaseType, receiverType, checker)
      : undefined;
    const failClosed = widenedType !== undefined;
    if (!exactDatabase && !failClosed) continue;
    const executionType = widenedType ?? receiverType;
    const elements = (declaration.name as Node & { readonly elements?: readonly Node[] }).elements ?? [];
    const removedMethods = new Set<DatabaseCall["method"]>();
    for (const element of elements) {
      const binding = element as Node & {
        readonly dotDotDotToken?: Node;
        readonly name?: Node;
        readonly propertyName?: Node & { readonly text?: string };
      };
      const name = binding.name?.kind === SyntaxKind.Identifier ? binding.name as Identifier : undefined;
      if (binding.dotDotDotToken !== undefined) {
        const methods = await restExecutionMethods(binding, executionType, checker, removedMethods);
        bindings.push({ declaration, failClosed, methods, name });
        continue;
      }
      const resolved = await bindingExecutionMethods(binding, executionType, checker, sourceFile, failClosed);
      for (const method of resolved.methods) removedMethods.add(method);
      if (resolved.methods.length === 0) continue;
      bindings.push({
        declaration,
        failClosed: resolved.failClosed || name === undefined,
        methods: resolved.methods,
        name,
      });
    }
  }
  return bindings;
}

async function narrowedDestructuredDatabaseMethodCalls(
  declarations: readonly VariableDeclaration[],
  patterns: readonly Node[],
  assignments: readonly Node[],
  checker: Checker,
  databaseType: Type | undefined,
  sourceFile: SourceFile,
  identifiers: readonly Node[],
  aliasedExportStarts: ReadonlySet<number>,
): Promise<DatabaseCall["method"][]> {
  if (databaseType === undefined) return [];
  const methods: DatabaseCall["method"][] = [];
  const candidates: Array<{ readonly elements: readonly Node[]; readonly receiverType: Type }> = [];
  for (const declaration of declarations) {
    if (declaration.initializer === undefined) continue;
    const receiverType = await checker.getTypeAtLocation(declaration.initializer);
    if (receiverType !== undefined) candidates.push({
      elements: (declaration.name as Node & { readonly elements?: readonly Node[] }).elements ?? [],
      receiverType,
    });
  }
  for (const pattern of patterns) {
    const receiverType = await checker.getTypeAtLocation(pattern);
    if (receiverType !== undefined) candidates.push({
      elements: (pattern as Node & { readonly elements?: readonly Node[] }).elements ?? [],
      receiverType,
    });
  }
  for (const node of assignments) {
    const assignment = node as Node & { readonly left: Node; readonly right: Node };
    const receiverType = await checker.getTypeAtLocation(assignment.right);
    if (receiverType !== undefined) candidates.push({
      elements: (assignment.left as Node & { readonly properties?: readonly Node[] }).properties ?? [],
      receiverType,
    });
  }
  for (const candidate of candidates) {
    if (await isDatabaseType(candidate.receiverType, checker)) continue;
    const executionType = await databaseAssignableWidenedType(databaseType, candidate.receiverType, checker);
    if (executionType === undefined) continue;
    const declaredMethods = await executionMethodsForType(executionType, checker, false);
    for (const element of candidate.elements) {
      const binding = element as Node & {
        readonly dotDotDotToken?: Node;
        readonly initializer?: Node;
        readonly name?: Node;
        readonly propertyName?: Node & { readonly text?: string };
      };
      if (binding.dotDotDotToken !== undefined) continue;
      const name = destructuringAliasTarget(binding);
      if (name === undefined) continue;
      const keys = await destructuringExecutionKeys(binding, checker, sourceFile, executionType);
      const narrowedMethods = keys.filter((key) => !declaredMethods.includes(key));
      if (narrowedMethods.length === 0) continue;
      const symbol = binding.kind === SyntaxKind.ShorthandPropertyAssignment
        ? await checker.getShorthandAssignmentValueSymbol(binding)
        : await checker.getSymbolAtLocation(name);
      if (symbol === undefined) continue;
      if (await hasExecutableAliasUse(
        symbol.id,
        name,
        identifiers,
        checker,
        sourceFile,
        aliasedExportStarts,
        new Set<number>(),
      )) {
        methods.push(...narrowedMethods);
      }
    }
  }
  return methods;
}

async function hasExecutableAliasUse(
  symbolId: number,
  declaration: Node,
  identifiers: readonly Node[],
  checker: Checker,
  sourceFile: SourceFile,
  aliasedExportStarts: ReadonlySet<number>,
  visited: Set<number>,
): Promise<boolean> {
  if (visited.has(symbolId)) return false;
  visited.add(symbolId);
  for (const identifier of identifiers) {
    if (identifier === declaration || (await checker.getSymbolAtLocation(identifier))?.id !== symbolId) continue;
    if ((identifier.parent.kind === SyntaxKind.PropertyDeclaration
      && (identifier.parent as Node & { readonly name?: Node }).name === identifier)
      || (identifier.parent.kind === SyntaxKind.BindingElement
        && (identifier.parent as Node & { readonly name?: Node }).name === identifier)
      || (identifier.parent.kind === SyntaxKind.VariableDeclaration
        && (identifier.parent as VariableDeclaration).name === identifier)) continue;
    const reference = identifier.parent.kind === SyntaxKind.PropertyAccessExpression
      && (identifier.parent as PropertyAccessExpression).name === identifier
      ? identifier.parent as PropertyAccessExpression : identifier;
    const { parent, value } = transparentCallBoundary(reference as Expression);
    if (parent.kind === SyntaxKind.CallExpression && (parent as CallExpression).expression === value) return true;
    if (parent.kind === SyntaxKind.PropertyAccessExpression
      && (parent as PropertyAccessExpression).expression === value
      && ["apply", "bind", "call"].includes((parent as PropertyAccessExpression).name.getText(sourceFile))) {
      const boundary = transparentCallBoundary(parent as PropertyAccessExpression);
      if (boundary.parent.kind === SyntaxKind.CallExpression
        && (boundary.parent as CallExpression).expression === boundary.value) return true;
    }
    if (parent.kind === SyntaxKind.ElementAccessExpression
      && (parent as ElementAccessExpression).expression === value) {
      const access = parent as ElementAccessExpression;
      const keyType = await checker.getTypeAtLocation(access.argumentExpression);
      const keyConstraint = keyType === undefined ? undefined : await checker.getBaseConstraintOfType(keyType);
      const keys = keyType === undefined ? undefined
        : await stringLiteralConstituents(keyType) ?? (keyConstraint === undefined
          ? undefined : await stringLiteralConstituents(keyConstraint));
      if (keys?.some((key) => key === "apply" || key === "bind" || key === "call")) {
        const boundary = transparentCallBoundary(access);
        if (boundary.parent.kind === SyntaxKind.CallExpression
          && (boundary.parent as CallExpression).expression === boundary.value) return true;
      }
    }
    if (parent.kind === SyntaxKind.VariableDeclaration
      && (parent as VariableDeclaration).initializer === value
      && (parent as VariableDeclaration).name.kind === SyntaxKind.Identifier) {
      const alias = (parent as VariableDeclaration).name as Identifier;
      if (!await isProvablyLocalDatabaseTarget(alias, checker, aliasedExportStarts)) return true;
      const aliasSymbol = await checker.getSymbolAtLocation(alias);
      if (aliasSymbol !== undefined
        && await hasExecutableAliasUse(
          aliasSymbol.id,
          alias,
          identifiers,
          checker,
          sourceFile,
          aliasedExportStarts,
          visited,
        )) return true;
      continue;
    }
    if (parent.kind === SyntaxKind.BinaryExpression
      && (parent as Node & { readonly right?: Node; readonly left?: Node; readonly operatorToken?: Node }).right === value
      && (parent as Node & { readonly operatorToken?: Node }).operatorToken?.kind === SyntaxKind.EqualsToken) {
      const alias = (parent as Node & { readonly left?: Node }).left;
      if (alias?.kind === SyntaxKind.Identifier || alias?.kind === SyntaxKind.PropertyAccessExpression) {
        if (!await isProvablyLocalDatabaseTarget(alias, checker, aliasedExportStarts)) return true;
        const aliasNode = alias.kind === SyntaxKind.PropertyAccessExpression
          ? (alias as PropertyAccessExpression).name : alias;
        const aliasSymbol = await checker.getSymbolAtLocation(aliasNode);
        if (aliasSymbol !== undefined
          && await hasExecutableAliasUse(
            aliasSymbol.id,
            aliasNode,
            identifiers,
            checker,
            sourceFile,
            aliasedExportStarts,
            visited,
          )) return true;
        continue;
      }
      return true;
    }
    if ((parent.kind === SyntaxKind.TypeOfExpression || parent.kind === SyntaxKind.VoidExpression)
      && (parent as Node & { readonly expression?: Node }).expression === value) continue;
    if ((parent.kind === SyntaxKind.CallExpression || parent.kind === SyntaxKind.NewExpression)
      && ((parent as Node & { readonly arguments?: readonly Node[] }).arguments ?? []).includes(value)) return true;
    if ((parent.kind === SyntaxKind.ReturnStatement
      && (parent as Node & { readonly expression?: Node }).expression === value)
      || (parent.kind === SyntaxKind.ArrowFunction && (parent as Node & { readonly body?: Node }).body === value)
      || (parent.kind === SyntaxKind.PropertyAssignment
        && (parent as Node & { readonly initializer?: Node }).initializer === value)
      || parent.kind === SyntaxKind.ArrayLiteralExpression
      || parent.kind === SyntaxKind.SpreadElement
      || parent.kind === SyntaxKind.SpreadAssignment
      || parent.kind === SyntaxKind.YieldExpression) return true;
    return true;
  }
  return false;
}

function destructuringAliasTarget(binding: Node & {
  readonly initializer?: Node;
  readonly name?: Node;
}): Identifier | undefined {
  const target = binding.kind === SyntaxKind.PropertyAssignment ? binding.initializer : binding.name;
  return target?.kind === SyntaxKind.Identifier ? target as Identifier : undefined;
}

async function destructuringExecutionKeys(
  binding: Node & {
    readonly name?: Node;
    readonly propertyName?: Node & { readonly text?: string };
  },
  checker: Checker,
  sourceFile: SourceFile,
  executionType: Type,
): Promise<DatabaseCall["method"][]> {
  const propertyName = binding.propertyName ?? binding.name;
  const key = await resolveBindingKey(propertyName, undefined, checker, sourceFile);
  if (key === "exec" || key === "prepare" || key === "query" || key === "run") return [key];
  if (propertyName?.kind !== SyntaxKind.ComputedPropertyName) return [];
  const expression = (propertyName as Node & { readonly expression?: Expression }).expression;
  const keyType = expression === undefined ? undefined : await checker.getTypeAtLocation(expression);
  const keyConstraint = keyType === undefined ? undefined : await checker.getBaseConstraintOfType(keyType);
  const keys = keyType === undefined ? undefined
    : await stringLiteralConstituents(keyType) ?? (keyConstraint === undefined
      ? undefined : await stringLiteralConstituents(keyConstraint));
  if (keys === undefined) return executionPropertyNamesForType(executionType, checker);
  return [...new Set(keys.filter((candidate): candidate is DatabaseCall["method"] =>
    candidate === "exec" || candidate === "prepare" || candidate === "query" || candidate === "run"))].sort();
}

async function rejectedDestructuredDatabaseMethods(
  patterns: readonly Node[],
  assignments: readonly Node[],
  checker: Checker,
  databaseType: Type | undefined,
  sourceFile: SourceFile,
): Promise<DatabaseCall["method"][]> {
  const methods: DatabaseCall["method"][] = [];
  for (const pattern of patterns) {
    const receiverType = await checker.getTypeAtLocation(pattern);
    if (receiverType === undefined) continue;
    const exactDatabase = await isDatabaseType(receiverType, checker);
    const widenedType = !exactDatabase && databaseType !== undefined
      ? await databaseCompatibleWidenedType(databaseType, receiverType, checker)
      : undefined;
    const failClosed = widenedType !== undefined;
    if (!exactDatabase && !failClosed) continue;
    methods.push(...await bindingElementDatabaseMethods(
      (pattern as Node & { readonly elements?: readonly Node[] }).elements ?? [],
      widenedType ?? receiverType,
      checker,
      sourceFile,
      failClosed,
    ));
  }
  for (const node of assignments) {
    const assignment = node as Node & { readonly left: Node; readonly right: Node };
    const receiverType = await checker.getTypeAtLocation(assignment.right);
    if (receiverType === undefined) continue;
    const exactDatabase = await isDatabaseType(receiverType, checker);
    const widenedType = !exactDatabase && databaseType !== undefined
      ? await databaseCompatibleWidenedType(databaseType, receiverType, checker)
      : undefined;
    const failClosed = widenedType !== undefined;
    if (!exactDatabase && !failClosed) continue;
    const properties = (assignment.left as Node & { readonly properties?: readonly Node[] }).properties ?? [];
    methods.push(...await bindingElementDatabaseMethods(
      properties,
      widenedType ?? receiverType,
      checker,
      sourceFile,
      failClosed,
    ));
  }
  return methods;
}

async function databaseReceiverEscapeMethods(
  expressions: readonly Expression[],
  checker: Checker,
  databaseType: Type | undefined,
  aliasedExportStarts: ReadonlySet<number>,
): Promise<DatabaseCall["method"][]> {
  const escaped: DatabaseCall["method"][] = [];
  for (const expression of expressions) {
    const { parent, value } = transparentReceiverBoundary(expression);
    const isInitializer = parent.kind === SyntaxKind.VariableDeclaration
      && (parent as VariableDeclaration).initializer === value;
    if (isInitializer && (parent as VariableDeclaration).name.kind === SyntaxKind.ObjectBindingPattern) continue;
    const isPropertyInitializer = parent.kind === SyntaxKind.PropertyDeclaration
      && (parent as Node & { readonly initializer?: Node }).initializer === value;
    const isAssertion = (parent.kind === SyntaxKind.AsExpression
      || parent.kind === SyntaxKind.TypeAssertionExpression || parent.kind === SyntaxKind.SatisfiesExpression)
      && (parent as Node & { readonly expression?: Node }).expression === value;
    const isAssignment = parent.kind === SyntaxKind.BinaryExpression
      && (parent as Node & { readonly right?: Node; readonly operatorToken?: Node }).right === value
      && (parent as Node & { readonly operatorToken?: Node }).operatorToken?.kind === SyntaxKind.EqualsToken;
    if (isAssignment
      && (parent as Node & { readonly left?: Node }).left?.kind === SyntaxKind.ObjectLiteralExpression) continue;
    const isArgument = (parent.kind === SyntaxKind.CallExpression || parent.kind === SyntaxKind.NewExpression)
      && ((parent as Node & { readonly arguments?: readonly Node[] }).arguments ?? []).includes(value);
    const isReturn = (parent.kind === SyntaxKind.ReturnStatement
      && (parent as Node & { readonly expression?: Node }).expression === value)
      || (parent.kind === SyntaxKind.ArrowFunction
        && (parent as Node & { readonly body?: Node }).body === value);
    const isObjectProperty = (parent.kind === SyntaxKind.PropertyAssignment
      && (parent as Node & { readonly initializer?: Node }).initializer === value)
      || (parent.kind === SyntaxKind.ShorthandPropertyAssignment
        && (parent as Node & { readonly name?: Node }).name === value)
      || (parent.kind === SyntaxKind.SpreadAssignment
        && (parent as Node & { readonly expression?: Node }).expression === value);
    const isUnprovenContainer = parent.kind === SyntaxKind.ArrayLiteralExpression
      || parent.kind === SyntaxKind.ConditionalExpression
      || parent.kind === SyntaxKind.AwaitExpression
      || parent.kind === SyntaxKind.YieldExpression
      || parent.kind === SyntaxKind.SpreadElement
      || (parent.kind === SyntaxKind.BinaryExpression
        && (parent as Node & { readonly operatorToken?: Node }).operatorToken?.kind !== SyntaxKind.EqualsToken);
    if (!isInitializer && !isPropertyInitializer && !isAssertion && !isAssignment && !isArgument && !isReturn
      && !isObjectProperty && !isUnprovenContainer) continue;
    if (expression.kind === SyntaxKind.Identifier) {
      const symbol = await checker.getSymbolAtLocation(expression);
      const declaration = await symbol?.declarations[0]?.resolve();
      if (declaration?.kind === SyntaxKind.BindingElement
        && declaration.parent.kind === SyntaxKind.ObjectBindingPattern
        && declaration.parent.parent.kind === SyntaxKind.VariableDeclaration) {
        const initializer = (declaration.parent.parent as VariableDeclaration).initializer;
        const receiverType = initializer === undefined ? undefined : await checker.getTypeAtLocation(initializer);
        if (receiverType !== undefined && (await isDatabaseType(receiverType, checker)
          || (databaseType !== undefined
            && await databaseCompatibleWidenedType(databaseType, receiverType, checker) !== undefined))) continue;
      }
    }
    const sourceType = await checker.getTypeAtLocation(expression);
    if (sourceType === undefined) continue;
    const exactDatabase = await isDatabaseType(sourceType, checker);
    const widenedType = !exactDatabase && databaseType !== undefined
      ? await databaseCompatibleWidenedType(databaseType, sourceType, checker)
      : undefined;
    if (!exactDatabase && widenedType === undefined) continue;
    const sourceMethods: DatabaseCall["method"][] = exactDatabase
      ? ["exec", "prepare", "query", "run"]
      : await executionMethodsForType(widenedType!, checker, true);
    const targetEscapeMethods = async (targetType: Type): Promise<DatabaseCall["method"][]> => {
      const targetMethods = await executionMethodsForType(targetType, checker, true);
      const retained = targetMethods.filter((method) => sourceMethods.includes(method));
      return retained.length > 0 ? retained : sourceMethods;
    };
    if (isArgument) {
      const call = parent as CallExpression;
      const index = call.arguments.indexOf(value as Expression);
      if (index === 0 && call.expression.kind === SyntaxKind.PropertyAccessExpression
        && ["bind", "call"].includes(
          (call.expression as PropertyAccessExpression).name.getText(call.expression.getSourceFile()),
        )) {
        if (await isDatabaseMethodThisBinding(call, checker)) continue;
        escaped.push(...sourceMethods);
        continue;
      }
    }
    if (isObjectProperty || isUnprovenContainer) {
      escaped.push(...sourceMethods);
      continue;
    }
    const contextualType = await checker.getContextualType(expression);
    if (!isInitializer && !isPropertyInitializer && !isAssignment
      && contextualType !== undefined && !await isDatabaseType(contextualType, checker)) {
      escaped.push(...await targetEscapeMethods(contextualType));
      continue;
    }
    if (isReturn) {
      const functionNode = enclosingFunction(expression);
      const signature = functionNode === undefined ? undefined : await checker.getSignatureFromDeclaration(functionNode);
      const targetType = signature === undefined ? undefined : await checker.getReturnTypeOfSignature(signature);
      if (targetType === undefined || !await isDatabaseType(targetType, checker)) {
        if (targetType === undefined) escaped.push(...sourceMethods);
        else escaped.push(...await targetEscapeMethods(targetType));
      } else if (functionNode === undefined || !isApprovedDatabaseReturn(functionNode)) {
        escaped.push(...sourceMethods);
      }
      continue;
    }
    if (isInitializer) {
      const target = (parent as VariableDeclaration).name;
      const targetType = await checker.getTypeAtLocation(target);
      if (targetType !== undefined && !await isDatabaseType(targetType, checker)) {
        const targetMethods = await executionMethodsForType(targetType, checker, true);
        if (targetMethods.length === 0
          || !await isProvablyLocalDatabaseTarget(target, checker, aliasedExportStarts)) {
          escaped.push(...await targetEscapeMethods(targetType));
        }
      } else if (isExportedVariableDeclaration(parent as VariableDeclaration, aliasedExportStarts)) {
        escaped.push(...sourceMethods);
      }
      continue;
    }
    if (isPropertyInitializer) {
      if (!isPrivatePropertyDeclaration(parent)) escaped.push(...sourceMethods);
      continue;
    }
    if (isAssertion) {
      const targetType = await checker.getTypeAtLocation(parent);
      if (targetType !== undefined && !await isDatabaseType(targetType, checker)) {
        escaped.push(...await targetEscapeMethods(targetType));
      }
      continue;
    }
    if (isAssignment) {
      const left = (parent as Node & { readonly left?: Node }).left;
      const targetType = left === undefined ? undefined : await checker.getTypeAtLocation(left);
      if (targetType !== undefined && !await isDatabaseType(targetType, checker)) {
        const targetMethods = await executionMethodsForType(targetType, checker, true);
        if (targetMethods.length === 0 || left === undefined
          || !await isProvablyLocalDatabaseTarget(left, checker, aliasedExportStarts)) {
          escaped.push(...await targetEscapeMethods(targetType));
        }
      } else if (left === undefined
        || !await isProvablyLocalDatabaseTarget(left, checker, aliasedExportStarts)) {
        escaped.push(...sourceMethods);
      }
      continue;
    }
    if (isArgument) {
      const call = parent as CallExpression;
      const index = call.arguments.indexOf(value as Expression);
      const signature = await checker.getResolvedSignature(call);
      const signatureDeclaration = await signature?.declaration?.resolve();
      const parameters = (signatureDeclaration as Node & { readonly parameters?: readonly Node[] } | undefined)
        ?.parameters ?? [];
      const parameter = parameters[Math.min(index, Math.max(0, parameters.length - 1))];
      const targetType = parameter === undefined ? undefined : await checker.getTypeAtLocation(parameter);
      if (targetType !== undefined && !await isDatabaseType(targetType, checker)) {
        escaped.push(...await targetEscapeMethods(targetType));
      } else if (signatureDeclaration === undefined || !isScannedImplementation(signatureDeclaration)) {
        escaped.push(...sourceMethods);
      }
    }
  }
  return escaped;
}

function transparentReceiverBoundary(expression: Expression): { readonly parent: Node; readonly value: Node } {
  let value: Node = expression;
  let parent = value.parent;
  while ((parent.kind === SyntaxKind.ParenthesizedExpression || parent.kind === SyntaxKind.NonNullExpression)
    && (parent as Node & { readonly expression?: Node }).expression === value) {
    value = parent;
    parent = value.parent;
  }
  return { parent, value };
}

function transparentCallBoundary(expression: Expression): { readonly parent: Node; readonly value: Node } {
  let value: Node = expression;
  let parent = value.parent;
  while ((parent.kind === SyntaxKind.ParenthesizedExpression || parent.kind === SyntaxKind.NonNullExpression
    || parent.kind === SyntaxKind.AsExpression || parent.kind === SyntaxKind.TypeAssertionExpression
    || parent.kind === SyntaxKind.SatisfiesExpression)
    && (parent as Node & { readonly expression?: Node }).expression === value) {
    value = parent;
    parent = value.parent;
  }
  return { parent, value };
}

function isProvenDirectCallReference(
  reference: Expression,
  directCallStarts: ReadonlySet<number>,
  sourceFile: SourceFile,
): boolean {
  const { parent, value } = transparentCallBoundary(reference);
  return parent.kind === SyntaxKind.CallExpression
    && (parent as CallExpression).expression === value
    && directCallStarts.has(parent.getStart(sourceFile));
}

async function hasOnlyProvenDirectCallUses(
  symbolId: number,
  declaration: Identifier,
  identifiers: readonly Identifier[],
  checker: Checker,
  sourceFile: SourceFile,
  directCallStarts: ReadonlySet<number>,
  aliasedExportStarts: ReadonlySet<number>,
  visited: Set<number>,
): Promise<boolean> {
  if (visited.has(symbolId)) return true;
  visited.add(symbolId);
  for (const identifier of identifiers) {
    if (identifier === declaration || (await checker.getSymbolAtLocation(identifier))?.id !== symbolId) continue;
    if ((identifier.parent.kind === SyntaxKind.VariableDeclaration
      && (identifier.parent as VariableDeclaration).name === identifier)
      || (identifier.parent.kind === SyntaxKind.BindingElement
        && (identifier.parent as Node & { readonly name?: Node }).name === identifier)
      || (identifier.parent.kind === SyntaxKind.PropertyDeclaration
        && (identifier.parent as Node & { readonly name?: Node }).name === identifier)) continue;
    const reference = identifier.parent.kind === SyntaxKind.PropertyAccessExpression
      && (identifier.parent as PropertyAccessExpression).name === identifier
      ? identifier.parent as PropertyAccessExpression : identifier;
    if (isProvenDirectCallReference(reference, directCallStarts, sourceFile)) continue;
    const { parent, value } = transparentCallBoundary(reference);
    if ((parent.kind === SyntaxKind.TypeOfExpression || parent.kind === SyntaxKind.VoidExpression)
      && (parent as Node & { readonly expression?: Node }).expression === value) continue;
    let aliasTarget: Node | undefined;
    if (parent.kind === SyntaxKind.VariableDeclaration
      && (parent as VariableDeclaration).initializer === value
      && (parent as VariableDeclaration).name.kind === SyntaxKind.Identifier) {
      aliasTarget = (parent as VariableDeclaration).name;
    } else if (parent.kind === SyntaxKind.BinaryExpression
      && (parent as Node & { readonly right?: Node; readonly operatorToken?: Node }).right === value
      && (parent as Node & { readonly operatorToken?: Node }).operatorToken?.kind === SyntaxKind.EqualsToken) {
      const left = (parent as Node & { readonly left?: Node }).left;
      if (left?.kind === SyntaxKind.Identifier || left?.kind === SyntaxKind.PropertyAccessExpression) aliasTarget = left;
    }
    if (aliasTarget === undefined
      || !await isProvablyLocalDatabaseTarget(aliasTarget, checker, aliasedExportStarts)) return false;
    const aliasNode = aliasTarget.kind === SyntaxKind.PropertyAccessExpression
      ? (aliasTarget as PropertyAccessExpression).name : aliasTarget;
    if (aliasNode.kind !== SyntaxKind.Identifier) return false;
    const alias = aliasNode as Identifier;
    const aliasSymbol = await checker.getSymbolAtLocation(alias);
    if (aliasSymbol === undefined || !await hasOnlyProvenDirectCallUses(
      aliasSymbol.id,
      alias,
      identifiers,
      checker,
      sourceFile,
      directCallStarts,
      aliasedExportStarts,
      visited,
    )) return false;
  }
  return true;
}

function isApprovedDatabaseReturn(functionNode: Node): boolean {
  const sourceFile = functionNode.getSourceFile();
  const name = functionNode.kind === SyntaxKind.FunctionDeclaration
    ? (functionNode as Node & { readonly name?: Identifier }).name?.getText(sourceFile)
    : undefined;
  return name === "openDatabase" && sourceFile.fileName.endsWith(MIGRATION_SOURCE);
}

async function isProvablyLocalDatabaseTarget(
  target: Node,
  checker: Checker,
  aliasedExportStarts: ReadonlySet<number>,
): Promise<boolean> {
  if (target.kind !== SyntaxKind.Identifier && target.kind !== SyntaxKind.PropertyAccessExpression) return false;
  const lookup = target.kind === SyntaxKind.PropertyAccessExpression
    ? (target as PropertyAccessExpression).name : target;
  const symbol = await checker.getSymbolAtLocation(lookup);
  if (symbol === undefined || symbol.declarations.length !== 1) return false;
  const declaration = await symbol.declarations[0]!.resolve();
  if (declaration?.kind === SyntaxKind.VariableDeclaration) {
    return isScannedImplementation(declaration)
      && !isExportedVariableDeclaration(declaration as VariableDeclaration, aliasedExportStarts);
  }
  if (declaration?.kind !== SyntaxKind.PropertyDeclaration || !isScannedImplementation(declaration)) return false;
  return isPrivatePropertyDeclaration(declaration);
}

function isScannedImplementation(declaration: Node): boolean {
  const file = declaration.getSourceFile().fileName;
  if (file.endsWith(".d.ts") || (!file.startsWith(`${ROOT}/src/`) && !file.startsWith(`${ROOT}/test/`))) {
    return false;
  }
  let cursor: Node | undefined = declaration;
  while (cursor !== undefined && cursor.kind !== SyntaxKind.SourceFile) {
    const modifiers = (cursor as Node & { readonly modifiers?: readonly Node[] }).modifiers ?? [];
    if (modifiers.some((modifier) => modifier.kind === SyntaxKind.DeclareKeyword)) return false;
    cursor = cursor.parent;
  }
  if (declaration.kind === SyntaxKind.FunctionDeclaration || declaration.kind === SyntaxKind.MethodDeclaration
    || declaration.kind === SyntaxKind.Constructor) {
    return (declaration as Node & { readonly body?: Node }).body !== undefined;
  }
  return declaration.kind !== SyntaxKind.MethodSignature && declaration.kind !== SyntaxKind.CallSignature;
}

function isPrivatePropertyDeclaration(declaration: Node): boolean {
  const name = (declaration as Node & { readonly name?: Node }).name;
  const modifiers = (declaration as Node & { readonly modifiers?: readonly Node[] }).modifiers ?? [];
  return name?.kind === SyntaxKind.PrivateIdentifier
    || modifiers.some((modifier) => modifier.kind === SyntaxKind.PrivateKeyword);
}

async function rejectedDatabaseParameterProperties(
  parameters: readonly Node[],
  checker: Checker,
  databaseType: Type | undefined,
): Promise<DatabaseCall["method"][]> {
  const methods: DatabaseCall["method"][] = [];
  for (const parameter of parameters) {
    const name = (parameter as Node & { readonly name?: Node }).name;
    if (name === undefined || isPrivatePropertyDeclaration(parameter)) continue;
    const type = await checker.getTypeAtLocation(name);
    if (type === undefined) continue;
    if (await isDatabaseType(type, checker)) methods.push("exec", "prepare", "query", "run");
    else if (databaseType !== undefined) {
      const widenedType = await databaseCompatibleWidenedType(databaseType, type, checker);
      if (widenedType !== undefined) methods.push(...await executionMethodsForType(widenedType, checker, true));
    }
  }
  return methods;
}

async function isDatabaseMethodThisBinding(call: CallExpression, checker: Checker): Promise<boolean> {
  if (call.expression.kind !== SyntaxKind.PropertyAccessExpression) return false;
  const target = (call.expression as PropertyAccessExpression).expression;
  if (target.kind !== SyntaxKind.PropertyAccessExpression && target.kind !== SyntaxKind.ElementAccessExpression) {
    return false;
  }
  const reference = await databaseMethodReferences(target as Expression, checker);
  return !reference.failClosed && reference.methods.length === 1;
}

async function findDatabaseType(checker: Checker, identifiers: readonly Identifier[]): Promise<Type | undefined> {
  for (const identifier of identifiers) {
    if (identifier.getText(identifier.getSourceFile()) !== "Database") continue;
    const type = await checker.getTypeAtLocation(identifier);
    if (type !== undefined && await isDatabaseType(type, checker)) return type;
  }
  return undefined;
}

async function requireDatabaseType(checker: Checker, sourceFile: SourceFile): Promise<Type> {
  const identifiers: Identifier[] = [];
  const visit = (node: Node): void => {
    if (node.kind === SyntaxKind.Identifier) identifiers.push(node as Identifier);
    node.forEachChild(visit);
  };
  visit(sourceFile);
  const type = await findDatabaseType(checker, identifiers);
  if (type === undefined) throw new Error("Canonical Bun Database type unavailable to atomic-write scanner");
  return type;
}

async function databaseCompatibleWidenedType(
  databaseType: Type,
  receiverType: Type,
  checker: Checker,
): Promise<Type | undefined> {
  const compatibleType = await databaseAssignableWidenedType(databaseType, receiverType, checker);
  return compatibleType !== undefined
    && (await executionMethodsForType(compatibleType, checker, false)).length > 0
    ? compatibleType
    : undefined;
}

async function databaseAssignableWidenedType(
  databaseType: Type,
  receiverType: Type,
  checker: Checker,
): Promise<Type | undefined> {
  if (await checker.isTypeAssignableTo(databaseType, receiverType)) return receiverType;
  const constraint = await checker.getBaseConstraintOfType(receiverType);
  return constraint !== undefined && await checker.isTypeAssignableTo(databaseType, constraint) ? constraint : undefined;
}

async function widenedDatabaseExecutionMethods(
  access: PropertyAccessExpression | ElementAccessExpression,
  checker: Checker,
  databaseType: Type,
  sourceFile: SourceFile,
): Promise<DatabaseCall["method"][]> {
  const receiver = access.expression;
  const receiverType = await checker.getTypeAtLocation(receiver);
  if (receiverType === undefined || await isDatabaseType(receiverType, checker)) return [];
  const executionType = await databaseAssignableWidenedType(databaseType, receiverType, checker);
  if (executionType === undefined) return [];
  const selectedType = await checker.getTypeAtLocation(access);
  const boundary = transparentCallBoundary(access);
  const selectedCallable = (selectedType !== undefined && await isPotentiallyCallableType(selectedType, checker))
    || (boundary.parent.kind === SyntaxKind.CallExpression
      && (boundary.parent as CallExpression).expression === boundary.value);
  const callableMethods = await executionMethodsForType(executionType, checker, true);
  if (access.kind === SyntaxKind.PropertyAccessExpression) {
    const method = access.name.getText(sourceFile);
    return (method === "exec" || method === "prepare" || method === "query" || method === "run")
      && selectedCallable
      ? [method] : [];
  }
  const keyType = await checker.getTypeAtLocation(access.argumentExpression);
  const keyConstraint = keyType === undefined ? undefined : await checker.getBaseConstraintOfType(keyType);
  const keys = keyType === undefined ? undefined
    : await stringLiteralConstituents(keyType) ?? (keyConstraint === undefined
      ? undefined : await stringLiteralConstituents(keyConstraint));
  const methods = keys?.filter((key): key is DatabaseCall["method"] =>
    key === "exec" || key === "prepare" || key === "query" || key === "run");
  if (methods !== undefined && methods.length === 0) return [];
  if (methods !== undefined) {
    const selectedMethods = methods.filter((method) => callableMethods.includes(method));
    if (selectedMethods.length === 0 && selectedCallable) return [...new Set(methods)].sort();
    return [...new Set(selectedMethods)].sort();
  }
  return selectedCallable ? await executionPropertyNamesForType(executionType, checker) : callableMethods;
}

async function executionPropertyNamesForType(
  type: Type,
  checker: Checker,
): Promise<DatabaseCall["method"][]> {
  const methods: DatabaseCall["method"][] = [];
  for (const method of ["exec", "prepare", "query", "run"] as const) {
    if (await checker.getPropertyOfType(type, method) !== undefined) methods.push(method);
  }
  return methods;
}

function enclosingFunction(node: Node): Node | undefined {
  let cursor: Node | undefined = node.parent;
  while (cursor !== undefined && cursor.kind !== SyntaxKind.SourceFile) {
    if (isFunctionScope(cursor)) return cursor;
    cursor = cursor.parent;
  }
  return undefined;
}

async function executionMethodsForType(
  type: Type,
  checker: Checker,
  failClosed: boolean,
): Promise<DatabaseCall["method"][]> {
  const methods: DatabaseCall["method"][] = [];
  for (const method of ["exec", "prepare", "query", "run"] as const) {
    const property = await checker.getPropertyOfType(type, method);
    if (property === undefined) continue;
    const propertyType = await checker.getTypeOfSymbol(property);
    if (propertyType === undefined) {
      if (failClosed) methods.push(method);
      continue;
    }
    if (await isPotentiallyCallableType(propertyType, checker)) methods.push(method);
  }
  return methods;
}

async function isPotentiallyCallableType(type: Type, checker: Checker): Promise<boolean> {
  if ((type.flags & TypeFlags.Any) !== 0
    || (await checker.getSignaturesOfType(type, SignatureKind.Call)).length > 0) return true;
  if (!type.isUnionType()) return false;
  for (const constituent of await type.getTypes()) {
    if (await isPotentiallyCallableType(constituent, checker)) return true;
  }
  return false;
}

async function isDatabaseType(type: Type, checker: Checker): Promise<boolean> {
  const runProperty = await checker.getPropertyOfType(type, "run");
  return databaseMethodDeclaration(await runProperty?.declarations[0]?.resolve()) === "run";
}

async function bindingElementDatabaseMethods(
  elements: readonly Node[],
  receiverType: Type,
  checker: Checker,
  sourceFile: SourceFile,
  failClosed = false,
): Promise<DatabaseCall["method"][]> {
  const methods: DatabaseCall["method"][] = [];
  const removedMethods = new Set<DatabaseCall["method"]>();
  for (const element of elements) {
    const binding = element as Node & {
      readonly dotDotDotToken?: Node;
      readonly name?: Node;
      readonly propertyName?: Node & { readonly text?: string };
    };
    if (binding.dotDotDotToken !== undefined) {
      methods.push(...await restExecutionMethods(binding, receiverType, checker, removedMethods));
      continue;
    }
    const resolved = await bindingExecutionMethods(binding, receiverType, checker, sourceFile, failClosed);
    methods.push(...resolved.methods);
    for (const method of resolved.methods) removedMethods.add(method);
  }
  return methods;
}

async function restExecutionMethods(
  binding: Node & { readonly expression?: Node; readonly name?: Node },
  receiverType: Type,
  checker: Checker,
  removedMethods: ReadonlySet<DatabaseCall["method"]>,
): Promise<DatabaseCall["method"][]> {
  const receiverMethods = await executionMethodsForType(receiverType, checker, true);
  const target = binding.name ?? binding.expression;
  const targetType = target === undefined ? undefined : await checker.getTypeAtLocation(target);
  const targetMethods = targetType === undefined || (targetType.flags & TypeFlags.Any) !== 0
    ? receiverMethods
    : await executionMethodsForType(targetType, checker, true);
  return targetMethods.filter((method) => receiverMethods.includes(method) && !removedMethods.has(method));
}

async function bindingExecutionMethods(
  binding: Node & {
    readonly name?: Node;
    readonly propertyName?: Node & { readonly text?: string };
  },
  receiverType: Type,
  checker: Checker,
  sourceFile: SourceFile,
  failClosed: boolean,
): Promise<{ readonly failClosed: boolean; readonly methods: DatabaseCall["method"][] }> {
  const propertyName = binding.propertyName ?? (binding.name?.kind === SyntaxKind.ComputedPropertyName
    ? binding.name as Node & { readonly text?: string }
    : undefined);
  const fallback = propertyName === undefined ? binding.name : undefined;
  const key = await resolveBindingKey(propertyName, fallback, checker, sourceFile);
  if (key === "exec" || key === "prepare" || key === "query" || key === "run") {
    if (failClosed) {
      const methods = await executionMethodsForType(receiverType, checker, true);
      return { failClosed: true, methods: methods.includes(key) ? [key] : [] };
    }
    const declaration = await (await checker.getPropertyOfType(receiverType, key))?.declarations[0]?.resolve();
    const method = databaseMethodDeclaration(declaration);
    return { failClosed: false, methods: method === undefined ? [] : [method] };
  }
  if (propertyName?.kind !== SyntaxKind.ComputedPropertyName) {
    return { failClosed, methods: [] };
  }
  const expression = (propertyName as Node & { readonly expression?: Expression }).expression;
  const keyType = expression === undefined ? undefined : await checker.getTypeAtLocation(expression);
  const keys = keyType === undefined ? undefined : await constrainedStringLiteralConstituents(keyType, checker);
  if (keys !== undefined) {
    const executionKeys = keys.filter((candidate): candidate is DatabaseCall["method"] =>
      candidate === "exec" || candidate === "prepare" || candidate === "query" || candidate === "run");
    if (executionKeys.length === 0) return { failClosed, methods: [] };
    if (failClosed) {
      const callableMethods = await executionMethodsForType(receiverType, checker, true);
      return {
        failClosed: true,
        methods: [...new Set(executionKeys.filter((method) => callableMethods.includes(method)))].sort(),
      };
    }
    const methods: DatabaseCall["method"][] = [];
    for (const executionKey of executionKeys) {
      const declaration = await (await checker.getPropertyOfType(receiverType, executionKey))?.declarations[0]?.resolve();
      const method = databaseMethodDeclaration(declaration);
      if (method !== undefined) methods.push(method);
    }
    return { failClosed: false, methods: [...new Set(methods)].sort() };
  }
  return {
    failClosed: true,
    methods: await executionMethodsForType(receiverType, checker, true),
  };
}

async function resolveBindingKey(
  propertyName: (Node & { readonly text?: string }) | undefined,
  fallback: Node | undefined,
  checker: Checker,
  sourceFile: SourceFile,
): Promise<string | undefined> {
  if (propertyName?.kind === SyntaxKind.ComputedPropertyName) {
    const expression = (propertyName as Node & { readonly expression?: Expression }).expression;
    return expression === undefined ? undefined : resolveStaticString(expression, checker, new Set<number>());
  }
  return propertyName?.text ?? propertyName?.getText(sourceFile) ?? fallback?.getText(sourceFile);
}

async function findExclusiveMigrationOwnedCallStarts(
  checker: Checker,
  sourceFile: SourceFile,
  calls: readonly CallExpression[],
  identifiers: readonly Identifier[],
): Promise<Set<number>> {
  const ownedScopes: Node[] = [];
  const helperDeclarations: Array<Node & { readonly body?: Node; readonly name?: Identifier }> = [];
  const visit = (node: Node): void => {
    if (node.kind === SyntaxKind.FunctionDeclaration) {
      helperDeclarations.push(node as Node & { readonly body?: Node; readonly name?: Identifier });
    }
    node.forEachChild(visit);
  };
  visit(sourceFile);

  for (const call of calls) {
    if (call.expression.kind !== SyntaxKind.PropertyAccessExpression
      || (call.expression as PropertyAccessExpression).name.getText(sourceFile) !== "transaction") continue;
    if (!await isDatabaseTransactionCall(call, checker)) continue;
    if (!/^migrate(?:[A-Z][A-Za-z0-9]*)?$/.test(enclosingFunctionName(call, sourceFile) ?? "")) continue;
    const callback = call.arguments[0] as (Expression & { readonly body?: Node }) | undefined;
    if (callback === undefined
      || (callback.kind !== SyntaxKind.ArrowFunction && callback.kind !== SyntaxKind.FunctionExpression)
      || callback.body?.kind !== SyntaxKind.Block) continue;
    const declaration = call.parent;
    if (declaration.kind !== SyntaxKind.VariableDeclaration
      || (declaration as VariableDeclaration).initializer !== call
      || (declaration.parent.flags & NodeFlags.Const) === 0
      || (declaration as VariableDeclaration).name.kind !== SyntaxKind.Identifier) continue;
    const name = (declaration as VariableDeclaration).name as Identifier;
    const symbol = await checker.getSymbolAtLocation(name);
    if (symbol === undefined) continue;
    const references: Identifier[] = [];
    for (const identifier of identifiers) {
      if (identifier === name || identifier.getText(sourceFile) !== name.getText(sourceFile)) continue;
      if ((await checker.getSymbolAtLocation(identifier))?.id === symbol.id) references.push(identifier);
    }
    if (references.length !== 1) continue;
    const property = references[0]!.parent;
    if (property.kind !== SyntaxKind.PropertyAccessExpression
      || (property as PropertyAccessExpression).expression !== references[0]
      || (property as PropertyAccessExpression).name.getText(sourceFile) !== "exclusive"
      || property.parent.kind !== SyntaxKind.CallExpression
      || (property.parent as CallExpression).expression !== property) continue;
    ownedScopes.push(callback);
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of helperDeclarations) {
      const name = declaration.name;
      const body = declaration.body;
      if (name === undefined || body === undefined || name.getText(sourceFile) === "migrate"
        || !/^migrate[A-Z][A-Za-z0-9]*$/.test(name.getText(sourceFile))
        || hasExportModifier(declaration)
        || ownedScopes.includes(declaration)) continue;
      const symbol = await checker.getSymbolAtLocation(name);
      if (symbol === undefined) continue;
      const references: Identifier[] = [];
      for (const identifier of identifiers) {
        if (identifier === name || identifier.getText(sourceFile) !== name.getText(sourceFile)) continue;
        if ((await checker.getSymbolAtLocation(identifier))?.id === symbol.id) references.push(identifier);
      }
      if (references.length === 0 || references.some((reference) =>
        reference.parent.kind !== SyntaxKind.CallExpression
        || (reference.parent as CallExpression).expression !== reference
        || !ownedByMigrationScope(reference.parent, ownedScopes))) continue;
      ownedScopes.push(declaration);
      changed = true;
    }
  }

  return new Set(calls
    .filter((call) => ownedByMigrationScope(call, ownedScopes))
    .map((call) => call.getStart(sourceFile)));
}

function hasExportModifier(node: Node): boolean {
  const modifiers = (node as Node & { readonly modifiers?: readonly Node[] }).modifiers ?? [];
  return modifiers.some((modifier) =>
    modifier.kind === SyntaxKind.ExportKeyword || modifier.kind === SyntaxKind.DefaultKeyword);
}

function isExportedVariableDeclaration(
  declaration: VariableDeclaration,
  aliasedExportStarts: ReadonlySet<number>,
): boolean {
  if (aliasedExportStarts.has(declaration.getStart(declaration.getSourceFile()))) return true;
  let exportedBinding = false;
  declaration.name.forEachChild(function visit(node): void {
    if (aliasedExportStarts.has(node.getStart(declaration.getSourceFile()))) exportedBinding = true;
    node.forEachChild(visit);
  });
  if (exportedBinding) return true;
  let cursor: Node | undefined = declaration.parent;
  while (cursor !== undefined && cursor.kind !== SyntaxKind.SourceFile) {
    if (cursor.kind === SyntaxKind.FunctionDeclaration || cursor.kind === SyntaxKind.FunctionExpression
      || cursor.kind === SyntaxKind.ArrowFunction || cursor.kind === SyntaxKind.MethodDeclaration) return false;
    if (hasExportModifier(cursor)) return true;
    cursor = cursor.parent;
  }
  return false;
}

async function exportedDeclarationStarts(checker: Checker, sourceFile: SourceFile): Promise<Set<number>> {
  const starts = new Set<number>();
  const exportReferences: Identifier[] = [];
  const visit = (node: Node): void => {
    if (node.kind === SyntaxKind.ExportSpecifier) {
      const specifier = node as Node & { readonly name: Identifier; readonly propertyName?: Identifier };
      exportReferences.push(specifier.propertyName ?? specifier.name);
    } else if (node.kind === SyntaxKind.ExportAssignment) {
      const expression = (node as Node & { readonly expression?: Node }).expression;
      if (expression?.kind === SyntaxKind.Identifier) exportReferences.push(expression as Identifier);
    }
    node.forEachChild(visit);
  };
  visit(sourceFile);
  for (const reference of exportReferences) {
    const symbol = await checker.getSymbolAtLocation(reference);
    if (symbol === undefined) continue;
    const resolved = symbol.declarations.some((declaration) => declaration.kind === SyntaxKind.ExportSpecifier)
      ? await checker.getAliasedSymbol(symbol) : symbol;
    for (const declaration of resolved.declarations) {
      const node = await declaration.resolve();
      if (node !== undefined && node.getSourceFile() === sourceFile) starts.add(node.getStart(sourceFile));
    }
  }
  return starts;
}

async function isDatabaseTransactionCall(call: CallExpression, checker: Checker): Promise<boolean> {
  const signature = await checker.getResolvedSignature(call);
  const declaration = await signature?.declaration?.resolve();
  return databaseDeclarationName(declaration) === "transaction";
}

function enclosingFunctionName(node: Node, sourceFile: SourceFile): string | undefined {
  let current: Node | undefined = node.parent;
  while (current !== undefined && current !== sourceFile) {
    if (current.kind === SyntaxKind.FunctionDeclaration) {
      return (current as Node & { readonly name?: Identifier }).name?.getText(sourceFile);
    }
    current = current.parent;
  }
  return undefined;
}

function ownedByMigrationScope(node: Node, scopes: readonly Node[]): boolean {
  let current: Node | undefined = node.parent;
  while (current !== undefined) {
    if (isFunctionScope(current)) return scopes.includes(current);
    current = current.parent;
  }
  return false;
}

function isFunctionScope(node: Node): boolean {
  return node.kind === SyntaxKind.ArrowFunction
    || node.kind === SyntaxKind.FunctionDeclaration
    || node.kind === SyntaxKind.FunctionExpression
    || node.kind === SyntaxKind.MethodDeclaration
    || node.kind === SyntaxKind.GetAccessor
    || node.kind === SyntaxKind.SetAccessor
    || node.kind === SyntaxKind.Constructor;
}

async function databaseMethodReferences(
  expression: Expression,
  checker: Checker,
  databaseType?: Type,
): Promise<DatabaseMethodReference> {
  if (databaseType !== undefined && (expression.kind === SyntaxKind.PropertyAccessExpression
    || expression.kind === SyntaxKind.ElementAccessExpression)) {
    const methods = await widenedDatabaseExecutionMethods(
      expression as PropertyAccessExpression | ElementAccessExpression,
      checker,
      databaseType,
      expression.getSourceFile(),
    );
    if (methods.length > 0) return { failClosed: true, methods };
  }
  let symbol;
  if (expression.kind === SyntaxKind.PropertyAccessExpression) {
    symbol = await checker.getSymbolAtLocation(expression);
  } else {
    const element = expression as ElementAccessExpression;
    const receiverType = await checker.getTypeAtLocation(element.expression);
    if (receiverType === undefined) return { failClosed: false, methods: [] };
    const keyType = await checker.getTypeAtLocation(element.argumentExpression);
    if (keyType === undefined) return { failClosed: false, methods: [] };
    const keys = await constrainedStringLiteralConstituents(keyType, checker);
    if (keys === undefined && await isDatabaseType(receiverType, checker)) {
      return { failClosed: true, methods: ["exec", "prepare", "query", "run"] };
    }
    if (keys !== undefined && keys.length > 0) {
      const executionKeys = keys.filter((key) =>
        key === "exec" || key === "prepare" || key === "query" || key === "run");
      if (executionKeys.length > 0 && executionKeys.length !== keys.length
        && await isDatabaseType(receiverType, checker)) {
        return { failClosed: true, methods: ["exec", "prepare", "query", "run"] };
      }
      const methods: DatabaseCall["method"][] = [];
      for (const key of executionKeys) {
        const property = await checker.getPropertyOfType(receiverType, key);
        const declaration = await property?.declarations[0]?.resolve();
        const method = databaseMethodDeclaration(declaration);
        if (method === undefined) return { failClosed: false, methods: [] };
        methods.push(method);
      }
      if (methods.length > 0) return { failClosed: false, methods: [...new Set(methods)].sort() };
    }
    const expressionType = await checker.getTypeAtLocation(element);
    if (expressionType === undefined) return { failClosed: false, methods: [] };
    const methods: DatabaseCall["method"][] = [];
    const signatures = await checker.getSignaturesOfType(expressionType, 0);
    for (const signature of signatures) {
      const declaration = await signature.declaration?.resolve();
      const method = databaseMethodDeclaration(declaration);
      if (method !== undefined) methods.push(method);
    }
    return { failClosed: false, methods: [...new Set(methods)].sort() };
  }
  const declaration = await symbol?.declarations[0]?.resolve();
  const method = databaseMethodDeclaration(declaration);
  return { failClosed: false, methods: method === undefined ? [] : [method] };
}

async function stringLiteralConstituents(type: Type): Promise<string[] | undefined> {
  if (type.isStringLiteralType()) return [type.value];
  if (!type.isUnionType()) return undefined;
  const values: string[] = [];
  for (const candidate of await type.getTypes()) {
    const literals = await stringLiteralConstituents(candidate);
    if (literals === undefined) return undefined;
    values.push(...literals);
  }
  return [...new Set(values)];
}

async function constrainedStringLiteralConstituents(
  type: Type,
  checker: Checker,
): Promise<string[] | undefined> {
  const direct = await stringLiteralConstituents(type);
  if (direct !== undefined) return direct;
  const constraint = await checker.getBaseConstraintOfType(type);
  return constraint === undefined ? undefined : stringLiteralConstituents(constraint);
}

function databaseMethodDeclaration(declaration: Node | undefined): DatabaseCall["method"] | undefined {
  const method = databaseDeclarationName(declaration);
  return method === "exec" || method === "prepare" || method === "query" || method === "run"
    ? method : undefined;
}

function databaseDeclarationName(declaration: Node | undefined): string | undefined {
  const owner = declaration?.parent;
  if (declaration === undefined || owner?.kind !== SyntaxKind.ClassDeclaration
    || (owner as Node & { readonly name?: { getText(source: SourceFile): string } })
      .name?.getText(owner.getSourceFile()) !== "Database"
    || !declaration.getSourceFile().fileName.endsWith("/bun-types/sqlite.d.ts")) return undefined;
  return (declaration as Node & { readonly name?: { getText(source: SourceFile): string } })
    .name?.getText(declaration.getSourceFile());
}

async function isApprovedConnectionSetupCall(
  call: CallExpression,
  sourceFile: SourceFile,
  sql: string | undefined,
  checker: Checker,
  identifiers: readonly Identifier[],
): Promise<boolean> {
  const argument = call.arguments[0];
  if (sql === undefined || argument === undefined || !CONNECTION_PRAGMAS.has(sql.trim())
    || (argument.kind !== SyntaxKind.StringLiteral
      && argument.kind !== SyntaxKind.NoSubstitutionTemplateLiteral)) return false;
  const declaration = nearestFunctionDeclaration(call);
  const functionName = declaration === undefined
    ? undefined
    : (declaration as Node & { readonly name?: Identifier }).name?.getText(sourceFile);
  if (functionName === "openDatabase") {
    if (sql.trim() === "PRAGMA journal_mode = WAL") return false;
    const statement = call.parent;
    const block = statement.parent;
    const tryStatement = block?.parent;
    const body = (declaration as Node & { readonly body?: Node }).body;
    return statement.kind === SyntaxKind.ExpressionStatement
      && block?.kind === SyntaxKind.Block
      && tryStatement?.kind === SyntaxKind.TryStatement
      && (tryStatement as Node & { readonly tryBlock?: Node }).tryBlock === block
      && tryStatement.parent === body;
  }
  if (declaration === undefined || functionName !== "enableWal" || sql.trim() !== "PRAGMA journal_mode = WAL"
    || !await hasOnlyApprovedEnableWalCallers(declaration, checker, identifiers, sourceFile)) return false;
  const body = (declaration as Node & { readonly body?: Node }).body;
  let cursor: Node | undefined = call.parent;
  let hasReturn = false;
  while (cursor !== undefined && cursor !== body) {
    if (cursor.kind === SyntaxKind.ReturnStatement) hasReturn = true;
    if (cursor.kind === SyntaxKind.IfStatement || cursor.kind === SyntaxKind.SwitchStatement
      || cursor.kind === SyntaxKind.ConditionalExpression || cursor.kind === SyntaxKind.WhileStatement
      || cursor.kind === SyntaxKind.DoStatement) return false;
    cursor = cursor.parent;
  }
  return cursor === body && hasReturn;
}

async function hasOnlyApprovedEnableWalCallers(
  declaration: Node,
  checker: Checker,
  identifiers: readonly Identifier[],
  sourceFile: SourceFile,
): Promise<boolean> {
  const name = (declaration as Node & { readonly name?: Identifier }).name;
  if (name === undefined) return false;
  const symbol = await checker.getSymbolAtLocation(name);
  if (symbol === undefined) return false;
  const references: Identifier[] = [];
  for (const identifier of identifiers) {
    if (identifier === name || identifier.getText(sourceFile) !== name.getText(sourceFile)) continue;
    if ((await checker.getSymbolAtLocation(identifier))?.id === symbol.id) references.push(identifier);
  }
  if (references.length !== 1) return false;
  const reference = references[0]!;
  if (reference.parent.kind !== SyntaxKind.CallExpression
    || (reference.parent as CallExpression).expression !== reference
    || enclosingFunctionName(reference, sourceFile) !== "openDatabase") return false;
  const callerStatement = directStatementInFunctionTry(reference.parent, sourceFile, "openDatabase");
  if (callerStatement === undefined) return false;
  const migrateDeclaration = identifiers.find((identifier) =>
    identifier.getText(sourceFile) === "migrate"
    && identifier.parent.kind === SyntaxKind.FunctionDeclaration
    && (identifier.parent as Node & { readonly name?: Identifier }).name === identifier);
  const migrateSymbol = migrateDeclaration === undefined
    ? undefined : await checker.getSymbolAtLocation(migrateDeclaration);
  if (migrateSymbol === undefined) return false;
  let migrateCall: Identifier | undefined;
  for (const identifier of identifiers) {
    if (identifier === migrateDeclaration || identifier.getText(sourceFile) !== "migrate"
      || identifier.parent.kind !== SyntaxKind.CallExpression
      || (identifier.parent as CallExpression).expression !== identifier
      || directStatementInFunctionTry(identifier.parent, sourceFile, "openDatabase")?.parent !== callerStatement.parent) {
      continue;
    }
    if ((await checker.getSymbolAtLocation(identifier))?.id === migrateSymbol.id) {
      migrateCall = identifier;
      break;
    }
  }
  return migrateCall !== undefined && migrateCall.parent.getStart(sourceFile) < callerStatement.getStart(sourceFile);
}

function directStatementInFunctionTry(
  node: Node,
  sourceFile: SourceFile,
  functionName: string,
): Node | undefined {
  let cursor: Node | undefined = node;
  while (cursor !== undefined && cursor.parent.kind !== SyntaxKind.Block) cursor = cursor.parent;
  if (cursor === undefined || cursor.parent.parent.kind !== SyntaxKind.TryStatement) return undefined;
  const tryStatement = cursor.parent.parent as Node & { readonly tryBlock?: Node };
  if (tryStatement.tryBlock !== cursor.parent || enclosingFunctionName(cursor, sourceFile) !== functionName) return undefined;
  return cursor;
}

function nearestFunctionDeclaration(node: Node): Node | undefined {
  let cursor: Node | undefined = node.parent;
  while (cursor !== undefined && cursor.kind !== SyntaxKind.SourceFile) {
    if (cursor.kind === SyntaxKind.FunctionDeclaration) return cursor;
    if (cursor.kind === SyntaxKind.FunctionExpression || cursor.kind === SyntaxKind.ArrowFunction
      || cursor.kind === SyntaxKind.MethodDeclaration) return undefined;
    cursor = cursor.parent;
  }
  return undefined;
}

function findConventionDatabaseCalls(text: string): DatabaseCall[] {
  return findCallCandidates(text).map((candidate) => ({
    approvedConnectionSetup: false,
    argumentStart: candidate.argumentStart,
    computed: candidate.computed,
    end: candidate.start,
    hasStaticArgument: hasCompleteStaticSqlArgument(text, candidate.argumentStart),
    method: candidate.method,
    migrationOwned: false,
    staticSql: readStaticSqlArgument(text, candidate.argumentStart),
    start: candidate.start,
  }));
}

function enclosingStatementEnd(node: Node): number {
  let cursor = node;
  while (cursor.parent.kind !== SyntaxKind.Block && cursor.parent.kind !== SyntaxKind.SourceFile) {
    cursor = cursor.parent;
  }
  return cursor.getEnd();
}

async function resolveStaticString(
  expression: Expression,
  checker: Checker,
  seenSymbols: Set<number>,
): Promise<string | undefined> {
  if (expression.kind === SyntaxKind.StringLiteral
    || expression.kind === SyntaxKind.NoSubstitutionTemplateLiteral) {
    return (expression as Expression & { readonly text: string }).text;
  }
  if (expression.kind === SyntaxKind.TemplateExpression) {
    const template = expression as TemplateExpression;
    let result = template.head.text;
    for (const span of template.templateSpans) {
      const value = await resolveStaticPrimitive(span.expression, checker, seenSymbols);
      if (value === undefined) return undefined;
      result += String(value) + span.literal.text;
    }
    return result;
  }
  if (expression.kind !== SyntaxKind.Identifier) return undefined;
  const symbol = await checker.getSymbolAtLocation(expression);
  if (symbol === undefined || seenSymbols.has(symbol.id)) return undefined;
  seenSymbols.add(symbol.id);
  try {
    if (symbol.declarations.length !== 1) return undefined;
    const declaration = await symbol.declarations[0]!.resolve();
    if (declaration?.kind !== SyntaxKind.VariableDeclaration
      || (declaration.parent.flags & NodeFlags.Const) === 0) return undefined;
    const initializer = (declaration as VariableDeclaration).initializer;
    if (initializer === undefined) return undefined;
    const value = await resolveStaticPrimitive(initializer, checker, seenSymbols);
    return value === undefined ? undefined : String(value);
  } finally {
    seenSymbols.delete(symbol.id);
  }
}

async function resolveStaticPrimitive(
  expression: Expression,
  checker: Checker,
  seenSymbols: Set<number>,
): Promise<string | number | undefined> {
  if (expression.kind === SyntaxKind.NumericLiteral) {
    return Number((expression as Expression & { readonly text: string }).text);
  }
  return resolveStaticString(expression, checker, seenSymbols);
}

function findCallCandidates(text: string): Array<{
  readonly argumentStart: number;
  readonly computed: boolean;
  readonly method: DatabaseCall["method"];
  readonly methodStart: number;
  readonly start: number;
}> {
  const calls: Array<{
    readonly argumentStart: number;
    readonly computed: boolean;
    readonly method: DatabaseCall["method"];
    readonly methodStart: number;
    readonly start: number;
  }> = [];
  const nonCodeRanges = lexicalNonCodeRanges(text);
  const pattern = /(?:\.\s*(exec|prepare|query|run)\b|\[\s*["'](exec|prepare|query|run)["']\s*\])/g;
  for (const match of text.matchAll(pattern)) {
    if (nonCodeRanges.some(({ end, start }) => match.index! >= start && match.index! < end)) continue;
    const method = (match[1] ?? match[2]) as DatabaseCall["method"];
    const methodOffset = match[0].indexOf(method);
    let cursor = match.index! + match[0].length;
    let genericDepth = 0;
    while (cursor < text.length) {
      const char = text[cursor]!;
      if (char === "<") genericDepth += 1;
      else if (char === ">" && genericDepth > 0) genericDepth -= 1;
      else if (char === "(" && genericDepth === 0) break;
      else if (!/\s/.test(char) && genericDepth === 0) break;
      cursor += 1;
    }
    if (text[cursor] !== "(") continue;
    calls.push({
      argumentStart: cursor + 1,
      computed: match[1] === undefined,
      method,
      methodStart: match.index! + methodOffset,
      start: match.index!,
    });
  }
  return calls;
}

function lexicalNonCodeRanges(text: string): Array<{ readonly end: number; readonly start: number }> {
  const ranges: Array<{ readonly end: number; readonly start: number }> = [];
  const templateExpressionDepths: number[] = [];
  const scanner = createScanner(false, undefined, text);
  let previousToken: SyntaxKind | undefined;
  const controlParens: boolean[] = [];
  const statementBlockBraces: boolean[] = [];
  let closedControlParen = false;
  let closedStatementBlock = false;
  let declarationBlockPending = false;
  let statementStart = true;
  for (let token = scanner.scan(); token !== SyntaxKind.EndOfFile; token = scanner.scan()) {
    if ((token === SyntaxKind.SlashToken || token === SyntaxKind.SlashEqualsToken)
      && (closedControlParen || closedStatementBlock || !canEndExpression(previousToken))) {
      token = scanner.reScanSlashToken();
    }
    if (token === SyntaxKind.TemplateHead) templateExpressionDepths.push(0);
    else if (token === SyntaxKind.OpenBraceToken && templateExpressionDepths.length > 0) {
      templateExpressionDepths[templateExpressionDepths.length - 1]! += 1;
    } else if (token === SyntaxKind.CloseBraceToken && templateExpressionDepths.length > 0) {
      const last = templateExpressionDepths.length - 1;
      if (templateExpressionDepths[last] === 0) {
        token = scanner.reScanTemplateToken(false);
        if (token === SyntaxKind.TemplateTail) templateExpressionDepths.pop();
      } else templateExpressionDepths[last]! -= 1;
    }
    if (token === SyntaxKind.SingleLineCommentTrivia
      || token === SyntaxKind.MultiLineCommentTrivia
      || token === SyntaxKind.StringLiteral
      || token === SyntaxKind.NoSubstitutionTemplateLiteral
      || token === SyntaxKind.TemplateHead
      || token === SyntaxKind.TemplateMiddle
      || token === SyntaxKind.TemplateTail
      || token === SyntaxKind.RegularExpressionLiteral) {
      ranges.push({ end: scanner.getTokenEnd(), start: scanner.getTokenStart() });
    }
    if (token !== SyntaxKind.WhitespaceTrivia && token !== SyntaxKind.NewLineTrivia
      && token !== SyntaxKind.SingleLineCommentTrivia && token !== SyntaxKind.MultiLineCommentTrivia) {
      const followsControlParen = closedControlParen;
      const wasStatementStart: boolean = statementStart;
      if ((token === SyntaxKind.FunctionKeyword || token === SyntaxKind.ClassKeyword) && wasStatementStart) {
        declarationBlockPending = true;
      }
      if (token === SyntaxKind.OpenParenToken) {
        controlParens.push(previousToken === SyntaxKind.IfKeyword
          || previousToken === SyntaxKind.WhileKeyword
          || previousToken === SyntaxKind.ForKeyword
          || previousToken === SyntaxKind.WithKeyword
          || previousToken === SyntaxKind.SwitchKeyword
          || previousToken === SyntaxKind.CatchKeyword);
      } else if (token === SyntaxKind.CloseParenToken) closedControlParen = controlParens.pop() ?? false;
      else closedControlParen = false;
      if (token === SyntaxKind.OpenBraceToken) {
        const statementBlock: boolean = followsControlParen
          || wasStatementStart
          || (declarationBlockPending && controlParens.length === 0)
          || previousToken === SyntaxKind.ElseKeyword
          || previousToken === SyntaxKind.DoKeyword
          || previousToken === SyntaxKind.TryKeyword
          || previousToken === SyntaxKind.FinallyKeyword;
        statementBlockBraces.push(statementBlock);
        if (declarationBlockPending && controlParens.length === 0) declarationBlockPending = false;
        closedStatementBlock = false;
        statementStart = statementBlock;
      } else if (token === SyntaxKind.CloseBraceToken) {
        closedStatementBlock = statementBlockBraces.pop() ?? false;
        statementStart = closedStatementBlock;
      } else {
        closedStatementBlock = false;
        statementStart = token === SyntaxKind.SemicolonToken
          || (wasStatementStart && isDeclarationModifier(token));
      }
      previousToken = token;
    }
  }
  return ranges;
}

function isDeclarationModifier(token: SyntaxKind): boolean {
  return token === SyntaxKind.ExportKeyword
    || token === SyntaxKind.DefaultKeyword
    || token === SyntaxKind.AsyncKeyword
    || token === SyntaxKind.DeclareKeyword
    || token === SyntaxKind.AbstractKeyword;
}

function canEndExpression(token: SyntaxKind | undefined): boolean {
  return token === SyntaxKind.Identifier
    || token === SyntaxKind.PrivateIdentifier
    || token === SyntaxKind.NumericLiteral
    || token === SyntaxKind.BigIntLiteral
    || token === SyntaxKind.StringLiteral
    || token === SyntaxKind.NoSubstitutionTemplateLiteral
    || token === SyntaxKind.TemplateTail
    || token === SyntaxKind.TrueKeyword
    || token === SyntaxKind.FalseKeyword
    || token === SyntaxKind.NullKeyword
    || token === SyntaxKind.ThisKeyword
    || token === SyntaxKind.SuperKeyword
    || token === SyntaxKind.CloseParenToken
    || token === SyntaxKind.CloseBracketToken
    || token === SyntaxKind.CloseBraceToken
    || token === SyntaxKind.PlusPlusToken
    || token === SyntaxKind.MinusMinusToken;
}

function readStaticSqlArgument(text: string, afterOpenParen: number): string | undefined {
  let cursor = afterOpenParen;
  while (/\s/.test(text[cursor] ?? "")) cursor += 1;
  const quote = text[cursor];
  if (quote === "'" || quote === '"') {
    const end = findQuotedEnd(text, cursor, quote);
    if (text.slice(cursor + 1, end - 1).includes("\\")) return undefined;
    return text.slice(cursor + 1, end - 1);
  }
  if (quote === "`") {
    const end = findTemplateEnd(text, cursor);
    if (templateHasInterpolation(text, cursor, end) || text.slice(cursor + 1, end).includes("\\")) return undefined;
    return text.slice(cursor + 1, end);
  }
  return undefined;
}

function hasCompleteStaticSqlArgument(text: string, afterOpenParen: number): boolean {
  let cursor = afterOpenParen;
  while (/\s/.test(text[cursor] ?? "")) cursor += 1;
  const quote = text[cursor];
  let end: number;
  if (quote === "'" || quote === '"') {
    end = findQuotedEnd(text, cursor, quote);
    if (text.slice(cursor + 1, end - 1).includes("\\")) return false;
  } else if (quote === "`") {
    const close = findTemplateEnd(text, cursor);
    if (templateHasInterpolation(text, cursor, close)
      || text.slice(cursor + 1, close).includes("\\")) return false;
    end = close + 1;
  } else return false;
  while (/\s/.test(text[end] ?? "")) end += 1;
  return text[end] === "," || text[end] === ")";
}

function templateHasInterpolation(text: string, start: number, end: number): boolean {
  for (let index = start + 1; index < end; index += 1) {
    if (text[index] === "\\") index += 1;
    else if (text[index] === "$" && text[index + 1] === "{") return true;
  }
  return false;
}

function findTemplateEnd(text: string, start: number): number {
  let interpolationDepth = 0;
  for (let index = start + 1; index < text.length;) {
    if (text[index] === "\\") {
      index += 2;
      continue;
    }
    if (interpolationDepth === 0) {
      if (text[index] === "`") return index;
      if (text[index] === "$" && text[index + 1] === "{") {
        interpolationDepth = 1;
        index += 2;
        continue;
      }
      index += 1;
      continue;
    }
    const skipped = skipQuotedOrComment(text, index);
    if (skipped !== index) {
      index = skipped;
      continue;
    }
    if (text[index] === "`") {
      index = findTemplateEnd(text, index) + 1;
      continue;
    }
    if (text[index] === "{") interpolationDepth += 1;
    else if (text[index] === "}") interpolationDepth -= 1;
    index += 1;
  }
  throw new Error(`Unterminated template literal at byte ${start}`);
}

function skipQuotedOrComment(text: string, start: number): number {
  const quote = text[start];
  if (quote === "'" || quote === '"') {
    return findQuotedEnd(text, start, quote);
  }
  if (text[start] === "/" && text[start + 1] === "/") {
    const end = text.indexOf("\n", start + 2);
    return end === -1 ? text.length : end + 1;
  }
  if (text[start] === "/" && text[start + 1] === "*") {
    const end = text.indexOf("*/", start + 2);
    if (end === -1) throw new Error(`Unterminated block comment at byte ${start}`);
    return end + 2;
  }
  return start;
}

function findQuotedEnd(text: string, start: number, quote: string): number {
  for (let index = start + 1; index < text.length; index += 1) {
    if (text[index] === "\\") index += 1;
    else if (text[index] === quote) return index + 1;
  }
  throw new Error(`Unterminated string literal at byte ${start}`);
}

function findFunctionBodies(
  text: string,
  acceptedName: RegExp,
  required = true,
): Array<{ readonly end: number; readonly start: number }> {
  const masked = maskNonCode(text);
  const signatures = [...masked.matchAll(/\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)]
    .filter((match) => acceptedName.test(match[1]!));
  if (required && signatures.length === 0) throw new Error(`Missing accepted function body`);
  return signatures.map((signature) => findBodyEnd(masked, signature.index! + signature[0].length));
}

function findBodyEnd(masked: string, afterSignature: number): { readonly end: number; readonly start: number } {
  const start = masked.indexOf("{", afterSignature);
  if (start === -1) throw new Error(`Missing function body at byte ${afterSignature}`);
  let depth = 0;
  for (let index = start; index < masked.length; index += 1) {
    if (masked[index] === "{") depth += 1;
    else if (masked[index] === "}" && --depth === 0) return { start, end: index };
  }
  throw new Error(`Unterminated function body at byte ${start}`);
}

function maskNonCode(text: string): string {
  const output = [...text];
  for (const { end, start } of lexicalNonCodeRanges(text)) {
    for (let cursor = start; cursor < end; cursor += 1) output[cursor] = " ";
  }
  for (let index = 0; index < text.length;) {
    const skipped = skipQuotedOrComment(text, index);
    const end = text[index] === "`" ? findTemplateEnd(text, index) + 1 : skipped;
    if (end !== index) {
      for (let cursor = index; cursor < end; cursor += 1) output[cursor] = " ";
      index = end;
    } else index += 1;
  }
  return output.join("");
}

function byId(left: { readonly id: string }, right: { readonly id: string }): number {
  return left.id.localeCompare(right.id);
}

async function sourceTypeScriptFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceTypeScriptFiles(path);
    return entry.isFile() && entry.name.endsWith(".ts") ? [path] : [];
  }));
  return paths.flat();
}

function resolveOwnerScope(sourceFile: SourceFile, frame: string): string {
  const match = /^(.*):(\d+)$/.exec(frame);
  if (match === null || !sourceFile.fileName.endsWith(`/${match[1]}`)) {
    throw new Error(`Owner frame ${frame} does not belong to ${sourceFile.fileName}`);
  }
  const position = sourceFile.getPositionOfLineAndCharacter(Number(match[2]) - 1, 0);
  let className: string | undefined;
  let methodName: string | undefined;
  const visit = (node: Node): void => {
    if (node.getFullStart() > position || position >= node.getEnd()) return;
    if (node.kind === SyntaxKind.ClassDeclaration) {
      className = (node as Node & { readonly name?: { getText(source: SourceFile): string } }).name?.getText(sourceFile);
    } else if (node.kind === SyntaxKind.Constructor) {
      methodName = "constructor";
    } else if (node.kind === SyntaxKind.MethodDeclaration) {
      methodName = (node as Node & { readonly name?: { getText(source: SourceFile): string } }).name?.getText(sourceFile);
    }
    node.forEachChild(visit);
  };
  visit(sourceFile);
  if (className === undefined || methodName === undefined) {
    throw new Error(`Owner frame ${frame} is not inside a class method`);
  }
  return `${className}.${methodName}`;
}

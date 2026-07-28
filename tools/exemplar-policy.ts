import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { API } from "typescript/unstable/async";
import {
  LanguageVariant,
  SyntaxKind,
  createScanner,
  isArrowFunction,
  isAsExpression,
  isBlock,
  isCallExpression,
  isExportDeclaration,
  isExportAssignment,
  isFunctionDeclaration,
  isFunctionExpression,
  isIdentifier,
  isImportDeclaration,
  isNamedExports,
  isNamedImports,
  isNamespaceImport,
  isNonNullExpression,
  isParenthesizedExpression,
  isPropertyAccessExpression,
  isStringLiteral,
  isSatisfiesExpression,
  isTypeAssertion,
  isVariableStatement,
  type Expression,
  type ModifiersBase,
  type Node,
  type SourceFile,
} from "typescript/unstable/ast";

export type ExemplarFinding = {
  readonly kind: "boundary" | "marker" | "test-focus" | "empty-export" | "trust";
  readonly path: string;
  readonly detail: string;
};

const exactExtensionPaths = new Set([
  "service/handler.ts",
  "service/input.schema.json",
  "service/output.schema.json",
  "service/service.config.ts",
]);
const extensionPrefixes = ["service/fixtures/"] as const;
const proofPaths = [
  "scripts/verify-exemplar-diff.ts",
  "scripts/scan-critical-placeholders.ts",
  "tools/exemplar-policy.ts",
  "test/exemplar/extension-boundary.test.ts",
] as const;
const markerPattern = /\b(?:TODO|FIXME|XXX)\b/;
const testRoots = new Set(["describe", "it", "test", "xdescribe", "xit", "xtest"]);
const forbiddenTestMembers = new Set(["if", "only", "skip", "todo", "skipIf", "todoIf"]);

type TreeEntry = { readonly mode: string; readonly type: string; readonly object: string; readonly path: string };

function git(repository: string, args: readonly string[]): string {
  const result = spawnSync("git", args, {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} exited ${result.status}: ${result.stderr.trim()}`);
  }
  return result.stdout;
}

function exactCommit(repository: string, revision: string): string {
  if (!/^[0-9a-f]{40}$/.test(revision)) throw new Error(`not an exact commit: ${revision}`);
  const resolved = git(repository, ["rev-parse", "--verify", `${revision}^{commit}`]).trim();
  if (resolved !== revision) throw new Error(`commit did not resolve exactly: ${revision}`);
  return resolved;
}

function treeEntries(repository: string, revision: string): readonly TreeEntry[] {
  return git(repository, ["ls-tree", "-r", "-z", "--full-tree", revision])
    .split("\0")
    .filter(Boolean)
    .map((record) => {
      const match = /^(\d+) (\w+) [0-9a-f]+\t(.+)$/.exec(record);
      if (!match) throw new Error(`invalid git tree record: ${record}`);
      const object = record.slice(record.indexOf(" ", record.indexOf(" ") + 1) + 1, record.indexOf("\t"));
      return { mode: match[1]!, type: match[2]!, object, path: match[3]! };
    });
}

function isExtensionPath(path: string): boolean {
  return exactExtensionPaths.has(path)
    || extensionPrefixes.some((prefix) =>
      path.startsWith(prefix)
      && path.length > prefix.length
      && (path.endsWith(".ts") || path.endsWith(".json"))
    );
}

function isCriticalPath(path: string): boolean {
  if (proofPaths.includes(path as (typeof proofPaths)[number])) return false;
  if (path === "Dockerfile" || path === "package.json") return true;
  return ["scripts/", "service/", "src/", "test/"].some((prefix) => path.startsWith(prefix))
    && (path.endsWith(".ts") || path.endsWith(".json"));
}

function blobText(repository: string, revision: string, path: string): string {
  return git(repository, ["show", `${revision}:${path}`]);
}

function commentMarkers(path: string, text: string): readonly ExemplarFinding[] {
  if (!path.endsWith(".ts")) {
    return markerPattern.test(text) ? [{ kind: "marker", path, detail: "forbidden critical marker" }] : [];
  }
  const scanner = createScanner(false, LanguageVariant.Standard, text);
  const findings: ExemplarFinding[] = [];
  for (let token = scanner.scan(); token !== SyntaxKind.EndOfFile; token = scanner.scan()) {
    if (
      (token === SyntaxKind.SingleLineCommentTrivia || token === SyntaxKind.MultiLineCommentTrivia)
      && markerPattern.test(scanner.getTokenText())
    ) {
      findings.push({ kind: "marker", path, detail: "forbidden critical marker in comment" });
    }
  }
  return findings;
}

function callParts(expression: Expression): { readonly roots: Set<string>; readonly members: Set<string> } {
  const roots = new Set<string>();
  const members = new Set<string>();
  const visit = (node: Node): void => {
    if (isIdentifier(node)) roots.add(node.text);
    if (isPropertyAccessExpression(node)) members.add(node.name.text);
    node.forEachChild(visit);
  };
  visit(expression);
  return { roots, members };
}

function hasModifier(node: ModifiersBase, kind: SyntaxKind): boolean {
  return node.modifiers?.some((modifier) => modifier.kind === kind) ?? false;
}

function unwrapTransparentExpression(expression: Expression): Expression {
  let current = expression;
  while (
    (
      isParenthesizedExpression(current)
      || isAsExpression(current)
      || isSatisfiesExpression(current)
      || isTypeAssertion(current)
      || isNonNullExpression(current)
    )
  ) current = current.expression;
  return current;
}

function isEmptyFunction(expression: Expression | undefined): boolean {
  if (expression === undefined) return false;
  const current = unwrapTransparentExpression(expression);
  return (isArrowFunction(current) || isFunctionExpression(current))
    && isBlock(current.body)
    && current.body.statements.length === 0;
}

function typescriptFindings(path: string, source: SourceFile): readonly ExemplarFinding[] {
  const findings: ExemplarFinding[] = [];
  const namedExports = new Set<string>();
  const localTestRoots = new Set(testRoots);
  const disabledTestRoots = new Set(["xdescribe", "xit", "xtest"]);
  const testNamespaces = new Set<string>();
  for (const statement of source.statements) {
    if (isExportDeclaration(statement) && !statement.moduleSpecifier && statement.exportClause && isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) namedExports.add((element.propertyName ?? element.name).text);
    }
    if (isExportAssignment(statement)) {
      const exportedExpression = unwrapTransparentExpression(statement.expression);
      if (isIdentifier(exportedExpression)) namedExports.add(exportedExpression.text);
    }
    if (
      isImportDeclaration(statement)
      && isStringLiteral(statement.moduleSpecifier)
      && statement.moduleSpecifier.text === "bun:test"
    ) {
      const bindings = statement.importClause?.namedBindings;
      if (bindings && isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          const importedName = (element.propertyName ?? element.name).text;
          if (testRoots.has(importedName)) localTestRoots.add(element.name.text);
          if (["xdescribe", "xit", "xtest"].includes(importedName)) disabledTestRoots.add(element.name.text);
        }
      } else if (bindings && isNamespaceImport(bindings)) {
        testNamespaces.add(bindings.name.text);
      }
    }
  }

  const exported = (node: ModifiersBase, name: string | undefined): boolean =>
    hasModifier(node, SyntaxKind.ExportKeyword) || (name !== undefined && namedExports.has(name));

  const visit = (node: Node): void => {
    if (isCallExpression(node)) {
      const parts = callParts(node.expression);
      if ([...parts.roots].some((root) => disabledTestRoots.has(root))) {
        findings.push({ kind: "test-focus", path, detail: "disabled test root" });
      } else if (
        (
          [...parts.roots].some((root) => localTestRoots.has(root))
          || (
            [...parts.roots].some((root) => testNamespaces.has(root))
            && [...parts.members].some((member) => testRoots.has(member))
          )
        )
        && [...parts.members].some((member) => forbiddenTestMembers.has(member))
      ) {
        const modifiers = [...parts.members].filter((member) => forbiddenTestMembers.has(member)).sort();
        findings.push({ kind: "test-focus", path, detail: `focused or skipped test call: ${modifiers.join(",")}` });
      }
    }

    if (isFunctionDeclaration(node) && node.body?.statements.length === 0 && exported(node, node.name?.text)) {
      findings.push({ kind: "empty-export", path, detail: `empty exported function ${node.name?.text ?? "default"}` });
    }
    if (isExportAssignment(node) && isEmptyFunction(node.expression)) {
      findings.push({ kind: "empty-export", path, detail: "empty default-exported function" });
    }
    if (isVariableStatement(node) && hasModifier(node, SyntaxKind.ExportKeyword)) {
      for (const declaration of node.declarationList.declarations) {
        if (isIdentifier(declaration.name) && isEmptyFunction(declaration.initializer)) {
          findings.push({ kind: "empty-export", path, detail: `empty exported function ${declaration.name.text}` });
        }
      }
    }
    if (isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (isIdentifier(declaration.name) && namedExports.has(declaration.name.text) && isEmptyFunction(declaration.initializer)) {
          findings.push({ kind: "empty-export", path, detail: `empty exported function ${declaration.name.text}` });
        }
      }
    }
    node.forEachChild(visit);
  };
  visit(source);
  return [...new Map(findings.map((finding) => [
    `${finding.kind}\0${finding.path}\0${finding.detail}`,
    finding,
  ])).values()];
}

export function verifyExtensionDelta(repository: string, baseRevision: string, tipRevision: string): readonly ExemplarFinding[] {
  const base = exactCommit(repository, baseRevision);
  const tip = exactCommit(repository, tipRevision);
  const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", base, tip], {
    cwd: repository,
    env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" },
  });
  if (ancestor.status !== 0) return [{ kind: "boundary", path: ".", detail: "tip does not descend from exact base" }];

  const changed = git(repository, ["diff", "--no-renames", "--name-only", "-z", base, tip, "--"])
    .split("\0").filter(Boolean).sort();
  const findings: ExemplarFinding[] = changed
    .filter((path) => !isExtensionPath(path))
    .map((path) => ({ kind: "boundary", path, detail: "path is outside the declared extension surface" }));

  const baseEntries = new Map(treeEntries(repository, base).map((entry) => [entry.path, entry]));
  const entries = new Map(treeEntries(repository, tip).map((entry) => [entry.path, entry]));
  const blobChanged = (path: string): boolean => {
    const before = baseEntries.get(path);
    const after = entries.get(path);
    return before?.type === "blob" && after?.type === "blob" && before.object !== after.object;
  };

  if (!blobChanged("service/handler.ts")) {
    findings.push({ kind: "boundary", path: "service/handler.ts", detail: "fresh exemplar must change service logic" });
  }
  if (!changed.some((path) =>
    (path === "service/input.schema.json" || path === "service/output.schema.json" || path.startsWith("service/fixtures/"))
    && blobChanged(path)
  )) {
    findings.push({ kind: "boundary", path: "service/", detail: "fresh exemplar must change schema or fixtures" });
  }

  for (const path of changed.filter(isExtensionPath)) {
    const entry = entries.get(path);
    if (!entry) {
      findings.push({ kind: "boundary", path, detail: "extension path was deleted" });
    } else if (entry.type !== "blob" || (entry.mode !== "100644" && entry.mode !== "100755")) {
      findings.push({ kind: "boundary", path, detail: `extension path has forbidden mode ${entry.mode}` });
    }
  }
  return findings;
}

export async function scanCriticalTree(repository: string, revision: string): Promise<readonly ExemplarFinding[]> {
  const tip = exactCommit(repository, revision);
  if (git(repository, ["rev-parse", "HEAD"]).trim() !== tip) {
    return [{ kind: "trust", path: ".", detail: "critical scan requires the target checkout at exact tip" }];
  }
  const criticalEntries = treeEntries(repository, tip).filter((candidate) => isCriticalPath(candidate.path));
  const dirty = git(repository, ["status", "--porcelain=v1", "--", ...criticalEntries.map((entry) => entry.path)]);
  if (dirty.trim()) return [{ kind: "trust", path: ".", detail: "critical target paths are dirty" }];

  const typeScriptPaths = criticalEntries.filter((entry) => entry.path.endsWith(".ts")).map((entry) => entry.path);
  const api = new API();
  const snapshot = await api.updateSnapshot({ openFiles: typeScriptPaths.map((path) => resolve(repository, path)) });
  const findings: ExemplarFinding[] = [];
  try {
    for (const entry of criticalEntries) {
      if (entry.type !== "blob" || (entry.mode !== "100644" && entry.mode !== "100755")) {
        findings.push({ kind: "trust", path: entry.path, detail: `critical path has forbidden mode ${entry.mode}` });
        continue;
      }
      const text = blobText(repository, tip, entry.path);
      findings.push(...commentMarkers(entry.path, text));
      if (entry.path.endsWith(".ts")) {
        const absolute = resolve(repository, entry.path);
        const project = await snapshot.getDefaultProjectForFile(absolute);
        const source = await project?.program.getSourceFile(absolute);
        if (!source || source.text !== text) {
          findings.push({ kind: "trust", path: entry.path, detail: "TypeScript parser snapshot does not match committed bytes" });
        } else {
          findings.push(...typescriptFindings(entry.path, source));
        }
      }
    }
  } finally {
    await snapshot.dispose();
    await api.close();
  }
  return findings;
}

export function assertTrustedVerifierCheckout(trustedRoot: string, baseRevision: string): void {
  const base = exactCommit(trustedRoot, baseRevision);
  const head = git(trustedRoot, ["rev-parse", "HEAD"]).trim();
  if (head !== base) throw new Error(`trusted verifier checkout must be at exact base ${base}`);
  const dirty = git(trustedRoot, ["status", "--porcelain=v1", "--", ...proofPaths]);
  if (dirty.trim()) throw new Error("trusted verifier or harness path is dirty");
  for (const path of proofPaths.slice(0, 3)) {
    const committed = git(trustedRoot, ["show", `${base}:${path}`]);
    if (committed !== readFileSync(resolve(trustedRoot, path), "utf8")) {
      throw new Error(`trusted verifier bytes differ from base: ${path}`);
    }
  }
}

export function formatFindings(findings: readonly ExemplarFinding[]): string {
  return findings.map((finding) => `${finding.kind}: ${finding.path}: ${finding.detail}`).join("\n");
}
